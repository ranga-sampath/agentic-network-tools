"""Cloud provider abstraction for Agentic Pipe Meter.

CloudProvider   — typing.Protocol defining the four required methods.
AzureProvider   — Azure implementation; all az CLI calls route through an
                  injected SafeExecShell so they are classified, gated if
                  RISKY, and audit-logged by the shell layer.

Design note: generate_port_open_commands requires dest_ip to look up the
NIC and its attached NSG. The Protocol includes dest_ip for this reason,
consistent with the preflight stage's available context (config.dest_ip).
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol, runtime_checkable

# SSH options used when routing blob operations through the source VM.
# Matches _SSH_BASE_OPTS in pipe_meter.py.
_SSH_BLOB_OPTS = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new"


# ---------------------------------------------------------------------------
# CloudProvider Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class CloudProvider(Protocol):
    def check_nsg_ports(
        self, source_ip: str, dest_ip: str, ports: list[int]
    ) -> dict[int, bool]:
        """True = port is open for measurement traffic (inbound dest + outbound src)."""
        ...

    def generate_port_open_commands(
        self, resource_group: str, dest_ip: str, ports: list[int]
    ) -> list[str]:
        """Return display-only az nsg rule create strings. Never execute them."""
        ...

    def read_blob(
        self, account: str, container: str, blob_name: str
    ) -> Optional[bytes]:
        """Return raw bytes, or None if the blob does not exist."""
        ...

    def write_blob(
        self, account: str, container: str, blob_name: str, data: bytes
    ) -> str:
        """Upload data and return the blob URL."""
        ...


# ---------------------------------------------------------------------------
# Port-range helper (used by _parse_effective_nsg and _find_safe_nsg_priority)
# ---------------------------------------------------------------------------

def _port_in_range(port: int, rule: dict) -> bool:
    """Return True if port matches the rule's destination port range(s)."""

    def _matches(range_str: str) -> bool:
        if range_str == "*":
            return True
        if range_str == str(port):
            return True
        if "-" in range_str:
            parts = range_str.split("-", 1)
            try:
                low, high = int(parts[0]), int(parts[1])
                return low <= port <= high
            except (ValueError, IndexError):
                return False
        return False

    if _matches(rule.get("destinationPortRange", "")):
        return True
    for r in rule.get("destinationPortRanges", []):
        if _matches(r):
            return True
    return False


# ---------------------------------------------------------------------------
# AzureProvider
# ---------------------------------------------------------------------------

class AzureProvider:
    """Azure implementation of CloudProvider.

    All az CLI commands are routed through the injected SafeExecShell so that
    read-only commands pass silently and mutative commands hit the HITL gate.
    """

    def __init__(
        self,
        shell,
        resource_group: str,
        subscription_id: Optional[str] = None,
        ssh_user: Optional[str] = None,
        source_public_ip: Optional[str] = None,
        source_vm_key_path: Optional[str] = None,
    ) -> None:
        self._shell = shell
        self._rg = resource_group
        self._sub = f" --subscription {subscription_id}" if subscription_id else ""
        # SSH prefix used to route blob ops through the source VM (inside VNet).
        # Set only when all three SSH params are provided.
        if ssh_user and source_public_ip:
            key_opt = f"-i {source_vm_key_path} " if source_vm_key_path else ""
            self._ssh_prefix = (
                f"ssh {key_opt}{_SSH_BLOB_OPTS} {ssh_user}@{source_public_ip}"
            )
            self._scp_prefix = f"scp {key_opt}{_SSH_BLOB_OPTS}"
            self._ssh_target = f"{ssh_user}@{source_public_ip}"
        else:
            self._ssh_prefix = None
            self._scp_prefix = None
            self._ssh_target = None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_nic_name(self, vm_ip: str) -> str:
        """Resolve a VM private IP to its NIC name within the resource group."""
        cmd = (
            f"az network nic list --resource-group {self._rg}{self._sub} "
            f"--query \"[?ipConfigurations[?privateIPAddress=='{vm_ip}']].name\" "
            f"--output tsv"
        )
        r = self._shell.execute({
            "command": cmd,
            "reasoning": f"Resolve IP {vm_ip} to NIC name in resource group {self._rg}",
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"NIC lookup failed for IP {vm_ip} in resource group {self._rg}: "
                f"{r['output'][:200]}"
            )
        lines = [ln.strip() for ln in r["output"].splitlines() if ln.strip()]
        if len(lines) == 0:
            raise RuntimeError(
                f"No NIC found for IP {vm_ip} in resource group {self._rg}"
            )
        if len(lines) > 1:
            raise RuntimeError(
                f"Ambiguous: {len(lines)} NICs matched IP {vm_ip} in resource group "
                f"{self._rg}. IPs may be reused across VNets. Resolve by scoping to a "
                f"single VNet or specifying the NIC name directly."
            )
        return lines[0]

    def _get_nsg_name(self, nic_name: str) -> str:
        """Return the NSG name associated with a NIC."""
        cmd = (
            f"az network nic show --resource-group {self._rg}{self._sub} "
            f"--name {nic_name} "
            f"--query \"networkSecurityGroup.id\" --output tsv"
        )
        r = self._shell.execute({
            "command": cmd,
            "reasoning": f"Get NSG attached to NIC {nic_name}",
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"NIC show failed for {nic_name}: {r['output'][:200]}"
            )
        resource_id = r["output"].strip()
        if not resource_id:
            raise RuntimeError(f"NIC {nic_name} has no NSG attached")
        return resource_id.split("/")[-1]

    def _get_effective_nsg_json(self, nic_name: str) -> str:
        """Call az network nic list-effective-nsg and return raw JSON string."""
        cmd = (
            f"az network nic list-effective-nsg --resource-group {self._rg}{self._sub} "
            f"--name {nic_name} --output json"
        )
        r = self._shell.execute({
            "command": cmd,
            "reasoning": f"Get effective NSG rules for NIC {nic_name}",
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"Effective NSG query failed for NIC {nic_name}: {r['output'][:200]}"
            )
        return r["output"]

    def _parse_effective_nsg(
        self, nsg_json: str, ports: list[int], direction: str = "Inbound"
    ) -> dict[int, bool]:
        """Parse effective NSG JSON; return {port: True/False} for each port.

        Walks effectiveSecurityRules in priority order (ascending = first match
        wins). Returns True if the first matching rule for a port is Allow;
        False if it is Deny or no rule matched (default deny).

        The `direction` parameter selects "Inbound" (default) or "Outbound".
        AZP tests always invoke with the default (Inbound).
        """
        data = json.loads(nsg_json)

        # Normalise: accept a raw list of rules, or Azure's nested envelope.
        if isinstance(data, list):
            rules = data
        elif "networkSecurityGroups" in data:
            rules = []
            for nsg in data["networkSecurityGroups"]:
                rules.extend(nsg.get("effectiveSecurityRules", []))
        elif "value" in data:
            rules = []
            for entry in data["value"]:
                nsg = entry.get("networkSecurityGroup", {})
                rules.extend(nsg.get("effectiveSecurityRules", []))
                rules.extend(entry.get("effectiveSecurityRules", []))
        else:
            rules = []

        # Sort ascending by priority — lower number = processed first.
        rules_sorted = sorted(rules, key=lambda r: int(r.get("priority", 65535)))

        result: dict[int, bool] = {}
        for port in ports:
            result[port] = False  # default deny
            for rule in rules_sorted:
                proto = rule.get("protocol", "")
                rule_dir = rule.get("direction", "")
                if rule_dir != direction:
                    continue
                if proto not in ("Tcp", "*", "All"):
                    continue
                if not _port_in_range(port, rule):
                    continue
                result[port] = rule.get("access", "Deny") == "Allow"
                break

        return result

    def _find_safe_nsg_priority(self, nsg_name: str, ports: list[int]) -> int:
        """Compute a collision-free priority for a new ALLOW rule.

        Algorithm per design §11:
        1. Fetch all user-defined security rules for the NSG.
        2. Find the minimum priority of any INBOUND DENY rule covering any target port.
        3. Place the new ALLOW rule 10 below that DENY (fires first).
        4. If no DENY rule exists, use 200 as the default.
        5. Decrement by 1 up to 10 times to avoid collisions with existing rules.
        """
        cmd = (
            f"az network nsg show --resource-group {self._rg}{self._sub} "
            f"--name {nsg_name} --query \"securityRules\" --output json"
        )
        r = self._shell.execute({
            "command": cmd,
            "reasoning": f"Scan NSG {nsg_name} to find a safe rule priority",
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"NSG rule scan failed for {nsg_name}: {r['output'][:200]}"
            )

        rules: list[dict] = json.loads(r["output"]) if r["output"].strip() else []

        existing_priorities = {int(rule.get("priority", 0)) for rule in rules}

        deny_priorities: list[int] = [
            int(rule["priority"])
            for rule in rules
            if rule.get("access") == "Deny"
            and rule.get("direction") == "Inbound"
            and any(_port_in_range(p, rule) for p in ports)
        ]

        if deny_priorities:
            target_priority = min(deny_priorities) - 10
            if target_priority < 100:
                raise RuntimeError(
                    f"Cannot place ALLOW rule above DENY at priority "
                    f"{min(deny_priorities)}. The DENY rule is already at Azure's "
                    f"minimum user priority (100). Manual NSG editing is required."
                )
        else:
            target_priority = 200

        # Collision avoidance: decrement by 1 up to 10 times.
        # Lower bound: Azure rejects user-defined rules with priority < 100.
        for _ in range(10):
            if target_priority < 100:
                raise RuntimeError(
                    f"Cannot find a free NSG priority >= 100 near "
                    f"{target_priority + 10}. Manual editing required."
                )
            if target_priority not in existing_priorities:
                return target_priority
            target_priority -= 1

        raise RuntimeError(
            f"Cannot find a free NSG priority near {target_priority + 10}. "
            f"Manual editing required."
        )

    # ------------------------------------------------------------------
    # CloudProvider protocol implementation
    # ------------------------------------------------------------------

    def check_nsg_ports(
        self, source_ip: str, dest_ip: str, ports: list[int]
    ) -> dict[int, bool]:
        """Return {port: True} only if inbound open on dest AND outbound open on source."""
        dest_nic = self._get_nic_name(dest_ip)
        dest_json = self._get_effective_nsg_json(dest_nic)
        dest_inbound = self._parse_effective_nsg(dest_json, ports, direction="Inbound")

        src_nic = self._get_nic_name(source_ip)
        src_json = self._get_effective_nsg_json(src_nic)
        src_outbound = self._parse_effective_nsg(src_json, ports, direction="Outbound")

        return {port: dest_inbound[port] and src_outbound[port] for port in ports}

    def generate_port_open_commands(
        self, resource_group: str, dest_ip: str, ports: list[int]
    ) -> list[str]:
        """Return display-only az nsg rule create strings for each blocked port.

        These strings are printed to the operator for review and then passed
        individually to shell.execute() — which gates them as RISKY.
        """
        dest_nic = self._get_nic_name(dest_ip)
        nsg_name = self._get_nsg_name(dest_nic)
        commands: list[str] = []
        for port in ports:
            priority = self._find_safe_nsg_priority(nsg_name, [port])
            commands.append(
                f"az network nsg rule create "
                f"--resource-group {resource_group} "
                f"--nsg-name {nsg_name} "
                f"--name AllowPipeMeter{port} "
                f"--priority {priority} "
                f"--direction Inbound "
                f"--access Allow "
                f"--protocol Tcp "
                f"--destination-port-ranges {port}"
                f"{self._sub}"
            )
        return commands

    def read_blob(
        self, account: str, container: str, blob_name: str
    ) -> Optional[bytes]:
        """Download a blob and return its bytes, or None if it does not exist.

        Routes through the source VM via SSH when SSH params were supplied to
        __init__ (required when the local machine is blocked by the storage
        network firewall but the source VM is in a whitelisted subnet).
        """
        if self._ssh_prefix:
            return self._read_blob_via_ssh(account, container, blob_name)
        return self._read_blob_local(account, container, blob_name)

    def write_blob(
        self, account: str, container: str, blob_name: str, data: bytes
    ) -> str:
        """Upload bytes to blob storage and return the blob URL.

        Routes through the source VM via SSH when SSH params were supplied to
        __init__ (required when the local machine is blocked by the storage
        network firewall but the source VM is in a whitelisted subnet).
        """
        if self._ssh_prefix:
            return self._write_blob_via_ssh(account, container, blob_name, data)
        return self._write_blob_local(account, container, blob_name, data)

    # ------------------------------------------------------------------
    # Blob helpers — local (original) path
    # ------------------------------------------------------------------

    def _read_blob_local(
        self, account: str, container: str, blob_name: str
    ) -> Optional[bytes]:
        """Download a blob locally and return its bytes, or None if not found."""
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="pmeter_blob_")
        os.close(tmp_fd)
        try:
            cmd = (
                f"az storage blob download "
                f"--account-name {account} "
                f"--container-name {container} "
                f"--name {blob_name} "
                f"--file {tmp_path} "
                f"--auth-mode login "
                f"--no-progress"
                f"{self._sub}"
            )
            r = self._shell.execute({
                "command": cmd,
                "reasoning": f"Download baseline blob {blob_name}",
            })
            if r["exit_code"] == 0:
                with open(tmp_path, "rb") as fh:
                    return fh.read()
            output = r["output"] or r.get("stderr", "")
            if r["exit_code"] == 3 or "BlobNotFound" in output or "not found" in output.lower():
                return None
            if "AuthorizationPermissionMismatch" in output or "403" in output:
                raise RuntimeError(
                    "Storage auth failed. Ensure 'az login' is current or identity "
                    "has Storage Blob Data Contributor role."
                )
            raise RuntimeError(f"Blob download failed: {output[:300] or '(no output)'}")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _write_blob_local(
        self, account: str, container: str, blob_name: str, data: bytes
    ) -> str:
        """Upload bytes to blob storage locally and return the blob URL."""
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="pmeter_blob_")
        os.close(tmp_fd)
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(data)
            cmd = (
                f"az storage blob upload "
                f"--account-name {account} "
                f"--container-name {container} "
                f"--name {blob_name} "
                f"--file {tmp_path} "
                f"--overwrite true "
                f"--auth-mode login"
                f"{self._sub}"
            )
            r = self._shell.execute({
                "command": cmd,
                "reasoning": f"Upload result artifact as {blob_name}",
            })
            if r["exit_code"] != 0:
                detail = r["output"] or r.get("stderr", "") or "(no output)"
                raise RuntimeError(f"Blob upload failed: {detail[:300]}")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return f"https://{account}.blob.core.windows.net/{container}/{blob_name}"

    # ------------------------------------------------------------------
    # Blob helpers — via source VM SSH (used when local machine is
    # blocked by the storage account network firewall)
    # ------------------------------------------------------------------

    def _generate_sas_url(
        self,
        account: str,
        container: str,
        blob_name: str,
        permissions: str = "racw",
        expiry_minutes: int = 60,
    ) -> str:
        """Generate a SAS URL for direct blob access from inside the VNet.

        Step 1 runs locally (management plane, not firewalled by storage
        network rules). Step 2 is a local HMAC computation — no network call.
        Returns a full https://…blob.core.windows.net/…?sas_token URL.
        """
        expiry = (
            datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        ).strftime("%Y-%m-%dT%H:%MZ")

        # Step 1: get storage account key (management plane — not blocked)
        keys_cmd = (
            f"az storage account keys list "
            f"--account-name {account} "
            f"--resource-group {self._rg}"
            f"{self._sub} "
            f"--query \"[0].value\" --output tsv"
        )
        r = self._shell.execute({
            "command": keys_cmd,
            "reasoning": (
                f"Retrieve storage account key for {account} "
                f"to generate SAS token (management plane call, not firewalled)"
            ),
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"Failed to retrieve storage account key for {account}: "
                f"{r['output'][:300]}"
            )
        account_key = r["output"].strip()

        # Step 2: generate SAS token locally (HMAC computation — no network call)
        sas_cmd = (
            f"az storage blob generate-sas "
            f"--account-name {account} "
            f"--account-key \"{account_key}\" "
            f"--container-name {container} "
            f"--name {blob_name} "
            f"--permissions {permissions} "
            f"--expiry {expiry} "
            f"--output tsv"
        )
        r = self._shell.execute({
            "command": sas_cmd,
            "reasoning": (
                f"Generate SAS token for {blob_name} (local HMAC computation, "
                f"no network call to storage plane)"
            ),
        })
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"Failed to generate SAS token for {blob_name}: "
                f"{r['output'][:300]}"
            )
        sas_token = r["output"].strip()
        return (
            f"https://{account}.blob.core.windows.net"
            f"/{container}/{blob_name}?{sas_token}"
        )

    def _write_blob_via_ssh(
        self, account: str, container: str, blob_name: str, data: bytes
    ) -> str:
        """Upload bytes through the source VM using SAS token + curl:
        1. Generate SAS URL locally (management plane key fetch + local HMAC)
        2. SCP local temp file → source VM /tmp
        3. SSH: curl PUT to blob endpoint using SAS URL (no az on source VM needed)
        4. SSH: rm temp file from source VM (best effort)
        """
        sas_url = self._generate_sas_url(account, container, blob_name)
        remote_tmp = f"/tmp/pmeter_blob_{os.urandom(4).hex()}.json"
        local_fd, local_tmp = tempfile.mkstemp(suffix=".json", prefix="pmeter_blob_")
        os.close(local_fd)
        remote_copied = False
        try:
            with open(local_tmp, "wb") as fh:
                fh.write(data)

            # Step 2: copy data file to source VM
            r = self._shell.execute({
                "command": (
                    f"{self._scp_prefix} {local_tmp} {self._ssh_target}:{remote_tmp}"
                ),
                "reasoning": "Copy blob data to source VM for VNet-internal upload",
            })
            if r["exit_code"] != 0:
                detail = r["output"] or r.get("stderr", "") or "(no output)"
                raise RuntimeError(
                    f"Blob upload failed (SCP to source VM): {detail[:200]}"
                )
            remote_copied = True

            # Step 3: curl PUT from source VM (inside whitelisted VNet subnet)
            # curl is universally available on Linux — no az installation required
            curl_cmd = (
                f"curl -s -w '%{{http_code}}' -o /dev/null "
                f"-X PUT "
                f"-H 'x-ms-blob-type: BlockBlob' "
                f"-H 'Content-Type: application/octet-stream' "
                f"--data-binary @{remote_tmp} "
                f"'{sas_url}'"
            )
            r = self._shell.execute({
                "command": f"{self._ssh_prefix} \"{curl_cmd}\"",
                "reasoning": (
                    f"Upload {blob_name} from source VM via curl+SAS "
                    f"(whitelisted by storage network firewall; no az on VM needed)"
                ),
            })
            if r["exit_code"] != 0:
                detail = r["output"] or r.get("stderr", "") or "(no output)"
                raise RuntimeError(
                    f"Blob upload failed (curl on source VM): {detail[:300]}"
                )
            http_status = r["output"].strip()[-3:]
            if http_status not in ("200", "201"):
                raise RuntimeError(
                    f"Blob upload returned HTTP {http_status} "
                    f"(expected 201). SAS may have expired or lacks write permission."
                )
        finally:
            if os.path.exists(local_tmp):
                os.unlink(local_tmp)
            if remote_copied:
                # Step 4: clean up temp file on source VM (best effort)
                self._shell.execute({
                    "command": f'{self._ssh_prefix} "rm -f {remote_tmp}"',
                    "reasoning": "Remove temporary blob file from source VM",
                })

        return f"https://{account}.blob.core.windows.net/{container}/{blob_name}"

    def _read_blob_via_ssh(
        self, account: str, container: str, blob_name: str
    ) -> Optional[bytes]:
        """Download a blob through the source VM using SAS token + curl:
        1. Generate SAS URL locally (management plane key fetch + local HMAC)
        2. SSH: curl GET to blob endpoint → source VM /tmp (no az on VM needed)
        3. SCP source VM /tmp → local temp file
        4. SSH: rm temp file from source VM (best effort)
        """
        sas_url = self._generate_sas_url(account, container, blob_name, permissions="r")
        remote_tmp = f"/tmp/pmeter_blob_{os.urandom(4).hex()}.json"
        local_fd, local_tmp = tempfile.mkstemp(suffix=".json", prefix="pmeter_blob_")
        os.close(local_fd)
        remote_exists = False
        try:
            # Step 2: curl GET on source VM (inside whitelisted VNet subnet)
            curl_cmd = (
                f"curl -s -w '%{{http_code}}' -o {remote_tmp} "
                f"'{sas_url}'"
            )
            r = self._shell.execute({
                "command": f"{self._ssh_prefix} \"{curl_cmd}\"",
                "reasoning": f"Download baseline blob {blob_name} via curl+SAS on source VM",
            })
            if r["exit_code"] != 0:
                detail = r["output"] or r.get("stderr", "") or "(no output)"
                raise RuntimeError(
                    f"Blob download failed (curl on source VM): {detail[:300]}"
                )
            http_status = r["output"].strip()[-3:]
            if http_status == "404":
                return None
            if http_status in ("403", "401"):
                raise RuntimeError(
                    f"Storage auth failed (HTTP {http_status}). "
                    "Ensure the storage account key is valid and SAS has read permission."
                )
            if http_status != "200":
                raise RuntimeError(
                    f"Blob download returned HTTP {http_status} (expected 200)."
                )
            remote_exists = True

            # Step 3: retrieve the file to local machine
            r = self._shell.execute({
                "command": (
                    f"{self._scp_prefix} {self._ssh_target}:{remote_tmp} {local_tmp}"
                ),
                "reasoning": "Retrieve downloaded blob from source VM",
            })
            if r["exit_code"] != 0:
                detail = r["output"] or r.get("stderr", "") or "(no output)"
                raise RuntimeError(
                    f"Blob download failed (SCP from source VM): {detail[:200]}"
                )

            with open(local_tmp, "rb") as fh:
                return fh.read()
        finally:
            if os.path.exists(local_tmp):
                os.unlink(local_tmp)
            if remote_exists:
                # Step 4: clean up temp file on source VM (best effort)
                self._shell.execute({
                    "command": f'{self._ssh_prefix} "rm -f {remote_tmp}"',
                    "reasoning": "Remove temporary blob file from source VM",
                })
