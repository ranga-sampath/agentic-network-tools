"""
providers.py — Shell and Azure provider for the Effective Network Inspector.

LocalShell:            Thin subprocess wrapper for standalone CLI mode.
                       Identical contract to SafeExecShell.
                       Copied verbatim from netfilter-inspector/firewall-inspector/providers.py.

AzureNetworkProvider:  Queries Azure control-plane computed network state.
                       get_nic_names_for_vm()   — NIC names attached to a VM
                       get_nic_names_for_vnet() — NIC names whose subnets are in a VNet
                       get_effective_routes_json()  — az network nic show-effective-route-table
                       get_effective_nsg_json()     — az network nic list-effective-nsg

Both methods require Network Contributor (not Reader) on the resource group:
    Microsoft.Network/networkInterfaces/effectiveRouteTable/action
    Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action
A clear RBAC error is raised when AuthorizationFailed appears in az output.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------

class ProviderError(RuntimeError):
    """Base class for all AzureNetworkProvider errors."""


class RBACError(ProviderError):
    """The identity running this tool lacks a required Azure RBAC permission.

    The caller should surface the full message to the operator — it identifies
    which permission is needed and how to grant it.
    """


class ThrottleExhausted(ProviderError):
    """Azure API throttled (HTTP 429) and all retry attempts were exhausted.

    The caller should back off or reduce concurrent NIC query load and retry.
    """


# ---------------------------------------------------------------------------
# Shell protocol — same contract as SafeExecShell
# ---------------------------------------------------------------------------

@runtime_checkable
class ShellProtocol(Protocol):
    def execute(self, cmd: dict) -> dict:
        """
        Execute a command.

        Args:
            cmd: dict with at least "command" (list[str]) key — an argument vector.
                 No shell=True; the first element must be the executable name.
                 Optional: "reasoning" (str) for HITL display.

        Returns:
            {
                "status":    "success" | "error" | "denied",
                "output":    str,
                "exit_code": int,
                "audit_id":  str,
            }
        """
        ...


# ---------------------------------------------------------------------------
# LocalShell
# ---------------------------------------------------------------------------

class LocalShell:
    """
    Thin subprocess wrapper for standalone CLI mode.

    Commands must be passed as argument vectors (list[str]) — shell=False is enforced.
    This eliminates shell injection risk from interpolated resource names.

    Creates a _commands.log in audit_dir with one JSON entry per execute() call.
    Log entries record: timestamp, command vector, exit code, output byte count.
    Full command output is NOT logged — the snapshot file captures relevant results.

    audit_dir and session_id are both required to enable logging.
    """

    def __init__(self, audit_dir: str | None = None, session_id: str | None = None):
        self._log_path: Path | None = None
        if audit_dir and session_id:
            audit = Path(audit_dir)
            audit.mkdir(parents=True, exist_ok=True)
            self._log_path = audit / f"{session_id}_commands.log"

    def execute(self, cmd: dict) -> dict:
        command: list[str] = cmd.get("command", [])
        try:
            proc = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            stdout    = proc.stdout
            output    = proc.stdout + proc.stderr
            status    = "success" if proc.returncode == 0 else "error"
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            stdout    = ""
            output    = "command timed out after 120 seconds"
            status    = "error"
            exit_code = -1

        self._log(command, exit_code, len(output.encode("utf-8", errors="replace")))

        return {
            "status":    status,
            "output":    output,   # stdout+stderr combined (general use, error display)
            "stdout":    stdout,   # stdout only (az CLI JSON lives here; stderr has warnings)
            "exit_code": exit_code,
            "audit_id":  "local",
        }

    def _log(self, command: list[str], exit_code: int, output_bytes: int) -> None:
        if self._log_path is None:
            return
        try:
            entry = json.dumps({
                "ts":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "command":      " ".join(command),
                "exit_code":    exit_code,
                "output_bytes": output_bytes,
            })
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(entry + "\n")
        except OSError:
            pass  # log failure must never abort the investigation


# ---------------------------------------------------------------------------
# AzureNetworkProvider
# ---------------------------------------------------------------------------

_RBAC_ERROR_MARKERS    = ("AuthorizationFailed", "does not have authorization")
_THROTTLE_MARKERS      = ("(429)", "Too Many Requests", "ThrottlingException", "RequestThrottled")


def _check_rbac(output: str, operation: str) -> None:
    """Raise RBACError with a clear message if az output signals auth failure."""
    for marker in _RBAC_ERROR_MARKERS:
        if marker in output:
            raise RBACError(
                f"RBAC error on {operation}. "
                f"The identity running this tool lacks the required action. "
                f"Assign 'Network Contributor' role (or a custom role with "
                f"Microsoft.Network/networkInterfaces/effectiveRouteTable/action and "
                f"Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action) "
                f"on the resource group. az output: {output[:300]}"
            )


def _is_throttled(output: str) -> bool:
    """Return True if az CLI output indicates an HTTP 429 throttle response."""
    return any(m in output for m in _THROTTLE_MARKERS)


def _execute_with_retry(
    shell: "ShellProtocol",
    cmd: dict,
    operation: str,
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> dict:
    """Execute cmd via shell, retrying on HTTP 429 with exponential backoff.

    Only throttle (HTTP 429) responses are retried. All other failures surface
    immediately to the caller. Raises ThrottleExhausted if every attempt returns
    a throttle error.

    Back-off schedule (base_delay=2.0): 2 s, 4 s, 8 s.
    Total wall-clock wait before ThrottleExhausted with max_retries=3: ≤14 s.
    """
    for attempt in range(max_retries + 1):
        result = shell.execute(cmd)
        if result["exit_code"] != 0 and _is_throttled(result.get("output", "")):
            if attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
                continue
            raise ThrottleExhausted(
                f"Azure API throttled (HTTP 429) for {operation} "
                f"after {max_retries} retries. "
                f"Wait and retry, or reduce concurrent NIC query load. "
                f"az output: {result.get('output', '')[:200]}"
            )
        return result
    # unreachable — loop always returns or raises; silences mypy
    return result  # type: ignore[return-value]


class AzureNetworkProvider:
    """
    Queries Azure control-plane computed network state for one or more NICs.

    All az CLI commands are routed through the injected shell. In standalone
    CLI mode this is LocalShell; in Ghost Agent mode this is SafeExecShell.

    Both effective-state operations require Network Contributor (not Reader):
        az network nic show-effective-route-table
        az network nic list-effective-nsg
    """

    def __init__(
        self,
        shell: ShellProtocol,
        resource_group: str,
        subscription_id: str | None = None,
    ):
        self._shell    = shell
        self._rg       = resource_group
        self._sub_args: list[str] = ["--subscription", subscription_id] if subscription_id else []

    # ------------------------------------------------------------------
    # NIC discovery
    # ------------------------------------------------------------------

    def get_nic_names_for_vm(self, vm_name: str) -> list[str]:
        """
        Return the list of NIC names attached to the named VM.

        Uses az vm nic list to retrieve NIC resource IDs, then extracts
        the NIC name from the last segment of each resource ID.

        Raises RuntimeError if the az call fails or no NICs are found.
        """
        cmd = [
            "az", "vm", "nic", "list",
            "--resource-group", self._rg,
            "--vm-name", vm_name,
            "--query", "[].id",
            "--output", "json",
        ] + self._sub_args
        r = _execute_with_retry(self._shell, {
            "command":   cmd,
            "reasoning": f"Discover NICs attached to VM {vm_name}",
        }, operation=f"az vm nic list for {vm_name}")
        if r["exit_code"] != 0:
            _check_rbac(r["output"], f"az vm nic list for {vm_name}")
            raise ProviderError(
                f"NIC discovery failed for VM {vm_name}: {r['output'][:200]}"
            )
        raw = r.get("stdout", r["output"]).strip()
        if not raw:
            return []

        ids: list = json.loads(raw)
        if not ids:
            return []

        # Resource ID format: .../providers/Microsoft.Network/networkInterfaces/<nic-name>
        return [rid.split("/")[-1] for rid in ids]

    def get_nic_names_for_vnet(self, vnet_id: str) -> list[str]:
        """
        Return NIC names for all NICs attached to subnets within the given VNet.

        Uses az network vnet subnet list to enumerate subnets, then extracts NIC
        names from ipConfigurations[].id in each subnet's response. This traversal
        correctly discovers NICs regardless of which resource group they live in.

        vnet_id: full Azure resource ID of the VNet, e.g.:
            /subscriptions/.../resourceGroups/.../providers/Microsoft.Network/virtualNetworks/my-vnet

        Raises ProviderError if the az call fails.
        Returns an empty list (not an error) if no NICs are found in the VNet.

        Note: Returns NIC names only. Cross-resource-group queries (hub-spoke) use
        the provider's default resource_group for effective-state calls; full cross-RG
        support (passing per-NIC RG to get_effective_routes_json) is a future enhancement.
        """
        # Parse VNet name and resource group from the ARM resource ID
        # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{name}
        parts = vnet_id.split("/")
        vnet_name = parts[-1]
        try:
            rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
            vnet_rg = parts[rg_idx + 1]
        except (StopIteration, IndexError):
            vnet_rg = self._rg  # fall back to provider default if ID is malformed

        cmd = [
            "az", "network", "vnet", "subnet", "list",
            "--vnet-name", vnet_name,
            "--resource-group", vnet_rg,
            "--output", "json",
        ] + self._sub_args
        r = _execute_with_retry(self._shell, {
            "command":   cmd,
            "reasoning": f"List subnets in VNet {vnet_name} to discover attached NICs",
        }, operation=f"az network vnet subnet list for {vnet_name}")
        if r["exit_code"] != 0:
            _check_rbac(r["output"], f"az network vnet subnet list for {vnet_name}")
            raise ProviderError(
                f"Subnet list failed for VNet {vnet_name} in resource group {vnet_rg}: "
                f"{r['output'][:200]}"
            )

        raw = r.get("stdout", r["output"]).strip()
        if not raw:
            return []

        subnets: list = json.loads(raw)
        seen: set[str] = set()
        result: list[str] = []
        for subnet in subnets:
            for ip_cfg in subnet.get("ipConfigurations", []):
                ip_cfg_id = ip_cfg.get("id", "")
                # ipConfig ID format:
                # /subscriptions/{sub}/resourceGroups/{nic_rg}/providers/
                #   Microsoft.Network/networkInterfaces/{nic_name}/ipConfigurations/{cfg_name}
                id_parts = ip_cfg_id.split("/")
                try:
                    ni_idx = next(
                        i for i, p in enumerate(id_parts)
                        if p.lower() == "networkinterfaces"
                    )
                    nic_name = id_parts[ni_idx + 1]
                except (StopIteration, IndexError):
                    continue
                if nic_name not in seen:
                    seen.add(nic_name)
                    result.append(nic_name)
        return result

    # ------------------------------------------------------------------
    # Effective state queries — return raw JSON strings
    # ------------------------------------------------------------------

    def get_effective_routes_json(self, nic_name: str) -> str:
        """
        Call az network nic show-effective-route-table and return raw JSON string.

        Requires: Microsoft.Network/networkInterfaces/effectiveRouteTable/action
        (Network Contributor or equivalent — not included in Reader).

        Raises RuntimeError on failure; includes a clear RBAC message when
        AuthorizationFailed appears in az output.
        """
        cmd = [
            "az", "network", "nic", "show-effective-route-table",
            "--resource-group", self._rg,
            "--name", nic_name,
            "--output", "json",
        ] + self._sub_args
        r = _execute_with_retry(self._shell, {
            "command":   cmd,
            "reasoning": f"Get effective route table for NIC {nic_name}",
        }, operation=f"az network nic show-effective-route-table for {nic_name}")
        if r["exit_code"] != 0:
            _check_rbac(r["output"], f"az network nic show-effective-route-table for {nic_name}")
            raise ProviderError(
                f"Effective route table query failed for NIC {nic_name}: {r['output'][:200]}"
            )
        return r.get("stdout", r["output"])

    def get_effective_nsg_json(self, nic_name: str) -> str:
        """
        Call az network nic list-effective-nsg and return raw JSON string.

        Requires: Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action
        (Network Contributor or equivalent — not included in Reader).

        Raises RuntimeError on failure; includes a clear RBAC message when
        AuthorizationFailed appears in az output.
        """
        cmd = [
            "az", "network", "nic", "list-effective-nsg",
            "--resource-group", self._rg,
            "--name", nic_name,
            "--output", "json",
        ] + self._sub_args
        r = _execute_with_retry(self._shell, {
            "command":   cmd,
            "reasoning": f"Get effective NSG rules for NIC {nic_name}",
        }, operation=f"az network nic list-effective-nsg for {nic_name}")
        if r["exit_code"] != 0:
            _check_rbac(r["output"], f"az network nic list-effective-nsg for {nic_name}")
            raise ProviderError(
                f"Effective NSG query failed for NIC {nic_name}: {r['output'][:200]}"
            )
        return r.get("stdout", r["output"])
