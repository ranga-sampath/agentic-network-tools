"""
providers.py — Shell and cloud provider implementations for the VM Firewall Inspector.

LocalShell:       Thin subprocess wrapper used in standalone CLI mode.
                  Same execute() return contract as SafeExecShell.
                  No HITL, no audit log beyond _commands.log.

_BaseSSHProvider: Shared SSH/SCP operations (StrictHostKeyChecking, optional ProxyCommand,
                  retrieve_probe_output, cleanup_probe_output). Extended by both
                  AzureProvider and SSHProvider.

AzureProvider:    Extends _BaseSSHProvider. Runs the probe via az vm run-command invoke.
                  Use when the target is an Azure VM (Cases 1 and 2 — direct or via bastion).

SSHProvider:      Extends _BaseSSHProvider. Runs the probe via direct SSH (bash -s).
                  Use for any SSH-accessible Linux host: Multipass, bare metal, non-Azure VMs.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Shell protocol — same contract as SafeExecShell
# ---------------------------------------------------------------------------

@runtime_checkable
class ShellProtocol(Protocol):
    def execute(self, cmd: dict) -> dict:
        """
        Execute a command.

        Args:
            cmd: dict with at least "command" (str) key.
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

    Creates a _commands.log in audit_dir with one JSON entry per execute() call.
    Log entries record: timestamp, command string, exit code, output byte count.
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
        command = cmd.get("command", "")
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output   = proc.stdout + proc.stderr
            status   = "success" if proc.returncode == 0 else "error"
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            output    = "command timed out after 120 seconds"
            status    = "error"
            exit_code = -1

        self._log(command, exit_code, len(output.encode("utf-8", errors="replace")))

        return {
            "status":    status,
            "output":    output,
            "exit_code": exit_code,
            "audit_id":  "local",
        }

    def _log(self, command: str, exit_code: int, output_bytes: int) -> None:
        if self._log_path is None:
            return
        try:
            entry = json.dumps({
                "ts":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "command":      command,
                "exit_code":    exit_code,
                "output_bytes": output_bytes,
            })
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(entry + "\n")
        except OSError:
            pass  # log failure must never abort the investigation


# ---------------------------------------------------------------------------
# _BaseSSHProvider — shared SSH/SCP operations
# ---------------------------------------------------------------------------

class _BaseSSHProvider:
    """
    SSH/SCP operations shared by AzureProvider and SSHProvider.

    Provides: _ssh_opts(), _proxy_command(), retrieve_probe_output(),
    cleanup_probe_output(). Subclasses add run_probe().

    Two SSH topology cases are supported:

        Case 1 — Direct (target VM has a public IP):
            bastion_public_ip is None.  SCP/SSH go directly to target_vm_ip.

        Case 2 — Two-hop via bastion (target VM has only a private IP):
            bastion_public_ip is set.  SCP/SSH use a ProxyCommand through the
            bastion host.  bastion_ssh_key defaults to target_ssh_key when both
            hosts share the same key.

    SSH/SCP commands always include:
        -o StrictHostKeyChecking=yes
        -o BatchMode=yes
    known_hosts must contain entries for all hosts used before first run.
    """

    def __init__(
        self,
        shell: ShellProtocol,
        ssh_user: str,
        target_vm_ip: str,
        target_ssh_key_path: str,
        bastion_public_ip: str | None = None,
        bastion_ssh_key_path: str | None = None,
    ):
        self._shell             = shell
        self._ssh_user          = ssh_user
        self._target_vm_ip      = target_vm_ip
        self._target_ssh_key    = target_ssh_key_path
        self._bastion_public_ip = bastion_public_ip
        # bastion key defaults to target key when both hosts share the same key
        self._bastion_ssh_key   = bastion_ssh_key_path or target_ssh_key_path

    # ---------------------------------------------------------------------------
    # Shared SSH options — applied to every SCP and SSH command without exception
    # ---------------------------------------------------------------------------

    def _ssh_opts(self) -> str:
        return (
            f"-o StrictHostKeyChecking=yes "
            f"-o BatchMode=yes "
            f"-i \"{self._target_ssh_key}\""
        )

    def _proxy_command(self) -> str:
        """
        Return a ProxyCommand option string for two-hop access (Case 2), or an
        empty string when the target is directly reachable (Case 1).

        ProxyCommand is used instead of ProxyJump so that a separate -i key can
        be specified for the bastion hop without relying on agent forwarding.
        """
        if not self._bastion_public_ip:
            return ""
        return (
            f'-o "ProxyCommand=ssh -W %h:%p'
            f" -i '{self._bastion_ssh_key}'"
            f" -o StrictHostKeyChecking=yes"
            f" -o BatchMode=yes"
            f' {self._ssh_user}@{self._bastion_public_ip}"'
        )

    # ---------------------------------------------------------------------------
    # Retrieval
    # ---------------------------------------------------------------------------

    def retrieve_probe_output(
        self,
        remote_path: str,
        local_path: str,
    ) -> None:
        """
        Retrieve the probe output file from the target VM via SCP.

        Case 1 (direct): SCP goes directly to target_vm_ip.
        Case 2 (two-hop): SCP tunnels through the bastion via ProxyCommand.

        Requires known_hosts entries for all hosts used.
        Raises RuntimeError on failure.
        """
        proxy = self._proxy_command()
        cmd_parts = ["scp", self._ssh_opts()]
        if proxy:
            cmd_parts.append(proxy)
        cmd_parts.append(f"{self._ssh_user}@{self._target_vm_ip}:{remote_path}")
        cmd_parts.append(f'"{local_path}"')
        cmd = " ".join(cmd_parts)

        result = self._shell.execute({
            "command":   cmd,
            "reasoning": f"Retrieve probe output from {self._target_vm_ip}:{remote_path}",
        })
        if result["status"] == "denied":
            raise RuntimeError("SCP retrieval denied by safety shell")
        if result["exit_code"] != 0:
            raise RuntimeError(
                f"SCP retrieval failed (exit {result['exit_code']}): "
                f"{result['output'][:200]}"
            )

    # ---------------------------------------------------------------------------
    # Cleanup
    # ---------------------------------------------------------------------------

    def cleanup_probe_output(
        self,
        remote_path: str,
    ) -> bool:
        """
        Remove probe output file from target VM via SSH.

        Case 1 (direct): SSH goes directly to target_vm_ip.
        Case 2 (two-hop): SSH tunnels through the bastion via ProxyCommand.

        Returns True on success, False on failure (warning only — caller logs and
        continues; investigation result is valid regardless of cleanup outcome).
        """
        proxy = self._proxy_command()
        cmd_parts = ["ssh", self._ssh_opts()]
        if proxy:
            cmd_parts.append(proxy)
        cmd_parts.append(f"{self._ssh_user}@{self._target_vm_ip}")
        cmd_parts.append(f'rm -f "{remote_path}"')
        cmd = " ".join(cmd_parts)

        result = self._shell.execute({
            "command":   cmd,
            "reasoning": f"Clean up probe temp file {remote_path} on {self._target_vm_ip}",
        })
        return result["exit_code"] == 0


# ---------------------------------------------------------------------------
# AzureProvider
# ---------------------------------------------------------------------------

class AzureProvider(_BaseSSHProvider):
    """
    Provides Azure-specific operations for the VM Firewall Inspector.

    Runs the probe via az vm run-command invoke (Azure control plane).
    All commands are issued through the injected shell, which may be LocalShell
    (standalone mode) or SafeExecShell (Ghost Agent mode).

    Inherits SSH/SCP operations from _BaseSSHProvider.
    """

    def __init__(
        self,
        shell: ShellProtocol,
        resource_group: str,
        ssh_user: str,
        target_vm_ip: str,
        target_ssh_key_path: str,
        subscription_id: str | None = None,
        bastion_public_ip: str | None = None,
        bastion_ssh_key_path: str | None = None,
    ):
        super().__init__(
            shell                = shell,
            ssh_user             = ssh_user,
            target_vm_ip         = target_vm_ip,
            target_ssh_key_path  = target_ssh_key_path,
            bastion_public_ip    = bastion_public_ip,
            bastion_ssh_key_path = bastion_ssh_key_path,
        )
        self._resource_group  = resource_group
        self._subscription_id = subscription_id

    # ---------------------------------------------------------------------------
    # Probe execution
    # ---------------------------------------------------------------------------

    def run_probe(
        self,
        vm_name: str,
        session_id: str,
        ssh_user: str,
        probe_script: str,
    ) -> dict:
        """
        Run the probe script on the target VM via az vm run-command invoke.

        The probe script is written to a local temp file and passed via @filename.
        This avoids shell-escaping the multi-line script inline.

        Returns the parsed stdout from the probe:
            {"probe_output_path": str, "probe_output_bytes": int}

        Raises RuntimeError if the run-command call fails or output cannot be parsed.
        """
        probe_tmp: str | None = None
        try:
            # Write probe to local temp file — cleaned up in finally
            fd, probe_tmp = tempfile.mkstemp(suffix=".sh", prefix="fw_probe_")
            os.close(fd)
            Path(probe_tmp).write_text(probe_script, encoding="utf-8")
            os.chmod(probe_tmp, 0o600)

            sub_flag = f" --subscription {self._subscription_id}" if self._subscription_id else ""
            cmd = (
                f"az vm run-command invoke"
                f"{sub_flag}"
                f" --resource-group {self._resource_group}"
                f" --name {vm_name}"
                f" --command-id RunShellScript"
                f" --scripts @{probe_tmp}"
                f" --parameters {session_id} {ssh_user}"
            )
            result = self._shell.execute({
                "command":   cmd,
                "reasoning": f"Run firewall probe on {vm_name} (session {session_id})",
            })

            if result["status"] == "denied":
                raise RuntimeError("Probe command denied by safety shell")
            if result["exit_code"] != 0:
                raise RuntimeError(
                    f"run-command invoke failed (exit {result['exit_code']}): "
                    f"{result['output'][:200]}"
                )

            return _parse_probe_response(result["output"])

        finally:
            if probe_tmp and Path(probe_tmp).exists():
                try:
                    Path(probe_tmp).unlink()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# SSHProvider
# ---------------------------------------------------------------------------

class SSHProvider(_BaseSSHProvider):
    """
    Provides direct-SSH probe execution for the VM Firewall Inspector.

    Runs the probe via SSH (sudo bash -s) rather than the Azure control plane.
    Use for any SSH-accessible Linux host: Multipass VMs, bare metal, or
    non-Azure VMs where az CLI is not available.

    Inherits SSH/SCP operations from _BaseSSHProvider.
    The probe script and all output formats are identical to AzureProvider —
    only the probe delivery mechanism differs.
    """

    def run_probe(
        self,
        vm_name: str,
        session_id: str,
        ssh_user: str,
        probe_script: str,
    ) -> dict:
        """
        Run the probe script on the target host via direct SSH.

        The probe script is written to a local temp file and piped to
        'sudo bash -s' on the remote host. The session_id and ssh_user
        are passed as positional parameters ($1, $2) to the script.

        Returns the parsed stdout from the probe:
            {"probe_output_path": str, "probe_output_bytes": int}

        Raises RuntimeError if the SSH command fails or output cannot be parsed.
        vm_name is used for display and reasoning only; it is not required to
        match any resource name on the target host.
        """
        probe_tmp: str | None = None
        try:
            # Write probe to local temp file — cleaned up in finally
            fd, probe_tmp = tempfile.mkstemp(suffix=".sh", prefix="fw_probe_")
            os.close(fd)
            Path(probe_tmp).write_text(probe_script, encoding="utf-8")
            os.chmod(probe_tmp, 0o600)

            # session_id is validated by validate_session_id() before run_probe() is called
            # (^[a-zA-Z0-9_-]{1,64}$ — safe to interpolate).
            # ssh_user is a config-supplied value (SSH username — alphanumeric).
            proxy = self._proxy_command()
            cmd_parts = ["ssh", self._ssh_opts()]
            if proxy:
                cmd_parts.append(proxy)
            cmd_parts.append(f"{self._ssh_user}@{self._target_vm_ip}")
            cmd_parts.append(f'"sudo bash -s -- {session_id} {ssh_user}"')
            cmd_parts.append(f'< "{probe_tmp}"')
            cmd = " ".join(cmd_parts)

            result = self._shell.execute({
                "command":   cmd,
                "reasoning": f"Run firewall probe on {vm_name} via direct SSH (session {session_id})",
            })

            if result["status"] == "denied":
                raise RuntimeError("Probe command denied by safety shell")
            if result["exit_code"] != 0:
                raise RuntimeError(
                    f"SSH probe failed (exit {result['exit_code']}): "
                    f"{result['output'][:200]}"
                )

            return _parse_probe_response(result["output"])

        finally:
            if probe_tmp and Path(probe_tmp).exists():
                try:
                    Path(probe_tmp).unlink()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Parse probe response (AzureProvider: JSON envelope; SSHProvider: raw stdout)
# ---------------------------------------------------------------------------

def _parse_probe_response(az_output: str) -> dict:
    """
    Extract PROBE_OUTPUT_PATH and PROBE_OUTPUT_BYTES from probe output.

    For AzureProvider: the az CLI returns a JSON envelope; stdout of the script
    is embedded in the 'message' field between '[stdout]' and '[stderr]' markers.

    For SSHProvider: output is the raw probe stdout (the two printf lines).

    Falls back to scanning the raw output if JSON parsing fails.

    Returns: {"probe_output_path": str, "probe_output_bytes": int}
    Raises:  RuntimeError if the expected lines cannot be found.
    """
    # Try JSON envelope first (AzureProvider path)
    stdout_text = ""
    try:
        data = json.loads(az_output)
        for item in data.get("value", []):
            msg = item.get("message", "")
            if "[stdout]" in msg:
                stdout_text = msg.split("[stdout]", 1)[1].split("[stderr]", 1)[0]
                break
    except (json.JSONDecodeError, AttributeError):
        stdout_text = az_output  # fall back to raw output (SSHProvider path)

    path_match  = None
    bytes_match = None
    for line in stdout_text.splitlines():
        line = line.strip()
        if line.startswith("PROBE_OUTPUT_PATH="):
            path_match = line.split("=", 1)[1]
        elif line.startswith("PROBE_OUTPUT_BYTES="):
            try:
                bytes_match = int(line.split("=", 1)[1])
            except ValueError:
                pass

    if not path_match:
        raise RuntimeError(
            "Probe output path not found in run-command response. "
            "Ensure the probe script ran successfully."
        )

    return {
        "probe_output_path":  path_match,
        "probe_output_bytes": bytes_match or 0,
    }
