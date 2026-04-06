"""
Tests for providers.py — LocalShell and AzureNetworkProvider.

All Azure calls are intercepted via a mock LocalShell — no real az CLI invocations.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from providers import LocalShell, AzureNetworkProvider

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shell_ok(stdout="[]", output=None):
    """Return a mock LocalShell whose execute() returns success with given stdout."""
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "success",
        "stdout": stdout,
        "output": output if output is not None else stdout,
        "exit_code": 0,
        "audit_id": "local",
    }
    return shell


def _shell_error(output="az error message", exit_code=1):
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "error",
        "stdout": "",
        "output": output,
        "exit_code": exit_code,
        "audit_id": "local",
    }
    return shell


def _provider(shell, rg="my-rg", sub=None):
    return AzureNetworkProvider(shell=shell, resource_group=rg, subscription_id=sub)


# ---------------------------------------------------------------------------
# LocalShell — subprocess behaviour
# ---------------------------------------------------------------------------

class TestLocalShell:

    def test_uses_shell_false(self, tmp_path):
        """TC-PROV-001: shell=False enforced."""
        shell = LocalShell()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
            shell.execute({"command": ["az", "--version"]})
            _, kwargs = mock_run.call_args
            assert kwargs.get("shell") is False

    def test_command_passed_as_list(self, tmp_path):
        """TC-PROV-001: command argument is a list, never a string."""
        shell = LocalShell()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            shell.execute({"command": ["az", "account", "show"]})
            args, _ = mock_run.call_args
            assert isinstance(args[0], list)
            assert args[0] == ["az", "account", "show"]

    def test_success_result_structure(self):
        shell = LocalShell()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='{"ok": 1}', stderr="")
            result = shell.execute({"command": ["az", "version"]})
        assert result["status"] == "success"
        assert result["exit_code"] == 0
        assert result["stdout"] == '{"ok": 1}'
        assert result["audit_id"] == "local"

    def test_non_zero_exit_code_returns_error_status(self):
        shell = LocalShell()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="some error")
            result = shell.execute({"command": ["az", "fail"]})
        assert result["status"] == "error"
        assert result["exit_code"] == 1

    def test_stdout_and_stderr_split_correctly(self):
        """stdout key is stdout-only; output key is stdout+stderr combined."""
        shell = LocalShell()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout='{"json": true}', stderr="WARNING: something"
            )
            result = shell.execute({"command": ["az", "thing"]})
        assert result["stdout"] == '{"json": true}'
        assert "WARNING: something" in result["output"]
        assert result["stdout"] not in result["output"] or result["output"].startswith('{"json": true}')

    def test_log_creates_file(self, tmp_path):
        """TC-PROV-016: execute() writes one log entry per call."""
        shell = LocalShell(audit_dir=str(tmp_path), session_id="test-sid")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="x", stderr="")
            shell.execute({"command": ["az", "a"]})
            shell.execute({"command": ["az", "b"]})
            shell.execute({"command": ["az", "c"]})

        log = (tmp_path / "test-sid_commands.log").read_text()
        lines = [l for l in log.splitlines() if l.strip()]
        assert len(lines) == 3
        for line in lines:
            entry = json.loads(line)
            assert "ts" in entry
            assert "command" in entry
            assert isinstance(entry["command"], str)  # joined, not a list
            assert "exit_code" in entry
            assert "output_bytes" in entry

    def test_log_failure_does_not_abort(self, tmp_path):
        """TC-PROV-017: Log write failure is silently swallowed."""
        shell = LocalShell(audit_dir=str(tmp_path), session_id="test-sid")
        # Make the log path unwritable by pointing it at a directory
        log_path = tmp_path / "test-sid_commands.log"
        log_path.mkdir()  # directory where file is expected — write will fail

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            result = shell.execute({"command": ["az", "version"]})  # must not raise

        assert result["status"] == "success"

    def test_timeout_returns_error(self):
        import subprocess
        shell = LocalShell()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="az", timeout=120)):
            result = shell.execute({"command": ["az", "slow"]})
        assert result["status"] == "error"
        assert result["exit_code"] == -1
        assert "timed out" in result["output"]


# ---------------------------------------------------------------------------
# AzureNetworkProvider — command vector construction
# ---------------------------------------------------------------------------

class TestAzureNetworkProviderCommands:

    def test_get_nic_names_for_vm_correct_vector(self):
        """TC-PROV-002: Exact argument vector for az vm nic list."""
        shell = _shell_ok(FIXTURES.joinpath("vm_nic_ids.json").read_text())
        provider = _provider(shell, rg="my-rg")
        provider.get_nic_names_for_vm("my-vm")

        cmd = shell.execute.call_args[0][0]["command"]
        assert cmd == [
            "az", "vm", "nic", "list",
            "--resource-group", "my-rg",
            "--vm-name", "my-vm",
            "--query", "[].id",
            "--output", "json",
        ]

    def test_subscription_id_appended_as_separate_args(self):
        """TC-PROV-003: --subscription appended as two list elements, not string interpolation."""
        shell = _shell_ok(FIXTURES.joinpath("vm_nic_ids.json").read_text())
        provider = _provider(shell, sub="sub-abc-123")
        provider.get_nic_names_for_vm("my-vm")

        cmd = shell.execute.call_args[0][0]["command"]
        assert "--subscription" in cmd
        sub_idx = cmd.index("--subscription")
        assert cmd[sub_idx + 1] == "sub-abc-123"
        # Must be separate elements — not concatenated into a single string
        assert not any("--subscription sub-abc-123" in arg for arg in cmd)

    def test_no_subscription_flag_when_omitted(self):
        """TC-PROV-004: No --subscription in vector when subscription_id is None."""
        shell = _shell_ok(FIXTURES.joinpath("vm_nic_ids.json").read_text())
        provider = _provider(shell, sub=None)
        provider.get_nic_names_for_vm("my-vm")

        cmd = shell.execute.call_args[0][0]["command"]
        assert "--subscription" not in cmd

    def test_get_effective_routes_json_correct_vector(self):
        """TC-PROV-010: Exact argument vector for show-effective-route-table."""
        shell = _shell_ok("{}")
        provider = _provider(shell)
        provider.get_effective_routes_json("nic-name")

        cmd = shell.execute.call_args[0][0]["command"]
        assert cmd == [
            "az", "network", "nic", "show-effective-route-table",
            "--resource-group", "my-rg",
            "--name", "nic-name",
            "--output", "json",
        ]

    def test_get_effective_nsg_json_correct_vector(self):
        """TC-PROV-011: Exact argument vector for list-effective-nsg."""
        shell = _shell_ok("{}")
        provider = _provider(shell)
        provider.get_effective_nsg_json("nic-name")

        cmd = shell.execute.call_args[0][0]["command"]
        assert cmd == [
            "az", "network", "nic", "list-effective-nsg",
            "--resource-group", "my-rg",
            "--name", "nic-name",
            "--output", "json",
        ]

    def test_get_nic_names_for_vnet_correct_vector(self):
        """az network nic list vector for VNet-scope discovery."""
        shell = _shell_ok("[]")
        provider = _provider(shell)
        provider.get_nic_names_for_vnet("/subscriptions/sub/virtualNetworks/vnet-1")

        cmd = shell.execute.call_args[0][0]["command"]
        assert cmd == [
            "az", "network", "nic", "list",
            "--resource-group", "my-rg",
            "--output", "json",
        ]

    def test_shell_metacharacter_in_rg_not_injected(self):
        """TC-PROV-015: Metacharacter in resource group is a literal argument, not executed."""
        shell = _shell_ok("[]")
        provider = _provider(shell, rg="rg; echo INJECTED")
        provider.get_nic_names_for_vnet("/subscriptions/sub/virtualNetworks/vnet-1")

        cmd = shell.execute.call_args[0][0]["command"]
        # The semicolon-containing string must appear as a single list element
        rg_idx = cmd.index("--resource-group")
        assert cmd[rg_idx + 1] == "rg; echo INJECTED"
        # Not split into multiple elements
        assert "echo" not in cmd


# ---------------------------------------------------------------------------
# AzureNetworkProvider — NIC discovery logic
# ---------------------------------------------------------------------------

class TestAzureNetworkProviderDiscovery:

    def test_nic_names_extracted_from_resource_ids(self):
        """TC-PROV-005: Last path segment of resource ID is the NIC name."""
        ids = json.dumps([
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a",
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-b",
        ])
        shell = _shell_ok(ids)
        provider = _provider(shell)
        result = provider.get_nic_names_for_vm("my-vm")
        assert result == ["nic-a", "nic-b"]

    def test_empty_nic_list_raises_runtime_error(self):
        """TC-PROV-006: Empty NIC list raises RuntimeError identifying the VM."""
        shell = _shell_ok("[]")
        provider = _provider(shell)
        with pytest.raises(RuntimeError, match="my-vm"):
            provider.get_nic_names_for_vm("my-vm")

    def test_non_zero_exit_raises_runtime_error(self):
        """TC-PROV-007: Non-zero exit code raises RuntimeError."""
        shell = _shell_error("ResourceNotFound: VM not found")
        provider = _provider(shell)
        with pytest.raises(RuntimeError):
            provider.get_nic_names_for_vm("missing-vm")

    def test_vnet_scope_filters_by_subnet_id(self):
        """TC-PROV-008: Only NICs whose subnet ID contains the VNet resource ID are returned."""
        vnet_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet"
        nics = [
            {
                "name": "nic-in-vnet",
                "ipConfigurations": [{"subnet": {
                    "id": f"{vnet_id}/subnets/subnet-1"
                }}],
            },
            {
                "name": "nic-other-vnet",
                "ipConfigurations": [{"subnet": {
                    "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/other-vnet/subnets/subnet-2"
                }}],
            },
        ]
        shell = _shell_ok(json.dumps(nics))
        provider = _provider(shell)
        result = provider.get_nic_names_for_vnet(vnet_id)
        assert result == ["nic-in-vnet"]

    def test_vnet_scope_case_insensitive_match(self):
        """VNet ID match is case-insensitive (Azure resource IDs are case-insensitive)."""
        vnet_id = "/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/MY-VNET"
        nics = [{
            "name": "nic-1",
            "ipConfigurations": [{"subnet": {"id": vnet_id.lower() + "/subnets/s1"}}],
        }]
        shell = _shell_ok(json.dumps(nics))
        provider = _provider(shell)
        result = provider.get_nic_names_for_vnet(vnet_id)
        assert "nic-1" in result

    def test_vnet_scope_no_match_returns_empty_list(self):
        """TC-PROV-009: No NICs in VNet returns [], not an error."""
        nics = [{"name": "nic-other", "ipConfigurations": [
            {"subnet": {"id": "/subscriptions/sub/virtualNetworks/different-vnet/subnets/s"}}
        ]}]
        shell = _shell_ok(json.dumps(nics))
        provider = _provider(shell)
        result = provider.get_nic_names_for_vnet("/subscriptions/sub/virtualNetworks/my-vnet")
        assert result == []

    def test_vnet_scope_empty_nic_list_returns_empty(self):
        shell = _shell_ok("[]")
        provider = _provider(shell)
        result = provider.get_nic_names_for_vnet("/subscriptions/sub/virtualNetworks/vnet")
        assert result == []


# ---------------------------------------------------------------------------
# AzureNetworkProvider — RBAC and error handling
# ---------------------------------------------------------------------------

class TestAzureNetworkProviderErrors:

    def test_rbac_error_authorization_failed(self):
        """TC-PROV-012: AuthorizationFailed in output raises RuntimeError with RBAC message."""
        shell = _shell_error(
            output="ERROR: The client does not have authorization. "
                   "AuthorizationFailed: policy assignment denied",
            exit_code=1,
        )
        provider = _provider(shell)
        with pytest.raises(RuntimeError, match="Network Contributor"):
            provider.get_effective_routes_json("nic-a")

    def test_rbac_error_does_not_have_authorization_phrase(self):
        """TC-PROV-013: 'does not have authorization' phrase also triggers RBAC error."""
        shell = _shell_error(
            output="The subscription does not have authorization to perform action 'effectiveRouteTable'",
            exit_code=1,
        )
        provider = _provider(shell)
        with pytest.raises(RuntimeError, match="Network Contributor"):
            provider.get_effective_routes_json("nic-a")

    def test_rbac_error_message_mentions_permission(self):
        """RBAC error message must identify the required permission — not a bare exception."""
        shell = _shell_error(output="AuthorizationFailed", exit_code=1)
        provider = _provider(shell)
        with pytest.raises(RuntimeError) as exc_info:
            provider.get_effective_nsg_json("nic-a")
        # Message must mention Network Contributor and the specific action
        msg = str(exc_info.value)
        assert "Network Contributor" in msg
        assert "effectiveRouteTable" in msg or "effectiveNetworkSecurityGroups" in msg or "Microsoft.Network" in msg

    def test_uses_stdout_not_output_for_az_json(self):
        """TC-PROV-014: JSON comes from stdout; stderr noise in output does not corrupt result."""
        valid_json = json.dumps({"value": []})
        noisy_output = valid_json + "\nWARNING: Extension is out of date"
        shell = MagicMock()
        shell.execute.return_value = {
            "status": "success",
            "stdout": valid_json,
            "output": noisy_output,
            "exit_code": 0,
            "audit_id": "local",
        }
        provider = _provider(shell)
        result = provider.get_effective_routes_json("nic-a")
        # Result must be the clean stdout, not the noisy combined output
        assert "WARNING" not in result
        assert result == valid_json

    def test_non_rbac_error_raises_runtime_error(self):
        """Generic non-RBAC az error raises RuntimeError (not RBAC message)."""
        shell = _shell_error("ResourceNotFound: NIC nic-a not found", exit_code=1)
        provider = _provider(shell)
        with pytest.raises(RuntimeError) as exc_info:
            provider.get_effective_routes_json("nic-a")
        assert "Network Contributor" not in str(exc_info.value)
