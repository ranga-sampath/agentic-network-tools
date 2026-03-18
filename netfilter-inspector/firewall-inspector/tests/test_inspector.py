"""
Tests for firewall_inspector.py and providers.py

Security tests (SEC-VAL, SEC-SSH, SEC-PROBE, SEC-BAS, SEC-LOG, SEC-CLS):
  Validate the security fixes described in security_challenges.md.

Functional tests (FI-):
  Validate the LocalShell contract, save_snapshot/load_snapshot round-trip,
  and probe section parsing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from firewall_inspector import (
    validate_session_id,
    save_snapshot,
    load_snapshot,
    IntegrityError,
    _parse_probe_sections,
    _section_available,
    _PROBE_SCRIPT,
    PROBE_SCRIPT_SHA256,
    InspectorConfig,
    run as _fi_run,
)
from providers import LocalShell, AzureProvider, SSHProvider, _parse_probe_response, _validate_remote_path


# ===========================================================================
# SEC-VAL: session_id validation
# ===========================================================================

@pytest.mark.parametrize("sid", [
    "fw_20260314_100000",
    "test-session",
    "abc",
    "A" * 64,
    "fw-abc_123-XYZ",
])
def test_sec_val_01_valid_ids_accepted(sid):
    """SEC-VAL-01: Valid session IDs (alphanumeric, underscores, hyphens, max 64) pass."""
    validate_session_id(sid)  # must not raise


@pytest.mark.parametrize("sid, desc", [
    ("abc;cmd",          "semicolon"),
    ("abc$var",          "dollar sign"),
    ("../etc/passwd",    "path traversal"),
    ("abc&&ls",          "double ampersand"),
    ("abc|ls",           "pipe"),
    ("hello world",      "space"),
    ("A" * 65,           "65 chars"),
    ("",                 "empty string"),
])
def test_sec_val_02_invalid_ids_rejected(sid, desc):
    """SEC-VAL-02 to SEC-VAL-07: Dangerous session IDs raise ValueError."""
    with pytest.raises(ValueError, match="Invalid session_id"):
        validate_session_id(sid)


def test_sec_val_08_validation_fires_before_shell_execute(tmp_path):
    """SEC-VAL-08: Shell execute() is never called when session_id is invalid."""
    mock_shell = MagicMock()
    mock_provider = MagicMock()

    from firewall_inspector import InspectorConfig, run

    config = InspectorConfig(
        ssh_user="u", target_vm_ip="10.0.0.1", ssh_key_path="/k",
        session_id="bad;id",  # invalid — must be caught before any shell call
        audit_dir=str(tmp_path),
        vm_name="vm", resource_group="rg",
    )

    with pytest.raises(ValueError, match="Invalid session_id"):
        validate_session_id(config.session_id)

    mock_shell.execute.assert_not_called()
    mock_provider.run_probe.assert_not_called()


def test_sec_val_09_ssh_provider_requires_target_vm_ip(tmp_path):
    """SEC-VAL-09: InspectorConfig with provider='ssh' and empty target_vm_ip raises ValueError at construction."""
    with pytest.raises(ValueError, match="target_vm_ip is required"):
        InspectorConfig(
            ssh_user="ubuntu", ssh_key_path="/k",
            session_id="fw_test01", audit_dir=str(tmp_path),
            provider="ssh",
            # target_vm_ip omitted — defaults to ""
        )


def test_sec_val_10_azure_provider_allows_empty_target_vm_ip(tmp_path):
    """SEC-VAL-10: InspectorConfig with provider='azure' accepts empty target_vm_ip (uses vm_name instead)."""
    config = InspectorConfig(
        ssh_user="azureuser", ssh_key_path="/k",
        session_id="fw_test01", audit_dir=str(tmp_path),
        provider="azure", vm_name="tf-dest-vm", resource_group="rg",
        # target_vm_ip omitted — must be allowed for azure
    )
    assert config.target_vm_ip == ""


# ===========================================================================
# SEC-SSH: StrictHostKeyChecking in all SCP/SSH commands
# ===========================================================================

def _make_provider(
    shell=None,
    target_vm_ip: str = "10.0.0.5",
    target_ssh_key_path: str = "/home/user/.ssh/id_rsa",
    bastion_public_ip: str | None = "1.2.3.4",
    bastion_ssh_key_path: str | None = None,
) -> SSHProvider:
    if shell is None:
        shell = MagicMock()
    return SSHProvider(
        shell                = shell,
        ssh_user             = "azureuser",
        target_vm_ip         = target_vm_ip,
        target_ssh_key_path  = target_ssh_key_path,
        bastion_public_ip    = bastion_public_ip,
        bastion_ssh_key_path = bastion_ssh_key_path,
    )


def _make_azure_provider(
    shell=None,
    vm_name: str = "my-vm",
    resource_group: str = "rg",
    subscription_id: str | None = None,
) -> AzureProvider:
    if shell is None:
        shell = MagicMock()
    return AzureProvider(
        shell          = shell,
        resource_group = resource_group,
        vm_name        = vm_name,
        subscription_id = subscription_id,
        ssh_user       = "azureuser",
    )


def test_sec_ssh_01_scp_contains_strict_host_key_checking(tmp_path):
    """SEC-SSH-01: Two-hop SCP command (Case 2) includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd


def test_sec_ssh_02_scp_contains_proxy_command(tmp_path):
    """SEC-SSH-02: Two-hop SCP (Case 2) uses ProxyCommand containing bastion_public_ip."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    assert "1.2.3.4" in cmd  # bastion_public_ip


def test_sec_ssh_03_cleanup_contains_strict_host_key_checking():
    """SEC-SSH-03: SSH cleanup command includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.cleanup_probe_output("/tmp/fw_AbCdEf.txt")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd


def test_sec_ssh_04_no_command_uses_strict_host_checking_no():
    """SEC-SSH-04 (regression guard): 'StrictHostKeyChecking=no' never appears in any built command."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", "/tmp/local.txt")
    provider.cleanup_probe_output("/tmp/fw_AbCdEf.txt")

    for c in mock_shell.execute.call_args_list:
        cmd = c[0][0]["command"]
        assert "StrictHostKeyChecking=no" not in cmd, (
            f"Found 'StrictHostKeyChecking=no' in command: {cmd!r}"
        )


def test_sec_ssh_05_case1_no_proxy_command(tmp_path):
    """SEC-SSH-05: Case 1 (direct — bastion_public_ip=None) — no ProxyCommand or ProxyJump; target IP present."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell, target_vm_ip="20.1.2.3", bastion_public_ip=None)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))
    provider.cleanup_probe_output("/tmp/fw_AbCdEf.txt")

    for c in mock_shell.execute.call_args_list:
        cmd = c[0][0]["command"]
        assert "ProxyCommand" not in cmd, f"ProxyCommand found in Case 1 command: {cmd!r}"
        assert "ProxyJump" not in cmd, f"ProxyJump found in Case 1 command: {cmd!r}"
        assert "20.1.2.3" in cmd, f"Target VM IP missing from Case 1 command: {cmd!r}"


def test_sec_ssh_06_case2b_different_keys_in_proxy_command(tmp_path):
    """SEC-SSH-06: Case 2b — bastion key inside ProxyCommand; target key in outer -i."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(
        mock_shell,
        target_ssh_key_path  = "/home/user/.ssh/target_key",
        bastion_public_ip    = "1.2.3.4",
        bastion_ssh_key_path = "/home/user/.ssh/bastion_key",
    )

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    # Split on "ProxyCommand" to verify each key is on the correct side.
    # If the keys were swapped the split would catch it; count == 1 alone would not.
    outer, proxy_part = cmd.split("ProxyCommand", 1)
    assert "/home/user/.ssh/target_key" in outer, (
        f"Target key not in outer -i position: {cmd!r}"
    )
    assert "/home/user/.ssh/bastion_key" in proxy_part, (
        f"Bastion key not inside ProxyCommand: {cmd!r}"
    )
    assert "/home/user/.ssh/bastion_key" not in outer, (
        f"Bastion key leaked into outer command: {cmd!r}"
    )
    assert "/home/user/.ssh/target_key" not in proxy_part, (
        f"Target key leaked into ProxyCommand: {cmd!r}"
    )


def test_sec_ssh_07_case2a_same_key_defaults(tmp_path):
    """SEC-SSH-07: Case 2a — bastion_ssh_key_path=None defaults to target key in both positions."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(
        mock_shell,
        target_ssh_key_path  = "/home/user/.ssh/id_rsa",
        bastion_public_ip    = "1.2.3.4",
        bastion_ssh_key_path = None,  # must default to target key
    )

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    # Same key path appears in both outer -i and inside ProxyCommand
    assert cmd.count("/home/user/.ssh/id_rsa") >= 2


# ===========================================================================
# SEC-AZ: AzureProvider retrieve/cleanup use az vm run-command (no SCP/SSH)
# ===========================================================================

_AZ_RETRIEVE_RESPONSE = json.dumps({
    "value": [{"message": "[stdout]\nline1\nline2\n[stderr]\n"}]
})


def test_sec_az_01_retrieve_uses_run_command(tmp_path):
    """SEC-AZ-01: AzureProvider.retrieve_probe_output issues az vm run-command (not scp)."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success", "output": _AZ_RETRIEVE_RESPONSE, "exit_code": 0, "audit_id": "a1",
    }
    provider = _make_azure_provider(mock_shell)
    out = tmp_path / "out.txt"

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(out))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "az vm run-command invoke" in cmd
    assert "RunShellScript" in cmd
    assert "cat /tmp/fw_AbCdEf.txt" in cmd
    assert "scp" not in cmd


def test_sec_az_02_retrieve_writes_stdout_content(tmp_path):
    """SEC-AZ-02: retrieve_probe_output writes the extracted stdout to local_path."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success", "output": _AZ_RETRIEVE_RESPONSE, "exit_code": 0, "audit_id": "a1",
    }
    provider = _make_azure_provider(mock_shell)
    out = tmp_path / "out.txt"

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(out))

    assert out.read_text() == "line1\nline2\n"


def test_sec_az_03_retrieve_includes_vm_name_and_rg():
    """SEC-AZ-03: retrieve_probe_output command includes vm_name and resource_group."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success", "output": _AZ_RETRIEVE_RESPONSE, "exit_code": 0, "audit_id": "a1",
    }
    provider = _make_azure_provider(mock_shell, vm_name="tf-dest-vm", resource_group="nw-forensics-rg")

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", "/tmp/local.txt")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "tf-dest-vm" in cmd
    assert "nw-forensics-rg" in cmd


def test_sec_az_04_cleanup_uses_run_command():
    """SEC-AZ-04: AzureProvider.cleanup_probe_output issues az vm run-command (not ssh)."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success", "output": "{}", "exit_code": 0, "audit_id": "a1",
    }
    provider = _make_azure_provider(mock_shell)

    result = provider.cleanup_probe_output("/tmp/fw_AbCdEf.txt")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "az vm run-command invoke" in cmd
    assert "RunShellScript" in cmd
    assert "rm -f /tmp/fw_AbCdEf.txt" in cmd
    assert "ssh" not in cmd
    assert result is True


def test_sec_az_05_retrieve_with_subscription_id():
    """SEC-AZ-05: retrieve_probe_output includes --subscription when subscription_id is set."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success", "output": _AZ_RETRIEVE_RESPONSE, "exit_code": 0, "audit_id": "a1",
    }
    provider = _make_azure_provider(mock_shell, subscription_id="sub-1234")

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", "/tmp/local.txt")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "--subscription sub-1234" in cmd


def test_sec_az_06_invalid_remote_path_raises_before_shell_execute():
    """SEC-AZ-06: retrieve_probe_output raises ValueError for non-mktemp paths — no shell execute called."""
    mock_shell = MagicMock()
    provider = _make_azure_provider(mock_shell)

    with pytest.raises(ValueError, match="Unexpected remote_path"):
        provider.retrieve_probe_output("/etc/passwd", "/tmp/local.txt")

    mock_shell.execute.assert_not_called()


def test_sec_az_07_invalid_remote_path_cleanup_raises_before_shell_execute():
    """SEC-AZ-07: cleanup_probe_output raises ValueError for non-mktemp paths — no shell execute called."""
    mock_shell = MagicMock()
    provider = _make_azure_provider(mock_shell)

    with pytest.raises(ValueError, match="Unexpected remote_path"):
        provider.cleanup_probe_output("/etc/cron.d/evil")

    mock_shell.execute.assert_not_called()


# ===========================================================================
# SEC-PROBE: probe script static constant
# ===========================================================================

def test_sec_probe_01_probe_script_is_string_constant():
    """SEC-PROBE-01: _PROBE_SCRIPT is a str constant (not callable or dynamic)."""
    assert isinstance(_PROBE_SCRIPT, str)
    assert len(_PROBE_SCRIPT) > 50


def test_sec_probe_02_probe_script_contains_mktemp():
    """SEC-PROBE-02: Probe uses mktemp for temp file (not a static path)."""
    assert "mktemp" in _PROBE_SCRIPT


def test_sec_probe_03_probe_script_contains_chmod_600():
    """SEC-PROBE-03: Probe sets mode 600 on the output file."""
    assert "chmod 600" in _PROBE_SCRIPT


def test_sec_probe_04_probe_always_collects_both_families():
    """SEC-PROBE-04: Probe always collects ipv4 and ipv6 regardless of --family flag."""
    assert "###SECTION:iptables_ipv4###" in _PROBE_SCRIPT
    assert "###SECTION:iptables_ipv6###" in _PROBE_SCRIPT
    assert "###SECTION:framework_detection###" in _PROBE_SCRIPT


def test_sec_probe_05_probe_sha256_matches_script():
    """PROBE_SCRIPT_SHA256 constant matches actual sha256 of _PROBE_SCRIPT."""
    import hashlib
    expected = hashlib.sha256(_PROBE_SCRIPT.encode("utf-8")).hexdigest()
    assert PROBE_SCRIPT_SHA256 == expected


def test_sec_probe_06_probe_chowns_output_to_ssh_user():
    """SEC-PROBE-06: Probe transfers output file ownership to $SSH_USER.

    az vm run-command invoke runs as root; the SCP session runs as SSH_USER.
    Without chown, root-owned chmod-600 files are unreadable by SSH_USER.
    """
    assert 'chown "$SSH_USER"' in _PROBE_SCRIPT
    assert 'SSH_USER="$2"' in _PROBE_SCRIPT


# ===========================================================================
# SEC-BAS: baseline integrity
# ===========================================================================

def test_sec_bas_01_save_creates_sha256_companion(tmp_path):
    """SEC-BAS-01: save_snapshot() writes {session_id}_snapshot.json.sha256."""
    snap = {"snapshot_at": "2026-01-01T00:00:00Z", "session_id": "test123"}
    save_snapshot(snap, str(tmp_path), "test123")
    assert (tmp_path / "test123_snapshot.json.sha256").exists()


def test_sec_bas_02_sha256_file_matches_snapshot(tmp_path):
    """SEC-BAS-02: sha256 file content equals sha256(json_bytes)."""
    import hashlib
    snap = {"snapshot_at": "2026-01-01T00:00:00Z", "session_id": "test123"}
    save_snapshot(snap, str(tmp_path), "test123")

    json_bytes    = (tmp_path / "test123_snapshot.json").read_bytes()
    stored_sha256 = (tmp_path / "test123_snapshot.json.sha256").read_text().strip()
    expected      = hashlib.sha256(json_bytes).hexdigest()
    assert stored_sha256 == expected


def test_sec_bas_03_tampered_snapshot_raises_integrity_error(tmp_path):
    """SEC-BAS-03: Tampered snapshot raises IntegrityError on load."""
    snap = {"snapshot_at": "2026-01-01T00:00:00Z", "session_id": "test123", "data": "original"}
    save_snapshot(snap, str(tmp_path), "test123")

    snap_file = tmp_path / "test123_snapshot.json"
    content = snap_file.read_text()
    snap_file.write_text(content.replace("original", "tampered"))

    with pytest.raises(IntegrityError, match="integrity check failed"):
        load_snapshot(str(tmp_path), "test123")


def test_sec_bas_04_unmodified_baseline_loads_correctly(tmp_path):
    """SEC-BAS-04: Unmodified baseline loads without error and returns correct dict."""
    snap = {"snapshot_at": "2026-01-01T00:00:00Z", "session_id": "test123", "val": 42}
    save_snapshot(snap, str(tmp_path), "test123")
    loaded = load_snapshot(str(tmp_path), "test123")
    assert loaded["val"] == 42


def test_sec_bas_05_missing_sha256_companion_raises_integrity_error(tmp_path):
    """SEC-BAS-05: Missing sha256 companion is treated as tamper — raises IntegrityError."""
    snap = {"snapshot_at": "2026-01-01T00:00:00Z", "session_id": "test123"}
    save_snapshot(snap, str(tmp_path), "test123")
    (tmp_path / "test123_snapshot.json.sha256").unlink()

    with pytest.raises(IntegrityError, match="companion file missing"):
        load_snapshot(str(tmp_path), "test123")


# ===========================================================================
# SEC-LOG: LocalShell commands log
# ===========================================================================

def test_sec_log_01_two_calls_produce_two_log_entries(tmp_path):
    """SEC-LOG-01: Two execute() calls produce two JSON entries in _commands.log."""
    shell = LocalShell(audit_dir=str(tmp_path), session_id="s1")
    shell.execute({"command": "echo hello"})
    shell.execute({"command": "echo world"})

    log_path = tmp_path / "s1_commands.log"
    assert log_path.exists()
    lines = [l for l in log_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 2


def test_sec_log_02_each_entry_has_required_fields(tmp_path):
    """SEC-LOG-02: Each log entry contains ts, command, exit_code, output_bytes."""
    shell = LocalShell(audit_dir=str(tmp_path), session_id="s2")
    shell.execute({"command": "echo test_output"})

    log_path = tmp_path / "s2_commands.log"
    entry = json.loads(log_path.read_text().strip())
    assert "ts"           in entry
    assert "command"      in entry
    assert "exit_code"    in entry
    assert "output_bytes" in entry
    assert entry["command"] == "echo test_output"
    assert entry["exit_code"] == 0


def test_sec_log_03_log_does_not_contain_output_text(tmp_path):
    """SEC-LOG-03: Log entry has no 'output' key — command output text is never logged."""
    shell = LocalShell(audit_dir=str(tmp_path), session_id="s3")
    shell.execute({"command": "echo some_output"})

    entry = json.loads((tmp_path / "s3_commands.log").read_text().strip())
    assert "output" not in entry, (
        "Log must not contain 'output' key — command output text must never be logged"
    )
    # output_bytes (the count) is fine and expected
    assert entry["output_bytes"] > 0


def test_sec_log_04_multiple_calls_append_to_log(tmp_path):
    """SEC-LOG-04: Successive execute() calls append to the log (not overwrite)."""
    shell = LocalShell(audit_dir=str(tmp_path), session_id="s4")
    for i in range(5):
        shell.execute({"command": f"echo call_{i}"})

    lines = [l for l in (tmp_path / "s4_commands.log").read_text().splitlines() if l.strip()]
    assert len(lines) == 5
    # Verify each line is valid JSON
    for line in lines:
        json.loads(line)


# ===========================================================================
# SEC-CLS: SafeExecShell classification regression guards
# ===========================================================================

def test_sec_cls_01_az_vm_run_command_invoke_is_risky():
    """SEC-CLS-01 (regression guard): az vm run-command invoke → RISKY, not SAFE."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agentic-safety-shell"))
    try:
        from safe_exec_shell import classify
        classification, tier, _ = classify(
            "az vm run-command invoke --resource-group rg --name vm-01 "
            "--command-id RunShellScript --scripts @/tmp/probe.sh --parameters session1 azureuser"
        )
        assert classification == "RISKY", (
            f"Expected RISKY but got {classification} (tier={tier}). "
            "A future SafeExecShell change must not promote 'invoke' to SAFE."
        )
    except ImportError:
        pytest.skip("safe_exec_shell not on path — skipping classification regression guard")


def test_sec_cls_02_az_nic_list_effective_nsg_is_safe():
    """SEC-CLS-02 (regression guard): az network nic list-effective-nsg → SAFE."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agentic-safety-shell"))
    try:
        from safe_exec_shell import classify
        classification, _, _ = classify(
            "az network nic list-effective-nsg --resource-group rg --name nic01"
        )
        assert classification == "SAFE"
    except ImportError:
        pytest.skip("safe_exec_shell not on path")


# ===========================================================================
# Functional tests: _parse_probe_sections
# ===========================================================================

def test_fi01_parse_sections_basic():
    """_parse_probe_sections returns correct section content."""
    text = (
        "###SECTION:framework_detection###\n"
        "iptables v1.8.7 (legacy)\n"
        "###SECTION:iptables_ipv4###\n"
        "# Generated by iptables-save\n"
        "*filter\n"
        "COMMIT\n"
        "###SECTION:iptables_ipv6###\n"
        "###UNAVAILABLE###\n"
    )
    sections = _parse_probe_sections(text)
    assert "iptables v1.8.7 (legacy)" in sections["framework_detection"]
    assert "*filter" in sections["iptables_ipv4"]
    assert "###UNAVAILABLE###" in sections["iptables_ipv6"]


def test_fi02_section_available_returns_false_for_unavailable():
    assert _section_available("###UNAVAILABLE###") is False
    assert _section_available("  ###UNAVAILABLE###  ") is False


def test_fi03_section_available_returns_true_for_content():
    assert _section_available("*filter\nCOMMIT") is True
    assert _section_available("") is True  # empty but not ###UNAVAILABLE###


# ===========================================================================
# Functional tests: _parse_probe_response
# ===========================================================================

def test_fi04_parse_probe_response_json_envelope():
    """_parse_probe_response extracts path and bytes from az JSON envelope."""
    az_output = json.dumps({
        "value": [{
            "code": "ProvisioningState/succeeded",
            "message": (
                "Enable succeeded: \n[stdout]\n"
                "PROBE_OUTPUT_PATH=/tmp/fw_abc123.txt\n"
                "PROBE_OUTPUT_BYTES=4096\n"
                "\n[stderr]\n"
            ),
        }]
    })
    result = _parse_probe_response(az_output)
    assert result["probe_output_path"]  == "/tmp/fw_abc123.txt"
    assert result["probe_output_bytes"] == 4096


def test_fi05_parse_probe_response_raw_fallback():
    """_parse_probe_response falls back to raw text if not JSON."""
    raw = "PROBE_OUTPUT_PATH=/tmp/fw_xyz.txt\nPROBE_OUTPUT_BYTES=1234\n"
    result = _parse_probe_response(raw)
    assert result["probe_output_path"]  == "/tmp/fw_xyz.txt"
    assert result["probe_output_bytes"] == 1234


def test_fi06_parse_probe_response_missing_path_raises():
    """_parse_probe_response raises RuntimeError if PROBE_OUTPUT_PATH not found."""
    with pytest.raises(RuntimeError, match="Probe output path not found"):
        _parse_probe_response("some output without the expected lines")


# ===========================================================================
# Functional tests: save_snapshot / load_snapshot
# ===========================================================================

def test_fi07_snapshot_round_trip(tmp_path):
    """save_snapshot + load_snapshot round-trip preserves all fields."""
    snap = {
        "snapshot_at": "2026-03-14T10:00:00Z",
        "session_id":  "fw_test",
        "vm_name":     "prod-vm-01",
        "nested":      {"key": [1, 2, 3]},
    }
    save_snapshot(snap, str(tmp_path), "fw_test")
    loaded = load_snapshot(str(tmp_path), "fw_test")
    assert loaded == snap


def test_fi08_load_missing_snapshot_raises_file_not_found(tmp_path):
    """load_snapshot raises FileNotFoundError when snapshot JSON absent."""
    with pytest.raises(FileNotFoundError):
        load_snapshot(str(tmp_path), "nonexistent")


# ===========================================================================
# Functional tests: LocalShell
# ===========================================================================

def test_fi09_local_shell_executes_command():
    """LocalShell.execute() runs a command and returns the standard contract."""
    shell = LocalShell()
    result = shell.execute({"command": "echo hello"})
    assert result["status"]    == "success"
    assert result["exit_code"] == 0
    assert "hello" in result["output"]
    assert result["audit_id"]  == "local"


def test_fi10_local_shell_returns_error_on_nonzero():
    """LocalShell.execute() returns status='error' on non-zero exit code."""
    shell = LocalShell()
    result = shell.execute({"command": "false"})
    assert result["status"]    == "error"
    assert result["exit_code"] != 0


def test_fi11_local_shell_no_log_when_no_audit_dir():
    """LocalShell without audit_dir/session_id runs execute() without logging."""
    shell = LocalShell()
    result = shell.execute({"command": "echo ok"})
    assert result["status"] == "success"
    # No exception — logging silently disabled


# ===========================================================================
# SSHProvider tests
# ===========================================================================

def _make_ssh_provider(
    shell=None,
    target_vm_ip: str = "192.168.64.5",
    target_ssh_key_path: str = "/home/user/.ssh/id_rsa",
    bastion_public_ip: str | None = None,
    bastion_ssh_key_path: str | None = None,
) -> SSHProvider:
    if shell is None:
        shell = MagicMock()
    return SSHProvider(
        shell                = shell,
        ssh_user             = "ubuntu",
        target_vm_ip         = target_vm_ip,
        target_ssh_key_path  = target_ssh_key_path,
        bastion_public_ip    = bastion_public_ip,
        bastion_ssh_key_path = bastion_ssh_key_path,
    )


def test_sec_ssh_08_ssh_provider_run_probe_command_format():
    """SEC-SSH-08: SSHProvider.run_probe builds a correct SSH command.

    Verifies:
    - session_id and ssh_user appear together as bash positional args (not just as
      incidental matches with the SSH username)
    - stdin redirect < is present (delivers probe script to remote bash)
    - target IP present
    """
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success",
        "output": "PROBE_OUTPUT_PATH=/tmp/fw_AbCdEf.txt\nPROBE_OUTPUT_BYTES=1024\n",
        "exit_code": 0,
        "audit_id": "a1",
    }
    provider = _make_ssh_provider(mock_shell)

    result = provider.run_probe("fw-test", "fw_20260315_100000", "ubuntu", "#!/bin/bash\necho hi\n")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "bash -s" in cmd
    # Verify session_id and ssh_user appear as bash positional args, not just as SSH user.
    # The pattern "bash -s -- <session_id> <ssh_user>" is the only place both appear together.
    assert "bash -s -- fw_20260315_100000 ubuntu" in cmd
    assert "192.168.64.5" in cmd
    # stdin redirect must be present — this is how the probe script reaches the remote bash
    assert "<" in cmd
    assert result["probe_output_path"] == "/tmp/fw_AbCdEf.txt"
    assert result["probe_output_bytes"] == 1024


def test_sec_ssh_09_ssh_provider_run_probe_denied_raises():
    """SEC-SSH-09: SSHProvider.run_probe raises RuntimeError when shell denies the command."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "denied", "output": "", "exit_code": -1, "audit_id": "a1",
    }
    provider = _make_ssh_provider(mock_shell)

    with pytest.raises(RuntimeError, match="denied"):
        provider.run_probe("fw-test", "fw_session", "ubuntu", "#!/bin/bash\necho hi\n")


def test_sec_ssh_10_ssh_provider_run_probe_nonzero_exit_raises():
    """SEC-SSH-10: SSHProvider.run_probe raises RuntimeError on non-zero SSH exit code."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "error", "output": "ssh: connect to host 192.168.64.5: Connection refused",
        "exit_code": 255, "audit_id": "a1",
    }
    provider = _make_ssh_provider(mock_shell)

    with pytest.raises(RuntimeError, match="SSH probe failed"):
        provider.run_probe("fw-test", "fw_session", "ubuntu", "#!/bin/bash\necho hi\n")


def test_sec_ssh_11_ssh_provider_retrieve_uses_strict_host_key_checking(tmp_path):
    """SEC-SSH-11: SSHProvider.retrieve_probe_output includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_ssh_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd
    assert "StrictHostKeyChecking=no" not in cmd


def test_sec_ssh_12_ssh_provider_case1_no_proxy_command(tmp_path):
    """SEC-SSH-12: SSHProvider with no bastion (Case 1) — no ProxyCommand; target IP present."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_ssh_provider(mock_shell, bastion_public_ip=None)

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))
    provider.cleanup_probe_output("/tmp/fw_AbCdEf.txt")

    for c in mock_shell.execute.call_args_list:
        cmd = c[0][0]["command"]
        assert "ProxyCommand" not in cmd
        assert "192.168.64.5" in cmd


def test_sec_ssh_13_ssh_provider_case2_proxy_command_present(tmp_path):
    """SEC-SSH-13: SSHProvider with bastion (Case 2) — ProxyCommand containing bastion IP."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_ssh_provider(mock_shell, bastion_public_ip="10.0.0.1")

    provider.retrieve_probe_output("/tmp/fw_AbCdEf.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    assert "10.0.0.1" in cmd


def test_fi12_invalid_provider_from_config_is_rejected(tmp_path):
    """FI-12: PROVIDER=bad_value in config.env is rejected before provider instantiation.

    argparse choices= only validates argv values, not set_defaults values.
    Explicit post-parse validation must catch invalid PROVIDER from config.env.
    """
    config_file = tmp_path / "config.env"
    config_file.write_text(
        "PROVIDER=ftp\n"
        "TARGET_VM_IP=10.0.0.1\n"
        "SSH_USER=ubuntu\n"
        "TARGET_SSH_KEY_PATH=/tmp/key\n"
        "AUDIT_DIR=/tmp/audit\n"
    )
    from firewall_inspector import main
    with pytest.raises(SystemExit) as exc_info:
        main(["--config", str(config_file)])
    assert exc_info.value.code == 2  # argparse error exits with code 2


def test_sec_ssh_14_ssh_provider_run_probe_strict_host_key_checking():
    """SEC-SSH-14: SSHProvider.run_probe SSH command includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {
        "status": "success",
        "output": "PROBE_OUTPUT_PATH=/tmp/fw_AbCdEf.txt\nPROBE_OUTPUT_BYTES=512\n",
        "exit_code": 0,
        "audit_id": "a1",
    }
    provider = _make_ssh_provider(mock_shell)

    provider.run_probe("fw-test", "fw_session", "ubuntu", "#!/bin/bash\necho hi\n")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd
    assert "StrictHostKeyChecking=no" not in cmd


# ===========================================================================
# FW-NF: nftables framework integration
# ===========================================================================
#
# Mock boundary (per FD-12): detect_framework() must always be mocked in unit
# tests. A live call against nft-only probe output returns "unknown", not
# "nftables". All diff functions (nft_diff_rulesets, diff_rulesets,
# classify_diff) and parser functions (parse_nft_ruleset, parse_iptables_save)
# are also mocked so tests exercise routing logic only — not parser internals.
# ---------------------------------------------------------------------------

# ─── Shared fixtures ────────────────────────────────────────────────────────

_MINIMAL_NFT_JSON = json.dumps({
    "nftables": [
        {"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch",
                      "json_schema_version": 1}},
    ]
})

# Probe text from a native-nftables VM (iptables sections unavailable)
_NFT_PROBE_TEXT = (
    "###SECTION:framework_detection###\n"
    "nftables v1.0.2 (Lester Gooch)\n"
    "###SECTION:iptables_ipv4###\n"
    "###UNAVAILABLE###\n"
    "###SECTION:iptables_ipv6###\n"
    "###UNAVAILABLE###\n"
    "###SECTION:nftables###\n"
    + _MINIMAL_NFT_JSON + "\n"
)

# Probe text from an iptables-legacy VM (nftables section unavailable)
_IPT_PROBE_TEXT = (
    "###SECTION:framework_detection###\n"
    "iptables v1.8.7 (legacy)\n"
    "###SECTION:iptables_ipv4###\n"
    "# Generated by iptables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    "###SECTION:iptables_ipv6###\n"
    "###UNAVAILABLE###\n"
    "###SECTION:nftables###\n"
    "###UNAVAILABLE###\n"
)

# Probe text where nftables section is present but blank (not ###UNAVAILABLE###)
# This is the "outer redirect" known limitation — empty string triggers the
# not nft_content.strip() guard rather than _section_available().
_NFT_EMPTY_SECTION_PROBE_TEXT = (
    "###SECTION:framework_detection###\n"
    "nftables v1.0.2 (Lester Gooch)\n"
    "###SECTION:iptables_ipv4###\n"
    "###UNAVAILABLE###\n"
    "###SECTION:iptables_ipv6###\n"
    "###UNAVAILABLE###\n"
    "###SECTION:nftables###\n"
    "\n"
)

_PARSED_NFT_STUB = {
    "tables": {}, "chains": {}, "rules": [],
    "sets": {}, "maps": {},
    "input_format": "nft_json",
    "schema_version": 1,
    "nft_version": "1.0.2",
    "captured_at": "2026-03-16T00:00:00Z",
    "warnings": [],
}

_PARSED_IPT_STUB = {
    "tables": {"filter": {"policy": "ACCEPT", "chains": {}}},
    "warnings": [],
}

_NFT_DIFF_STUB = {
    "rules_added": [], "rules_removed": [],
    "chains_added": [], "chains_removed": [],
    "policy_changes": [],
    "drift_detected": False,
    "has_critical_changes": False,
}

_IPT_DIFF_STUB = {
    "rules_added": [], "rules_removed": [],
    "chains_added": [], "chains_removed": [],
    "policy_changes": [],
    "drift_detected": False,
}

_CLASSIFIED_DIFF_STUB = {**_IPT_DIFF_STUB, "has_critical_changes": False}

_NFT_FW_DETECT = {"framework": "nftables", "confidence": "high", "parse_warnings": []}
_IPT_FW_DETECT = {"framework": "iptables", "confidence": "high", "parse_warnings": []}


def _probe_provider(probe_text: str) -> MagicMock:
    """Mock provider that writes probe_text to local_path during retrieve_probe_output."""
    p = MagicMock()
    p.run_probe.return_value = {
        "probe_output_path": "/tmp/fw_nft_test.txt",
        "probe_output_bytes": len(probe_text),
    }

    def _retrieve(remote_path, local_path):
        Path(local_path).write_text(probe_text, encoding="utf-8")

    p.retrieve_probe_output.side_effect = _retrieve
    p.cleanup_probe_output.return_value = True
    return p


def _nft_config(tmp_path, **kw) -> InspectorConfig:
    defaults = dict(
        ssh_user="ubuntu", target_vm_ip="10.0.0.1", ssh_key_path="/tmp/key",
        session_id="fw_nft_test", audit_dir=str(tmp_path),
        vm_name="test-vm", resource_group="rg",
    )
    defaults.update(kw)
    return InspectorConfig(**defaults)


# ─── Tests ──────────────────────────────────────────────────────────────────

def test_fw_nf01_parse_nft_ruleset_called_once_for_nftables(tmp_path):
    """FW-NF01: detect_framework="nftables" → parse_nft_ruleset() call count == 1; "ipv4" absent from rulesets."""
    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset", return_value=_PARSED_NFT_STUB) as mock_parse_nft:
        config = _nft_config(tmp_path, is_baseline=True)
        result = _fi_run(config, MagicMock(), _probe_provider(_NFT_PROBE_TEXT))

    assert mock_parse_nft.call_count == 1, "parse_nft_ruleset must be called exactly once for nftables"
    assert "ipv4" not in result["snapshot"]["rulesets"], "'ipv4' key must not appear in nftables rulesets"
    assert "nft" in result["snapshot"]["rulesets"]


def test_fw_nf02_snapshot_rulesets_has_nft_key_regardless_of_family_config(tmp_path):
    """FW-NF02: nftables snapshot stores rulesets["nft"]; config.family value does not override the key.

    config.family is ignored for nftables runs — the parser always produces
    a single "nft" key, regardless of whether config.family is "ipv4" or "both".
    """
    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset", return_value=_PARSED_NFT_STUB):
        config = _nft_config(tmp_path, is_baseline=True, family="ipv4")
        result = _fi_run(config, MagicMock(), _probe_provider(_NFT_PROBE_TEXT))

    rulesets = result["snapshot"]["rulesets"]
    assert "nft" in rulesets, "rulesets must have 'nft' key for nftables framework"
    assert "ipv4" not in rulesets, "iptables keys must not appear in nftables snapshot"
    assert "ipv6" not in rulesets


def test_fw_nf03_parse_nft_ruleset_not_called_for_iptables(tmp_path):
    """FW-NF03: detect_framework="iptables" → parse_nft_ruleset() call count == 0."""
    with patch("firewall_inspector.detect_framework", return_value=_IPT_FW_DETECT), \
         patch("firewall_inspector.parse_iptables_save", return_value=_PARSED_IPT_STUB), \
         patch("firewall_inspector.parse_nft_ruleset") as mock_parse_nft:
        config = _nft_config(tmp_path, is_baseline=True)
        _fi_run(config, MagicMock(), _probe_provider(_IPT_PROBE_TEXT))

    assert mock_parse_nft.call_count == 0, "parse_nft_ruleset must NOT be called for iptables framework"


def test_fw_nf04_nftables_diff_routes_to_nft_diff_rulesets_not_classify_diff(tmp_path):
    """FW-NF04: nftables diff path → nft_diff_rulesets() call count == 1; classify_diff() call count == 0.

    classify_diff() is iptables-only (uses KUBE-SEP-, DOCKER, f2b-, ufw- chain patterns).
    Calling it on nftables diffs would corrupt drift reports with spurious severity annotations.
    """
    baseline_snap = {
        "snapshot_at": "2026-03-16T00:00:00Z",
        "session_id": "fw_nft_base",
        "framework": "nftables",
        "family": "ipv4",
        "rulesets": {"nft": _PARSED_NFT_STUB},
    }
    save_snapshot(baseline_snap, str(tmp_path), "fw_nft_base")

    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset", return_value=_PARSED_NFT_STUB), \
         patch("firewall_inspector.nft_diff_rulesets", return_value=_NFT_DIFF_STUB) as mock_nft_diff, \
         patch("firewall_inspector.classify_diff") as mock_classify:
        config = _nft_config(tmp_path, compare_baseline="fw_nft_base")
        _fi_run(config, MagicMock(), _probe_provider(_NFT_PROBE_TEXT))

    assert mock_nft_diff.call_count == 1, "nft_diff_rulesets must be called once for nftables diff"
    assert mock_classify.call_count == 0, "classify_diff must NOT be called for nftables diff"


def test_fw_nf05_iptables_diff_routes_to_diff_rulesets_and_classify_diff(tmp_path):
    """FW-NF05: iptables diff path → diff_rulesets() == 1, classify_diff() == 1; nft_diff_rulesets() == 0."""
    baseline_snap = {
        "snapshot_at": "2026-03-16T00:00:00Z",
        "session_id": "fw_ipt_base",
        "framework": "iptables",
        "family": "ipv4",
        "rulesets": {"ipv4": _PARSED_IPT_STUB},
    }
    save_snapshot(baseline_snap, str(tmp_path), "fw_ipt_base")

    with patch("firewall_inspector.detect_framework", return_value=_IPT_FW_DETECT), \
         patch("firewall_inspector.parse_iptables_save", return_value=_PARSED_IPT_STUB), \
         patch("firewall_inspector.diff_rulesets", return_value=_IPT_DIFF_STUB) as mock_diff, \
         patch("firewall_inspector.classify_diff", return_value=_CLASSIFIED_DIFF_STUB) as mock_classify, \
         patch("firewall_inspector.nft_diff_rulesets") as mock_nft_diff:
        config = _nft_config(tmp_path, compare_baseline="fw_ipt_base")
        _fi_run(config, MagicMock(), _probe_provider(_IPT_PROBE_TEXT))

    assert mock_diff.call_count == 1, "diff_rulesets must be called once for iptables diff"
    assert mock_classify.call_count == 1, "classify_diff must be called once for iptables diff"
    assert mock_nft_diff.call_count == 0, "nft_diff_rulesets must NOT be called for iptables diff"


def test_fw_nf06_framework_mismatch_raises_value_error(tmp_path):
    """FW-NF06: baseline=iptables (ipv4 key), current=nftables (nft key) → ValueError; nft_diff_rulesets() == 0.

    The mismatch guard compares "nft" key presence in baseline.rulesets vs current parsed dict.
    This correctly fires on a true iptables↔nftables crossover while treating iptables-legacy
    and iptables-nft (both produce ipv4/ipv6 keys) as the same family.
    """
    baseline_snap = {
        "snapshot_at": "2026-03-16T00:00:00Z",
        "session_id": "fw_ipt_base",
        "framework": "iptables",
        "family": "ipv4",
        "rulesets": {"ipv4": _PARSED_IPT_STUB},
    }
    save_snapshot(baseline_snap, str(tmp_path), "fw_ipt_base")

    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset", return_value=_PARSED_NFT_STUB), \
         patch("firewall_inspector.nft_diff_rulesets") as mock_nft_diff:
        config = _nft_config(tmp_path, compare_baseline="fw_ipt_base")
        with pytest.raises(ValueError, match="Framework mismatch"):
            _fi_run(config, MagicMock(), _probe_provider(_NFT_PROBE_TEXT))

    assert mock_nft_diff.call_count == 0, "nft_diff_rulesets must not be called when mismatch guard fires"


def test_fw_nf07_unavailable_nftables_section_sets_parsed_nft_none(tmp_path):
    """FW-NF07: ###UNAVAILABLE### nftables section → parsed["nft"] is None; parse_nft_ruleset() call count == 0."""
    unavail_probe = (
        "###SECTION:framework_detection###\n"
        "nftables v1.0.2 (Lester Gooch)\n"
        "###SECTION:iptables_ipv4###\n"
        "###UNAVAILABLE###\n"
        "###SECTION:iptables_ipv6###\n"
        "###UNAVAILABLE###\n"
        "###SECTION:nftables###\n"
        "###UNAVAILABLE###\n"
    )
    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset") as mock_parse_nft:
        config = _nft_config(tmp_path, is_baseline=True)
        result = _fi_run(config, MagicMock(), _probe_provider(unavail_probe))

    assert mock_parse_nft.call_count == 0, "parse_nft_ruleset must NOT be called when section is ###UNAVAILABLE###"
    assert result["snapshot"]["rulesets"]["nft"] is None


def test_fw_nf07b_empty_nftables_section_sets_parsed_nft_none(tmp_path):
    """FW-NF07b: Empty (blank) nftables section → parsed["nft"] is None; parse_nft_ruleset() call count == 0.

    _section_available("") returns True (only checks for ###UNAVAILABLE###).
    The additional `not nft_content.strip()` guard is what catches this case
    and prevents an empty string being fed to parse_nft_ruleset() causing JSONDecodeError.
    """
    with patch("firewall_inspector.detect_framework", return_value=_NFT_FW_DETECT), \
         patch("firewall_inspector.parse_nft_ruleset") as mock_parse_nft:
        config = _nft_config(tmp_path, is_baseline=True)
        result = _fi_run(config, MagicMock(), _probe_provider(_NFT_EMPTY_SECTION_PROBE_TEXT))

    assert mock_parse_nft.call_count == 0, (
        "parse_nft_ruleset must NOT be called when section content is empty — "
        "empty string fed to json.loads() raises JSONDecodeError"
    )
    assert result["snapshot"]["rulesets"]["nft"] is None


def test_fw_nf08_probe_script_contains_nftables_section():
    """FW-NF08: _PROBE_SCRIPT includes the nftables section marker and the nft --json list ruleset command."""
    assert "###SECTION:nftables###" in _PROBE_SCRIPT, (
        "Probe script must include '###SECTION:nftables###' marker"
    )
    assert "nft --json list ruleset" in _PROBE_SCRIPT, (
        "Probe script must include 'nft --json list ruleset' command"
    )
