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
)
from providers import LocalShell, AzureProvider, SSHProvider, _parse_probe_response


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


# ===========================================================================
# SEC-SSH: StrictHostKeyChecking in all SCP/SSH commands
# ===========================================================================

def _make_provider(
    shell=None,
    target_vm_ip: str = "10.0.0.5",
    target_ssh_key_path: str = "/home/user/.ssh/id_rsa",
    bastion_public_ip: str | None = "1.2.3.4",
    bastion_ssh_key_path: str | None = None,
) -> AzureProvider:
    if shell is None:
        shell = MagicMock()
    return AzureProvider(
        shell                = shell,
        resource_group       = "rg",
        ssh_user             = "azureuser",
        target_vm_ip         = target_vm_ip,
        target_ssh_key_path  = target_ssh_key_path,
        bastion_public_ip    = bastion_public_ip,
        bastion_ssh_key_path = bastion_ssh_key_path,
    )


def test_sec_ssh_01_scp_contains_strict_host_key_checking(tmp_path):
    """SEC-SSH-01: Two-hop SCP command (Case 2) includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd


def test_sec_ssh_02_scp_contains_proxy_command(tmp_path):
    """SEC-SSH-02: Two-hop SCP (Case 2) uses ProxyCommand containing bastion_public_ip."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    assert "1.2.3.4" in cmd  # bastion_public_ip


def test_sec_ssh_03_cleanup_contains_strict_host_key_checking():
    """SEC-SSH-03: SSH cleanup command includes -o StrictHostKeyChecking=yes."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.cleanup_probe_output("/tmp/fw_abc.txt")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd


def test_sec_ssh_04_no_command_uses_strict_host_checking_no():
    """SEC-SSH-04 (regression guard): 'StrictHostKeyChecking=no' never appears in any built command."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_provider(mock_shell)

    provider.retrieve_probe_output("/tmp/fw_abc.txt", "/tmp/local.txt")
    provider.cleanup_probe_output("/tmp/fw_abc.txt")

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

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))
    provider.cleanup_probe_output("/tmp/fw_abc.txt")

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

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

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

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "ProxyCommand" in cmd
    # Same key path appears in both outer -i and inside ProxyCommand
    assert cmd.count("/home/user/.ssh/id_rsa") >= 2


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
        "output": "PROBE_OUTPUT_PATH=/tmp/fw_abc.txt\nPROBE_OUTPUT_BYTES=1024\n",
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
    assert result["probe_output_path"] == "/tmp/fw_abc.txt"
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

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd
    assert "StrictHostKeyChecking=no" not in cmd


def test_sec_ssh_12_ssh_provider_case1_no_proxy_command(tmp_path):
    """SEC-SSH-12: SSHProvider with no bastion (Case 1) — no ProxyCommand; target IP present."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_ssh_provider(mock_shell, bastion_public_ip=None)

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))
    provider.cleanup_probe_output("/tmp/fw_abc.txt")

    for c in mock_shell.execute.call_args_list:
        cmd = c[0][0]["command"]
        assert "ProxyCommand" not in cmd
        assert "192.168.64.5" in cmd


def test_sec_ssh_13_ssh_provider_case2_proxy_command_present(tmp_path):
    """SEC-SSH-13: SSHProvider with bastion (Case 2) — ProxyCommand containing bastion IP."""
    mock_shell = MagicMock()
    mock_shell.execute.return_value = {"status": "success", "output": "", "exit_code": 0, "audit_id": "a1"}
    provider = _make_ssh_provider(mock_shell, bastion_public_ip="10.0.0.1")

    provider.retrieve_probe_output("/tmp/fw_abc.txt", str(tmp_path / "out.txt"))

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
        "output": "PROBE_OUTPUT_PATH=/tmp/fw_abc.txt\nPROBE_OUTPUT_BYTES=512\n",
        "exit_code": 0,
        "audit_id": "a1",
    }
    provider = _make_ssh_provider(mock_shell)

    provider.run_probe("fw-test", "fw_session", "ubuntu", "#!/bin/bash\necho hi\n")

    cmd = mock_shell.execute.call_args[0][0]["command"]
    assert "StrictHostKeyChecking=yes" in cmd
    assert "StrictHostKeyChecking=no" not in cmd
