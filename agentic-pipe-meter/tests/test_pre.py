"""PRE-01 to PRE-19: preflight() tests."""

import json
import os
import pytest
from unittest.mock import MagicMock, patch
from helpers import shell_ok, shell_fail, shell_denied
from pipe_meter import preflight, PreflightResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IPERF_VER = "iperf version 2.1.9 (3 May 2022) pthreads"
TOOL_CHECKS_OK = [
    shell_ok(""),               # which qperf source
    shell_ok(""),               # which iperf source
    shell_ok(IPERF_VER),        # iperf -v source
    shell_ok(""),               # which qperf dest
    shell_ok(""),               # which iperf dest
    shell_ok(IPERF_VER),        # iperf -v dest
]


# ---------------------------------------------------------------------------
# PRE-01  Happy path: NSG open, tools present
# ---------------------------------------------------------------------------

def test_pre01_happy_path(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-01 M: All checks pass; preflight returns success."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = list(TOOL_CHECKS_OK)
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.ports_open is True
    assert result.tools_ready is True
    assert result.actions_taken == []


# ---------------------------------------------------------------------------
# PRE-02  Artifact written on success
# ---------------------------------------------------------------------------

def test_pre02_artifact_written(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-02 M: _preflight.json artifact written on success."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = list(TOOL_CHECKS_OK)
    preflight(base_config, mock_shell, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_preflight.json"
    assert art_path.exists()
    data = json.loads(art_path.read_text())
    assert data["ports_open"] is True
    assert data["tools_ready"] is True
    assert data["session_id"] == base_config.session_id


# ---------------------------------------------------------------------------
# PRE-03  Port blocked, operator approves remediation
# ---------------------------------------------------------------------------

def test_pre03_port_blocked_approved(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-03 M: Blocked port triggers remediation; approval opens port."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [
        shell_ok(""),   # az nsg rule create
        *TOOL_CHECKS_OK,
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.ports_open is True
    assert "Opened ports" in result.actions_taken[0]


# ---------------------------------------------------------------------------
# PRE-04  Port blocked, operator denies remediation
# ---------------------------------------------------------------------------

def test_pre04_port_blocked_denied(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-04 M: Blocked port denied → ports_open=False."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [shell_denied()]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.ports_open is False
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-05  Port blocked, remediation command fails
# ---------------------------------------------------------------------------

def test_pre05_port_open_cmd_fails(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-05 M: NSG rule create fails → ports_open=False."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [shell_fail("Error: nsg rule create failed", exit_code=1)]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.ports_open is False


# ---------------------------------------------------------------------------
# PRE-06  NSG check raises RuntimeError
# ---------------------------------------------------------------------------

def test_pre06_nsg_check_raises(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-06 G: Provider RuntimeError propagates."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.side_effect = RuntimeError("NIC lookup failed")
    with pytest.raises(RuntimeError, match="NIC lookup failed"):
        preflight(base_config, mock_shell, mock_provider)


# ---------------------------------------------------------------------------
# PRE-07  Artifact written even when NSG check raises
# ---------------------------------------------------------------------------

def test_pre07_artifact_on_port_denied(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-07 G: _preflight.json written when port remediation is denied."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: False}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [shell_denied()]
    preflight(base_config, mock_shell, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_preflight.json"
    assert art_path.exists()


# ---------------------------------------------------------------------------
# PRE-08  qperf missing on source → install offered (apt)
# ---------------------------------------------------------------------------

def test_pre08_qperf_missing_install_apt(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-08 M: Missing qperf triggers install attempt (apt)."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("", exit_code=1),  # which qperf source — missing
        shell_ok(""),                 # which iperf source
        shell_ok(""),                 # which apt-get
        shell_ok(""),                 # apt-get install
        shell_ok(IPERF_VER),          # iperf -v source
        shell_ok(""),                 # which qperf dest
        shell_ok(""),                 # which iperf dest
        shell_ok(IPERF_VER),          # iperf -v dest
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is True
    assert any("Installed" in a for a in result.actions_taken)


# ---------------------------------------------------------------------------
# PRE-09  Install denied → tools_ready=False
# ---------------------------------------------------------------------------

def test_pre09_install_denied(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-09 M: Install denied → tools_ready=False."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("", exit_code=1),  # which qperf source — missing
        shell_ok(""),                 # which iperf source
        shell_ok(""),                 # which apt-get
        shell_denied(),               # apt-get install denied
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-10  Install fails → tools_ready=False
# ---------------------------------------------------------------------------

def test_pre10_install_fails(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-10 M: Install command fails → tools_ready=False."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("", exit_code=1),    # which qperf source — missing
        shell_ok(""),                   # which iperf source
        shell_ok(""),                   # which apt-get
        shell_fail("dpkg failed", 1),   # apt-get install fails
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-11  iperf version 3 detected
# ---------------------------------------------------------------------------

def test_pre11_iperf3_detected(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-11 M: iperf3 on source → tools_ready=False."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),                           # which qperf source
        shell_ok(""),                           # which iperf source
        shell_ok("iperf version 3.1 (cJSON)"),  # iperf -v source — wrong version
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-12  SSH failure (exit 255) on source
# ---------------------------------------------------------------------------

def test_pre12_ssh_failure_source(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-12 M: SSH exit 255 on source → tools_ready=False."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("ssh: connect to host", exit_code=255),  # which qperf source
        shell_ok(""),                                        # which iperf source (not reached)
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-13  Both VMs need tools, first succeeds, second fails
# ---------------------------------------------------------------------------

def test_pre13_second_vm_install_fails(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-13 G: First VM install OK, second VM install denied."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("", exit_code=1),  # which qperf source — missing
        shell_ok(""),                 # which iperf source
        shell_ok(""),                 # which apt-get source
        shell_ok(""),                 # apt-get install source — ok
        shell_ok(IPERF_VER),          # iperf -v source
        shell_fail("", exit_code=1),  # which qperf dest — missing
        shell_ok(""),                 # which iperf dest
        shell_ok(""),                 # which apt-get dest
        shell_denied(),               # apt-get install dest — denied
    ]
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is False


# ---------------------------------------------------------------------------
# PRE-14  yum used when apt-get absent
# ---------------------------------------------------------------------------

def test_pre14_yum_fallback(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-14 G: yum used when apt-get not found."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_fail("", exit_code=1),  # which qperf source — missing
        shell_ok(""),                 # which iperf source
        shell_fail("", exit_code=1),  # which apt-get — not found
        shell_ok(""),                 # yum install
        shell_ok(IPERF_VER),          # iperf -v source
        shell_ok(""),                 # which qperf dest
        shell_ok(""),                 # which iperf dest
        shell_ok(IPERF_VER),          # iperf -v dest
    ]
    # Check that yum was used
    result = preflight(base_config, mock_shell, mock_provider)
    assert result.tools_ready is True
    # Verify the install command used yum
    calls = [str(c) for c in mock_shell.execute.call_args_list]
    assert any("yum" in c for c in calls)


# ---------------------------------------------------------------------------
# PRE-15  Blocked ports in artifact
# ---------------------------------------------------------------------------

def test_pre15_blocked_ports_in_artifact(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-15 G: blocked_ports list in artifact when port denied."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [shell_denied()]
    preflight(base_config, mock_shell, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_preflight.json"
    data = json.loads(art_path.read_text())
    assert 5001 in data["blocked_ports"]


# ---------------------------------------------------------------------------
# PRE-16  actions_taken recorded in artifact
# ---------------------------------------------------------------------------

def test_pre16_actions_taken_in_artifact(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-16 G: actions_taken recorded in artifact after port fix."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [
        shell_ok(""),   # nsg rule create
        *TOOL_CHECKS_OK,
    ]
    preflight(base_config, mock_shell, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_preflight.json"
    data = json.loads(art_path.read_text())
    assert len(data["actions_taken"]) > 0


# ---------------------------------------------------------------------------
# PRE-17  Preflight prints NSG blocked message
# ---------------------------------------------------------------------------

def test_pre17_blocked_console_message(base_config, mock_shell, mock_provider, tmp_path, capsys):
    """PRE-17 G: Console message includes blocked port numbers."""
    base_config.audit_dir = str(tmp_path)
    mock_provider.check_nsg_ports.return_value = {5001: False, 19765: True}
    mock_provider.generate_port_open_commands.return_value = ["az network nsg rule create ..."]
    mock_shell.execute.side_effect = [shell_denied()]
    preflight(base_config, mock_shell, mock_provider)
    out = capsys.readouterr().out
    assert "5001" in out


# ---------------------------------------------------------------------------
# PRE-18  preflight with source_public_ip (jump host)
# ---------------------------------------------------------------------------

def test_pre18_source_public_ip(tmp_path, mock_shell, mock_provider):
    """PRE-18 G: source_public_ip used for SSH routing."""
    from pipe_meter import PipelineConfig
    config = PipelineConfig(
        source_ip="10.0.0.4",
        dest_ip="10.0.0.5",
        ssh_user="azureuser",
        test_type="latency",
        iterations=2,
        is_baseline=False,
        storage_account="mystorage",
        container="results",
        resource_group="my-rg",
        session_id="pmeter_test",
        audit_dir=str(tmp_path),
        source_public_ip="1.2.3.4",
    )
    mock_shell.execute.side_effect = [*TOOL_CHECKS_OK, shell_ok("")]  # extra: which curl
    result = preflight(config, mock_shell, mock_provider)
    assert result.ports_open is True
    # source SSH calls should use the public IP
    calls = [str(c) for c in mock_shell.execute.call_args_list]
    assert any("1.2.3.4" in c for c in calls)


# ---------------------------------------------------------------------------
# PRE-19  Timestamp present in artifact
# ---------------------------------------------------------------------------

def test_pre19_timestamp_in_artifact(base_config, mock_shell, mock_provider, tmp_path):
    """PRE-19 O: timestamp_utc field present in _preflight.json."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = list(TOOL_CHECKS_OK)
    preflight(base_config, mock_shell, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_preflight.json"
    data = json.loads(art_path.read_text())
    assert "timestamp_utc" in data


# ---------------------------------------------------------------------------
# PRE-20  which curl present on source VM → tools_ready=True
# ---------------------------------------------------------------------------

def test_pre20_curl_present(tmp_path, mock_shell, mock_provider):
    """PRE-20 M: which curl succeeds on source VM → tools_ready=True."""
    from pipe_meter import PipelineConfig
    config = PipelineConfig(
        source_ip="10.0.0.4",
        dest_ip="10.0.0.5",
        ssh_user="azureuser",
        test_type="latency",
        iterations=2,
        is_baseline=False,
        storage_account="mystorage",
        container="results",
        resource_group="my-rg",
        session_id="pmeter_test",
        audit_dir=str(tmp_path),
        source_public_ip="1.2.3.4",
    )
    mock_shell.execute.side_effect = [*TOOL_CHECKS_OK, shell_ok("/usr/bin/curl")]
    result = preflight(config, mock_shell, mock_provider)
    assert result.tools_ready is True


# ---------------------------------------------------------------------------
# PRE-21  which curl missing on source VM → tools_ready=False
# ---------------------------------------------------------------------------

def test_pre21_curl_missing(tmp_path, mock_shell, mock_provider):
    """PRE-21 M: which curl fails on source VM → tools_ready=False."""
    from pipe_meter import PipelineConfig
    config = PipelineConfig(
        source_ip="10.0.0.4",
        dest_ip="10.0.0.5",
        ssh_user="azureuser",
        test_type="latency",
        iterations=2,
        is_baseline=False,
        storage_account="mystorage",
        container="results",
        resource_group="my-rg",
        session_id="pmeter_test",
        audit_dir=str(tmp_path),
        source_public_ip="1.2.3.4",
    )
    mock_shell.execute.side_effect = [*TOOL_CHECKS_OK, shell_fail("", exit_code=1)]
    result = preflight(config, mock_shell, mock_provider)
    assert result.tools_ready is False
    assert result.ports_open is True
