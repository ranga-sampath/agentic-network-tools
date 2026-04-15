"""
test_cli.py — Unit tests for security_rule_inspector.py CLI functions

Covers:
  T-CLI-01 through T-CLI-12  Argument parsing, mode detection, session ID,
  traffic tuple validation, collision check, audit dir creation.
"""

import argparse
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from security_rule_inspector import (
    _check_collision,
    _detect_mode,
    _enforce_session_prefix,
    _ensure_audit_dir,
    _validate_traffic_tuple,
)
from nsg_engine import TrafficTuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(**kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace with traffic flags defaulting to None."""
    defaults = {
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "proto": None,
        "direction": None,
        "vm_name": "test-vm",
        "resource_group": "test-rg",
        "nic_name": None,
        "subscription_id": None,
        "session_id": None,
        "audit_dir": "./audit",
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# T-CLI-01 — Mode detection: all five → verdict
# ---------------------------------------------------------------------------

def test_cli_01_all_five_traffic_flags_verdict_mode():
    """T-CLI-01: All five traffic flags → verdict mode [CLI]"""
    args = _make_args(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        proto="tcp",
        direction="inbound",
    )
    assert _detect_mode(args) == "verdict"


# ---------------------------------------------------------------------------
# T-CLI-02 — Mode detection: none → audit
# ---------------------------------------------------------------------------

def test_cli_02_no_traffic_flags_audit_mode():
    """T-CLI-02: No traffic flags → audit mode [CLI]"""
    args = _make_args()
    assert _detect_mode(args) == "audit"


# ---------------------------------------------------------------------------
# T-CLI-03 — Mode detection: partial tuple → exit 2
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provided_count", [1, 2, 3, 4])
def test_cli_03_partial_traffic_flags_exit_2(provided_count):
    """T-CLI-03: Partial traffic tuple (1, 2, 3, or 4 flags) → exit 2 [CLI, DANGER]"""
    # Use the first 'provided_count' flags from the five available
    flag_values = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "proto": "tcp",
        "direction": "inbound",
    }
    keys = list(flag_values.keys())[:provided_count]
    args = _make_args(**{k: flag_values[k] for k in keys})

    with pytest.raises(SystemExit) as exc_info:
        _detect_mode(args)
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# T-CLI-04 — _validate_traffic_tuple() normalises protocol case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("TCP", "Tcp"),
    ("udp", "Udp"),
    ("*", "*"),
    ("icmp", "Icmp"),
])
def test_cli_04_validate_normalises_protocol_case(raw, expected):
    """T-CLI-04: _validate_traffic_tuple() normalises protocol case [CLI]"""
    args = _make_args(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=80,
        proto=raw,
        direction="inbound",
    )
    tt = _validate_traffic_tuple(args)
    assert tt.protocol == expected


# ---------------------------------------------------------------------------
# T-CLI-05 — _validate_traffic_tuple() normalises direction case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("INBOUND", "Inbound"),
    ("outbound", "Outbound"),
])
def test_cli_05_validate_normalises_direction_case(raw, expected):
    """T-CLI-05: _validate_traffic_tuple() normalises direction case [CLI]"""
    args = _make_args(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=80,
        proto="tcp",
        direction=raw,
    )
    tt = _validate_traffic_tuple(args)
    assert tt.direction == expected


# ---------------------------------------------------------------------------
# T-CLI-06 — _validate_traffic_tuple() rejects invalid IP
# ---------------------------------------------------------------------------

def test_cli_06_validate_rejects_invalid_src_ip(capsys):
    """T-CLI-06: Invalid src_ip → exit 2 with 'Invalid IP address' message [CLI]"""
    args = _make_args(
        src_ip="not-an-ip",
        dst_ip="10.0.0.2",
        dst_port=80,
        proto="tcp",
        direction="inbound",
    )
    with pytest.raises(SystemExit) as exc_info:
        _validate_traffic_tuple(args)
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "Invalid IP address" in captured.err


# ---------------------------------------------------------------------------
# T-CLI-07 — _validate_traffic_tuple() rejects port out of range
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port,should_exit", [
    (0, True),
    (65536, True),
    (65535, False),
    (1, False),
])
def test_cli_07_validate_port_range(port, should_exit):
    """T-CLI-07: Port out of range → exit 2; valid ports pass [CLI]"""
    args = _make_args(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=port,
        proto="tcp",
        direction="inbound",
    )
    if should_exit:
        with pytest.raises(SystemExit) as exc_info:
            _validate_traffic_tuple(args)
        assert exc_info.value.code == 2
    else:
        result = _validate_traffic_tuple(args)
        assert isinstance(result, TrafficTuple)
        assert result.dst_port == port


# ---------------------------------------------------------------------------
# T-CLI-08 — _enforce_session_prefix()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("input_id,expected", [
    ("myrun", "nsg_myrun"),
    ("nsg_myrun", "nsg_myrun"),
    ("nsg_", "nsg_"),
])
def test_cli_08_enforce_session_prefix(input_id, expected):
    """T-CLI-08: _enforce_session_prefix() prepends nsg_ when absent [CLI]"""
    assert _enforce_session_prefix(input_id) == expected


# ---------------------------------------------------------------------------
# T-CLI-09 — _check_collision() exits 2 when artifact exists
# ---------------------------------------------------------------------------

def test_cli_09_check_collision_exits_when_artifact_exists(tmp_path, capsys):
    """T-CLI-09: _check_collision() exits 2 when artifact exists [CLI]"""
    session_id = "nsg_test123"
    (tmp_path / f"{session_id}_raw.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        _check_collision(session_id, tmp_path)
    assert exc_info.value.code == 2

    captured = capsys.readouterr()
    assert session_id in captured.err
    assert str(tmp_path) in captured.err


# ---------------------------------------------------------------------------
# T-CLI-10 — _check_collision() passes when no artifacts exist
# ---------------------------------------------------------------------------

def test_cli_10_check_collision_passes_when_no_artifacts(tmp_path):
    """T-CLI-10: _check_collision() passes when no artifacts exist [CLI]"""
    # Empty directory — should not raise
    _check_collision("nsg_test456", tmp_path)


# ---------------------------------------------------------------------------
# T-CLI-11 — _ensure_audit_dir() creates directory if absent
# ---------------------------------------------------------------------------

def test_cli_11_ensure_audit_dir_creates_directory(tmp_path):
    """T-CLI-11: _ensure_audit_dir() creates directory if absent [CLI]"""
    new_dir = tmp_path / "nested" / "audit"
    assert not new_dir.exists()

    result = _ensure_audit_dir(str(new_dir))
    assert new_dir.exists()
    assert isinstance(result, Path)


# ---------------------------------------------------------------------------
# T-CLI-12 — --nic-name override
# ---------------------------------------------------------------------------

def test_cli_12_nic_name_override_accepted():
    """T-CLI-12: --nic-name override sets nic_name on parsed args [CLI]"""
    import security_rule_inspector

    # Patch sys.argv to simulate CLI invocation with --nic-name
    test_argv = [
        "security_rule_inspector.py",
        "--vm-name", "test-vm",
        "--resource-group", "test-rg",
        "--nic-name", "override-nic",
    ]
    with patch("sys.argv", test_argv), patch("sys.exit"):
        parser = argparse.ArgumentParser()
        parser.add_argument("--vm-name", required=True)
        parser.add_argument("--resource-group", required=True)
        parser.add_argument("--src-ip", default=None)
        parser.add_argument("--dst-ip", default=None)
        parser.add_argument("--dst-port", default=None, type=int)
        parser.add_argument("--proto", default=None)
        parser.add_argument("--direction", default=None)
        parser.add_argument("--nic-name", default=None)
        parser.add_argument("--subscription-id", default=None)
        parser.add_argument("--session-id", default=None)
        parser.add_argument("--audit-dir", default="./audit")
        args = parser.parse_args(test_argv[1:])

    assert args.nic_name == "override-nic"


# ---------------------------------------------------------------------------
# T-CLI-13 — Mode detection: 4 flags, dst_ip absent, direction=inbound → verdict
# ---------------------------------------------------------------------------

def test_cli_13_four_flags_no_dst_ip_inbound_verdict_mode():
    """T-CLI-13: src_ip + dst_port + proto + direction=inbound, dst_ip absent → verdict mode [CLI]"""
    args = _make_args(
        src_ip="10.0.1.4",
        dst_ip=None,
        dst_port=5432,
        proto="tcp",
        direction="inbound",
    )
    assert _detect_mode(args) == "verdict"


# ---------------------------------------------------------------------------
# T-CLI-14 — Mode detection: 4 flags, dst_ip absent, direction=outbound → exit 2
# ---------------------------------------------------------------------------

def test_cli_14_four_flags_no_dst_ip_outbound_exits_2():
    """T-CLI-14: dst_ip absent + direction=outbound is not a valid partial tuple → exit 2 [CLI]"""
    args = _make_args(
        src_ip="10.0.1.4",
        dst_ip=None,
        dst_port=5432,
        proto="tcp",
        direction="outbound",
    )
    with pytest.raises(SystemExit) as exc_info:
        _detect_mode(args)
    assert exc_info.value.code == 2
