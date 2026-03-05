"""SSH-01 to SSH-08: SSH command template and _make_ssh_opts() tests."""

import pytest
from pipe_meter import (
    _S1, _S2, _S3, _S4, _S5, _S6, _S7, _S8, _S9, _S10, _S11, _S12,
    _make_ssh_opts, _SSH_BASE_OPTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OPTS = _SSH_BASE_OPTS
USER = "azureuser"
SRC = "10.0.0.4"
DST = "10.0.0.5"


def _all_templates_with_opts(opts):
    """Return all S1–S12 templates using the given opts."""
    return [
        _S1(opts, USER, DST),
        _S2(opts, USER, DST, ["9876"]),
        _S3(opts, USER, DST, "qperf"),
        _S4(opts, USER, SRC, "qperf"),
        _S5(opts, USER, SRC),
        _S6(opts, USER, SRC),
        _S7(opts, USER, SRC),
        _S8(opts, USER, DST),
        _S9(opts, USER, DST),
        _S10(opts, USER, SRC, DST),
        _S11(opts, USER, SRC, DST),
        _S12(opts, USER, SRC),
    ]


# ---------------------------------------------------------------------------
# SSH-01  _S8 nohup qperf contains </dev/null
# ---------------------------------------------------------------------------

def test_ssh01_s8_devnull():
    """SSH-01 M: _S8 (qperf server) uses </dev/null to detach stdin."""
    cmd = _S8(OPTS, USER, DST)
    assert "</dev/null" in cmd


# ---------------------------------------------------------------------------
# SSH-02  _S9 nohup iperf contains </dev/null
# ---------------------------------------------------------------------------

def test_ssh02_s9_devnull():
    """SSH-02 M: _S9 (iperf server) uses </dev/null to detach stdin."""
    cmd = _S9(OPTS, USER, DST)
    assert "</dev/null" in cmd


# ---------------------------------------------------------------------------
# SSH-03  All templates S1–S12 contain the three base SSH opts
# ---------------------------------------------------------------------------

def test_ssh03_all_templates_have_base_opts():
    """SSH-03 M: All S1–S12 templates contain ConnectTimeout, BatchMode, StrictHostKeyChecking."""
    templates = _all_templates_with_opts(OPTS)
    for cmd in templates:
        assert "ConnectTimeout=15" in cmd, f"Missing ConnectTimeout in: {cmd}"
        assert "BatchMode=yes" in cmd, f"Missing BatchMode in: {cmd}"
        assert "StrictHostKeyChecking=accept-new" in cmd, f"Missing StrictHostKeyChecking in: {cmd}"


# ---------------------------------------------------------------------------
# SSH-04  _S10 (qperf client) includes -m 1024 tcp_lat flags
# ---------------------------------------------------------------------------

def test_ssh04_s10_measurement_flags():
    """SSH-04 M: _S10 includes '-m 1024 tcp_lat' measurement flags."""
    cmd = _S10(OPTS, USER, SRC, DST)
    assert "-m 1024" in cmd
    assert "tcp_lat" in cmd


# ---------------------------------------------------------------------------
# SSH-05  _S11 (iperf client) includes -P 8 -t 10 flags
# ---------------------------------------------------------------------------

def test_ssh05_s11_measurement_flags():
    """SSH-05 M: _S11 includes '-P 8 -t 10' measurement flags."""
    cmd = _S11(OPTS, USER, SRC, DST)
    assert "-P 8" in cmd
    assert "-t 10" in cmd


# ---------------------------------------------------------------------------
# SSH-06  _make_ssh_opts: no key, no jump → base opts only
# ---------------------------------------------------------------------------

def test_ssh06_make_ssh_opts_base_only():
    """SSH-06 M: No key/jump args → opts equals _SSH_BASE_OPTS."""
    opts = _make_ssh_opts()
    assert opts == _SSH_BASE_OPTS


# ---------------------------------------------------------------------------
# SSH-07  _make_ssh_opts: with jump_key_path → ProxyCommand used
# ---------------------------------------------------------------------------

def test_ssh07_proxy_command_with_jump_key():
    """SSH-07 M: With jump_user, jump_host, jump_key_path → ProxyCommand in opts."""
    opts = _make_ssh_opts(
        key_path="/home/user/.ssh/dest_key",
        jump_user="azureuser",
        jump_host="1.2.3.4",
        jump_key_path="/home/user/.ssh/jump_key",
    )
    assert "ProxyCommand" in opts
    assert "jump_key" in opts
    assert "-W %h:%p" in opts


# ---------------------------------------------------------------------------
# SSH-08  _make_ssh_opts: with jump but no jump_key_path → -J used (no ProxyCommand)
# ---------------------------------------------------------------------------

def test_ssh08_jump_without_key_uses_j():
    """SSH-08 M: Jump without key_path → uses -J (not ProxyCommand)."""
    opts = _make_ssh_opts(
        jump_user="azureuser",
        jump_host="1.2.3.4",
    )
    assert "-J azureuser@1.2.3.4" in opts
    assert "ProxyCommand" not in opts
