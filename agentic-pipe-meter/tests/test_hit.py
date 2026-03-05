"""HIT-01 to HIT-23: _make_hitl_callback() and HITL gate tests."""

import pytest
from pipe_meter import _make_hitl_callback, _PIPE_METER_AUTO_APPROVE_PATTERNS


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _cb():
    """Return a fresh HITL callback."""
    return _make_hitl_callback()


def _auto_approve_check(command, monkeypatch):
    """Verify command is auto-approved (no input() called)."""
    monkeypatch.setattr(
        "builtins.input",
        lambda _: (_ for _ in ()).throw(AssertionError("input() was called")),
    )
    cb = _cb()
    result = cb(command, "reason", "none", tier=1)
    assert result.action == "approve"


def _gate_fires(command, monkeypatch, answer="deny"):
    """Verify command hits the manual gate (input() called)."""
    called = []
    monkeypatch.setattr("builtins.input", lambda _: (called.append(True), answer)[1])
    cb = _cb()
    result = cb(command, "reason", "risk", tier=2)
    assert called, "input() was not called — gate did not fire"
    return result


# ---------------------------------------------------------------------------
# HIT-01  S10 (qperf client) auto-approved
# ---------------------------------------------------------------------------

def test_hit01_qperf_client_auto(monkeypatch):
    """HIT-01 M: qperf client command auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"qperf 10.0.0.5 -m 1024 tcp_lat\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-02  S11 (iperf client) auto-approved
# ---------------------------------------------------------------------------

def test_hit02_iperf_client_auto(monkeypatch):
    """HIT-02 M: iperf client command auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"iperf -c 10.0.0.5 -P 8 -t 10\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-03  S4 (which qperf) auto-approved
# ---------------------------------------------------------------------------

def test_hit03_which_qperf_auto(monkeypatch):
    """HIT-03 M: 'which qperf' auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"which qperf\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-04  S4 (which iperf) auto-approved
# ---------------------------------------------------------------------------

def test_hit04_which_iperf_auto(monkeypatch):
    """HIT-04 M: 'which iperf' auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"which iperf\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-05  S12 (iperf -v) auto-approved
# ---------------------------------------------------------------------------

def test_hit05_iperf_version_auto(monkeypatch):
    """HIT-05 M: iperf -v command auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"iperf -v 2>&1\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-06  S1 (lsof -ti) auto-approved
# ---------------------------------------------------------------------------

def test_hit06_lsof_auto(monkeypatch):
    """HIT-06 M: lsof -ti stale pid check auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.5 \"lsof -ti :5001,:19765 2>/dev/null\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-07  S8 (nohup qperf server) auto-approved
# ---------------------------------------------------------------------------

def test_hit07_qperf_server_start_auto(monkeypatch):
    """HIT-07 M: nohup qperf server start auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.5 \"nohup qperf </dev/null > /tmp/qperf_server.log 2>&1 & echo $!\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-08  S9 (nohup iperf -s server) auto-approved
# ---------------------------------------------------------------------------

def test_hit08_iperf_server_start_auto(monkeypatch):
    """HIT-08 M: nohup iperf -s server start auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.5 \"nohup iperf -s </dev/null > /tmp/iperf_server.log 2>&1 & echo $!\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-09  S2 (kill by PID) auto-approved
# ---------------------------------------------------------------------------

def test_hit09_kill_by_pid_auto(monkeypatch):
    """HIT-09 M: kill PIDs teardown command auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.5 \"kill 9876 2>/dev/null; true\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-10  S3 (pkill -f) auto-approved
# ---------------------------------------------------------------------------

def test_hit10_pkill_auto(monkeypatch):
    """HIT-10 M: pkill -f teardown command auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.5 \"pkill -f 'qperf' 2>/dev/null; true\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-11  az nic list (read-only) auto-approved
# ---------------------------------------------------------------------------

def test_hit11_az_nic_list_auto(monkeypatch):
    """HIT-11 M: az network nic list auto-approved."""
    _auto_approve_check(
        "az network nic list --resource-group my-rg --output tsv",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-12  az nic show auto-approved
# ---------------------------------------------------------------------------

def test_hit12_az_nic_show_auto(monkeypatch):
    """HIT-12 M: az network nic show auto-approved."""
    _auto_approve_check(
        "az network nic show --resource-group my-rg --name my-nic --output tsv",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-13  az nic list-effective-nsg auto-approved
# ---------------------------------------------------------------------------

def test_hit13_effective_nsg_auto(monkeypatch):
    """HIT-13 M: az network nic list-effective-nsg auto-approved."""
    _auto_approve_check(
        "az network nic list-effective-nsg --resource-group my-rg --name my-nic --output json",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-14  az nsg show auto-approved
# ---------------------------------------------------------------------------

def test_hit14_nsg_show_auto(monkeypatch):
    """HIT-14 M: az network nsg show auto-approved."""
    _auto_approve_check(
        "az network nsg show --resource-group my-rg --name my-nsg --output json",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-15  az storage blob download auto-approved
# ---------------------------------------------------------------------------

def test_hit15_blob_download_auto(monkeypatch):
    """HIT-15 M: az storage blob download auto-approved."""
    _auto_approve_check(
        "az storage blob download --account-name mystorage --container-name results --name blob.json --file /tmp/f.json --auth-mode login --no-progress",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-16  az storage blob upload auto-approved
# ---------------------------------------------------------------------------

def test_hit16_blob_upload_auto(monkeypatch):
    """HIT-16 M: az storage blob upload auto-approved."""
    _auto_approve_check(
        "az storage blob upload --account-name mystorage --container-name results --name blob.json --file /tmp/f.json --overwrite true --auth-mode login",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-17  SCP non-pmeter filename → gate fires
# ---------------------------------------------------------------------------

def test_hit17_scp_non_pmeter_gate(monkeypatch):
    """HIT-17 M: scp with non-pmeter filename triggers manual gate."""
    result = _gate_fires(
        "scp -o BatchMode=yes /etc/passwd user@host:/tmp/passwd",
        monkeypatch,
        answer="deny",
    )
    assert result.action == "deny"


# ---------------------------------------------------------------------------
# HIT-18  az nsg rule create → gate fires
# ---------------------------------------------------------------------------

def test_hit18_nsg_rule_create_gate(monkeypatch):
    """HIT-18 M: az nsg rule create triggers manual gate."""
    result = _gate_fires(
        "az network nsg rule create --resource-group my-rg --nsg-name my-nsg --name AllowPipeMeter5001 --priority 190",
        monkeypatch,
        answer="deny",
    )
    assert result.action == "deny"


# ---------------------------------------------------------------------------
# HIT-19  apt-get install → gate fires
# ---------------------------------------------------------------------------

def test_hit19_apt_install_gate(monkeypatch):
    """HIT-19 M: apt-get install triggers manual gate."""
    result = _gate_fires(
        "ssh -o ConnectTimeout=15 azureuser@10.0.0.4 \"sudo apt-get install -y qperf iperf\"",
        monkeypatch,
        answer="deny",
    )
    assert result.action == "deny"


# ---------------------------------------------------------------------------
# HIT-20  Operator approves at gate
# ---------------------------------------------------------------------------

def test_hit20_operator_approves(monkeypatch):
    """HIT-20 M: Operator typing 'approve' at gate → action='approve'."""
    monkeypatch.setattr("builtins.input", lambda _: "approve")
    cb = _cb()
    result = cb("az network nsg rule create ...", "reason", "risk", tier=2)
    assert result.action == "approve"


# ---------------------------------------------------------------------------
# HIT-21  Operator denies at gate
# ---------------------------------------------------------------------------

def test_hit21_operator_denies(monkeypatch):
    """HIT-21 M: Operator typing 'deny' at gate → action='deny'."""
    monkeypatch.setattr("builtins.input", lambda _: "deny")
    cb = _cb()
    result = cb("az network nsg rule create ...", "reason", "risk", tier=2)
    assert result.action == "deny"


# ---------------------------------------------------------------------------
# HIT-22  EOFError in non-interactive → deny
# ---------------------------------------------------------------------------

def test_hit22_eof_denies(monkeypatch):
    """HIT-22 M: EOFError (non-interactive) → action='deny'."""
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))
    cb = _cb()
    result = cb("az network nsg rule create ...", "reason", "risk", tier=2)
    assert result.action == "deny"


# ---------------------------------------------------------------------------
# HIT-23  scp pmeter_blob_ prefix auto-approved
# ---------------------------------------------------------------------------

def test_hit23_scp_pmeter_blob_auto(monkeypatch):
    """HIT-23 M: scp with pmeter_blob_ prefix is auto-approved."""
    _auto_approve_check(
        "scp -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new /tmp/pmeter_blob_abcd1234.json user@10.0.0.4:/tmp/pmeter_blob_abcd1234.json",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-24  az storage account keys list → auto-approved
# ---------------------------------------------------------------------------

def test_hit24_az_storage_keys_list_auto_approved(monkeypatch):
    """HIT-24 M: az storage account keys list is auto-approved (management plane)."""
    _auto_approve_check(
        "az storage account keys list --account-name mystorage --resource-group my-rg --query \"[0].value\" --output tsv",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-25  az storage blob generate-sas → auto-approved
# ---------------------------------------------------------------------------

def test_hit25_az_storage_blob_generate_sas_auto_approved(monkeypatch):
    """HIT-25 M: az storage blob generate-sas is auto-approved (local HMAC)."""
    _auto_approve_check(
        "az storage blob generate-sas --account-name mystorage --account-key \"abc123=\" --container-name results --name foo.json --permissions racw --expiry 2025-01-01T00:00Z --output tsv",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-26  ssh ... curl ... blob.core.windows.net → auto-approved
# ---------------------------------------------------------------------------

def test_hit26_ssh_curl_blob_auto_approved(monkeypatch):
    """HIT-26 M: SSH-wrapped curl PUT to blob.core.windows.net is auto-approved."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 -o BatchMode=yes azureuser@1.2.3.4 \"curl -s -w '%{http_code}' -o /dev/null -X PUT -H 'x-ms-blob-type: BlockBlob' --data-binary @/tmp/pmeter_blob_abcd.json 'https://mystorage.blob.core.windows.net/results/foo.json?sv=2021'\"",
        monkeypatch,
    )


# ---------------------------------------------------------------------------
# HIT-27  ssh ... which curl → auto-approved
# ---------------------------------------------------------------------------

def test_hit27_which_curl_auto_approved(monkeypatch):
    """HIT-27 M: which curl on source VM is auto-approved (preflight check)."""
    _auto_approve_check(
        "ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i /path/key.pem azureuser@1.2.3.4 \"which curl\"",
        monkeypatch,
    )
