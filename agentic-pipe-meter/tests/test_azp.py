"""AZP-01 to AZP-24: AzureProvider._parse_effective_nsg() and check_nsg_ports() tests."""

import json
import pytest
from unittest.mock import MagicMock
from providers import AzureProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider(shell=None):
    shell = shell or MagicMock(execute=MagicMock())
    return AzureProvider(shell, "my-rg")


def _rule(priority, access, direction, proto="Tcp", port_range="*"):
    return {
        "priority": priority,
        "access": access,
        "direction": direction,
        "protocol": proto,
        "destinationPortRange": port_range,
        "destinationPortRanges": [],
    }


def _nsg_json(rules):
    """Wrap rules in a list (raw format)."""
    return json.dumps(rules)


# ---------------------------------------------------------------------------
# AZP-01  Allow rule → port open
# ---------------------------------------------------------------------------

def test_azp01_allow_rule(tmp_path):
    """AZP-01 M: Single Allow rule → port open."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", port_range="5001")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-02  Deny rule → port closed
# ---------------------------------------------------------------------------

def test_azp02_deny_rule():
    """AZP-02 M: Single Deny rule → port closed."""
    p = _provider()
    rules = [_rule(100, "Deny", "Inbound", port_range="5001")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-03  No matching rule → default deny
# ---------------------------------------------------------------------------

def test_azp03_no_matching_rule():
    """AZP-03 M: No rule matches port → False (default deny)."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", port_range="80")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-04  Priority ordering: lower wins (Allow first)
# ---------------------------------------------------------------------------

def test_azp04_priority_lower_wins_allow():
    """AZP-04 M: Lower priority Allow beats higher priority Deny."""
    p = _provider()
    rules = [
        _rule(100, "Allow", "Inbound", port_range="5001"),
        _rule(200, "Deny", "Inbound", port_range="5001"),
    ]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-05  Priority ordering: lower wins (Deny first)
# ---------------------------------------------------------------------------

def test_azp05_priority_lower_wins_deny():
    """AZP-05 M: Lower priority Deny beats higher priority Allow."""
    p = _provider()
    rules = [
        _rule(100, "Deny", "Inbound", port_range="5001"),
        _rule(200, "Allow", "Inbound", port_range="5001"),
    ]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-06  Wildcard port matches any port
# ---------------------------------------------------------------------------

def test_azp06_wildcard_port():
    """AZP-06 M: destinationPortRange='*' matches port 5001."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", port_range="*")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-07  Multiple ports, some open some closed
# ---------------------------------------------------------------------------

def test_azp07_multiple_ports_partial():
    """AZP-07 M: Multiple ports, different results per port."""
    p = _provider()
    rules = [
        _rule(100, "Allow", "Inbound", port_range="5001"),
        _rule(100, "Deny", "Inbound", port_range="19765"),
    ]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001, 19765])
    assert result[5001] is True
    assert result[19765] is False


# ---------------------------------------------------------------------------
# AZP-08  Range notation "5000-5010" matches 5001
# ---------------------------------------------------------------------------

def test_azp08_port_range_notation():
    """AZP-08 M: Port range '5000-5010' matches port 5001."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", port_range="5000-5010")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-09  Direction filtering: Outbound rule ignored for Inbound query
# ---------------------------------------------------------------------------

def test_azp09_direction_filtering():
    """AZP-09 M: Outbound Allow rule has no effect on Inbound query."""
    p = _provider()
    rules = [_rule(100, "Allow", "Outbound", port_range="5001")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-10  Non-TCP protocol skipped
# ---------------------------------------------------------------------------

def test_azp10_non_tcp_skipped():
    """AZP-10 M: UDP rule not matched for TCP port check."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", proto="Udp", port_range="5001")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-11  check_nsg_ports: both inbound+outbound open → True
# ---------------------------------------------------------------------------

def test_azp11_check_nsg_both_open():
    """AZP-11 M: check_nsg_ports returns True when inbound+outbound open."""
    p = _provider()
    # Patch _parse_effective_nsg to return specific values
    p._get_nic_name = MagicMock(return_value="my-nic")
    p._get_effective_nsg_json = MagicMock(return_value=json.dumps([]))
    p._parse_effective_nsg = MagicMock(side_effect=[
        {5001: True, 19765: True},   # dest inbound
        {5001: True, 19765: True},   # src outbound
    ])
    result = p.check_nsg_ports("10.0.0.4", "10.0.0.5", [5001, 19765])
    assert result[5001] is True
    assert result[19765] is True


# ---------------------------------------------------------------------------
# AZP-12  check_nsg_ports: inbound closed → False
# ---------------------------------------------------------------------------

def test_azp12_check_nsg_inbound_closed():
    """AZP-12 M: check_nsg_ports returns False when inbound closed."""
    p = _provider()
    p._get_nic_name = MagicMock(return_value="my-nic")
    p._get_effective_nsg_json = MagicMock(return_value=json.dumps([]))
    p._parse_effective_nsg = MagicMock(side_effect=[
        {5001: False, 19765: True},  # dest inbound: 5001 closed
        {5001: True, 19765: True},   # src outbound: all open
    ])
    result = p.check_nsg_ports("10.0.0.4", "10.0.0.5", [5001, 19765])
    assert result[5001] is False


# ---------------------------------------------------------------------------
# AZP-13  check_nsg_ports: outbound closed → False
# ---------------------------------------------------------------------------

def test_azp13_check_nsg_outbound_closed():
    """AZP-13 M: check_nsg_ports returns False when outbound closed."""
    p = _provider()
    p._get_nic_name = MagicMock(return_value="my-nic")
    p._get_effective_nsg_json = MagicMock(return_value=json.dumps([]))
    p._parse_effective_nsg = MagicMock(side_effect=[
        {5001: True, 19765: True},   # dest inbound: all open
        {5001: True, 19765: False},  # src outbound: 19765 closed
    ])
    result = p.check_nsg_ports("10.0.0.4", "10.0.0.5", [5001, 19765])
    assert result[19765] is False


# ---------------------------------------------------------------------------
# AZP-14  Azure nested envelope format (networkSecurityGroups key)
# ---------------------------------------------------------------------------

def test_azp14_nsg_envelope_format():
    """AZP-14 G: Nested networkSecurityGroups envelope parsed correctly."""
    p = _provider()
    data = {
        "networkSecurityGroups": [{
            "effectiveSecurityRules": [
                _rule(100, "Allow", "Inbound", port_range="5001")
            ]
        }]
    }
    result = p._parse_effective_nsg(json.dumps(data), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-15  'value' envelope format
# ---------------------------------------------------------------------------

def test_azp15_value_envelope_format():
    """AZP-15 G: 'value' envelope format parsed correctly."""
    p = _provider()
    data = {
        "value": [{
            "networkSecurityGroup": {},
            "effectiveSecurityRules": [
                _rule(100, "Allow", "Inbound", port_range="5001")
            ]
        }]
    }
    result = p._parse_effective_nsg(json.dumps(data), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-16  destinationPortRanges list key used
# ---------------------------------------------------------------------------

def test_azp16_destination_port_ranges_list():
    """AZP-16 G: destinationPortRanges (list) key used for matching."""
    p = _provider()
    rule = {
        "priority": 100,
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "destinationPortRange": "",
        "destinationPortRanges": ["5001", "19765"],
    }
    result = p._parse_effective_nsg(json.dumps([rule]), [5001, 19765])
    assert result[5001] is True
    assert result[19765] is True


# ---------------------------------------------------------------------------
# AZP-17  _get_nic_name: success
# ---------------------------------------------------------------------------

def test_azp17_get_nic_name_success():
    """AZP-17 M: _get_nic_name returns stripped NIC name."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0, "output": "my-nic\n", "status": "success", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    assert p._get_nic_name("10.0.0.5") == "my-nic"


# ---------------------------------------------------------------------------
# AZP-18  _get_nic_name: exit_code != 0 → RuntimeError
# ---------------------------------------------------------------------------

def test_azp18_get_nic_name_failure():
    """AZP-18 M: _get_nic_name raises RuntimeError on failure."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 1, "output": "Error", "status": "error", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    with pytest.raises(RuntimeError, match="NIC lookup failed"):
        p._get_nic_name("10.0.0.5")


# ---------------------------------------------------------------------------
# AZP-19  _get_nic_name: no NIC found → RuntimeError
# ---------------------------------------------------------------------------

def test_azp19_get_nic_name_none_found():
    """AZP-19 M: Empty NIC output → RuntimeError."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0, "output": "", "status": "success", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    with pytest.raises(RuntimeError, match="No NIC found"):
        p._get_nic_name("10.0.0.5")


# ---------------------------------------------------------------------------
# AZP-20  _get_nic_name: multiple NICs → RuntimeError
# ---------------------------------------------------------------------------

def test_azp20_get_nic_name_multiple():
    """AZP-20 M: Multiple NICs returned → RuntimeError."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0, "output": "nic-a\nnic-b\n", "status": "success", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    with pytest.raises(RuntimeError, match="Ambiguous"):
        p._get_nic_name("10.0.0.5")


# ---------------------------------------------------------------------------
# AZP-21  _get_nsg_name: success
# ---------------------------------------------------------------------------

def test_azp21_get_nsg_name_success():
    """AZP-21 M: _get_nsg_name returns last segment of resource ID."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0,
        "output": "/subscriptions/sub/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg\n",
        "status": "success", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    assert p._get_nsg_name("my-nic") == "my-nsg"


# ---------------------------------------------------------------------------
# AZP-22  _get_nsg_name: no NSG attached → RuntimeError
# ---------------------------------------------------------------------------

def test_azp22_get_nsg_name_none():
    """AZP-22 M: Empty output → RuntimeError (no NSG attached)."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0, "output": "", "status": "success", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg")
    with pytest.raises(RuntimeError, match="no NSG attached"):
        p._get_nsg_name("my-nic")


# ---------------------------------------------------------------------------
# AZP-23  Outbound direction passed correctly to _parse_effective_nsg
# ---------------------------------------------------------------------------

def test_azp23_outbound_direction():
    """AZP-23 M: Outbound direction query only matches Outbound rules."""
    p = _provider()
    rules = [
        _rule(100, "Allow", "Inbound", port_range="5001"),   # should not match
        _rule(200, "Allow", "Outbound", port_range="5001"),  # should match
    ]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001], direction="Outbound")
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-24  Protocol '*' matches
# ---------------------------------------------------------------------------

def test_azp24_protocol_wildcard():
    """AZP-24 M: Protocol='*' matches TCP port check."""
    p = _provider()
    rules = [_rule(100, "Allow", "Inbound", proto="*", port_range="5001")]
    result = p._parse_effective_nsg(_nsg_json(rules), [5001])
    assert result[5001] is True


# ---------------------------------------------------------------------------
# AZP-25  _generate_sas_url: success returns full HTTPS URL
# ---------------------------------------------------------------------------

def test_azp25_generate_sas_url_success():
    """AZP-25 M: _generate_sas_url returns full https://...blob.core.windows.net URL."""
    shell = MagicMock(execute=MagicMock(side_effect=[
        {"exit_code": 0, "output": "abc123key==\n", "status": "success", "audit_id": "a1"},  # keys list
        {"exit_code": 0, "output": "sv=2021&se=2025&sp=racw&sig=XYZ\n", "status": "success", "audit_id": "a2"},  # generate-sas
    ]))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    url = p._generate_sas_url("mystorage", "results", "foo.json")
    assert url.startswith("https://mystorage.blob.core.windows.net/results/foo.json?")
    assert "sv=2021" in url


# ---------------------------------------------------------------------------
# AZP-26  _generate_sas_url: keys list fails → RuntimeError
# ---------------------------------------------------------------------------

def test_azp26_generate_sas_keys_fail():
    """AZP-26 M: keys list failure → RuntimeError."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 1, "output": "Authorization failed", "status": "error", "audit_id": "a1"
    }))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    with pytest.raises(RuntimeError, match="Failed to retrieve storage account key"):
        p._generate_sas_url("mystorage", "results", "foo.json")


# ---------------------------------------------------------------------------
# AZP-27  _generate_sas_url: generate-sas fails → RuntimeError
# ---------------------------------------------------------------------------

def test_azp27_generate_sas_token_fail():
    """AZP-27 M: generate-sas failure → RuntimeError."""
    shell = MagicMock(execute=MagicMock(side_effect=[
        {"exit_code": 0, "output": "abc123key==\n", "status": "success", "audit_id": "a1"},
        {"exit_code": 1, "output": "Error generating SAS", "status": "error", "audit_id": "a2"},
    ]))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    with pytest.raises(RuntimeError, match="Failed to generate SAS token"):
        p._generate_sas_url("mystorage", "results", "foo.json")


# ---------------------------------------------------------------------------
# AZP-28  _write_blob_via_ssh: curl 201 → success, returns blob URL
# ---------------------------------------------------------------------------

def test_azp28_write_blob_via_ssh_success():
    """AZP-28 M: curl returns 201 → _write_blob_via_ssh returns blob URL."""
    shell = MagicMock(execute=MagicMock(side_effect=[
        {"exit_code": 0, "output": "abc123==\n", "status": "success", "audit_id": "a1"},     # keys list
        {"exit_code": 0, "output": "sv=2021&sig=X\n", "status": "success", "audit_id": "a2"}, # generate-sas
        {"exit_code": 0, "output": "", "status": "success", "audit_id": "a3"},                # SCP
        {"exit_code": 0, "output": "201", "status": "success", "audit_id": "a4"},             # curl PUT
        {"exit_code": 0, "output": "", "status": "success", "audit_id": "a5"},                # rm
    ]))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    url = p._write_blob_via_ssh("mystorage", "results", "foo.json", b'{"data": 1}')
    assert url == "https://mystorage.blob.core.windows.net/results/foo.json"


# ---------------------------------------------------------------------------
# AZP-29  _write_blob_via_ssh: curl non-201 → RuntimeError
# ---------------------------------------------------------------------------

def test_azp29_write_blob_via_ssh_curl_error():
    """AZP-29 M: curl returns non-201 HTTP status → RuntimeError."""
    shell = MagicMock(execute=MagicMock(side_effect=[
        {"exit_code": 0, "output": "abc123==\n", "status": "success", "audit_id": "a1"},
        {"exit_code": 0, "output": "sv=2021&sig=X\n", "status": "success", "audit_id": "a2"},
        {"exit_code": 0, "output": "", "status": "success", "audit_id": "a3"},                # SCP
        {"exit_code": 0, "output": "403", "status": "success", "audit_id": "a4"},             # curl → 403
        {"exit_code": 0, "output": "", "status": "success", "audit_id": "a5"},                # rm
    ]))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    with pytest.raises(RuntimeError, match="HTTP 403"):
        p._write_blob_via_ssh("mystorage", "results", "foo.json", b'{}')


# ---------------------------------------------------------------------------
# AZP-30  _read_blob_via_ssh: curl 200 → returns bytes
# ---------------------------------------------------------------------------

def test_azp30_read_blob_via_ssh_success(tmp_path):
    """AZP-30 M: curl returns 200 → _read_blob_via_ssh returns bytes."""
    import tempfile, os
    # Write a known file to tmp so SCP "download" can read it
    local_data = b'{"result": "ok"}'

    scp_dest = [None]

    def fake_execute(cmd_dict):
        cmd = cmd_dict["command"]
        if cmd.startswith("az storage account keys"):
            return {"exit_code": 0, "output": "abc123==\n", "status": "success", "audit_id": "a1"}
        if cmd.startswith("az storage blob generate-sas"):
            return {"exit_code": 0, "output": "sv=2021&sig=X\n", "status": "success", "audit_id": "a2"}
        if "curl" in cmd:
            return {"exit_code": 0, "output": "200", "status": "success", "audit_id": "a3"}
        if cmd.startswith("scp") and "pmeter_blob_" in cmd:
            # Extract local destination path (last token) and write data there
            parts = cmd.split()
            dest = parts[-1]
            scp_dest[0] = dest
            with open(dest, "wb") as f:
                f.write(local_data)
            return {"exit_code": 0, "output": "", "status": "success", "audit_id": "a4"}
        # rm
        return {"exit_code": 0, "output": "", "status": "success", "audit_id": "a5"}

    shell = MagicMock(execute=MagicMock(side_effect=fake_execute))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    result = p._read_blob_via_ssh("mystorage", "results", "foo.json")
    assert result == local_data


# ---------------------------------------------------------------------------
# AZP-31  _read_blob_via_ssh: curl 404 → returns None
# ---------------------------------------------------------------------------

def test_azp31_read_blob_via_ssh_not_found():
    """AZP-31 M: curl returns 404 → _read_blob_via_ssh returns None."""
    shell = MagicMock(execute=MagicMock(side_effect=[
        {"exit_code": 0, "output": "abc123==\n", "status": "success", "audit_id": "a1"},
        {"exit_code": 0, "output": "sv=2021&sig=X\n", "status": "success", "audit_id": "a2"},
        {"exit_code": 0, "output": "404", "status": "success", "audit_id": "a3"},             # curl → 404
        {"exit_code": 0, "output": "", "status": "success", "audit_id": "a4"},                # rm (not called)
    ]))
    p = AzureProvider(shell, "my-rg", ssh_user="azureuser", source_public_ip="1.2.3.4")
    result = p._read_blob_via_ssh("mystorage", "results", "missing.json")
    assert result is None
