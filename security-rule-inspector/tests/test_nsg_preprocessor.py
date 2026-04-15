"""
test_nsg_preprocessor.py — Unit tests for nsg_preprocessor.py

Covers:
  T-PP-01 through T-PP-14  Envelope parsing, gate identification,
  rule normalisation, shadow detection, file errors.
"""

import json
import os
import tempfile

import pytest

import nsg_preprocessor
from nsg_preprocessor import preprocess
from conftest import fixture_path


# ---------------------------------------------------------------------------
# T-PP-01 — Format 1 ("value" wrapper)
# ---------------------------------------------------------------------------

def test_pp_01_format_value_wrapper():
    """T-PP-01: Format 1 ('value' wrapper) parses correctly [PREPROCESS]"""
    result = preprocess(fixture_path("fx-01-inbound-both-allow.json"))
    assert "error" not in result
    assert result["gate_count"] == 2


# ---------------------------------------------------------------------------
# T-PP-02 — Format 2 ("networkSecurityGroups" wrapper)
# ---------------------------------------------------------------------------

def test_pp_02_format_network_security_groups_wrapper(tmp_path):
    """T-PP-02: Format 2 ('networkSecurityGroups' wrapper) parses correctly [PREPROCESS]"""
    # Load the fx-01 fixture and re-wrap its entries
    with open(fixture_path("fx-01-inbound-both-allow.json"), encoding="utf-8") as fh:
        original = json.load(fh)

    rewrapped = {"networkSecurityGroups": original["value"]}
    alt_path = tmp_path / "alt_format.json"
    alt_path.write_text(json.dumps(rewrapped), encoding="utf-8")

    result = preprocess(str(alt_path))
    assert "error" not in result
    assert result["gate_count"] == 2


# ---------------------------------------------------------------------------
# T-PP-03 — Format 4 (single NSG, "effectiveSecurityRules" at top level)
# ---------------------------------------------------------------------------

def test_pp_03_format_single_nsg_top_level(tmp_path):
    """T-PP-03: Format 4 (single NSG, 'effectiveSecurityRules' at top level) [PREPROCESS]"""
    with open(fixture_path("fx-01-inbound-both-allow.json"), encoding="utf-8") as fh:
        original = json.load(fh)

    # Take the first entry and unwrap it to the top level
    first_entry = original["value"][0]
    single_nsg = {
        "networkSecurityGroup": first_entry["networkSecurityGroup"],
        "association": first_entry["association"],
        "effectiveSecurityRules": first_entry["effectiveSecurityRules"],
    }

    p = tmp_path / "single_nsg.json"
    p.write_text(json.dumps(single_nsg), encoding="utf-8")

    result = preprocess(str(p))
    assert "error" not in result
    assert result["gate_count"] == 1
    assert len(result["gates"][0]["inbound_rules"]) > 0


# ---------------------------------------------------------------------------
# T-PP-04 — Gate identification by association type
# ---------------------------------------------------------------------------

def test_pp_04_gate_identification_by_association_type():
    """T-PP-04: Gate identification by association type [PREPROCESS]"""
    result = preprocess(fixture_path("fx-01-inbound-both-allow.json"))
    gates = result["gates"]

    subnet_gate = next((g for g in gates if g["association_type"] == "subnet"), None)
    nic_gate = next((g for g in gates if g["association_type"] == "networkInterface"), None)

    assert subnet_gate is not None
    assert subnet_gate["gate"] == "subnet-nsg"

    assert nic_gate is not None
    assert nic_gate["gate"] == "nic-nsg"


# ---------------------------------------------------------------------------
# T-PP-05 — Association absent — fallback label and parse warning
# ---------------------------------------------------------------------------

def test_pp_05_association_absent_fallback_label_and_warning(tmp_path):
    """T-PP-05: Association absent — fallback label and parse warning [PREPROCESS]"""
    entry = {
        "networkSecurityGroup": {
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
        },
        # No "association" key
        "effectiveSecurityRules": [],
    }
    data = {"value": [entry]}
    p = tmp_path / "no_assoc.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    assert result["gate_count"] == 1

    gate = result["gates"][0]
    assert gate["association_type"] == "unknown"
    assert gate["gate"] == "subnet-nsg"  # positional fallback: _FALLBACK_GATE_NAMES[0]

    assert any("no 'association' field" in w or "association" in w.lower()
               for w in result["parse_warnings"])


# ---------------------------------------------------------------------------
# T-PP-06 — Rule normalisation — plural port array preferred over singular
# ---------------------------------------------------------------------------

def test_pp_06_plural_ports_preferred_over_singular(tmp_path):
    """T-PP-06: destinationPortRanges preferred over destinationPortRange [PREPROCESS]"""
    rule = {
        "name": "test-rule",
        "priority": 100,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "sourceAddressPrefix": "*",
        "sourcePortRange": "*",
        "destinationAddressPrefix": "*",
        "destinationPortRange": "443",      # singular
        "destinationPortRanges": ["80", "443"],  # plural — should win
    }
    entry = {
        "networkSecurityGroup": {"id": "/x/test-nsg"},
        "association": {"subnet": {"id": "/x/subnet"}},
        "effectiveSecurityRules": [rule],
    }
    data = {"value": [entry]}
    p = tmp_path / "plural_ports.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    inbound = result["gates"][0]["inbound_rules"]
    assert len(inbound) == 1
    assert inbound[0]["destination_ports"] == ["80", "443"]


# ---------------------------------------------------------------------------
# T-PP-07 — Rule normalisation — expanded address preferred over plain
# ---------------------------------------------------------------------------

def test_pp_07_expanded_address_preferred_over_plain(tmp_path):
    """T-PP-07: expandedSourceAddressPrefix preferred over sourceAddressPrefix [PREPROCESS]"""
    rule = {
        "name": "test-rule",
        "priority": 100,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "sourceAddressPrefix": "VirtualNetwork",          # plain — should be ignored
        "expandedSourceAddressPrefix": ["10.0.0.0/16", "10.1.0.0/16"],  # expanded — wins
        "sourcePortRange": "*",
        "destinationAddressPrefix": "*",
        "destinationPortRange": "*",
    }
    entry = {
        "networkSecurityGroup": {"id": "/x/test-nsg"},
        "association": {"subnet": {"id": "/x/subnet"}},
        "effectiveSecurityRules": [rule],
    }
    data = {"value": [entry]}
    p = tmp_path / "expanded_addr.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    inbound = result["gates"][0]["inbound_rules"]
    # sorted join: "10.0.0.0/16" < "10.1.0.0/16"
    assert inbound[0]["source_address"] == "10.0.0.0/16, 10.1.0.0/16"


# ---------------------------------------------------------------------------
# T-PP-08 — Protocol "All" preserved
# ---------------------------------------------------------------------------

def test_pp_08_protocol_all_preserved(tmp_path):
    """T-PP-08: Protocol 'All' preserved as-is (not converted to '*') [PREPROCESS]"""
    rule = {
        "name": "test-rule",
        "priority": 100,
        "direction": "Inbound",
        "access": "Deny",
        "protocol": "All",
        "sourceAddressPrefix": "*",
        "sourcePortRange": "*",
        "destinationAddressPrefix": "*",
        "destinationPortRange": "*",
    }
    entry = {
        "networkSecurityGroup": {"id": "/x/test-nsg"},
        "association": {"subnet": {"id": "/x/subnet"}},
        "effectiveSecurityRules": [rule],
    }
    data = {"value": [entry]}
    p = tmp_path / "protocol_all.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    inbound = result["gates"][0]["inbound_rules"]
    assert inbound[0]["protocol"] == "All"


# ---------------------------------------------------------------------------
# T-PP-09 — Rules sorted by priority ascending within gate
# ---------------------------------------------------------------------------

def test_pp_09_rules_sorted_by_priority_ascending():
    """T-PP-09: Rules sorted by priority ascending (fx-08) [PREPROCESS]"""
    result = preprocess(fixture_path("fx-08-port-range.json"))
    inbound = result["gates"][0]["inbound_rules"]

    assert inbound[0]["priority"] == 50
    assert inbound[1]["priority"] == 100
    assert inbound[2]["priority"] == 110


# ---------------------------------------------------------------------------
# T-PP-10 — Shadow detection sets shadowed_by on shadowed rules
# ---------------------------------------------------------------------------

def test_pp_10_shadow_detection_sets_shadowed_by():
    """T-PP-10: Shadow detection — shadowed_by set on shadowed rule (fx-04) [PREPROCESS]"""
    result = preprocess(fixture_path("fx-04-shadowed-allow-rule.json"))
    subnet_gate = next(g for g in result["gates"] if g["association_type"] == "subnet")
    inbound = subnet_gate["inbound_rules"]

    https_rule = next(r for r in inbound if r["name"] == "allow-https-inbound")
    deny_all = next(r for r in inbound if r["name"] == "deny-all-custom")

    assert https_rule["shadowed_by"] == "deny-all-custom"
    assert deny_all["shadowed_by"] is None


# ---------------------------------------------------------------------------
# T-PP-11 — Shadow detection NOT triggered for partial-overlap rules
# ---------------------------------------------------------------------------

def test_pp_11_shadow_not_triggered_for_partial_overlap(tmp_path):
    """T-PP-11: Tcp-only deny does NOT shadow a Udp allow (partial overlap) [PREPROCESS]"""
    rules = [
        {
            "name": "deny-tcp-all",
            "priority": 100,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "Tcp",     # Tcp-only — does NOT cover Udp
            "sourceAddressPrefix": "*",
            "sourcePortRange": "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "0-65535",
        },
        {
            "name": "allow-udp-dns",
            "priority": 200,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Udp",
            "sourceAddressPrefix": "*",
            "sourcePortRange": "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "53",
        },
    ]
    entry = {
        "networkSecurityGroup": {"id": "/x/test-nsg"},
        "association": {"subnet": {"id": "/x/subnet"}},
        "effectiveSecurityRules": rules,
    }
    data = {"value": [entry]}
    p = tmp_path / "partial_overlap.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    inbound = result["gates"][0]["inbound_rules"]
    udp_rule = next(r for r in inbound if r["name"] == "allow-udp-dns")
    assert udp_rule["shadowed_by"] is None


# ---------------------------------------------------------------------------
# T-PP-12 — File not found → error dict
# ---------------------------------------------------------------------------

def test_pp_12_file_not_found_returns_error_dict():
    """T-PP-12: File not found → error dict [PREPROCESS]"""
    result = preprocess("/nonexistent/path/that-does-not-exist.json")
    assert "error" in result
    assert "gate_count" not in result


# ---------------------------------------------------------------------------
# T-PP-13 — Invalid JSON → error dict
# ---------------------------------------------------------------------------

def test_pp_13_invalid_json_returns_error_dict(tmp_path):
    """T-PP-13: Invalid JSON → error dict [PREPROCESS]"""
    p = tmp_path / "invalid.json"
    p.write_text("{invalid json}", encoding="utf-8")

    result = preprocess(str(p))
    assert "error" in result


# ---------------------------------------------------------------------------
# T-PP-14 — Empty entries list → gate_count 0 with parse warning
# ---------------------------------------------------------------------------

def test_pp_14_empty_value_array_gate_count_zero(tmp_path):
    """T-PP-14: Empty entries list → gate_count 0 with parse warning [PREPROCESS]"""
    data = {"value": []}
    p = tmp_path / "empty_value.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    result = preprocess(str(p))
    assert "error" not in result
    assert result["gate_count"] == 0
    assert any("No NSG entries found" in w for w in result["parse_warnings"])
