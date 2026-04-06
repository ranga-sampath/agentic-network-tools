"""
Tests for diff.py — normalization and diff engine.

All tests are pure-function: no I/O, no mocking, no Azure.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from diff import extract_routes, extract_nsg_rules, compute_diff

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(nics):
    """Build a minimal snapshot dict with a list of NIC entries."""
    return {"session_id": "test-snap", "nics": nics}


def _nic(name, routes=None, nsg_rules=None, error=None):
    return {
        "nic_name": name,
        "effective_routes": routes or [],
        "effective_nsg_rules": nsg_rules or [],
        "error": error,
    }


def _route(prefix, source="Default", next_hop_type="VnetLocal", next_hop_ip=None, state="Active"):
    return {
        "addressPrefix": prefix,
        "nextHopType": next_hop_type,
        "nextHopIpAddress": next_hop_ip,
        "source": source,
        "state": state,
    }


def _rule(name, direction="Inbound", priority=100, access="Allow", protocol="Tcp",
          src_prefix="*", dst_prefix="*", dst_port="443"):
    return {
        "name": name,
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "sourceAddressPrefix": src_prefix,
        "sourceAddressPrefixes": [],
        "destinationAddressPrefix": dst_prefix,
        "destinationAddressPrefixes": [],
        "destinationPortRange": dst_port,
        "destinationPortRanges": [dst_port],
    }


# ---------------------------------------------------------------------------
# extract_routes
# ---------------------------------------------------------------------------

class TestExtractRoutes:

    def test_value_envelope(self):
        """TC-DIFF-001: {"value": [...]} envelope is parsed."""
        raw = (FIXTURES / "routes_value_envelope.json").read_text()
        routes = extract_routes(raw)
        assert len(routes) == 2
        prefixes = [r["addressPrefix"] for r in routes]
        assert "0.0.0.0/0" in prefixes
        assert "10.0.0.0/16" in prefixes

    def test_bare_list_envelope(self):
        """TC-DIFF-002: Bare list [...] is parsed correctly."""
        data = [
            {"addressPrefix": "10.1.0.0/24", "nextHopType": "VnetLocal",
             "nextHopIpAddress": [], "source": "Default", "state": "Active"}
        ]
        routes = extract_routes(json.dumps(data))
        assert len(routes) == 1
        assert routes[0]["addressPrefix"] == "10.1.0.0/24"

    def test_list_valued_address_prefix_collapsed(self):
        """TC-DIFF-003: addressPrefix as list is collapsed to scalar."""
        data = {"value": [
            {"addressPrefix": ["10.5.0.0/24"], "nextHopType": "VnetLocal",
             "nextHopIpAddress": [], "source": "Default", "state": "Active"}
        ]}
        routes = extract_routes(json.dumps(data))
        assert routes[0]["addressPrefix"] == "10.5.0.0/24"
        assert isinstance(routes[0]["addressPrefix"], str)

    def test_empty_string_returns_empty_list(self):
        """TC-DIFF-004: Empty input returns []."""
        assert extract_routes("") == []

    def test_whitespace_only_returns_empty_list(self):
        assert extract_routes("   \n") == []

    def test_malformed_json_returns_empty_list(self):
        """TC-DIFF-005: Malformed JSON returns [] without raising."""
        assert extract_routes("{not valid json") == []

    def test_sorted_by_address_prefix(self):
        """Output is sorted by addressPrefix."""
        data = {"value": [
            {"addressPrefix": "192.168.0.0/16", "nextHopType": "VnetLocal",
             "nextHopIpAddress": [], "source": "Default", "state": "Active"},
            {"addressPrefix": "10.0.0.0/8", "nextHopType": "VnetLocal",
             "nextHopIpAddress": [], "source": "Default", "state": "Active"},
        ]}
        routes = extract_routes(json.dumps(data))
        assert routes[0]["addressPrefix"] == "10.0.0.0/8"
        assert routes[1]["addressPrefix"] == "192.168.0.0/16"

    def test_next_hop_ip_list_collapsed(self):
        """nextHopIpAddress as single-element list is collapsed to scalar."""
        data = {"value": [
            {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance",
             "nextHopIpAddress": ["10.0.1.4"], "source": "User", "state": "Active"}
        ]}
        routes = extract_routes(json.dumps(data))
        assert routes[0]["nextHopIpAddress"] == "10.0.1.4"

    def test_next_hop_ip_empty_list_becomes_none(self):
        """nextHopIpAddress as [] collapses to None."""
        data = {"value": [
            {"addressPrefix": "10.0.0.0/16", "nextHopType": "VnetLocal",
             "nextHopIpAddress": [], "source": "Default", "state": "Active"}
        ]}
        routes = extract_routes(json.dumps(data))
        assert routes[0]["nextHopIpAddress"] is None

    def test_bgp_routes_parsed(self):
        """VirtualNetworkGateway-sourced routes are parsed correctly."""
        raw = (FIXTURES / "routes_bgp.json").read_text()
        routes = extract_routes(raw)
        bgp = [r for r in routes if r["source"] == "VirtualNetworkGateway"]
        assert len(bgp) == 2
        prefixes = {r["addressPrefix"] for r in bgp}
        assert "10.2.0.0/24" in prefixes
        assert "192.168.0.0/16" in prefixes


# ---------------------------------------------------------------------------
# extract_nsg_rules
# ---------------------------------------------------------------------------

class TestExtractNsgRules:

    def test_nsg_envelope(self):
        """TC-DIFF-006: networkSecurityGroups envelope parsed."""
        raw = (FIXTURES / "nsg_nsg_envelope.json").read_text()
        rules = extract_nsg_rules(raw)
        assert len(rules) == 2
        names = {r["name"] for r in rules}
        assert "allow-https" in names
        assert "deny-all-inbound" in names

    def test_value_envelope(self):
        """TC-DIFF-007: {"value": [...]} envelope parsed."""
        raw = (FIXTURES / "nsg_value_envelope.json").read_text()
        rules = extract_nsg_rules(raw)
        assert len(rules) == 1
        assert rules[0]["name"] == "allow-ssh"

    def test_bare_list_envelope(self):
        """TC-DIFF-008: Bare list parsed."""
        data = [_rule("test-rule")]
        rules = extract_nsg_rules(json.dumps(data))
        assert len(rules) == 1
        assert rules[0]["name"] == "test-rule"

    def test_list_fields_sorted(self):
        """TC-DIFF-009: destinationPortRanges sorted to eliminate false diffs."""
        data = [
            {
                "name": "multi-port",
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "*",
                "sourceAddressPrefixes": [],
                "destinationAddressPrefix": "*",
                "destinationAddressPrefixes": [],
                "destinationPortRange": "",
                "destinationPortRanges": ["443", "80", "22"],
            }
        ]
        rules = extract_nsg_rules(json.dumps(data))
        assert rules[0]["destinationPortRanges"] == ["22", "443", "80"]

    def test_empty_string_returns_empty_list(self):
        """TC-DIFF-010: Empty input returns []."""
        assert extract_nsg_rules("") == []

    def test_sorted_by_direction_then_priority(self):
        """Output sorted by (direction, priority)."""
        data = [
            {**_rule("outbound-200", direction="Outbound", priority=200),
             "sourceAddressPrefixes": [], "destinationAddressPrefixes": [], "destinationPortRanges": []},
            {**_rule("inbound-300", direction="Inbound", priority=300),
             "sourceAddressPrefixes": [], "destinationAddressPrefixes": [], "destinationPortRanges": []},
            {**_rule("inbound-100", direction="Inbound", priority=100),
             "sourceAddressPrefixes": [], "destinationAddressPrefixes": [], "destinationPortRanges": []},
        ]
        rules = extract_nsg_rules(json.dumps(data))
        assert rules[0]["name"] == "inbound-100"
        assert rules[1]["name"] == "inbound-300"
        assert rules[2]["name"] == "outbound-200"

    def test_priority_cast_to_int(self):
        """Priority stored as a string in az output is cast to int."""
        data = [
            {**_rule("r1"), "priority": "150",
             "sourceAddressPrefixes": [], "destinationAddressPrefixes": [], "destinationPortRanges": []}
        ]
        rules = extract_nsg_rules(json.dumps(data))
        assert rules[0]["priority"] == 150
        assert isinstance(rules[0]["priority"], int)

    def test_source_address_prefixes_sorted(self):
        data = [
            {**_rule("r1"),
             "sourceAddressPrefixes": ["192.168.1.0/24", "10.0.0.0/8"],
             "destinationAddressPrefixes": [],
             "destinationPortRanges": []}
        ]
        rules = extract_nsg_rules(json.dumps(data))
        assert rules[0]["sourceAddressPrefixes"] == ["10.0.0.0/8", "192.168.1.0/24"]


# ---------------------------------------------------------------------------
# compute_diff
# ---------------------------------------------------------------------------

class TestComputeDiff:

    def test_no_drift_identical_snapshots(self):
        """TC-DIFF-011: Identical snapshots → drift_detected=false."""
        r = _route("10.0.0.0/16")
        snap = _snap([_nic("nic-a", routes=[r])])
        diff = compute_diff(snap, snap)
        assert diff["drift_detected"] is False
        assert diff["changes_count"] == 0
        assert diff["nic_diffs"] == []

    def test_drift_detected_is_always_present(self):
        """TC-DIFF-026: drift_detected field is always present, never absent."""
        snap = _snap([_nic("nic-a")])
        diff = compute_diff(snap, snap)
        assert "drift_detected" in diff
        assert diff["drift_detected"] is False

    def test_bgp_route_removed(self):
        """TC-DIFF-012: BGP route removed → bgp_route_change, change_type=removed."""
        bgp_route = _route("10.2.0.0/24", source="VirtualNetworkGateway",
                           next_hop_type="VirtualNetworkGateway")
        baseline = _snap([_nic("nic-a", routes=[bgp_route])])
        compare  = _snap([_nic("nic-a", routes=[])])
        diff = compute_diff(baseline, compare)
        assert diff["drift_detected"] is True
        assert diff["changes_count"] == 1
        assert diff["changes_by_category"] == {"bgp_route_change": 1}
        change = diff["nic_diffs"][0]["changes"][0]
        assert change["change_type"] == "removed"
        assert change["category"] == "bgp_route_change"
        assert change["route"]["source"] == "VirtualNetworkGateway"

    def test_bgp_route_added(self):
        """TC-DIFF-013: BGP route added → bgp_route_change, change_type=added."""
        bgp_route = _route("10.2.0.0/24", source="VirtualNetworkGateway",
                           next_hop_type="VirtualNetworkGateway")
        baseline = _snap([_nic("nic-a", routes=[])])
        compare  = _snap([_nic("nic-a", routes=[bgp_route])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"] == {"bgp_route_change": 1}
        assert diff["nic_diffs"][0]["changes"][0]["change_type"] == "added"

    def test_udr_next_hop_changed(self):
        """TC-DIFF-014: UDR next-hop changed → udr_route_change, change_type=changed."""
        r_before = _route("0.0.0.0/0", source="User",
                          next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.4")
        r_after  = _route("0.0.0.0/0", source="User",
                          next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.5")
        baseline = _snap([_nic("nic-a", routes=[r_before])])
        compare  = _snap([_nic("nic-a", routes=[r_after])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"] == {"udr_route_change": 1}
        change = diff["nic_diffs"][0]["changes"][0]
        assert change["change_type"] == "changed"
        assert "route_before" in change
        assert "route_after" in change
        assert change["route_after"]["nextHopIpAddress"] == "10.0.1.5"

    def test_system_route_changed(self):
        """TC-DIFF-015: Default-sourced route changed → system_route_change."""
        r_before = _route("10.0.0.0/16", source="Default", state="Active")
        r_after  = _route("10.0.0.0/16", source="Default", state="Invalid")
        baseline = _snap([_nic("nic-a", routes=[r_before])])
        compare  = _snap([_nic("nic-a", routes=[r_after])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"] == {"system_route_change": 1}

    def test_nsg_rule_added(self):
        """TC-DIFF-016: NSG rule added → security_rule_change, change_type=added."""
        deny_rule = _rule("deny-ssh", direction="Inbound", priority=100, access="Deny", dst_port="22")
        deny_rule.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                          "destinationPortRanges": ["22"]})
        baseline = _snap([_nic("nic-a", nsg_rules=[])])
        compare  = _snap([_nic("nic-a", nsg_rules=[deny_rule])])
        diff = compute_diff(baseline, compare)
        assert diff["drift_detected"] is True
        assert diff["changes_by_category"] == {"security_rule_change": 1}
        change = diff["nic_diffs"][0]["changes"][0]
        assert change["change_type"] == "added"
        assert change["category"] == "security_rule_change"

    def test_nsg_rule_removed(self):
        """TC-DIFF-017: NSG rule removed → security_rule_change, change_type=removed."""
        rule = _rule("allow-https")
        rule.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                     "destinationPortRanges": ["443"]})
        baseline = _snap([_nic("nic-a", nsg_rules=[rule])])
        compare  = _snap([_nic("nic-a", nsg_rules=[])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"] == {"security_rule_change": 1}
        assert diff["nic_diffs"][0]["changes"][0]["change_type"] == "removed"

    def test_nsg_rule_priority_changed(self):
        """TC-DIFF-018: Same rule name, priority changed → security_rule_change, changed."""
        r_before = _rule("allow-https", priority=200)
        r_before.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                         "destinationPortRanges": ["443"]})
        r_after = _rule("allow-https", priority=100)
        r_after.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                        "destinationPortRanges": ["443"]})
        baseline = _snap([_nic("nic-a", nsg_rules=[r_before])])
        compare  = _snap([_nic("nic-a", nsg_rules=[r_after])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"] == {"security_rule_change": 1}
        change = diff["nic_diffs"][0]["changes"][0]
        assert change["change_type"] == "changed"
        assert "rule_before" in change
        assert "rule_after" in change

    def test_mixed_changes_multiple_categories(self):
        """TC-DIFF-019: BGP removed + UDR changed + NSG added on same NIC."""
        bgp = _route("10.2.0.0/24", source="VirtualNetworkGateway",
                     next_hop_type="VirtualNetworkGateway")
        udr_before = _route("0.0.0.0/0", source="User",
                            next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.4")
        udr_after  = _route("0.0.0.0/0", source="User",
                            next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.9")
        nsg_rule = _rule("deny-ssh")
        nsg_rule.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                         "destinationPortRanges": ["22"]})

        baseline = _snap([_nic("nic-a", routes=[bgp, udr_before], nsg_rules=[])])
        compare  = _snap([_nic("nic-a", routes=[udr_after], nsg_rules=[nsg_rule])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_count"] == 3
        assert diff["changes_by_category"]["bgp_route_change"] == 1
        assert diff["changes_by_category"]["udr_route_change"] == 1
        assert diff["changes_by_category"]["security_rule_change"] == 1

    def test_multi_nic_changes_on_one_nic_only(self):
        """TC-DIFF-020: Two NICs; only one has changes. Clean NIC not in nic_diffs."""
        bgp = _route("10.2.0.0/24", source="VirtualNetworkGateway",
                     next_hop_type="VirtualNetworkGateway")
        baseline = _snap([_nic("nic-a", routes=[bgp]), _nic("nic-b")])
        compare  = _snap([_nic("nic-a", routes=[]),    _nic("nic-b")])
        diff = compute_diff(baseline, compare)
        nic_names = [d["nic_name"] for d in diff["nic_diffs"]]
        assert "nic-a" in nic_names
        assert "nic-b" not in nic_names

    def test_new_nic_in_compare_all_added(self):
        """TC-DIFF-021: NIC present in compare but not baseline → all entries added."""
        r1 = _route("10.0.0.0/16")
        r2 = _route("10.1.0.0/24", source="User", next_hop_type="VirtualAppliance",
                    next_hop_ip="10.0.1.4")
        nsg = _rule("allow-https")
        nsg.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                    "destinationPortRanges": ["443"]})
        baseline = _snap([_nic("nic-a")])
        compare  = _snap([_nic("nic-a"), _nic("nic-b", routes=[r1, r2], nsg_rules=[nsg])])
        diff = compute_diff(baseline, compare)
        nic_b_diff = next(d for d in diff["nic_diffs"] if d["nic_name"] == "nic-b")
        added = [c for c in nic_b_diff["changes"] if c["change_type"] == "added"]
        # 2 routes + 1 NSG rule = 3 added
        assert len(added) == 3

    def test_errored_nic_in_compare_excluded_and_in_skipped(self):
        """TC-DIFF-022: NIC errored in compare → excluded from diff, in skipped_nics."""
        r = _route("10.0.0.0/16")
        baseline = _snap([_nic("nic-a", routes=[r])])
        compare  = _snap([_nic("nic-a", error="RBAC failure")])
        diff = compute_diff(baseline, compare)
        assert "nic-a" in diff["skipped_nics"]
        assert diff["nic_diffs"] == []
        assert diff["drift_detected"] is False

    def test_errored_nic_in_baseline_excluded_and_in_skipped(self):
        """TC-DIFF-023: NIC errored in baseline → excluded from diff, in skipped_nics."""
        r = _route("10.0.0.0/16")
        baseline = _snap([_nic("nic-a", error="Timed out")])
        compare  = _snap([_nic("nic-a", routes=[r])])
        diff = compute_diff(baseline, compare)
        assert "nic-a" in diff["skipped_nics"]
        assert diff["nic_diffs"] == []
        assert diff["drift_detected"] is False

    def test_unknown_route_source_defaults_to_udr(self):
        """TC-DIFF-024: Unknown route source categorised as udr_route_change."""
        unknown_route = _route("10.9.0.0/24", source="UnknownFutureSource",
                               next_hop_type="VnetLocal")
        baseline = _snap([_nic("nic-a", routes=[])])
        compare  = _snap([_nic("nic-a", routes=[unknown_route])])
        diff = compute_diff(baseline, compare)
        assert diff["changes_by_category"].get("udr_route_change", 0) == 1
        assert diff["changes_count"] == 1

    def test_reordered_nsg_list_fields_no_false_positive(self):
        """TC-DIFF-025: Same ports in different list order → no diff (sorted at normalisation)."""
        def _make_rule_with_ports(ports):
            return {
                "name": "multi-port",
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "*",
                "sourceAddressPrefixes": [],
                "destinationAddressPrefix": "*",
                "destinationAddressPrefixes": [],
                "destinationPortRange": "",
                "destinationPortRanges": ports,
            }

        rule_a = _make_rule_with_ports(["80", "443", "22"])
        rule_b = _make_rule_with_ports(["443", "22", "80"])

        # Run both through extract_nsg_rules to get normalised forms
        from diff import extract_nsg_rules as _enr
        rules_a = _enr(json.dumps([rule_a]))
        rules_b = _enr(json.dumps([rule_b]))

        baseline = {"session_id": "b", "nics": [{"nic_name": "nic-a",
            "effective_routes": [], "effective_nsg_rules": rules_a, "error": None}]}
        compare  = {"session_id": "c", "nics": [{"nic_name": "nic-a",
            "effective_routes": [], "effective_nsg_rules": rules_b, "error": None}]}
        diff = compute_diff(baseline, compare)
        assert diff["drift_detected"] is False

    def test_skipped_nics_field_always_present(self):
        """TC-DIFF-AG2: skipped_nics field present even when empty."""
        snap = _snap([_nic("nic-a")])
        diff = compute_diff(snap, snap)
        assert "skipped_nics" in diff
        assert diff["skipped_nics"] == []

    def test_baseline_session_id_in_diff(self):
        baseline = {"session_id": "sess-baseline", "nics": []}
        compare  = {"session_id": "sess-compare",  "nics": []}
        diff = compute_diff(baseline, compare)
        assert diff["baseline_session_id"] == "sess-baseline"
        assert diff["compare_session_id"] == "sess-compare"

    def test_two_empty_snapshots_no_drift(self):
        """TC-BOUND-004: Both snapshots empty → drift_detected=false, no exception."""
        diff = compute_diff(_snap([]), _snap([]))
        assert diff["drift_detected"] is False
        assert diff["changes_count"] == 0
        assert diff["nic_diffs"] == []
        assert diff["skipped_nics"] == []

    def test_all_four_categories_in_one_diff(self):
        """TC-BOUND-008: All four change categories can appear in a single diff."""
        bgp  = _route("10.2.0.0/24", source="VirtualNetworkGateway",
                      next_hop_type="VirtualNetworkGateway")
        udr  = _route("0.0.0.0/0",   source="User",
                      next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.4")
        udr2 = _route("0.0.0.0/0",   source="User",
                      next_hop_type="VirtualAppliance", next_hop_ip="10.0.1.9")
        sys_r_b = _route("10.0.0.0/16", source="Default", state="Active")
        sys_r_c = _route("10.0.0.0/16", source="Default", state="Invalid")
        nsg_r = _rule("deny-ssh")
        nsg_r.update({"sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                      "destinationPortRanges": ["22"]})

        baseline = _snap([_nic("nic-a",
            routes=[bgp, udr, sys_r_b],
            nsg_rules=[])])
        compare  = _snap([_nic("nic-a",
            routes=[udr2, sys_r_c],
            nsg_rules=[nsg_r])])
        diff = compute_diff(baseline, compare)
        assert set(diff["changes_by_category"].keys()) == {
            "bgp_route_change", "udr_route_change",
            "system_route_change", "security_rule_change"
        }
        assert diff["changes_count"] == 4
