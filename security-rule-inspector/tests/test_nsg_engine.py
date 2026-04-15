"""
test_nsg_engine.py — Unit tests for nsg_engine.py

Covers:
  T-EV-01 through T-EV-10  evaluate_verdict() fixture-based correctness
  T-MR-01 through T-MR-14  _match_rule() detailed matching logic
  T-SH-01 through T-SH-04  _collect_shadows() shadow assembly
  T-PM-01 through T-PM-05  _detect_permissive() permissive detection
  T-AU-01 through T-AU-06  audit() mode findings
"""

import pytest

import nsg_engine
import nsg_preprocessor
from nsg_engine import (
    TrafficTuple,
    _collect_shadows,
    _detect_permissive,
    _evaluate_gate,
    _is_unresolvable,
    _is_wildcard_address,
    _match_rule,
    audit,
    evaluate_verdict,
)
from conftest import fixture_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(fixture_name: str) -> dict:
    """Preprocess a fixture file and return the rule_sets dict."""
    return nsg_preprocessor.preprocess(fixture_path(fixture_name))


def _make_rule(
    name: str = "test-rule",
    priority: int = 100,
    direction: str = "Inbound",
    access: str = "Allow",
    protocol: str = "*",
    source_address: str = "*",
    destination_address: str = "*",
    destination_ports: list = None,
    is_default: bool = False,
    shadowed_by: str = None,
) -> dict:
    """Build a normalised rule dict for unit testing."""
    return {
        "name": name,
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "source_address": source_address,
        "source_ports": ["*"],
        "destination_address": destination_address,
        "destination_ports": destination_ports if destination_ports is not None else ["*"],
        "is_default": is_default,
        "shadowed_by": shadowed_by,
    }


def _make_rule_sets(
    subnet_inbound: list = None,
    subnet_outbound: list = None,
    nic_inbound: list = None,
    nic_outbound: list = None,
    parse_warnings: list = None,
) -> dict:
    """Build a minimal rule_sets dict for synthetic engine tests."""
    gates = []
    if subnet_inbound is not None or subnet_outbound is not None:
        gates.append({
            "gate": "subnet-nsg",
            "nsg_name": "test-subnet-nsg",
            "nsg_id": "",
            "association_type": "subnet",
            "association_id": "",
            "inbound_rules": subnet_inbound or [],
            "outbound_rules": subnet_outbound or [],
        })
    if nic_inbound is not None or nic_outbound is not None:
        gates.append({
            "gate": "nic-nsg",
            "nsg_name": "test-nic-nsg",
            "nsg_id": "",
            "association_type": "networkInterface",
            "association_id": "",
            "inbound_rules": nic_inbound or [],
            "outbound_rules": nic_outbound or [],
        })
    return {
        "gate_count": len(gates),
        "gates": gates,
        "parse_warnings": parse_warnings or [],
    }


# ---------------------------------------------------------------------------
# 5.1  evaluate_verdict() — fixture-based verdict correctness
# ---------------------------------------------------------------------------

class TestEvaluateVerdictFixtures:

    def test_ev_01_both_gates_allow_inbound(self):
        """T-EV-01: Both gates ALLOW inbound (fx-01) [GATE-ORDER, MATCH]"""
        rule_sets = _load("fx-01-inbound-both-allow.json")
        traffic = TrafficTuple(
            src_ip="10.0.0.5",
            dst_ip="10.0.1.10",
            dst_port=443,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "ALLOW"
        assert result["gate1"]["verdict"] == "ALLOW"
        assert result["gate2"]["verdict"] == "ALLOW"
        assert result["gate2"]["evaluated"] is True

    def test_ev_02_nic_gate_indeterminate_virtual_network_tag(self):
        """T-EV-02: NIC gate INDETERMINATE due to VirtualNetwork tag (fx-01) [MATCH, GATE-ORDER, INDETERMINATE]"""
        rule_sets = _load("fx-01-inbound-both-allow.json")
        # 192.168.1.1 is NOT in 10.0.0.0/16 — misses allow-https-nic
        # Then hits AllowVnetInBound with src=VirtualNetwork → unresolvable
        traffic = TrafficTuple(
            src_ip="192.168.1.1",
            dst_ip="10.0.1.10",
            dst_port=443,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "INDETERMINATE"
        assert result["gate1"]["verdict"] == "ALLOW"
        assert result["gate2"]["verdict"] == "INDETERMINATE"
        assert result["gate2"]["evaluated"] is True
        assert result["gate2"]["unresolvable_rule"]["name"] == "AllowVnetInBound"
        assert result["gate2"]["decisive_rule"] is None

    def test_ev_03_subnet_deny_short_circuits_nic(self):
        """T-EV-03: Subnet deny short-circuits NIC (fx-02) [SHORT-CIRCUIT, GATE-ORDER]"""
        rule_sets = _load("fx-02-subnet-deny-overrides-nic-allow.json")
        traffic = TrafficTuple(
            src_ip="10.0.1.5",
            dst_ip="10.0.2.10",
            dst_port=5432,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "DENY"
        assert result["gate2"]["evaluated"] is False
        assert result["gate2"]["skip_reason"] == "PRIOR_GATE_DENY"
        assert result["gate2"]["decisive_rule"] is None

    def test_ev_04_port_specific_deny_skipped_then_indeterminate(self):
        """T-EV-04: Port-specific deny skipped; VirtualNetwork tag causes INDETERMINATE (fx-02) [MATCH, INDETERMINATE]"""
        rule_sets = _load("fx-02-subnet-deny-overrides-nic-allow.json")
        # Port 22 doesn't match subnet deny on port 5432 → falls through to VirtualNetwork
        traffic = TrafficTuple(
            src_ip="10.0.1.5",
            dst_ip="10.0.2.10",
            dst_port=22,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "INDETERMINATE"
        assert result["gate2"]["evaluated"] is False
        assert result["gate2"]["skip_reason"] == "PRIOR_GATE_INDETERMINATE"
        assert result["gate1"]["unresolvable_rule"]["name"] == "AllowVnetInBound"

    def test_ev_05_both_gates_evaluated_nic_denies(self):
        """T-EV-05: Both gates evaluated inbound; NIC denies last (fx-03) [GATE-ORDER, MATCH]"""
        rule_sets = _load("fx-03-nic-deny-clean-subnet.json")
        traffic = TrafficTuple(
            src_ip="1.2.3.4",
            dst_ip="10.0.1.20",
            dst_port=8080,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "DENY"
        assert result["gate1"]["verdict"] == "ALLOW"
        assert result["gate2"]["verdict"] == "DENY"
        assert result["gate2"]["evaluated"] is True
        assert result["gate2"]["decisive_rule"]["name"] == "deny-port-8080-nic"

    def test_ev_06_shadowed_allow_not_selected_deny_all_wins(self):
        """T-EV-06: Shadowed allow not selected; deny-all wins (fx-04) [SHADOW, MATCH, DANGER]"""
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        traffic = TrafficTuple(
            src_ip="1.2.3.4",
            dst_ip="10.0.1.5",
            dst_port=443,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "DENY"
        assert result["gate1"]["decisive_rule"]["name"] == "deny-all-custom"
        # The shadowed allow rule must NEVER be cited as decisive
        assert result["gate1"]["decisive_rule"]["name"] != "allow-https-inbound"
        assert result["gate2"]["evaluated"] is False
        assert result["gate2"]["skip_reason"] == "PRIOR_GATE_DENY"

    def test_ev_07_outbound_nic_evaluated_first(self):
        """T-EV-07: Outbound — NIC evaluated first, subnet ALLOW irrelevant (fx-05) [GATE-ORDER, SHORT-CIRCUIT, DANGER]"""
        rule_sets = _load("fx-05-outbound-nic-first.json")
        traffic = TrafficTuple(
            src_ip="10.0.1.10",
            dst_ip="10.0.3.5",
            dst_port=22,
            protocol="Tcp",
            direction="Outbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "DENY"
        assert result["gate1"]["gate"] == "nic"
        assert result["gate2"]["evaluated"] is False
        assert result["gate2"]["skip_reason"] == "PRIOR_GATE_DENY"
        # Subnet's allow-ssh-to-backend must NEVER appear as decisive rule
        if result["gate1"]["decisive_rule"]:
            assert result["gate1"]["decisive_rule"]["name"] != "allow-ssh-to-backend"

    def test_ev_08_single_gate_no_nic_nsg_allow(self):
        """T-EV-08 (part 1): Single gate, no NIC NSG, port 80 allowed (fx-06) [GATE-ORDER, MATCH]"""
        rule_sets = _load("fx-06-no-nic-nsg.json")
        traffic = TrafficTuple(
            src_ip="10.0.1.10",
            dst_ip="10.0.1.5",
            dst_port=80,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "ALLOW"
        assert result["gate1"]["verdict"] == "ALLOW"
        assert result["gate2"]["decisive_rule"] is None

    def test_ev_08_single_gate_unresolvable_at_internet_rule(self):
        """T-EV-08 (part 2): Port 3306, Internet service tag causes INDETERMINATE (fx-06)"""
        rule_sets = _load("fx-06-no-nic-nsg.json")
        # allow-http-from-web-tier (p=100, port=80): port 3306 ≠ 80 → no match
        # deny-direct-internet-inbound (p=200, src=Internet): Internet is unresolvable → INDETERMINATE
        traffic = TrafficTuple(
            src_ip="10.0.1.10",
            dst_ip="10.0.1.5",
            dst_port=3306,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "INDETERMINATE"
        assert result["gate1"]["unresolvable_rule"]["name"] == "deny-direct-internet-inbound"

    def test_ev_09_default_only_internet_source_indeterminate(self):
        """T-EV-09 (part 1): Default deny for internet source, no custom rules (fx-09) [MATCH]"""
        rule_sets = _load("fx-09-default-rule-wins.json")
        # AllowVnetInBound (p=65000, src=VirtualNetwork): unresolvable → INDETERMINATE
        traffic = TrafficTuple(
            src_ip="203.0.113.50",
            dst_ip="10.0.1.5",
            dst_port=443,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["final_verdict"] == "INDETERMINATE"

    def test_ev_09_synthetic_expanded_vnet_deny_all_wins(self):
        """T-EV-09 (part 2): VirtualNetwork pre-expanded, 203.0.113.50 not in range → DenyAllInBound fires"""
        # Synthetic rule set: VirtualNetwork expanded to 10.0.0.0/8, then DenyAllInBound
        rule_sets = _make_rule_sets(
            subnet_inbound=[
                _make_rule(
                    name="AllowVnetInBound",
                    priority=65000,
                    access="Allow",
                    protocol="All",
                    source_address="10.0.0.0/8",  # pre-expanded; 203.0.113.50 NOT in it
                    destination_address="*",
                    destination_ports=["*"],
                    is_default=True,
                ),
                _make_rule(
                    name="DenyAllInBound",
                    priority=65500,
                    access="Deny",
                    protocol="All",
                    source_address="*",
                    destination_address="*",
                    destination_ports=["*"],
                    is_default=True,
                ),
            ],
        )
        traffic = TrafficTuple(
            src_ip="203.0.113.50",
            dst_ip="10.0.1.5",
            dst_port=443,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)

        assert result["gate1"]["decisive_rule"]["name"] == "DenyAllInBound"
        assert result["gate1"]["decisive_rule"]["is_default"] is True

    def test_ev_10a_port_range_lower_bound_inclusive(self):
        """T-EV-10a: Port 8080 matches range 8080-8090 (lower bound inclusive)"""
        rule_sets = _load("fx-08-port-range.json")
        traffic = TrafficTuple(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            dst_port=8080,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)
        assert result["final_verdict"] == "ALLOW"

    def test_ev_10b_port_range_upper_bound_inclusive(self):
        """T-EV-10b: Port 8090 matches range 8080-8090 (upper bound inclusive)"""
        rule_sets = _load("fx-08-port-range.json")
        traffic = TrafficTuple(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            dst_port=8090,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)
        assert result["final_verdict"] == "ALLOW"

    def test_ev_10c_port_below_range_falls_through_to_indeterminate(self):
        """T-EV-10c: Port 8079 below range, falls through to AllowVnetInBound (VirtualNetwork → INDETERMINATE)"""
        rule_sets = _load("fx-08-port-range.json")
        traffic = TrafficTuple(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            dst_port=8079,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)
        assert result["final_verdict"] == "INDETERMINATE"

    def test_ev_10d_port_above_range_falls_through_to_indeterminate(self):
        """T-EV-10d: Port 8091 above range, falls through to AllowVnetInBound (VirtualNetwork → INDETERMINATE)"""
        rule_sets = _load("fx-08-port-range.json")
        traffic = TrafficTuple(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            dst_port=8091,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)
        assert result["final_verdict"] == "INDETERMINATE"

    def test_ev_10e_deny_before_allow_range(self):
        """T-EV-10e: 192.168.1.5:8085 matches deny at p=50 before allow range at p=100"""
        rule_sets = _load("fx-08-port-range.json")
        traffic = TrafficTuple(
            src_ip="192.168.1.5",
            dst_ip="10.0.0.10",
            dst_port=8085,
            protocol="Tcp",
            direction="Inbound",
        )
        result = evaluate_verdict(rule_sets, traffic)
        assert result["final_verdict"] == "DENY"
        assert result["gate1"]["decisive_rule"]["name"] == "deny-port-8085-override"


# ---------------------------------------------------------------------------
# 5.2  _match_rule() — detailed matching logic
# ---------------------------------------------------------------------------

class TestMatchRule:

    def test_mr_01_protocol_all_matches_tcp(self):
        """T-MR-01: Protocol 'All' matches Tcp [MATCH]"""
        rule = _make_rule(protocol="All")
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_02_protocol_wildcard_matches_udp(self):
        """T-MR-02: Protocol '*' matches Udp [MATCH]"""
        rule = _make_rule(protocol="*")
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 53, "Udp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_03_protocol_mismatch_tcp_rule_does_not_match_udp(self):
        """T-MR-03: Tcp rule does NOT match Udp traffic [MATCH, DANGER]"""
        rule = _make_rule(protocol="Tcp")
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Udp", "Inbound")
        assert _match_rule(rule, traffic) is False

    def test_mr_04_source_cidr_last_address_in_slash24(self):
        """T-MR-04: Source 10.0.1.255 matches 10.0.1.0/24 (last address) [MATCH]"""
        rule = _make_rule(
            protocol="Tcp",
            source_address="10.0.1.0/24",
            destination_ports=["*"],
        )
        traffic = TrafficTuple("10.0.1.255", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_05_source_cidr_just_outside(self):
        """T-MR-05: Source 10.0.2.0 is NOT in 10.0.1.0/24 [MATCH, DANGER]"""
        rule = _make_rule(
            protocol="Tcp",
            source_address="10.0.1.0/24",
            destination_ports=["*"],
        )
        traffic = TrafficTuple("10.0.2.0", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is False

    def test_mr_06_comma_separated_source_first_matches(self):
        """T-MR-06: Comma-separated source — first value matches [MATCH]"""
        rule = _make_rule(source_address="10.0.0.0/8, 192.168.0.0/16")
        traffic = TrafficTuple("10.1.2.3", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_07_comma_separated_source_second_matches(self):
        """T-MR-07: Comma-separated source — second value matches [MATCH]"""
        rule = _make_rule(source_address="10.0.0.0/8, 192.168.0.0/16")
        traffic = TrafficTuple("192.168.1.5", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_08_unresolvable_service_tag_returns_none(self):
        """T-MR-08: Service tag 'AzureMonitor' in source returns None (UNRESOLVABLE) [INDETERMINATE, DANGER]"""
        rule = _make_rule(source_address="AzureMonitor")
        traffic = TrafficTuple("10.0.0.5", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is None

    def test_mr_09_resolvable_cidr_before_unresolvable_tag_matches(self):
        """T-MR-09: Resolvable CIDR before unresolvable tag — match found first [INDETERMINATE]"""
        # Preprocessor sorts addresses: "10.0.0.0/16" < "Storage" (ASCII '1' < 'S')
        rule = _make_rule(source_address="10.0.0.0/16, Storage")
        traffic = TrafficTuple("10.0.1.5", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_10_cidr_first_matches_service_tag_never_reached(self):
        """T-MR-10: CIDR first (preprocessor sort) — match; tag alone → None [INDETERMINATE]"""
        # CIDR first: 10.0.1.5 ∈ 10.0.0.0/16 → True
        rule_cidr_first = _make_rule(source_address="10.0.0.0/16, AzureCloud")
        traffic = TrafficTuple("10.0.1.5", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule_cidr_first, traffic) is True

        # Tag alone: AzureCloud is unresolvable → None
        rule_tag_only = _make_rule(source_address="AzureCloud")
        assert _match_rule(rule_tag_only, traffic) is None

    def test_mr_11_port_range_0_65535_treated_as_wildcard(self):
        """T-MR-11: '0-65535' port range treated as wildcard [MATCH]"""
        rule = _make_rule(destination_ports=["0-65535"])
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 443, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_12_any_source_address_is_wildcard(self):
        """T-MR-12: Source address 'Any' is treated as wildcard [MATCH]"""
        assert _is_wildcard_address("Any") is True
        rule = _make_rule(source_address="Any")
        traffic = TrafficTuple("203.0.113.1", "10.0.0.1", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_13_zero_cidr_source_is_wildcard(self):
        """T-MR-13: Source '0.0.0.0/0' is treated as wildcard [MATCH]"""
        assert _is_wildcard_address("0.0.0.0/0") is True
        rule = _make_rule(source_address="0.0.0.0/0")
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True

    def test_mr_14_source_port_always_matches(self):
        """T-MR-14: Source port is not evaluated; destination port wildcard matches [MATCH]"""
        rule = _make_rule(
            protocol="Tcp",
            source_address="*",
            destination_ports=["*"],
        )
        # source_ports=["22"] in the rule — engine ignores source port
        rule["source_ports"] = ["22"]
        traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
        assert _match_rule(rule, traffic) is True


# ---------------------------------------------------------------------------
# 5.3  _collect_shadows() — shadow assembly
# ---------------------------------------------------------------------------

class TestCollectShadows:

    def test_sh_01_shadow_present_lookup_succeeds(self):
        """T-SH-01: Shadow present; lookup succeeds (fx-04) [SHADOW]"""
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        subnet_gate = next(
            g for g in rule_sets["gates"] if g["association_type"] == "subnet"
        )
        inbound_rules = subnet_gate["inbound_rules"]

        result = _collect_shadows(inbound_rules, "subnet", "Inbound")

        assert any(
            sr["rule"]["name"] == "allow-https-inbound"
            and sr["shadowed_by"]["name"] == "deny-all-custom"
            and sr["gate"] == "subnet"
            and sr["direction"] == "Inbound"
            for sr in result
        )

    def test_sh_02_multiple_shadows_in_same_gate(self):
        """T-SH-02: Multiple shadows in same gate (fx-04) [SHADOW]

        deny-all-custom (p=100, Deny, All, *, *) shadows all lower-priority rules
        with different access. DenyAllInBound (p=65500, also Deny) is the SAME access
        as deny-all-custom, so the shadow algorithm (which requires OPPOSITE access)
        does not flag it. Expected shadow count is 4.
        """
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        subnet_gate = next(
            g for g in rule_sets["gates"] if g["association_type"] == "subnet"
        )
        inbound_rules = subnet_gate["inbound_rules"]

        result = _collect_shadows(inbound_rules, "subnet", "Inbound")

        # allow-https-inbound, allow-ssh-inbound, AllowVnetInBound,
        # AllowAzureLoadBalancerInBound all have access=Allow → shadowed
        shadowed_names = {sr["rule"]["name"] for sr in result}
        assert "allow-https-inbound" in shadowed_names
        assert "allow-ssh-inbound" in shadowed_names
        assert "AllowVnetInBound" in shadowed_names
        assert "AllowAzureLoadBalancerInBound" in shadowed_names
        # DenyAllInBound has same access (Deny) as deny-all-custom → NOT shadowed
        assert "DenyAllInBound" not in shadowed_names
        assert len(result) >= 4
        assert all(sr["shadowed_by"]["name"] == "deny-all-custom" for sr in result)

    def test_sh_03_no_shadows_empty_result(self):
        """T-SH-03: No shadows — empty result [SHADOW]"""
        rules = [
            _make_rule(name="rule-a", priority=100, shadowed_by=None),
            _make_rule(name="rule-b", priority=200, shadowed_by=None),
        ]
        result = _collect_shadows(rules, "subnet", "Inbound")
        assert result == []

    def test_sh_04_orphan_shadowed_by_name_excluded_with_warning(self):
        """T-SH-04: Orphan shadowed_by name — entry excluded; parse warning generated [SHADOW]"""
        rules = [
            _make_rule(name="rule-a", priority=100, shadowed_by="nonexistent-rule"),
        ]
        warnings = []
        result = _collect_shadows(rules, "subnet", "Inbound", warnings)

        assert result == []
        assert any("nonexistent-rule" in w for w in warnings)


# ---------------------------------------------------------------------------
# 5.4  _detect_permissive() — permissive rule detection
# ---------------------------------------------------------------------------

class TestDetectPermissive:

    def test_pm_01_custom_allow_wildcard_source_flagged(self):
        """T-PM-01: Custom ALLOW with wildcard source [AUDIT]"""
        rule = _make_rule(
            access="Allow",
            is_default=False,
            source_address="*",
            destination_address="10.0.0.1",
            destination_ports=["443"],
        )
        result = _detect_permissive([rule], "subnet", "Inbound")

        assert len(result) == 1
        assert result[0]["wildcard_dimensions"] == ["source"]

    def test_pm_02_custom_allow_wildcard_port_and_destination_flagged(self):
        """T-PM-02: Custom ALLOW with wildcard port and destination [AUDIT]"""
        rule = _make_rule(
            access="Allow",
            is_default=False,
            source_address="10.0.0.0/8",
            destination_address="*",
            destination_ports=["*"],
        )
        result = _detect_permissive([rule], "subnet", "Inbound")

        assert len(result) == 1
        dims = result[0]["wildcard_dimensions"]
        assert "port" in dims
        assert "destination" in dims

    def test_pm_03_default_allow_not_flagged(self):
        """T-PM-03: Default ALLOW with all wildcards — NOT flagged [AUDIT]"""
        rule = _make_rule(
            name="AllowVnetOutBound",
            access="Allow",
            is_default=True,
            source_address="*",
            destination_address="*",
            destination_ports=["*"],
        )
        result = _detect_permissive([rule], "nic", "Outbound")
        assert result == []

    def test_pm_04_deny_with_all_wildcards_not_flagged(self):
        """T-PM-04: DENY rule with all wildcards — NOT flagged [AUDIT]"""
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        subnet_gate = next(
            g for g in rule_sets["gates"] if g["association_type"] == "subnet"
        )
        inbound_rules = subnet_gate["inbound_rules"]

        result = _detect_permissive(inbound_rules, "subnet", "Inbound")

        permissive_names = {pr["rule"]["name"] for pr in result}
        assert "deny-all-custom" not in permissive_names

    def test_pm_05_custom_allow_no_wildcards_not_flagged(self):
        """T-PM-05: Custom ALLOW with no wildcards — NOT flagged [AUDIT]"""
        rule = _make_rule(
            access="Allow",
            is_default=False,
            source_address="10.0.1.0/24",
            destination_address="10.0.2.0/24",
            destination_ports=["443"],
        )
        result = _detect_permissive([rule], "subnet", "Inbound")
        assert result == []


# ---------------------------------------------------------------------------
# 5.5  audit() — audit mode findings
# ---------------------------------------------------------------------------

class TestAudit:

    def test_au_01_full_audit_fx04_correct_shadow_findings(self):
        """T-AU-01: Full audit on fx-04 produces correct shadow findings [AUDIT, SHADOW]"""
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        result = audit(rule_sets)

        shadowed = result["findings"]["shadowed_rules"]
        shadowed_names = {sr["rule"]["name"] for sr in shadowed}

        # 4 Allow rules shadowed by deny-all-custom (same-access Deny not shadowed)
        assert "allow-https-inbound" in shadowed_names
        assert "allow-ssh-inbound" in shadowed_names
        assert "AllowVnetInBound" in shadowed_names
        assert "AllowAzureLoadBalancerInBound" in shadowed_names

        # Verify gate and direction on each shadowed entry
        for sr in shadowed:
            assert sr["gate"] == "subnet"
            assert sr["direction"] == "Inbound"
            assert sr["shadowed_by"]["name"] == "deny-all-custom"

        # NIC gate has only defaults — no shadows from NIC
        nic_shadows = [sr for sr in shadowed if sr["gate"] == "nic"]
        assert nic_shadows == []

    def test_au_02_default_only_gates_flagged_fx09(self):
        """T-AU-02: Default-only gates flagged (fx-09) [AUDIT]"""
        rule_sets = _load("fx-09-default-rule-wins.json")
        result = audit(rule_sets)

        default_only = result["findings"]["default_only_gates"]
        keys = {(d["gate"], d["direction"]) for d in default_only}

        assert ("subnet", "Inbound") in keys
        assert ("subnet", "Outbound") in keys
        assert ("nic", "Inbound") in keys
        assert ("nic", "Outbound") in keys
        # Both NSGs are present but contain only default rules
        for d in default_only:
            assert d["nsg_absent"] is False

    def test_au_03_missing_nic_nsg_flagged_as_absent_fx06(self):
        """T-AU-03: Missing NIC NSG flagged as nsg_absent (fx-06) [AUDIT]"""
        rule_sets = _load("fx-06-no-nic-nsg.json")
        result = audit(rule_sets)

        default_only = result["findings"]["default_only_gates"]
        nic_entries = [d for d in default_only if d["gate"] == "nic"]

        nic_inbound = next((d for d in nic_entries if d["direction"] == "Inbound"), None)
        nic_outbound = next((d for d in nic_entries if d["direction"] == "Outbound"), None)

        assert nic_inbound is not None
        assert nic_outbound is not None
        assert nic_inbound["nsg_absent"] is True
        assert nic_outbound["nsg_absent"] is True

    def test_au_04_permissive_rules_detected_fx04(self):
        """T-AU-04: Permissive rules detected in fx-04 [AUDIT]"""
        rule_sets = _load("fx-04-shadowed-allow-rule.json")
        result = audit(rule_sets)

        permissive = result["findings"]["permissive_rules"]
        permissive_names = {pr["rule"]["name"] for pr in permissive}

        assert "allow-https-inbound" in permissive_names
        assert "allow-ssh-inbound" in permissive_names
        assert "deny-all-custom" not in permissive_names

        https_rule = next(pr for pr in permissive if pr["rule"]["name"] == "allow-https-inbound")
        assert set(https_rule["wildcard_dimensions"]) == {"source", "destination"}

        ssh_rule = next(pr for pr in permissive if pr["rule"]["name"] == "allow-ssh-inbound")
        assert ssh_rule["wildcard_dimensions"] == ["destination"]

    def test_au_05_rule_inventory_sorted_by_priority_fx10(self):
        """T-AU-05: Rule inventory sorted by priority ascending (fx-10) [AUDIT]"""
        rule_sets = _load("fx-10-complex-production.json")
        result = audit(rule_sets)

        rules = result["rule_sets"]["inbound"]["gate1"]["rules"]
        priorities = [r["priority"] for r in rules]
        assert priorities == sorted(priorities)

    def test_au_06_gate_assignment_direction_dependent_fx05(self):
        """T-AU-06: Gate1/Gate2 assignment is direction-dependent (fx-05) [GATE-ORDER, AUDIT]"""
        rule_sets = _load("fx-05-outbound-nic-first.json")
        result = audit(rule_sets)

        # Outbound: Gate 1 = NIC, Gate 2 = subnet
        assert result["rule_sets"]["outbound"]["gate1"]["gate"] == "nic"
        assert result["rule_sets"]["outbound"]["gate2"]["gate"] == "subnet"
        # Inbound: Gate 1 = subnet, Gate 2 = NIC
        assert result["rule_sets"]["inbound"]["gate1"]["gate"] == "subnet"
        assert result["rule_sets"]["inbound"]["gate2"]["gate"] == "nic"
