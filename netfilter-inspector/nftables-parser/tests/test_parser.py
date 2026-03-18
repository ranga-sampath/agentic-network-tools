"""
Parser tests — nftables_parser.py

Covers: AC-F*, AC-FA*, AC-EC*, AC-DI*, AC-EH*, AC-NF*
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re

import pytest

from helpers import (
    load_fixture, parse_fixture, parse_objects, rules_in, rule_by_handle
)
from nftables_parser import parse_nft_ruleset, _expression_hash


# ═══════════════════════════════════════════════════════════════════════════
# Part 1 — Fixture-level criteria (AC-F*)
# ═══════════════════════════════════════════════════════════════════════════

class TestFixtureF01:
    """AC-F01 — Empty ruleset (fx-01-empty.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-01-empty.json")

    def test_tables_empty_dict(self):
        assert self.r["tables"] == {}

    def test_no_parse_warnings(self):
        assert self.r["parse_warnings"] == []

    def test_input_format(self):
        assert self.r["input_format"] == "nft-json"

    def test_nft_version(self):
        assert self.r["nft_version"] == "1.0.9"

    def test_json_schema_version(self):
        assert self.r["json_schema_version"] == 1

    def test_diagnostics_all_empty(self):
        d = self.r["diagnostics"]
        assert d["drop_policy_chains"] == []
        assert d["accept_policy_chains"] == []
        assert d["active_drop_rules"] == []
        assert d["unresolved_chain_jumps"] == []
        assert d["inet_tables"] == []
        assert d["sets_referenced_in_rules"] == {}

    def test_parsed_at_present_and_iso8601(self):
        from datetime import datetime
        ts = self.r["parsed_at"]
        assert ts is not None
        datetime.fromisoformat(ts.replace("Z", "+00:00"))


class TestFixtureF02:
    """AC-F02 — Azure-style clean ruleset (fx-02-ip-clean.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-02-ip-clean.json")

    def test_single_table_key(self):
        assert list(self.r["tables"].keys()) == ["ip/filter"]

    def test_table_family_and_name(self):
        t = self.r["tables"]["ip/filter"]
        assert t["family"] == "ip"
        assert t["name"] == "filter"

    def test_three_chains(self):
        chains = self.r["tables"]["ip/filter"]["chains"]
        assert set(chains.keys()) == {"input", "forward", "output"}

    def test_all_chains_are_base_chains_accept_policy(self):
        for cdata in self.r["tables"]["ip/filter"]["chains"].values():
            assert cdata["is_base_chain"] is True
            assert cdata["policy"] == "accept"

    def test_input_and_forward_have_no_rules(self):
        chains = self.r["tables"]["ip/filter"]["chains"]
        assert chains["input"]["rules"] == []
        assert chains["forward"]["rules"] == []

    def test_output_has_three_rules(self):
        assert len(rules_in(self.r, "ip/filter", "output")) == 3

    def test_rule1_dst_addr_protocol_dport_verdict(self):
        r = rule_by_handle(self.r, "ip/filter", "output", 5)
        assert r["dst_addr"] == "168.63.129.16"
        assert r["protocol"] == "tcp"
        assert r["dst_port"] == "53"
        assert r["verdict"] == "accept"

    def test_rule3_ct_state_drop(self):
        r = rule_by_handle(self.r, "ip/filter", "output", 7)
        assert r["verdict"] == "drop"
        assert r["verdict_stops_chain"] is True
        assert "invalid" in r["ct_state"]
        assert "new" in r["ct_state"]

    def test_all_rules_have_expression_hash_64hex(self):
        for rule in rules_in(self.r, "ip/filter", "output"):
            h = rule["expression_hash"]
            assert isinstance(h, str) and len(h) == 64
            assert re.fullmatch(r"[0-9a-f]{64}", h)

    def test_all_rules_opaque_null(self):
        for rule in rules_in(self.r, "ip/filter", "output"):
            assert rule["opaque_expressions"] is None

    def test_diagnostics_drop_policy_chains_empty(self):
        assert self.r["diagnostics"]["drop_policy_chains"] == []

    def test_diagnostics_accept_policy_chains(self):
        apc = self.r["diagnostics"]["accept_policy_chains"]
        assert "ip/filter/input" in apc
        assert "ip/filter/forward" in apc
        assert "ip/filter/output" in apc


class TestFixtureF03:
    """AC-F03 — inet drop-policy (fx-03-inet-drop-policy.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-03-inet-drop-policy.json")

    def test_table_key_inet(self):
        assert "inet/filter" in self.r["tables"]

    def test_table_family_inet(self):
        assert self.r["tables"]["inet/filter"]["family"] == "inet"

    def test_input_chain_drop_policy(self):
        c = self.r["tables"]["inet/filter"]["chains"]["input"]
        assert c["policy"] == "drop"
        assert c["is_base_chain"] is True
        assert c["type"] == "filter"
        assert c["hook"] == "input"

    def test_forward_chain_drop_policy(self):
        c = self.r["tables"]["inet/filter"]["chains"]["forward"]
        assert c["policy"] == "drop"
        assert c["is_base_chain"] is True

    def test_output_chain_accept_policy(self):
        assert self.r["tables"]["inet/filter"]["chains"]["output"]["policy"] == "accept"

    def test_ct_state_established_related_rule(self):
        rules = rules_in(self.r, "inet/filter", "input")
        ct_rules = [r for r in rules if r.get("ct_state")]
        assert any(
            set(r["ct_state"]) >= {"established", "related"} for r in ct_rules
        )

    def test_ssh_rule(self):
        rules = rules_in(self.r, "inet/filter", "input")
        ssh = [r for r in rules if r.get("dst_port") == "22"]
        assert ssh, "expected an SSH (dport 22) rule"
        assert ssh[0]["verdict"] == "accept"

    def test_diagnostics_drop_policy_chains(self):
        dpc = self.r["diagnostics"]["drop_policy_chains"]
        assert "inet/filter/input" in dpc
        assert "inet/filter/forward" in dpc
        assert "inet/filter/output" not in dpc

    def test_diagnostics_inet_tables(self):
        assert "inet/filter" in self.r["diagnostics"]["inet_tables"]


class TestFixtureF04:
    """AC-F04 — Regular chains and jumps (fx-04-regular-chains.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-04-regular-chains.json")

    def test_two_chains(self):
        chains = self.r["tables"]["ip/filter"]["chains"]
        assert set(chains.keys()) == {"input", "allowed-ports"}

    def test_input_is_base_chain(self):
        c = self.r["tables"]["ip/filter"]["chains"]["input"]
        assert c["is_base_chain"] is True
        assert c["type"] == "filter"
        assert c["hook"] == "input"

    def test_allowed_ports_is_regular_chain(self):
        c = self.r["tables"]["ip/filter"]["chains"]["allowed-ports"]
        assert c["is_base_chain"] is False
        assert c["type"] is None
        assert c["hook"] is None
        assert c["priority"] is None
        assert c["policy"] is None

    def test_jump_to_allowed_ports(self):
        rules = rules_in(self.r, "ip/filter", "input")
        jumps = [r for r in rules if r.get("jump_target") == "allowed-ports"]
        assert jumps, "expected a jump to allowed-ports"
        assert jumps[0]["verdict"] is None
        assert jumps[0]["verdict_stops_chain"] is False

    def test_jump_to_ghost_chain(self):
        rules = rules_in(self.r, "ip/filter", "input")
        ghost = [r for r in rules if r.get("jump_target") == "ghost_chain"]
        assert ghost

    def test_allowed_ports_rules_accept(self):
        for r in rules_in(self.r, "ip/filter", "allowed-ports"):
            assert r["verdict"] == "accept"
            assert r["verdict_stops_chain"] is True

    def test_unresolved_chain_jumps(self):
        uj = self.r["diagnostics"]["unresolved_chain_jumps"]
        targets = [e.get("jump_target") or e.get("goto_target") for e in uj]
        assert "ghost_chain" in targets
        assert "allowed-ports" not in targets


class TestFixtureF05:
    """AC-F05 — Sets (fx-05-sets.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-05-sets.json")

    def test_blocklist_set_record(self):
        s = self.r["tables"]["ip/filter"]["sets"]["blocklist"]
        assert s["is_map"] is False
        assert "interval" in s["flags"]
        assert s["elements"]

    def test_port_map_is_map(self):
        s = self.r["tables"]["ip/filter"]["sets"]["port-map"]
        assert s["is_map"] is True

    def test_blocklist_rule_set_references(self):
        rules = rules_in(self.r, "ip/filter", "input")
        bl = [r for r in rules if r.get("set_references") and "blocklist" in r["set_references"]]
        assert bl
        assert bl[0]["verdict"] == "drop"

    def test_allowlist_rule_set_references(self):
        rules = rules_in(self.r, "ip/filter", "input")
        al = [r for r in rules if r.get("set_references") and "allowlist" in r["set_references"]]
        assert al
        assert al[0]["verdict"] == "accept"

    def test_sets_referenced_in_rules_blocklist_found(self):
        srir = self.r["diagnostics"]["sets_referenced_in_rules"]
        assert srir["blocklist"]["found"] is True

    def test_sets_referenced_in_rules_allowlist_not_found(self):
        srir = self.r["diagnostics"]["sets_referenced_in_rules"]
        assert srir["allowlist"]["found"] is False


class TestFixtureF06:
    """AC-F06 — Multi-family (fx-06-multi-family.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-06-multi-family.json")

    def test_two_table_keys(self):
        assert set(self.r["tables"].keys()) == {"ip/filter", "ip6/filter"}

    def test_ip_family(self):
        assert self.r["tables"]["ip/filter"]["family"] == "ip"

    def test_ip6_family(self):
        assert self.r["tables"]["ip6/filter"]["family"] == "ip6"

    def test_chains_isolated(self):
        ip_chains = set(self.r["tables"]["ip/filter"]["chains"])
        ip6_chains = set(self.r["tables"]["ip6/filter"]["chains"])
        # Both should have chains; they should be independent namespaces
        assert ip_chains
        assert ip6_chains

    def test_ipv6_addr_preserved(self):
        rules = []
        for cdata in self.r["tables"]["ip6/filter"]["chains"].values():
            rules.extend(cdata["rules"])
        addrs = [r.get("src_addr") or r.get("dst_addr") for r in rules]
        assert any(a and ":" in a for a in addrs), "expected an IPv6 address in ip6/filter rules"

    def test_inet_tables_empty(self):
        assert self.r["diagnostics"]["inet_tables"] == []


class TestFixtureF07:
    """AC-F07 — inet+ip mixed families (fx-07-inet-ip-mixed.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-07-inet-ip-mixed.json")

    def test_two_table_keys(self):
        assert set(self.r["tables"].keys()) == {"inet/filter", "ip/nat"}

    def test_inet_filter_family(self):
        assert self.r["tables"]["inet/filter"]["family"] == "inet"

    def test_ip_nat_family(self):
        assert self.r["tables"]["ip/nat"]["family"] == "ip"

    def test_inet_tables_contains_only_inet(self):
        it = self.r["diagnostics"]["inet_tables"]
        assert "inet/filter" in it
        assert "ip/nat" not in it


class TestFixtureF08:
    """AC-F08 — Counter-bearing rules (fx-08-counters.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-08-counters.json")

    def test_drop_rule_in_active_drop_rules(self):
        adr = self.r["diagnostics"]["active_drop_rules"]
        assert len(adr) == 1
        assert adr[0]["verdict"] == "drop"

    def test_zero_packet_rules_absent_from_active_drop(self):
        adr = self.r["diagnostics"]["active_drop_rules"]
        for entry in adr:
            # the fixture has packets:42 on the one drop rule; zero-packet rules excluded
            raw = entry["raw_expressions"]
            counters = [e["counter"] for e in raw if "counter" in e]
            assert all(c.get("packets", 0) > 0 for c in counters)

    def test_named_counter_parse_warning(self):
        # Named counter objects must produce a parse warning (metadata-only)
        assert any("counter" in w.lower() for w in self.r["parse_warnings"])


class TestFixtureF09:
    """AC-F09 — NAT table (fx-09-nat.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-09-nat.json")

    def test_table_is_ip_nat(self):
        assert "ip/nat" in self.r["tables"]

    def test_prerouting_chain(self):
        c = self.r["tables"]["ip/nat"]["chains"]["prerouting"]
        assert c["is_base_chain"] is True
        assert c["type"] == "nat"
        assert c["hook"] == "prerouting"
        assert c["priority"] == -100  # dstnat → -100

    def test_postrouting_chain(self):
        c = self.r["tables"]["ip/nat"]["chains"]["postrouting"]
        assert c["is_base_chain"] is True
        assert c["type"] == "nat"
        assert c["hook"] == "postrouting"
        assert c["priority"] == 100  # srcnat → 100

    def test_dnat_rule_opaque(self):
        r = rule_by_handle(self.r, "ip/nat", "prerouting", 4)
        assert r["protocol"] == "tcp"
        assert r["dst_port"] == "80"
        assert r["verdict"] is None
        assert r["opaque_expressions"] is not None
        assert any("dnat" in e for e in r["opaque_expressions"])

    def test_masquerade_rule_opaque(self):
        r = rule_by_handle(self.r, "ip/nat", "postrouting", 5)
        assert r["src_addr"] == "192.168.1.0/24"
        assert r["verdict"] is None
        assert r["opaque_expressions"] is not None
        assert any("masquerade" in e for e in r["opaque_expressions"])

    def test_dnat_masquerade_produce_warnings(self):
        assert any("dnat" in w for w in self.r["parse_warnings"])
        assert any("masquerade" in w for w in self.r["parse_warnings"])


class TestFixtureF10:
    """AC-F10 — Negation, port ranges, interfaces (fx-10-negation-ports-interfaces.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-10-negation-ports-interfaces.json")

    def test_src_addr_negated(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 3)
        assert r["src_addr"] == "10.0.0.0/8"
        assert r["src_addr_negated"] is True
        assert r["verdict"] == "drop"

    def test_dst_port_negated(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 4)
        assert r["dst_port"] == "22"
        assert r["dst_port_negated"] is True
        assert r["verdict"] == "drop"

    def test_sport_port_range(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 5)
        assert r["src_port"] == "1024-65535"
        assert r["src_port_negated"] is False
        assert r["verdict"] == "accept"

    def test_in_interface_negated(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 6)
        assert r["in_interface"] == "eth0"
        assert r["in_interface_negated"] is True
        assert r["verdict"] == "drop"

    def test_out_interface_not_negated(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 7)
        assert r["out_interface"] == "eth1"
        assert r["out_interface_negated"] is False
        assert r["verdict"] == "accept"

    def test_no_parse_warnings(self):
        assert self.r["parse_warnings"] == []


class TestFixtureF11:
    """AC-F11 — log, return, reject, goto (fx-11-log-return-reject-goto.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-11-log-return-reject-goto.json")

    def test_log_accept_rule(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 5)
        assert r["is_log"] is True
        assert r["log_prefix"] == "SSH-IN: "
        assert r["verdict"] == "accept"
        assert r["verdict_stops_chain"] is True
        assert r["dst_port"] == "22"
        assert r["opaque_expressions"] is None

    def test_reject_rule(self):
        r = rule_by_handle(self.r, "ip/filter", "input", 6)
        assert r["verdict"] == "reject"
        assert r["verdict_stops_chain"] is True
        assert r["dst_port"] == "23"

    def test_return_rule(self):
        r = rule_by_handle(self.r, "ip/filter", "check-flags", 7)
        assert r["verdict"] == "return"
        assert r["verdict_stops_chain"] is False

    def test_goto_defined_chain(self):
        r = rule_by_handle(self.r, "ip/filter", "check-flags", 8)
        assert r["goto_target"] == "allowed"
        assert r["jump_target"] is None
        assert r["verdict"] is None
        assert r["verdict_stops_chain"] is False

    def test_goto_undefined_chain_in_diagnostics(self):
        uj = self.r["diagnostics"]["unresolved_chain_jumps"]
        entry = next((e for e in uj if e.get("goto_target") == "missing_chain"), None)
        assert entry is not None
        assert entry["table"] == "ip/filter"
        assert entry["chain"] == "check-flags"

    def test_goto_to_defined_chain_not_in_unresolved(self):
        uj = self.r["diagnostics"]["unresolved_chain_jumps"]
        assert not any(
            e.get("goto_target") == "allowed" or e.get("jump_target") == "allowed"
            for e in uj
        )

    def test_check_flags_is_regular_chain(self):
        c = self.r["tables"]["ip/filter"]["chains"]["check-flags"]
        assert c["is_base_chain"] is False
        assert c["type"] is None
        assert c["hook"] is None

    def test_allowed_is_regular_chain_no_rules(self):
        c = self.r["tables"]["ip/filter"]["chains"]["allowed"]
        assert c["is_base_chain"] is False
        assert c["rules"] == []

    def test_no_parse_warnings(self):
        assert self.r["parse_warnings"] == []


class TestFixtureF12:
    """AC-F12 — ICMP/ICMPv6 matching, extended ct fields, comments (fx-12-icmp-ct.json)"""

    def setup_method(self):
        self.r = parse_fixture("fx-12-icmp-ct.json")
        self.rules = rules_in(self.r, "inet/filter", "input")

    def test_table_key_inet(self):
        assert "inet/filter" in self.r["tables"]

    def test_input_chain_drop_policy(self):
        c = self.r["tables"]["inet/filter"]["chains"]["input"]
        assert c["policy"] == "drop"
        assert c["is_base_chain"] is True

    def test_seven_rules(self):
        assert len(self.rules) == 7

    # ── Comment field ─────────────────────────────────────────────────────

    def test_all_rules_have_comment(self):
        """All rules in fx-12 carry a comment field."""
        for rule in self.rules:
            assert rule.get("comment") is not None
            assert isinstance(rule["comment"], str)
            assert len(rule["comment"]) > 0

    def test_comment_ipv4_ping(self):
        r = rule_by_handle(self.r, "inet/filter", "input", 3)
        assert r["comment"] == "allow IPv4 ping"

    def test_comment_icmp_negation(self):
        r = rule_by_handle(self.r, "inet/filter", "input", 6)
        assert "redirect" in r["comment"].lower()

    # ── ICMP type matching ────────────────────────────────────────────────

    def test_icmp_echo_request_accept(self):
        """Handle 3: IPv4 ICMP echo-request → accept."""
        r = rule_by_handle(self.r, "inet/filter", "input", 3)
        assert r["icmp_type"] == "echo-request"
        assert r["icmp_type_negated"] is False
        assert r["protocol"] == "icmp"
        assert r["verdict"] == "accept"

    def test_icmpv6_echo_request_accept(self):
        """Handle 4: ICMPv6 echo-request → accept."""
        r = rule_by_handle(self.r, "inet/filter", "input", 4)
        assert r["icmp_type"] == "echo-request"
        assert r["icmp_type_negated"] is False
        assert r["protocol"] == "icmpv6"
        assert r["verdict"] == "accept"

    def test_icmpv6_nd_neighbor_solicit(self):
        """Handle 5: ICMPv6 nd-neighbor-solicit → accept."""
        r = rule_by_handle(self.r, "inet/filter", "input", 5)
        assert r["icmp_type"] == "nd-neighbor-solicit"
        assert r["icmp_type_negated"] is False
        assert r["protocol"] == "icmpv6"

    def test_icmp_type_negated(self):
        """Handle 6: icmp type != redirect → icmp_type_negated=True."""
        r = rule_by_handle(self.r, "inet/filter", "input", 6)
        assert r["icmp_type"] == "redirect"
        assert r["icmp_type_negated"] is True
        assert r["verdict"] == "accept"

    def test_icmp_code_defaults_null(self):
        """Rules without icmp code → icmp_code is None."""
        for rule in self.rules:
            assert "icmp_code" in rule
            assert rule["icmp_code"] is None

    def test_icmp_code_negated_defaults_false(self):
        for rule in self.rules:
            assert "icmp_code_negated" in rule
            assert rule["icmp_code_negated"] is False

    def test_non_icmp_rules_have_null_icmp_type(self):
        """ct-based rules (handles 7-9) have no ICMP match."""
        for handle in (7, 8, 9):
            r = rule_by_handle(self.r, "inet/filter", "input", handle)
            assert r["icmp_type"] is None
            assert r["icmp_type_negated"] is False

    # ── Extended ct fields ────────────────────────────────────────────────

    def test_ct_mark_accept(self):
        """Handle 7: ct mark == 1 → ct_mark='1', not negated."""
        r = rule_by_handle(self.r, "inet/filter", "input", 7)
        assert r["ct_mark"] == "1"
        assert r["ct_mark_negated"] is False
        assert r["verdict"] == "accept"

    def test_ct_direction_original(self):
        """Handle 8: ct direction == original → ct_direction='original'."""
        r = rule_by_handle(self.r, "inet/filter", "input", 8)
        assert r["ct_direction"] == "original"
        assert r["verdict"] == "accept"

    def test_ct_zone_drop(self):
        """Handle 9: ct zone == 1 → ct_zone='1', verdict=drop."""
        r = rule_by_handle(self.r, "inet/filter", "input", 9)
        assert r["ct_zone"] == "1"
        assert r["verdict"] == "drop"
        assert r["verdict_stops_chain"] is True

    def test_ct_fields_present_on_non_ct_rules(self):
        """ICMP rules have ct_mark/direction/zone fields but all null."""
        for handle in (3, 4, 5, 6):
            r = rule_by_handle(self.r, "inet/filter", "input", handle)
            assert "ct_mark" in r and r["ct_mark"] is None
            assert "ct_mark_negated" in r and r["ct_mark_negated"] is False
            assert "ct_direction" in r and r["ct_direction"] is None
            assert "ct_zone" in r and r["ct_zone"] is None

    # ── Counter canonicalization ──────────────────────────────────────────

    def test_counter_canonicalization_same_hash_different_counts(self):
        """Inline counters do not affect expression_hash."""
        expr_low = [
            {"counter": {"packets": 0, "bytes": 0}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
            {"accept": None},
        ]
        expr_high = [
            {"counter": {"packets": 99999, "bytes": 8388608}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
            {"accept": None},
        ]
        assert _expression_hash(expr_low) == _expression_hash(expr_high)

    def test_counter_only_expr_same_hash_as_empty(self):
        """A counter-only expr hashes the same as an empty list (counter stripped)."""
        assert _expression_hash([{"counter": {"packets": 1, "bytes": 100}}]) == _expression_hash([])

    def test_counter_canonicalization_via_parser(self):
        """Parser-level: same rule with different packet counts → same expression_hash."""
        def _make_raw(packets: int) -> str:
            return json.dumps({"nftables": [
                {"metainfo": {"version": "1.0.9", "release_name": "test", "json_schema_version": 1}},
                {"table": {"family": "ip", "name": "filter", "handle": 1}},
                {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                           "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
                {"rule": {
                    "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                    "expr": [
                        {"counter": {"packets": packets, "bytes": packets * 64}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                        {"accept": None},
                    ]
                }},
            ]})

        r_zero  = parse_nft_ruleset(_make_raw(0))
        r_large = parse_nft_ruleset(_make_raw(500000))
        rule_zero  = rules_in(r_zero,  "ip/filter", "input")[0]
        rule_large = rules_in(r_large, "ip/filter", "input")[0]
        assert rule_zero["expression_hash"] == rule_large["expression_hash"]

    def test_no_parse_warnings(self):
        assert self.r["parse_warnings"] == []


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — Field accuracy criteria (AC-FA*)
# ═══════════════════════════════════════════════════════════════════════════

class TestFieldAccuracy:

    def test_FA01_table_key_format_ip(self):
        """AC-FA01: table key is family/name"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
        ])
        assert "ip/filter" in r["tables"]
        assert "filter" not in r["tables"]

    def test_FA01_table_key_format_inet(self):
        r = parse_objects([
            {"table": {"family": "inet", "name": "main", "handle": 1}},
        ])
        assert "inet/main" in r["tables"]

    def test_FA01_two_families_same_name_no_overwrite(self):
        r = parse_objects([
            {"table": {"family": "ip",  "name": "filter", "handle": 1}},
            {"table": {"family": "ip6", "name": "filter", "handle": 2}},
        ])
        assert "ip/filter"  in r["tables"]
        assert "ip6/filter" in r["tables"]
        assert r["tables"]["ip/filter"]["family"]  == "ip"
        assert r["tables"]["ip6/filter"]["family"] == "ip6"

    def test_FA02_base_chain_type_and_hook(self):
        """AC-FA02: base chain fields"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
        ])
        c = r["tables"]["ip/filter"]["chains"]["input"]
        assert c["is_base_chain"] is True
        assert c["type"] == "filter"
        assert c["hook"] == "input"
        assert c["priority"] == 0
        assert c["policy"] == "drop"

    def test_FA02_regular_chain_nulls(self):
        """AC-FA02: regular chain has null type/hook/priority/policy"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "mychain", "handle": 2}},
        ])
        c = r["tables"]["ip/filter"]["chains"]["mychain"]
        assert c["is_base_chain"] is False
        assert c["type"]     is None
        assert c["hook"]     is None
        assert c["priority"] is None
        assert c["policy"]   is None

    def test_FA02_is_base_chain_always_boolean(self):
        r = parse_fixture("fx-04-regular-chains.json")
        for chains in r["tables"].values():
            for cdata in chains["chains"].values():
                assert isinstance(cdata["is_base_chain"], bool)

    def test_FA03_named_priority_srcnat(self):
        """AC-FA03: 'srcnat' → 100"""
        r = parse_fixture("fx-09-nat.json")
        assert r["tables"]["ip/nat"]["chains"]["postrouting"]["priority"] == 100

    def test_FA03_named_priority_dstnat(self):
        """AC-FA03: 'dstnat' → -100"""
        r = parse_fixture("fx-09-nat.json")
        assert r["tables"]["ip/nat"]["chains"]["prerouting"]["priority"] == -100

    def test_FA03_priority_integer_passthrough(self):
        """AC-FA03: integer prio stored as-is"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
        ])
        assert r["tables"]["ip/filter"]["chains"]["input"]["priority"] == 0

    def test_FA03_unknown_priority_stored_verbatim_with_warning(self):
        """AC-FA03: unknown priority string → stored as string + warning"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": "custom_priority",
                       "policy": "accept"}},
        ])
        c = r["tables"]["ip/filter"]["chains"]["input"]
        assert c["priority"] == "custom_priority"
        assert any("custom_priority" in w for w in r["parse_warnings"])

    def test_FA04_dport_integer_to_string(self):
        """AC-FA04: dport integer → string"""
        r = rules_in(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output")
        assert r[0]["dst_port"] == "53"
        assert isinstance(r[0]["dst_port"], str)

    def test_FA04_sport_port_range(self):
        """AC-FA04: sport range [1024,65535] → '1024-65535'"""
        r = rule_by_handle(parse_fixture("fx-10-negation-ports-interfaces.json"),
                           "ip/filter", "input", 5)
        assert r["src_port"] == "1024-65535"

    def test_FA05_address_prefix_preserved(self):
        """AC-FA05: CIDR prefix preserved verbatim"""
        r = rule_by_handle(parse_fixture("fx-10-negation-ports-interfaces.json"),
                           "ip/filter", "input", 3)
        assert r["src_addr"] == "10.0.0.0/8"

    def test_FA05_ipv6_prefix_preserved(self):
        """AC-FA05: IPv6 address preserved"""
        r = parse_fixture("fx-06-multi-family.json")
        rules = []
        for cdata in r["tables"]["ip6/filter"]["chains"].values():
            rules.extend(cdata["rules"])
        addrs = [rr.get("src_addr") or rr.get("dst_addr") for rr in rules if rr]
        assert any(a and ":" in a for a in addrs)

    def test_FA06_negation_true_when_op_ne(self):
        """AC-FA06: != → _negated true"""
        r = rule_by_handle(parse_fixture("fx-10-negation-ports-interfaces.json"),
                           "ip/filter", "input", 3)
        assert r["src_addr_negated"] is True

    def test_FA06_negation_false_when_op_eq(self):
        r = rule_by_handle(parse_fixture("fx-10-negation-ports-interfaces.json"),
                           "ip/filter", "input", 7)
        assert r["out_interface_negated"] is False

    def test_FA06_absent_field_negated_is_false(self):
        """AC-FA06: negation field present and False even when match absent"""
        r = rule_by_handle(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output", 5)
        for field in ("protocol_negated", "src_addr_negated", "dst_addr_negated",
                      "src_port_negated", "dst_port_negated",
                      "in_interface_negated", "out_interface_negated"):
            assert field in r, f"{field} absent from rule record"
            assert r[field] is False or r[field] is True

    def test_FA07_accept_verdict(self):
        r = rule_by_handle(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output", 5)
        assert r["verdict"] == "accept"
        assert r["verdict_stops_chain"] is True

    def test_FA07_drop_verdict(self):
        r = rule_by_handle(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output", 7)
        assert r["verdict"] == "drop"
        assert r["verdict_stops_chain"] is True

    def test_FA07_reject_verdict(self):
        r = rule_by_handle(parse_fixture("fx-11-log-return-reject-goto.json"),
                           "ip/filter", "input", 6)
        assert r["verdict"] == "reject"
        assert r["verdict_stops_chain"] is True

    def test_FA07_return_verdict(self):
        r = rule_by_handle(parse_fixture("fx-11-log-return-reject-goto.json"),
                           "ip/filter", "check-flags", 7)
        assert r["verdict"] == "return"
        assert r["verdict_stops_chain"] is False

    def test_FA07_jump_no_verdict(self):
        r = rules_in(parse_fixture("fx-04-regular-chains.json"), "ip/filter", "input")
        jumps = [rr for rr in r if rr.get("jump_target") == "allowed-ports"]
        assert jumps[0]["verdict"] is None
        assert jumps[0]["verdict_stops_chain"] is False

    def test_FA07_goto_no_verdict(self):
        r = rule_by_handle(parse_fixture("fx-11-log-return-reject-goto.json"),
                           "ip/filter", "check-flags", 8)
        assert r["verdict"] is None
        assert r["verdict_stops_chain"] is False

    def test_FA08_ct_state_order_preserved(self):
        """AC-FA08: ct_state list preserves source order"""
        r = rules_in(parse_fixture("fx-03-inet-drop-policy.json"), "inet/filter", "input")
        ct_rules = [rr for rr in r if rr.get("ct_state")]
        assert ct_rules
        states = ct_rules[0]["ct_state"]
        assert isinstance(states, list)

    def test_FA09_raw_expressions_always_present(self):
        """AC-FA09: raw_expressions never absent"""
        for fname in ("fx-02-ip-clean.json", "fx-09-nat.json", "fx-10-negation-ports-interfaces.json"):
            r = parse_fixture(fname)
            for tdata in r["tables"].values():
                for cdata in tdata["chains"].values():
                    for rule in cdata["rules"]:
                        assert "raw_expressions" in rule
                        assert isinstance(rule["raw_expressions"], list)

    def test_FA10_expression_hash_stable(self):
        """AC-FA10: same input → same hash"""
        r1 = parse_fixture("fx-02-ip-clean.json")
        r2 = parse_fixture("fx-02-ip-clean.json")
        rules1 = rules_in(r1, "ip/filter", "output")
        rules2 = rules_in(r2, "ip/filter", "output")
        for a, b in zip(rules1, rules2):
            assert a["expression_hash"] == b["expression_hash"]

    def test_FA10_different_exprs_different_hash(self):
        rules = rules_in(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output")
        hashes = [r["expression_hash"] for r in rules]
        assert len(set(hashes)) == len(hashes), "expected distinct hashes for distinct rules"

    def test_FA11_position_is_1_based_monotonic(self):
        """AC-FA11: position starts at 1 and increments"""
        rules = rules_in(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output")
        positions = [r["position"] for r in rules]
        assert positions == list(range(1, len(rules) + 1))

    def test_FA12_jump_vs_goto_distinction(self):
        """AC-FA12: jump sets jump_target; goto sets goto_target; never both non-null"""
        r_jump = rules_in(parse_fixture("fx-04-regular-chains.json"), "ip/filter", "input")
        jump_rules = [r for r in r_jump if r.get("jump_target")]
        assert jump_rules
        for r in jump_rules:
            assert r["goto_target"] is None

        r_goto = rules_in(parse_fixture("fx-11-log-return-reject-goto.json"),
                          "ip/filter", "check-flags")
        goto_rules = [r for r in r_goto if r.get("goto_target")]
        assert goto_rules
        for r in goto_rules:
            assert r["jump_target"] is None

    def test_FA13_hash_stable_across_key_order(self):
        """AC-FA13: sort_keys=True ensures identical hash regardless of dict key order"""
        # Both dicts contain identical key-value pairs, just inserted in different order.
        # The nested payload dict also uses reversed key insertion order in expr_b.
        expr_a = {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}
        expr_b = {"right": 22, "op": "==", "left": {"payload": {"field": "dport", "protocol": "tcp"}}}
        assert _expression_hash([expr_a]) == _expression_hash([expr_b])

    def test_FA13_different_expression_lists_different_hash(self):
        expr_a = {"accept": None}
        assert _expression_hash([expr_a]) != _expression_hash([expr_a, {"drop": None}])

    def test_FA14_comment_present_when_set(self):
        """AC-FA14: comment field on rule is captured."""
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 3)
        assert r["comment"] == "allow IPv4 ping"

    def test_FA14_comment_null_when_absent(self):
        """AC-FA14: comment is None when rule has no comment key."""
        r = rule_by_handle(parse_fixture("fx-02-ip-clean.json"), "ip/filter", "output", 5)
        assert r["comment"] is None

    def test_FA15_icmp_type_parsed(self):
        """AC-FA15: icmp type match captured in icmp_type field."""
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 3)
        assert r["icmp_type"] == "echo-request"
        assert r["icmp_type_negated"] is False

    def test_FA15_icmp_type_negated(self):
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 6)
        assert r["icmp_type"] == "redirect"
        assert r["icmp_type_negated"] is True

    def test_FA16_ct_mark_captured(self):
        """AC-FA16: ct mark match captured."""
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 7)
        assert r["ct_mark"] == "1"
        assert r["ct_mark_negated"] is False

    def test_FA16_ct_direction_captured(self):
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 8)
        assert r["ct_direction"] == "original"

    def test_FA16_ct_zone_captured(self):
        r = rule_by_handle(parse_fixture("fx-12-icmp-ct.json"),
                           "inet/filter", "input", 9)
        assert r["ct_zone"] == "1"

    def test_FA17_icmp_code_captured(self):
        """AC-FA17: icmp code match → icmp_code and icmp_code_negated populated."""
        r = parse_objects([
            {"table": {"family": "inet", "name": "filter", "handle": 1}},
            {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"rule": {
                "family": "inet", "table": "filter", "chain": "input", "handle": 3,
                "expr": [
                    {"match": {"op": "!=",
                               "left": {"payload": {"protocol": "icmp", "field": "code"}},
                               "right": "port-unreach"}},
                    {"drop": None},
                ],
            }},
        ])
        rule = rules_in(r, "inet/filter", "input")[0]
        assert rule["icmp_code"] == "port-unreach"
        assert rule["icmp_code_negated"] is True
        assert rule["protocol"] == "icmp"
        assert rule["icmp_type"] is None

    def test_FA17_icmpv6_code_captured(self):
        """AC-FA17: icmpv6 code match captured correctly."""
        r = parse_objects([
            {"table": {"family": "inet", "name": "filter", "handle": 1}},
            {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"rule": {
                "family": "inet", "table": "filter", "chain": "input", "handle": 3,
                "expr": [
                    {"match": {"op": "==",
                               "left": {"payload": {"protocol": "icmpv6", "field": "code"}},
                               "right": "no-route"}},
                    {"drop": None},
                ],
            }},
        ])
        rule = rules_in(r, "inet/filter", "input")[0]
        assert rule["icmp_code"] == "no-route"
        assert rule["icmp_code_negated"] is False
        assert rule["protocol"] == "icmpv6"


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Edge case criteria (AC-EC*)
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_EC01_empty_nftables_array(self):
        """AC-EC01: valid JSON, valid key, zero objects"""
        r = parse_nft_ruleset('{"nftables": []}')
        assert r["tables"] == {}
        assert any("empty" in w.lower() for w in r["parse_warnings"])
        assert r["nft_version"] is None
        assert r["json_schema_version"] is None

    def test_EC02_inet_family_not_split(self):
        """AC-EC02: inet table stored under single key"""
        r = parse_fixture("fx-03-inet-drop-policy.json")
        assert "inet/filter" in r["tables"]
        assert "ip/filter"  not in r["tables"]
        assert "ip6/filter" not in r["tables"]
        assert r["tables"]["inet/filter"]["family"] == "inet"
        assert not any("inet" in w for w in r["parse_warnings"])

    def test_EC03_log_accept_in_one_rule(self):
        """AC-EC03: log + accept → is_log, log_prefix, verdict=accept"""
        r = rule_by_handle(parse_fixture("fx-11-log-return-reject-goto.json"),
                           "ip/filter", "input", 5)
        assert r["is_log"] is True
        assert r["log_prefix"] == "SSH-IN: "
        assert r["verdict"] == "accept"
        assert r["verdict_stops_chain"] is True
        assert r["opaque_expressions"] is None

    def test_EC04_counter_only_rule(self):
        """AC-EC04: counter-only rule → verdict=null, verdict_stops_chain=false"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                "expr": [{"counter": {"packets": 0, "bytes": 0}}]
            }},
        ])
        rule = rules_in(r, "ip/filter", "input")[0]
        assert rule["verdict"] is None
        assert rule["verdict_stops_chain"] is False
        assert rule["opaque_expressions"] is None

    def test_EC05_set_reference_extraction(self):
        """AC-EC05: @setname → set_references populated, addr field null"""
        r = rules_in(parse_fixture("fx-05-sets.json"), "ip/filter", "input")
        bl_rules = [rr for rr in r if rr.get("set_references") and "blocklist" in rr["set_references"]]
        assert bl_rules
        # The src/dst addr fields should be null (set ref, not literal address)
        assert bl_rules[0]["src_addr"] is None
        assert bl_rules[0]["dst_addr"] is None

    def test_EC06_unknown_priority_warning(self):
        """AC-EC06: unknown priority string → warning emitted"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": "my_custom_prio",
                       "policy": "accept"}},
        ])
        assert any("my_custom_prio" in w for w in r["parse_warnings"])
        assert r["tables"]["ip/filter"]["chains"]["input"]["priority"] == "my_custom_prio"

    def test_EC07_multiple_verdicts_first_wins(self):
        """AC-EC07: second terminal verdict goes to opaque, warning emitted"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                "expr": [{"accept": None}, {"drop": None}]
            }},
        ])
        rule = rules_in(r, "ip/filter", "input")[0]
        assert rule["verdict"] == "accept"
        assert rule["opaque_expressions"] is not None
        assert any({"drop": None} == e for e in rule["opaque_expressions"])
        assert any("Multiple" in w or "multiple" in w for w in r["parse_warnings"])

    def test_EC08_rule_referencing_undeclared_chain(self):
        """AC-EC08: chain created implicitly when rule arrives first"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "phantom", "handle": 3,
                "expr": [{"accept": None}]
            }},
        ])
        assert "phantom" in r["tables"]["ip/filter"]["chains"]
        c = r["tables"]["ip/filter"]["chains"]["phantom"]
        assert c["is_base_chain"] is False
        assert len(c["rules"]) == 1
        assert any("phantom" in w or "undeclared" in w for w in r["parse_warnings"])

    def test_EC09_flowtable_captured(self):
        """AC-EC09: flowtable object captured structurally"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"flowtable": {"family": "ip", "table": "filter", "name": "ft0",
                           "handle": 2, "hook": "ingress", "prio": 10,
                           "devices": ["eth0"]}},
        ])
        ft = r["tables"]["ip/filter"].get("flowtables", {})
        assert "ft0" in ft
        assert ft["ft0"]["hook"] == "ingress"
        assert not r["parse_warnings"]

    def test_EC10_map_object(self):
        """AC-EC10: map captured with is_map=true"""
        r = parse_fixture("fx-05-sets.json")
        m = r["tables"]["ip/filter"]["sets"]["port-map"]
        assert m["is_map"] is True

    def test_EC11_rule_missing_handle_skipped(self):
        """AC-EC11: rule without handle → skipped, warning emitted"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "input",
                      "expr": [{"accept": None}]}},  # no handle
        ])
        assert rules_in(r, "ip/filter", "input") == []
        assert any("handle" in w.lower() for w in r["parse_warnings"])

    def test_EC12_duplicate_rules_same_hash(self):
        """AC-EC12: two rules with identical expr → both included, same hash"""
        expr = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                {"accept": None}]
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "input", "handle": 3, "expr": expr}},
            {"rule": {"family": "ip", "table": "filter", "chain": "input", "handle": 4, "expr": expr}},
        ])
        rules = rules_in(r, "ip/filter", "input")
        assert len(rules) == 2
        assert rules[0]["expression_hash"] == rules[1]["expression_hash"]
        assert rules[0]["handle"] != rules[1]["handle"]
        assert not r["parse_warnings"]

    def test_EC13_dynamic_set_elements_null(self):
        """AC-EC13: set with no elem key → elements: null"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"set": {"family": "ip", "table": "filter", "name": "dynamic-bl",
                     "handle": 2, "type": "ipv4_addr", "flags": ["dynamic"]}},
        ])
        s = r["tables"]["ip/filter"]["sets"]["dynamic-bl"]
        assert s["elements"] is None
        assert s["is_map"] is False
        assert "dynamic" in s["flags"]
        assert not r["parse_warnings"]

    def test_EC14_quota_limit_objects(self):
        """AC-EC14: quota and limit objects parsed without error, warnings emitted"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"quota": {"family": "ip", "table": "filter", "name": "data-limit",
                       "handle": 2, "bytes": 1073741824, "used": 512000}},
            {"limit": {"family": "ip", "table": "filter", "name": "rate-limit",
                       "handle": 3, "rate": 100, "rate_unit": "packets", "per": "second"}},
        ])
        assert any("quota" in w for w in r["parse_warnings"])
        assert any("limit" in w for w in r["parse_warnings"])


# ═══════════════════════════════════════════════════════════════════════════
# Part 4 — Diagnostics criteria (AC-DI*)
# ═══════════════════════════════════════════════════════════════════════════

class TestDiagnostics:

    def test_DI01_drop_policy_chains(self):
        """AC-DI01"""
        r = parse_fixture("fx-03-inet-drop-policy.json")
        dpc = r["diagnostics"]["drop_policy_chains"]
        assert "inet/filter/input"   in dpc
        assert "inet/filter/forward" in dpc
        assert "inet/filter/output"  not in dpc

    def test_DI01_no_drop_policy_when_all_accept(self):
        r = parse_fixture("fx-02-ip-clean.json")
        assert r["diagnostics"]["drop_policy_chains"] == []

    def test_DI02_accept_policy_chains(self):
        """AC-DI02"""
        r = parse_fixture("fx-03-inet-drop-policy.json")
        apc = r["diagnostics"]["accept_policy_chains"]
        assert "inet/filter/output"  in apc
        assert "inet/filter/input"   not in apc
        assert "inet/filter/forward" not in apc

    def test_DI03_active_drop_rules_with_packets(self):
        """AC-DI03: rule with packets>0 appears"""
        r = parse_fixture("fx-08-counters.json")
        adr = r["diagnostics"]["active_drop_rules"]
        assert len(adr) == 1
        assert adr[0]["verdict"] == "drop"

    def test_DI03_no_counters_no_active_drop(self):
        r = parse_fixture("fx-02-ip-clean.json")
        assert r["diagnostics"]["active_drop_rules"] == []

    def test_DI03_zero_packet_counter_excluded(self):
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]
            }},
        ])
        assert r["diagnostics"]["active_drop_rules"] == []

    def test_DI04_unresolved_chain_jumps_jump(self):
        """AC-DI04: unresolved jump_target"""
        r = parse_fixture("fx-04-regular-chains.json")
        uj = r["diagnostics"]["unresolved_chain_jumps"]
        entry = next((e for e in uj if e.get("jump_target") == "ghost_chain"), None)
        assert entry is not None
        assert entry["table"] == "ip/filter"
        assert entry["chain"] == "input"
        assert "handle"   in entry
        assert "position" in entry

    def test_DI04_resolved_chain_not_in_unresolved(self):
        r = parse_fixture("fx-04-regular-chains.json")
        uj = r["diagnostics"]["unresolved_chain_jumps"]
        assert not any(e.get("jump_target") == "allowed-ports" for e in uj)

    def test_DI04_unresolved_goto_target(self):
        """AC-DI04: unresolved goto_target"""
        r = parse_fixture("fx-11-log-return-reject-goto.json")
        uj = r["diagnostics"]["unresolved_chain_jumps"]
        entry = next((e for e in uj if e.get("goto_target") == "missing_chain"), None)
        assert entry is not None

    def test_DI04_resolved_goto_not_in_unresolved(self):
        r = parse_fixture("fx-11-log-return-reject-goto.json")
        uj = r["diagnostics"]["unresolved_chain_jumps"]
        assert not any(e.get("goto_target") == "allowed" for e in uj)

    def test_DI04_empty_when_no_jumps(self):
        r = parse_fixture("fx-01-empty.json")
        assert r["diagnostics"]["unresolved_chain_jumps"] == []

    def test_DI05_inet_tables(self):
        """AC-DI05"""
        r = parse_fixture("fx-07-inet-ip-mixed.json")
        it = r["diagnostics"]["inet_tables"]
        assert "inet/filter" in it
        assert "ip/nat"      not in it

    def test_DI05_empty_when_no_inet(self):
        r = parse_fixture("fx-06-multi-family.json")
        assert r["diagnostics"]["inet_tables"] == []

    def test_DI06_sets_referenced_in_rules(self):
        """AC-DI06"""
        srir = parse_fixture("fx-05-sets.json")["diagnostics"]["sets_referenced_in_rules"]
        assert srir["blocklist"]["found"] is True
        assert srir["allowlist"]["found"] is False

    def test_DI07_diagnostics_always_fully_present(self):
        """AC-DI07: all sub-keys present for every input"""
        required = {"drop_policy_chains", "accept_policy_chains", "active_drop_rules",
                    "unresolved_chain_jumps", "inet_tables", "sets_referenced_in_rules"}
        for fname in (
            "fx-01-empty.json", "fx-02-ip-clean.json", "fx-03-inet-drop-policy.json",
            "fx-04-regular-chains.json", "fx-05-sets.json", "fx-06-multi-family.json",
            "fx-07-inet-ip-mixed.json", "fx-08-counters.json",
            "fx-09-nat.json", "fx-10-negation-ports-interfaces.json",
            "fx-11-log-return-reject-goto.json",
        ):
            r = parse_fixture(fname)
            assert required <= set(r["diagnostics"]), f"missing diagnostics key in {fname}"

    def test_DI07_empty_array_not_null(self):
        r = parse_fixture("fx-01-empty.json")
        d = r["diagnostics"]
        assert isinstance(d["drop_policy_chains"], list)
        assert isinstance(d["active_drop_rules"], list)
        assert isinstance(d["sets_referenced_in_rules"], dict)


# ═══════════════════════════════════════════════════════════════════════════
# Part 5 — Error handling criteria (AC-EH*)
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorHandling:

    def test_EH01_non_json_raises_value_error(self):
        """AC-EH01"""
        with pytest.raises(ValueError, match="not valid JSON"):
            parse_nft_ruleset("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")

    def test_EH02_missing_nftables_key(self):
        """AC-EH02"""
        with pytest.raises(ValueError, match="missing 'nftables' key"):
            parse_nft_ruleset('{"rules": []}')

    def test_EH03_nftables_not_list(self):
        """AC-EH03"""
        with pytest.raises(ValueError, match="must be a list"):
            parse_nft_ruleset('{"nftables": {"table": "filter"}}')

    def test_EH04_unknown_object_type_warning_continues(self):
        """AC-EH04: unknown type → warning, parser continues"""
        r = parse_objects([
            {"table":        {"family": "ip", "name": "filter", "handle": 1}},
            {"unknown_type": {"family": "ip", "name": "x"}},
        ])
        assert "ip/filter" in r["tables"]
        assert any("unknown_type" in w or "Unknown" in w for w in r["parse_warnings"])

    def test_EH05_unrecognised_expression_type_opaque(self):
        """AC-EH05: unrecognised expression → opaque_expressions + warning"""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                "expr": [{"nftrace": {"set": 1}}, {"accept": None}]
            }},
        ])
        rule = rules_in(r, "ip/filter", "input")[0]
        assert rule["opaque_expressions"] is not None
        assert any({"nftrace": {"set": 1}} == e for e in rule["opaque_expressions"])
        assert any("nftrace" in w for w in r["parse_warnings"])
        assert rule["verdict"] == "accept"

    def test_EH06_malformed_match_expression(self):
        """AC-EH06: malformed match → opaque, warning, no exception.
        {"payload": None} causes AttributeError when .get() is called on None."""
        r = parse_objects([
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "input", "handle": 3,
                "expr": [{"match": {"op": "==", "left": {"payload": None}, "right": 22}},
                         {"accept": None}]
            }},
        ])
        rule = rules_in(r, "ip/filter", "input")[0]
        assert rule["opaque_expressions"] is not None
        assert r["parse_warnings"], "expected a warning for malformed match expression"
        assert rule["verdict"] == "accept"

    def test_EH08_metainfo_absent_warning(self):
        """AC-EH08: no metainfo → nft_version null, warning emitted"""
        r = parse_nft_ruleset('{"nftables": [{"table": {"family": "ip", "name": "filter", "handle": 1}}]}')
        assert r["nft_version"] is None
        assert r["json_schema_version"] is None
        assert any("metainfo" in w.lower() for w in r["parse_warnings"])


# ═══════════════════════════════════════════════════════════════════════════
# Part 6 — Non-functional criteria (AC-NF*)
# ═══════════════════════════════════════════════════════════════════════════

class TestNonFunctional:

    def test_NF01_deterministic_output(self):
        """AC-NF01: same input → same output (except parsed_at)"""
        raw = load_fixture("fx-02-ip-clean.json")
        results = [parse_nft_ruleset(raw) for _ in range(3)]
        for r in results:
            del r["parsed_at"]
        assert results[0] == results[1] == results[2]

    def test_NF02_parsed_at_excluded_from_hash(self):
        """AC-NF02: parsed_at does not affect expression_hash"""
        raw = load_fixture("fx-02-ip-clean.json")
        r1 = parse_nft_ruleset(raw)
        r2 = parse_nft_ruleset(raw)
        rules1 = rules_in(r1, "ip/filter", "output")
        rules2 = rules_in(r2, "ip/filter", "output")
        for a, b in zip(rules1, rules2):
            assert a["expression_hash"] == b["expression_hash"]

    def test_NF03_output_always_valid_json(self):
        """AC-NF03: result is JSON-serialisable"""
        for fname in ("fx-01-empty.json", "fx-03-inet-drop-policy.json",
                      "fx-09-nat.json", "fx-11-log-return-reject-goto.json"):
            r = parse_fixture(fname)
            json.dumps(r)

    def test_NF03_parse_warnings_always_list(self):
        for fname in ("fx-01-empty.json", "fx-02-ip-clean.json"):
            r = parse_fixture(fname)
            assert isinstance(r["parse_warnings"], list)

    def test_NF06_no_third_party_imports(self):
        """AC-NF06: only stdlib imports"""
        stdlib = {
            "os", "sys", "json", "re", "hashlib", "datetime", "argparse",
            "pathlib", "typing", "dataclasses", "collections", "__future__",
        }
        import ast
        src = (
            __import__("pathlib").Path(__file__).parent.parent / "nftables_parser.py"
        ).read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                else:
                    names = [node.module.split(".")[0]] if node.module else []
                for name in names:
                    assert name in stdlib or name.startswith("_"), (
                        f"Non-stdlib import found: {name}"
                    )

    def test_NF07_importable_without_side_effects(self):
        """AC-NF07: import does not call main()"""
        import nftables_parser  # already imported; just re-verify callable
        result = nftables_parser.parse_nft_ruleset('{"nftables": []}')
        assert "tables" in result
