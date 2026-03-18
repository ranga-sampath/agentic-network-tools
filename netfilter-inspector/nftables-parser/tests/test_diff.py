"""
Diff engine tests — nftables_diff.py

Covers: AC-D01 through AC-D32
"""
from __future__ import annotations

import copy
import json

import pytest

from helpers import parse_fixture, parse_objects, assert_summary_matches_lists
from nftables_diff import diff_rulesets, summary_diff


# ── helpers ───────────────────────────────────────────────────────────────

def _clean_parsed():
    """Return two independent copies of a clean ip/filter parse."""
    return parse_fixture("fx-02-ip-clean.json"), parse_fixture("fx-02-ip-clean.json")


def _empty_parsed():
    return parse_fixture("fx-01-empty.json"), parse_fixture("fx-01-empty.json")


def _make_fake_rule(table, chain, handle, verdict="accept", position=1, expr=None):
    """Build a minimal rule record compatible with diff_rulesets."""
    import hashlib, json as _json
    raw = expr or [{"accept": None}]
    h = hashlib.sha256(_json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {
        "table": table, "chain": chain, "handle": handle, "position": position,
        "protocol": None, "protocol_negated": False,
        "src_addr": None, "src_addr_negated": False,
        "dst_addr": None, "dst_addr_negated": False,
        "src_port": None, "src_port_negated": False,
        "dst_port": None, "dst_port_negated": False,
        "in_interface": None, "in_interface_negated": False,
        "out_interface": None, "out_interface_negated": False,
        "ct_state": None,
        "verdict": verdict, "verdict_stops_chain": verdict in ("accept", "drop", "reject"),
        "jump_target": None, "goto_target": None,
        "opaque_expressions": None, "set_references": None,
        "raw_expressions": raw,
        "expression_hash": h,
        "is_log": False, "log_prefix": None, "counters": None,
    }


def _add_rule(parsed: dict, table_key: str, chain_name: str, rule: dict) -> dict:
    d = copy.deepcopy(parsed)
    d["tables"][table_key]["chains"][chain_name]["rules"].append(rule)
    return d


def _remove_rule(parsed: dict, table_key: str, chain_name: str, handle: int) -> dict:
    d = copy.deepcopy(parsed)
    d["tables"][table_key]["chains"][chain_name]["rules"] = [
        r for r in d["tables"][table_key]["chains"][chain_name]["rules"]
        if r["handle"] != handle
    ]
    return d


def _set_policy(parsed: dict, table_key: str, chain_name: str, policy: str) -> dict:
    d = copy.deepcopy(parsed)
    d["tables"][table_key]["chains"][chain_name]["policy"] = policy
    return d


# ═══════════════════════════════════════════════════════════════════════════
# Basic drift detection
# ═══════════════════════════════════════════════════════════════════════════

def test_D01_identical_no_drift():
    """AC-D01"""
    baseline, current = _clean_parsed()
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is False
    assert d["has_critical_changes"] is False
    for lst in d["changes"].values():
        assert lst == [] or lst == {}, f"expected empty change list"
    assert_summary_matches_lists(d)


def test_D02_rule_added():
    """AC-D02"""
    baseline, current = _clean_parsed()
    new_rule = _make_fake_rule("ip/filter", "output", handle=99, verdict="accept", position=4)
    current = _add_rule(current, "ip/filter", "output", new_rule)
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert len(d["changes"]["rules_added"]) == 1
    assert d["changes"]["rules_added"][0]["handle"] == 99
    assert d["changes"]["rules_removed"] == []
    assert d["changes"]["rules_recreated"] == []
    assert_summary_matches_lists(d)


def test_D03_rule_removed():
    """AC-D03"""
    baseline, current = _clean_parsed()
    current = _remove_rule(current, "ip/filter", "output", 5)
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert len(d["changes"]["rules_removed"]) == 1
    assert d["changes"]["rules_removed"][0]["handle"] == 5
    assert d["changes"]["rules_added"] == []
    assert d["changes"]["rules_recreated"] == []
    assert_summary_matches_lists(d)


def test_D04_rule_repositioned():
    """AC-D04: same handle + hash, different position"""
    baseline, current = _clean_parsed()
    current["tables"]["ip/filter"]["chains"]["output"]["rules"][0]["position"] = 99
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    repos = d["changes"]["rules_repositioned"]
    assert len(repos) == 1
    entry = repos[0]
    assert entry["handle"] == 5
    assert entry["baseline_position"] == 1
    assert entry["current_position"] == 99
    # Check identity fields present; non-identity fields absent
    assert "expression_hash" in entry["rule"]
    assert "handle"   not in entry["rule"]
    assert "position" not in entry["rule"]
    assert d["changes"]["rules_added"]   == []
    assert d["changes"]["rules_removed"] == []
    assert_summary_matches_lists(d)


def test_D05_rule_recreated():
    """AC-D05: same hash, new handle → rules_recreated"""
    baseline, current = _clean_parsed()
    # Remove handle 5 from current; add same content with handle 50
    orig = baseline["tables"]["ip/filter"]["chains"]["output"]["rules"][0]
    new_rule = copy.deepcopy(orig)
    new_rule["handle"] = 50
    current = _remove_rule(current, "ip/filter", "output", 5)
    current = _add_rule(current, "ip/filter", "output", new_rule)
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert d["summary"]["rules_recreated"] == 1
    assert d["summary"]["rules_added"]   == 0
    assert d["summary"]["rules_removed"] == 0
    rec = d["changes"]["rules_recreated"][0]
    assert rec["baseline_rule"]["handle"] == 5
    assert rec["current_rule"]["handle"]  == 50
    assert "note" in rec
    assert_summary_matches_lists(d)


def test_D06_recreated_drop_rule_is_critical():
    """AC-D06: DROP recreation → has_critical_changes=true"""
    baseline, current = _clean_parsed()
    drop_rule = _make_fake_rule("ip/filter", "output", 99, verdict="drop", position=4)
    b_with_drop = _add_rule(baseline, "ip/filter", "output", drop_rule)

    new_drop = copy.deepcopy(drop_rule)
    new_drop["handle"] = 100
    c_with_drop = _remove_rule(copy.deepcopy(b_with_drop), "ip/filter", "output", 99)
    c_with_drop = _add_rule(c_with_drop, "ip/filter", "output", new_drop)

    d = diff_rulesets(b_with_drop, c_with_drop)
    assert d["changes"]["rules_recreated"]
    assert d["has_critical_changes"] is True
    assert d["drift_detected"] is True


def test_D07_recreated_accept_rule_not_critical():
    """AC-D07: ACCEPT recreation → has_critical_changes=false"""
    baseline, current = _clean_parsed()
    orig = baseline["tables"]["ip/filter"]["chains"]["output"]["rules"][0]
    new_rule = copy.deepcopy(orig)
    new_rule["handle"] = 50
    current = _remove_rule(current, "ip/filter", "output", 5)
    current = _add_rule(current, "ip/filter", "output", new_rule)
    d = diff_rulesets(baseline, current)
    assert d["changes"]["rules_recreated"]
    assert d["has_critical_changes"] is False


def test_D08_chain_added_no_double_counting():
    """AC-D08: new chain → chains_added, rules NOT in rules_added"""
    baseline, current = _clean_parsed()
    current["tables"]["ip/filter"]["chains"]["new-chain"] = {
        "name": "new-chain", "handle": 99, "is_base_chain": False,
        "type": None, "hook": None, "priority": None, "policy": None,
        "rules": [_make_fake_rule("ip/filter", "new-chain", 100), _make_fake_rule("ip/filter", "new-chain", 101, position=2)],
    }
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    added = d["changes"]["chains_added"]
    assert any(e["chain"] == "new-chain" for e in added)
    entry = next(e for e in added if e["chain"] == "new-chain")
    assert entry["table"] == "ip/filter"
    assert entry["is_base_chain"] is False
    assert entry["rule_count"] == 2
    # Rules of new-chain must NOT be in rules_added
    assert not any(r["chain"] == "new-chain" for r in d["changes"]["rules_added"])
    assert_summary_matches_lists(d)


def test_D09_chain_removed_no_double_counting():
    """AC-D09: removed chain rules not in rules_removed"""
    baseline, current = _clean_parsed()
    # Add a chain to baseline that isn't in current
    baseline["tables"]["ip/filter"]["chains"]["old-chain"] = {
        "name": "old-chain", "handle": 99, "is_base_chain": False,
        "type": None, "hook": None, "priority": None, "policy": None,
        "rules": [_make_fake_rule("ip/filter", "old-chain", 100)],
    }
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    removed = d["changes"]["chains_removed"]
    assert any(e["chain"] == "old-chain" for e in removed)
    assert not any(r["chain"] == "old-chain" for r in d["changes"]["rules_removed"])
    assert_summary_matches_lists(d)


def test_D10_table_added():
    """AC-D10: new table → tables_added, chains in chains_added, no rules in rules_added"""
    baseline, current = _clean_parsed()
    current["tables"]["ip/nat"] = {
        "family": "ip", "name": "nat", "handle": 99,
        "chains": {
            "prerouting": {
                "name": "prerouting", "handle": 100, "is_base_chain": True,
                "type": "nat", "hook": "prerouting", "priority": -100, "policy": "accept",
                "rules": [_make_fake_rule("ip/nat", "prerouting", 101)],
            }
        },
        "sets": {},
    }
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert "ip/nat" in d["changes"]["tables_added"]
    assert any(e["table"] == "ip/nat" for e in d["changes"]["chains_added"])
    assert not any(r.get("table") == "ip/nat" for r in d["changes"]["rules_added"])
    assert_summary_matches_lists(d)


def test_D11_table_removed():
    """AC-D11"""
    baseline, current = _clean_parsed()
    baseline["tables"]["ip/nat"] = {
        "family": "ip", "name": "nat", "handle": 99,
        "chains": {
            "prerouting": {
                "name": "prerouting", "handle": 100, "is_base_chain": True,
                "type": "nat", "hook": "prerouting", "priority": -100, "policy": "accept",
                "rules": [],
            }
        },
        "sets": {},
    }
    d = diff_rulesets(baseline, current)
    assert "ip/nat" in d["changes"]["tables_removed"]
    assert not any(r.get("table") == "ip/nat" for r in d["changes"]["rules_removed"])
    assert_summary_matches_lists(d)


def test_D12_policy_accept_to_drop_critical():
    """AC-D12"""
    baseline, current = _clean_parsed()
    current = _set_policy(current, "ip/filter", "input", "drop")
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert d["has_critical_changes"] is True
    pc = d["changes"]["policy_changes"]
    entry = next(e for e in pc if e["chain"] == "input")
    assert entry["baseline_policy"] == "accept"
    assert entry["current_policy"]  == "drop"
    assert_summary_matches_lists(d)


def test_D13_policy_drop_to_accept_not_critical():
    """AC-D13"""
    baseline = parse_fixture("fx-03-inet-drop-policy.json")
    current  = copy.deepcopy(baseline)
    current["tables"]["inet/filter"]["chains"]["input"]["policy"] = "accept"
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert d["has_critical_changes"] is False
    assert_summary_matches_lists(d)


def test_D14_drop_rule_added_critical():
    """AC-D14"""
    baseline, current = _clean_parsed()
    drop_rule = _make_fake_rule("ip/filter", "output", 99, verdict="drop", position=4)
    current = _add_rule(current, "ip/filter", "output", drop_rule)
    d = diff_rulesets(baseline, current)
    assert d["has_critical_changes"] is True
    assert d["changes"]["rules_added"][0]["verdict"] == "drop"


def test_D15_reject_rule_removed_critical():
    """AC-D15"""
    baseline, current = _clean_parsed()
    reject_rule = _make_fake_rule("ip/filter", "output", 99, verdict="reject", position=4)
    reject_rule["raw_expressions"] = [{"reject": {"type": "icmpx", "expr": "port-unreach"}}]
    import hashlib, json as _j
    reject_rule["expression_hash"] = hashlib.sha256(
        _j.dumps(reject_rule["raw_expressions"], sort_keys=True, separators=(',',':')).encode()
    ).hexdigest()
    b = _add_rule(baseline, "ip/filter", "output", reject_rule)
    d = diff_rulesets(b, current)
    assert d["has_critical_changes"] is True
    assert d["changes"]["rules_removed"]


def test_D16_log_rule_repositioned_not_critical():
    """AC-D16"""
    baseline, current = _clean_parsed()
    log_rule = _make_fake_rule("ip/filter", "output", 98, verdict=None, position=1)
    log_rule["is_log"] = True
    log_rule["raw_expressions"] = [{"log": {"prefix": "TEST: "}}]
    import hashlib, json as _j
    log_rule["expression_hash"] = hashlib.sha256(
        _j.dumps(log_rule["raw_expressions"], sort_keys=True, separators=(',',':')).encode()
    ).hexdigest()
    b = _add_rule(baseline, "ip/filter", "output", log_rule)
    c = copy.deepcopy(b)
    c["tables"]["ip/filter"]["chains"]["output"]["rules"][-1]["position"] = 5
    d = diff_rulesets(b, c)
    assert d["drift_detected"] is True
    assert d["has_critical_changes"] is False
    assert d["changes"]["rules_repositioned"]
    assert_summary_matches_lists(d)


def test_D17_cross_format_raises():
    """AC-D17"""
    baseline = {"input_format": "iptables-save", "tables": {}}
    current  = {"input_format": "nft-json",      "tables": {}}
    with pytest.raises(ValueError, match="iptables-save"):
        diff_rulesets(baseline, current)


def test_D18_both_inputs_must_be_nft_json():
    """AC-D18"""
    b = {"input_format": "nft-json",       "tables": {}}
    c = {"input_format": "ip6tables-save", "tables": {}}
    with pytest.raises(ValueError):
        diff_rulesets(b, c)


def test_D19_invalid_input_missing_tables():
    """AC-D19"""
    with pytest.raises(ValueError, match="missing"):
        diff_rulesets({"input_format": "nft-json"}, {"input_format": "nft-json", "tables": {}})

    with pytest.raises(ValueError, match="dict"):
        diff_rulesets("not a dict", {"input_format": "nft-json", "tables": {}})


def test_D20_both_empty_no_drift():
    """AC-D20"""
    b, c = _empty_parsed()
    d = diff_rulesets(b, c)
    assert d["drift_detected"] is False
    assert d["has_critical_changes"] is False
    assert_summary_matches_lists(d)


def test_D21_empty_baseline_non_empty_current():
    """AC-D21: all current tables in tables_added, no double-counting"""
    baseline = parse_fixture("fx-01-empty.json")
    current  = parse_fixture("fx-02-ip-clean.json")
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert "ip/filter" in d["changes"]["tables_added"]
    assert d["changes"]["rules_added"] == []
    assert_summary_matches_lists(d)


def test_D22_schema_version_mismatch_warning():
    """AC-D22"""
    baseline, current = _clean_parsed()
    baseline["json_schema_version"] = 1
    current["json_schema_version"]  = 2
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is False
    assert any("json_schema_version" in w for w in d["current_parse_warnings"])
    assert d["has_critical_changes"] is False


def test_D23_summary_counts_match_lists_multiple_scenarios():
    """AC-D23: always true across many inputs"""
    baseline, current = _clean_parsed()
    scenarios = [
        diff_rulesets(baseline, current),
        diff_rulesets(parse_fixture("fx-01-empty.json"), parse_fixture("fx-02-ip-clean.json")),
        diff_rulesets(parse_fixture("fx-03-inet-drop-policy.json"), parse_fixture("fx-03-inet-drop-policy.json")),
    ]
    for d in scenarios:
        assert_summary_matches_lists(d)


def test_D24_parse_warnings_passed_through():
    """AC-D24: current warnings in output; drift_detected not set by warning alone"""
    baseline, current = _clean_parsed()
    current["parse_warnings"] = ["Unknown object at index 3"]
    d = diff_rulesets(baseline, current)
    assert "Unknown object at index 3" in d["current_parse_warnings"]
    assert d["drift_detected"] is False


def test_D25_output_has_all_top_level_keys():
    """AC-D25"""
    baseline, current = _clean_parsed()
    d = diff_rulesets(baseline, current)
    required = {
        "diff_at", "input_format", "baseline_parsed_at", "current_parsed_at",
        "baseline_parse_warnings", "current_parse_warnings",
        "drift_detected", "has_critical_changes", "summary", "changes",
    }
    assert required <= set(d.keys())
    assert d["input_format"] == "nft-json"

    changes_required = {
        "tables_added", "tables_removed", "chains_added", "chains_removed",
        "policy_changes", "rules_added", "rules_removed",
        "rules_repositioned", "rules_recreated",
    }
    assert changes_required <= set(d["changes"].keys())

    from datetime import datetime
    datetime.fromisoformat(d["diff_at"].replace("Z", "+00:00"))
    json.dumps(d)


def test_D26_inet_table_drift():
    """AC-D26: inet table diffed correctly"""
    baseline = parse_fixture("fx-03-inet-drop-policy.json")
    current  = copy.deepcopy(baseline)
    current["tables"]["inet/filter"]["chains"]["input"]["policy"] = "drop"
    # already drop, change to accept to trigger a policy change
    current["tables"]["inet/filter"]["chains"]["output"]["policy"] = "drop"
    d = diff_rulesets(baseline, current)
    assert d["input_format"] == "nft-json"
    assert d["changes"]["policy_changes"]
    pc = next(e for e in d["changes"]["policy_changes"] if e["chain"] == "output")
    assert pc["table"] == "inet/filter"
    assert d["has_critical_changes"] is True


def test_D27_duplicate_handles_in_chain_raises():
    """AC-D27"""
    baseline, current = _clean_parsed()
    # Inject a duplicate handle into current
    dup = copy.deepcopy(current["tables"]["ip/filter"]["chains"]["output"]["rules"][0])
    current["tables"]["ip/filter"]["chains"]["output"]["rules"].append(dup)
    with pytest.raises(ValueError):
        diff_rulesets(baseline, current)


def test_D28_same_handle_different_hash_warning_and_remove_add():
    """AC-D28"""
    baseline, current = _clean_parsed()
    # Mutate expression_hash of handle 5 in current (simulates malformed input)
    current["tables"]["ip/filter"]["chains"]["output"]["rules"][0]["expression_hash"] = "a" * 64
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    handles_removed = {r["handle"] for r in d["changes"]["rules_removed"]}
    handles_added   = {r["handle"] for r in d["changes"]["rules_added"]}
    assert 5 in handles_removed
    assert 5 in handles_added
    assert not any(
        e["baseline_rule"]["handle"] == 5 for e in d["changes"]["rules_recreated"]
    )
    assert any("expression_hash" in w or "hash" in w for w in d["current_parse_warnings"])


def test_D29_chain_priority_change_in_policy_changes():
    """AC-D29"""
    baseline, current = _clean_parsed()
    current["tables"]["ip/filter"]["chains"]["input"]["priority"] = -100
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    pc = d["changes"]["policy_changes"]
    entry = next((e for e in pc if e["chain"] == "input" and "priority" in str(e)), None)
    assert entry is not None
    assert "note" in entry
    assert d["has_critical_changes"] is False  # priority change alone not critical
    assert_summary_matches_lists(d)


def test_D30_chain_type_change_in_policy_changes():
    """AC-D30"""
    baseline, current = _clean_parsed()
    current["tables"]["ip/filter"]["chains"]["input"]["type"] = "nat"
    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    pc = d["changes"]["policy_changes"]
    entry = next(
        (e for e in pc if e["chain"] == "input" and "current_type" in e),
        None
    )
    assert entry is not None, f"expected type-change entry in policy_changes, got: {pc}"
    assert "note" in entry
    assert entry["baseline_type"] == "filter"
    assert entry["current_type"]  == "nat"
    assert_summary_matches_lists(d)


def test_D31_relational_parser_to_diff_end_to_end():
    """AC-D31: inputs produced entirely by parse_nft_ruleset()"""
    import json as _json
    # Load and parse the clean fixture
    baseline = parse_fixture("fx-02-ip-clean.json")

    # Construct a modified version with an extra DROP rule
    raw = _json.loads(open(
        __import__("pathlib").Path(__file__).parent.parent / "nftables-samples" / "fx-02-ip-clean.json"
    ).read())
    raw["nftables"].append({
        "rule": {
            "family": "ip", "table": "filter", "chain": "output", "handle": 99,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                           "right": "10.0.0.1"}},
                {"drop": None}
            ]
        }
    })
    from nftables_parser import parse_nft_ruleset
    current = parse_nft_ruleset(_json.dumps(raw))

    d = diff_rulesets(baseline, current)
    assert d["drift_detected"] is True
    assert d["has_critical_changes"] is True
    assert len(d["changes"]["rules_added"]) == 1
    added = d["changes"]["rules_added"][0]
    assert added["handle"] == 99
    assert added["verdict"] == "drop"
    assert added["table"]  == "ip/filter"
    assert added["chain"]  == "output"
    assert len(added["expression_hash"]) == 64
    assert d["changes"]["rules_removed"] == []
    assert_summary_matches_lists(d)


def test_D32_change_lists_sorted_deterministically():
    """AC-D32"""
    baseline = parse_fixture("fx-01-empty.json")
    # Build a current with rules in two tables, two chains each
    current = copy.deepcopy(baseline)
    for tname, family in [("filter", "ip"), ("nat", "ip")]:
        tkey = f"ip/{tname}"
        current["tables"][tkey] = {"family": family, "name": tname, "handle": 1, "chains": {}, "sets": {}}
        for cname, hook, h_offset in [("forward", "forward", 0), ("input", "input", 10)]:
            current["tables"][tkey]["chains"][cname] = {
                "name": cname, "handle": h_offset + 2, "is_base_chain": True,
                "type": "filter", "hook": hook, "priority": 0, "policy": "accept",
                "rules": [
                    _make_fake_rule(tkey, cname, h_offset + 3, position=1),
                    _make_fake_rule(tkey, cname, h_offset + 4, position=2,
                                    expr=[{"match": {"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"accept":None}]),
                ],
            }

    d = diff_rulesets(baseline, current)
    added = d["changes"]["rules_added"]
    # All rules from tables_added chains are NOT in rules_added (no double-counting)
    assert added == []
    # chains_added should be sorted by (table, chain)
    chain_keys = [(e["table"], e["chain"]) for e in d["changes"]["chains_added"]]
    assert chain_keys == sorted(chain_keys)


def test_D33_counter_canonicalization_enables_recreation_detection():
    """AC-D33: rules with same non-counter expressions but different counter values
    are identified as rules_recreated when handles differ."""
    import hashlib, json as _j

    exprs_low  = [
        {"counter": {"packets": 0,     "bytes": 0}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
        {"accept": None},
    ]
    exprs_high = [
        {"counter": {"packets": 50000, "bytes": 3200000}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
        {"accept": None},
    ]

    # Reproduce counter-stripping hash logic: strip counter dicts before hashing
    def _strip_hash(exprs):
        canonical = [e for e in exprs if not (isinstance(e, dict) and "counter" in e)]
        return hashlib.sha256(
            _j.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest()

    h = _strip_hash(exprs_low)
    assert h == _strip_hash(exprs_high), "pre-condition: both exprs must hash the same"

    def _counter_rule(handle, exprs, position=4):
        return {
            "table": "ip/filter", "chain": "output",
            "handle": handle, "position": position,
            "comment": None,
            "protocol": "tcp", "protocol_negated": False,
            "src_addr": None, "src_addr_negated": False,
            "dst_addr": None, "dst_addr_negated": False,
            "src_port": None, "src_port_negated": False,
            "dst_port": "22",  "dst_port_negated": False,
            "in_interface": None, "in_interface_negated": False,
            "out_interface": None, "out_interface_negated": False,
            "ct_state": None,
            "icmp_type": None, "icmp_type_negated": False,
            "icmp_code": None, "icmp_code_negated": False,
            "ct_mark": None, "ct_mark_negated": False,
            "ct_direction": None, "ct_zone": None,
            "verdict": "accept", "verdict_stops_chain": True,
            "jump_target": None, "goto_target": None,
            "opaque_expressions": None, "set_references": None,
            "raw_expressions": exprs,
            "expression_hash": h,
            "is_log": False, "log_prefix": None, "counters": None,
        }

    baseline, current = _clean_parsed()
    b = _add_rule(baseline, "ip/filter", "output", _counter_rule(88, exprs_low))
    c = _add_rule(current,  "ip/filter", "output", _counter_rule(89, exprs_high))

    d = diff_rulesets(b, c)
    assert d["summary"]["rules_recreated"] == 1
    assert d["summary"]["rules_added"]     == 0
    assert d["summary"]["rules_removed"]   == 0
    rec = d["changes"]["rules_recreated"][0]
    assert rec["baseline_rule"]["handle"] == 88
    assert rec["current_rule"]["handle"]  == 89
    assert_summary_matches_lists(d)


def test_D34_comment_in_repositioned_rule_identity():
    """AC-D34: comment field appears in repositioned rule's identity sub-dict."""
    import hashlib, json as _j

    expr = [{"accept": None}]
    h = hashlib.sha256(
        _j.dumps(expr, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()

    rule_b = {
        "table": "ip/filter", "chain": "output",
        "handle": 88, "position": 4,
        "comment": "my-rule-comment",
        "protocol": None, "protocol_negated": False,
        "src_addr": None, "src_addr_negated": False,
        "dst_addr": None, "dst_addr_negated": False,
        "src_port": None, "src_port_negated": False,
        "dst_port": None, "dst_port_negated": False,
        "in_interface": None, "in_interface_negated": False,
        "out_interface": None, "out_interface_negated": False,
        "ct_state": None,
        "icmp_type": None, "icmp_type_negated": False,
        "icmp_code": None, "icmp_code_negated": False,
        "ct_mark": None, "ct_mark_negated": False,
        "ct_direction": None, "ct_zone": None,
        "verdict": "accept", "verdict_stops_chain": True,
        "jump_target": None, "goto_target": None,
        "opaque_expressions": None, "set_references": None,
        "raw_expressions": expr,
        "expression_hash": h,
        "is_log": False, "log_prefix": None, "counters": None,
    }
    rule_c = copy.deepcopy(rule_b)
    rule_c["position"] = 9  # repositioned

    baseline, current = _clean_parsed()
    b = _add_rule(baseline, "ip/filter", "output", rule_b)
    c = _add_rule(current,  "ip/filter", "output", rule_c)

    d = diff_rulesets(b, c)
    repos = d["changes"]["rules_repositioned"]
    entry = next(e for e in repos if e["handle"] == 88)
    assert entry["rule"].get("comment") == "my-rule-comment"
    assert_summary_matches_lists(d)


# ═══════════════════════════════════════════════════════════════════════════
# summary_diff()
# ═══════════════════════════════════════════════════════════════════════════

class TestSummaryDiff:

    def test_EX01_no_drift_returns_single_line(self):
        """No drift → output is 'No drift detected.'"""
        baseline, current = _clean_parsed()
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "No drift detected." in out
        assert "Rules Added" not in out
        assert "Rules Removed" not in out

    def test_EX02_drift_header_present(self):
        baseline, current = _clean_parsed()
        current = _set_policy(current, "ip/filter", "input", "accept")  # no real change
        new_rule = _make_fake_rule("ip/filter", "output", 99, verdict="accept", position=4)
        current = _add_rule(current, "ip/filter", "output", new_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "Drift detected." in out
        assert "nftables Ruleset Diff" in out

    def test_EX03_critical_policy_change_labelled(self):
        """Policy accept → drop emits CRITICAL label."""
        baseline, current = _clean_parsed()
        current = _set_policy(current, "ip/filter", "input", "drop")
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "CRITICAL" in out
        assert "Policy Changes" in out
        assert "accept" in out
        assert "drop" in out

    def test_EX04_drop_rule_added_labelled_critical(self):
        """Added DROP rule → section header and rule line both note CRITICAL."""
        baseline, current = _clean_parsed()
        drop_rule = _make_fake_rule("ip/filter", "output", 99, verdict="drop", position=4)
        current = _add_rule(current, "ip/filter", "output", drop_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "CRITICAL" in out
        assert "Rules Added" in out
        assert "drop" in out

    def test_EX05_accept_rule_added_not_critical(self):
        """Added ACCEPT rule → no CRITICAL label."""
        baseline, current = _clean_parsed()
        new_rule = _make_fake_rule("ip/filter", "output", 99, verdict="accept", position=4)
        current = _add_rule(current, "ip/filter", "output", new_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "CRITICAL" not in out
        assert "Rules Added" in out

    def test_EX06_removed_drop_rule_labelled_critical(self):
        """Removed DROP rule → CRITICAL in output."""
        baseline, current = _clean_parsed()
        drop_rule = _make_fake_rule("ip/filter", "output", 99, verdict="drop", position=4)
        b = _add_rule(baseline, "ip/filter", "output", drop_rule)
        d = diff_rulesets(b, current)
        out = summary_diff(d)
        assert "CRITICAL" in out
        assert "Rules Removed" in out

    def test_EX07_recreated_section_present(self):
        """rules_recreated → dedicated section in output."""
        baseline, current = _clean_parsed()
        orig = baseline["tables"]["ip/filter"]["chains"]["output"]["rules"][0]
        new_rule = copy.deepcopy(orig)
        new_rule["handle"] = 50
        current = _remove_rule(current, "ip/filter", "output", 5)
        current = _add_rule(current, "ip/filter", "output", new_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "Rules Recreated" in out
        # old and new handles referenced
        assert "5" in out
        assert "50" in out

    def test_EX08_verbose_includes_full_dict(self):
        """verbose=True includes raw JSON for each changed rule."""
        baseline, current = _clean_parsed()
        new_rule = _make_fake_rule("ip/filter", "output", 99, verdict="accept", position=4)
        current = _add_rule(current, "ip/filter", "output", new_rule)
        d = diff_rulesets(baseline, current)
        out_default = summary_diff(d, verbose=False)
        out_verbose = summary_diff(d, verbose=True)
        # verbose output contains raw JSON fields not in default
        assert "expression_hash" in out_verbose
        assert "expression_hash" not in out_default

    def test_EX09_parse_warnings_appended(self):
        """Parse warnings appear at the bottom of the output."""
        baseline, current = _clean_parsed()
        current["parse_warnings"] = ["Unrecognised object at index 5"]
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "Unrecognised object at index 5" in out
        assert "Current Parse Warnings" in out

    def test_EX10_output_is_string_no_bare_braces(self):
        """Output is a string; no raw Python dict repr ({...}) from accidental str()."""
        baseline, current = _clean_parsed()
        drop_rule = _make_fake_rule("ip/filter", "output", 99, verdict="drop", position=4)
        current = _add_rule(current, "ip/filter", "output", drop_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert isinstance(out, str)
        # repr of a dict starts with { — ensure we're not leaking raw dicts
        import re
        assert not re.search(r"(?<!\[)`?\{['\"]", out), "raw dict repr found in output"

    def test_EX11_summary_table_only_nonzero_rows(self):
        """Summary table omits zero-count rows."""
        baseline, current = _clean_parsed()
        new_rule = _make_fake_rule("ip/filter", "output", 99, verdict="accept", position=4)
        current = _add_rule(current, "ip/filter", "output", new_rule)
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        # Only "Rules added" row should appear (count=1); tables/chains rows omitted
        assert "| Rules added" in out or "| Rules Added" in out or "rules_added" in out.lower()
        assert "| 0 " not in out

    def test_EX12_priority_change_rendered(self):
        """Priority change in policy_changes → enforcement order note in output."""
        baseline, current = _clean_parsed()
        current["tables"]["ip/filter"]["chains"]["input"]["priority"] = -100
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "Policy Changes" in out
        assert "priority" in out
        assert "enforcement order affected" in out

    def test_EX13_type_change_rendered(self):
        """Chain type change → both old and new type names appear in Policy Changes."""
        baseline, current = _clean_parsed()
        current["tables"]["ip/filter"]["chains"]["input"]["type"] = "nat"
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "Policy Changes" in out
        assert "filter" in out
        assert "nat" in out

    def test_EX14_no_drift_with_warnings_shows_warnings(self):
        """No drift + parse warnings → 'No drift detected.' AND warnings section."""
        baseline, current = _clean_parsed()
        current["parse_warnings"] = ["Unknown object at index 9"]
        d = diff_rulesets(baseline, current)
        out = summary_diff(d)
        assert "No drift detected." in out
        assert "Unknown object at index 9" in out
        assert "Current Parse Warnings" in out
