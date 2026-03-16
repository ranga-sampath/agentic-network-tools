"""
Tests for iptables_diff.py — AC-D01 through AC-D25.

All tests use synthetic inputs (inline rule strings) so the condition
under test is unambiguous and independent of fixture files.
"""
import json
import pytest

from conftest import parse
from iptables_diff import diff_rulesets, _RULE_IDENTITY_FIELDS


# ---------------------------------------------------------------------------
# AC-D01 — Identical inputs produce no drift
# ---------------------------------------------------------------------------

def test_d01_identical_no_drift():
    """Same ruleset as both baseline and current → drift_detected false, all lists empty."""
    rs = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(rs, rs)
    assert result["drift_detected"] is False
    assert result["has_critical_changes"] is False
    changes = result["changes"]
    for key in ("tables_added", "tables_removed", "chains_added", "chains_removed",
                "policy_changes", "rules_added", "rules_removed", "rules_repositioned"):
        assert changes[key] == [], f"Expected {key} to be empty"
    summary = result["summary"]
    for key in summary:
        assert summary[key] == 0, f"Expected summary[{key}] to be 0"


# ---------------------------------------------------------------------------
# AC-D02 — Rule added to existing chain
# ---------------------------------------------------------------------------

def test_d02_rule_added():
    """N+1 rules in current → new rule in rules_added; absent from removed and repositioned."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert len(result["changes"]["rules_added"]) == 1
    assert result["changes"]["rules_added"][0]["dst_port"] == "80"
    assert result["changes"]["rules_removed"] == []
    assert result["changes"]["rules_repositioned"] == []


# ---------------------------------------------------------------------------
# AC-D03 — Rule removed from existing chain
# ---------------------------------------------------------------------------

def test_d03_rule_removed():
    """N-1 rules in current → removed rule in rules_removed; absent from added and repositioned."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert len(result["changes"]["rules_removed"]) == 1
    assert result["changes"]["rules_removed"][0]["dst_port"] == "80"
    assert result["changes"]["rules_added"] == []
    assert result["changes"]["rules_repositioned"] == []


# ---------------------------------------------------------------------------
# AC-D04 — Rule repositioned within chain
# ---------------------------------------------------------------------------

def test_d04_rule_repositioned():
    """Two rules swap order → both in rules_repositioned; absent from added and removed."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["changes"]["rules_added"] == []
    assert result["changes"]["rules_removed"] == []
    repos = result["changes"]["rules_repositioned"]
    assert len(repos) == 2
    port22 = next(r for r in repos if r["rule"]["dst_port"] == "22")
    assert port22["baseline_position"] == 1
    assert port22["current_position"] == 2


# ---------------------------------------------------------------------------
# AC-D05 — Chain added to existing table
# ---------------------------------------------------------------------------

def test_d05_chain_added():
    """New user-defined chain in current → in chains_added with correct fields; its rules NOT in rules_added."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        ":MY-CHAIN - [0:0]\n"
        "-A MY-CHAIN -p tcp --dport 22 -j ACCEPT\n"
        "-A MY-CHAIN -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    chains_added = result["changes"]["chains_added"]
    assert len(chains_added) == 1
    c = chains_added[0]
    assert c["table"] == "filter"
    assert c["chain"] == "MY-CHAIN"
    assert c["type"] == "user-defined"
    assert c["rule_count"] == 2
    # No double-counting: rules in MY-CHAIN must not appear in rules_added
    assert result["changes"]["rules_added"] == []


# ---------------------------------------------------------------------------
# AC-D06 — Chain removed from existing table
# ---------------------------------------------------------------------------

def test_d06_chain_removed():
    """User-defined chain absent from current → in chains_removed; its rules NOT in rules_removed."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        ":MY-CHAIN - [0:0]\n"
        "-A MY-CHAIN -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    chains_removed = result["changes"]["chains_removed"]
    assert len(chains_removed) == 1
    assert chains_removed[0]["chain"] == "MY-CHAIN"
    assert chains_removed[0]["rule_count"] == 1
    # No double-counting
    assert result["changes"]["rules_removed"] == []


# ---------------------------------------------------------------------------
# AC-D07 — Entire table added
# ---------------------------------------------------------------------------

def test_d07_table_added():
    """nat table appears in current → in tables_added; all its chains in chains_added; no rules_added."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        "*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "-A PREROUTING -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert "nat" in result["changes"]["tables_added"]
    nat_chains = [c for c in result["changes"]["chains_added"] if c["table"] == "nat"]
    chain_names = {c["chain"] for c in nat_chains}
    assert "PREROUTING" in chain_names
    assert "OUTPUT" in chain_names
    # No double-counting
    assert result["changes"]["rules_added"] == []


# ---------------------------------------------------------------------------
# AC-D08 — Entire table removed
# ---------------------------------------------------------------------------

def test_d08_table_removed():
    """nat table absent from current → in tables_removed; all its chains in chains_removed; no rules_removed."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        "*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "-A PREROUTING -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert "nat" in result["changes"]["tables_removed"]
    nat_chains = [c for c in result["changes"]["chains_removed"] if c["table"] == "nat"]
    chain_names = {c["chain"] for c in nat_chains}
    assert "PREROUTING" in chain_names
    assert "OUTPUT" in chain_names
    # No double-counting
    assert result["changes"]["rules_removed"] == []


# ---------------------------------------------------------------------------
# AC-D09 — Chain default policy changed
# ---------------------------------------------------------------------------

def test_d09_policy_changed():
    """ACCEPT → DROP on filter/INPUT → entry in policy_changes with correct before/after values."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    pc = result["changes"]["policy_changes"]
    assert len(pc) == 1
    assert pc[0]["table"] == "filter"
    assert pc[0]["chain"] == "INPUT"
    assert pc[0]["baseline_policy"] == "ACCEPT"
    assert pc[0]["current_policy"] == "DROP"


# ---------------------------------------------------------------------------
# AC-D10 — Counter-only changes produce no drift
# ---------------------------------------------------------------------------

def test_d10_counter_only_no_drift():
    """Per-rule counters differ between baseline and current; rule content identical → no drift."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "[5:500] -A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "[9999:9999999] -A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is False
    for key in ("rules_added", "rules_removed", "rules_repositioned", "policy_changes"):
        assert result["changes"][key] == []


# ---------------------------------------------------------------------------
# AC-D11 — Counters file vs non-counters file, same rules
# ---------------------------------------------------------------------------

def test_d11_counters_vs_no_counters_no_drift():
    """iptables-save (packet_count null) vs iptables-save-counters (non-null) → no drift."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "[0:0] -A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    assert baseline["input_format"] == "iptables-save"
    assert current["input_format"] == "iptables-save-counters"
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is False
    assert result["changes"]["rules_added"] == []
    assert result["changes"]["rules_removed"] == []


# ---------------------------------------------------------------------------
# AC-D12 — DROP rule added → has_critical_changes
# ---------------------------------------------------------------------------

def test_d12_drop_rule_added_critical():
    """New -j DROP rule in current → rules_added contains it, has_critical_changes true."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 23 -j DROP\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is True
    assert len(result["changes"]["rules_added"]) == 1
    assert result["changes"]["rules_added"][0]["target"] == "DROP"


# ---------------------------------------------------------------------------
# AC-D13 — REJECT rule removed → has_critical_changes
# ---------------------------------------------------------------------------

def test_d13_reject_rule_removed_critical():
    """A -j REJECT rule removed → rules_removed contains it, has_critical_changes true."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 23 -j REJECT\n"
        "COMMIT\n"
    )
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is True
    assert len(result["changes"]["rules_removed"]) == 1
    assert result["changes"]["rules_removed"][0]["target"] == "REJECT"


# ---------------------------------------------------------------------------
# AC-D14 — Policy changed ACCEPT → DROP → has_critical_changes
# ---------------------------------------------------------------------------

def test_d14_policy_change_critical():
    """filter/INPUT policy ACCEPT → DROP → has_critical_changes true."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["has_critical_changes"] is True
    assert len(result["changes"]["policy_changes"]) == 1


# ---------------------------------------------------------------------------
# AC-D15 — Only a LOG rule repositioned → has_critical_changes: false
# ---------------------------------------------------------------------------

def test_d15_log_repositioned_not_critical():
    """LOG rule moves position; no other changes → drift true, has_critical_changes false."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -j LOG\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -j LOG\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is False
    assert len(result["changes"]["rules_repositioned"]) == 2
    assert result["changes"]["rules_added"] == []
    assert result["changes"]["rules_removed"] == []


# ---------------------------------------------------------------------------
# has_critical_changes — chains_added / chains_removed containing DROP or REJECT
# (Gap exposed by M1 review finding — not covered by AC-D12..D15)
# ---------------------------------------------------------------------------

def test_chain_added_with_drop_triggers_critical():
    """Chain added to existing table with DROP rule → has_critical_changes true; no rules_added."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        ":BLOCK-LIST - [0:0]\n"
        "-A BLOCK-LIST -s 10.0.0.0/8 -j DROP\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is True
    assert len(result["changes"]["chains_added"]) == 1
    # No double-counting — DROP rule must not appear in rules_added
    assert result["changes"]["rules_added"] == []


def test_chain_removed_with_reject_triggers_critical():
    """Chain removed from existing table with REJECT rule → has_critical_changes true; no rules_removed."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        ":ALLOW-LIST - [0:0]\n"
        "-A ALLOW-LIST -s 192.168.0.0/24 -j REJECT\n"
        "COMMIT\n"
    )
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is True
    assert len(result["changes"]["chains_removed"]) == 1
    # No double-counting
    assert result["changes"]["rules_removed"] == []


# ---------------------------------------------------------------------------
# AC-D16 — Duplicate rules: one copy removed
# ---------------------------------------------------------------------------

def test_d16_duplicate_one_removed():
    """baseline: 2 identical LOG rules; current: 1 → exactly one in rules_removed; remaining not flagged."""
    log_rule = "-A INPUT -j LOG"
    baseline = parse(f"*filter\n:INPUT ACCEPT [0:0]\n{log_rule}\n{log_rule}\nCOMMIT\n")
    current = parse(f"*filter\n:INPUT ACCEPT [0:0]\n{log_rule}\nCOMMIT\n")
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert len(result["changes"]["rules_removed"]) == 1
    assert result["changes"]["rules_removed"][0]["target"] == "LOG"
    assert result["changes"]["rules_added"] == []
    assert result["changes"]["rules_repositioned"] == []


# ---------------------------------------------------------------------------
# AC-D17 — Duplicate rules: both repositioned
# ---------------------------------------------------------------------------

def test_d17_duplicates_both_repositioned():
    """2 identical LOG rules at positions 1,2 in baseline → positions 2,3 in current (new rule at pos 1); both in rules_repositioned."""
    log_rule = "-A INPUT -j LOG"
    baseline = parse(
        f"*filter\n:INPUT ACCEPT [0:0]\n"
        f"{log_rule}\n{log_rule}\n"
        "COMMIT\n"
    )
    current = parse(
        f"*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        f"{log_rule}\n{log_rule}\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    # tcp rule is newly added
    assert len(result["changes"]["rules_added"]) == 1
    assert result["changes"]["rules_added"][0]["dst_port"] == "22"
    # Both LOG rules are repositioned (1→2, 2→3), not added or removed
    repos = result["changes"]["rules_repositioned"]
    assert len(repos) == 2
    positions = sorted((r["baseline_position"], r["current_position"]) for r in repos)
    assert positions[0] == (1, 2)
    assert positions[1] == (2, 3)
    # No LOG rules in added or removed
    assert result["changes"]["rules_removed"] == []
    log_repos = [r for r in result["changes"]["rules_added"] if r["target"] == "LOG"]
    assert log_repos == []


# ---------------------------------------------------------------------------
# AC-D18 — Cross-family inputs rejected
# ---------------------------------------------------------------------------

def test_d18_cross_family_rejected():
    """baseline ipv4, current ipv6 → ValueError naming both families."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", family="ipv4")
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", family="ipv6")
    with pytest.raises(ValueError, match="ipv4") as exc_info:
        diff_rulesets(baseline, current)
    assert "ipv6" in str(exc_info.value)


# ---------------------------------------------------------------------------
# AC-D19 — Invalid input rejected
# ---------------------------------------------------------------------------

def test_d19_invalid_input_missing_tables():
    """Dict missing 'tables' key → ValueError; message identifies which input is invalid."""
    valid = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    invalid = {"family": "ipv4"}  # missing 'tables'
    with pytest.raises(ValueError, match="baseline"):
        diff_rulesets(invalid, valid)
    with pytest.raises(ValueError, match="current"):
        diff_rulesets(valid, invalid)


def test_d19_invalid_input_missing_family():
    """Dict missing 'family' key → ValueError."""
    valid = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    invalid = {"tables": {}}  # missing 'family'
    with pytest.raises(ValueError):
        diff_rulesets(invalid, valid)


# ---------------------------------------------------------------------------
# AC-D20 — Summary counts always match change list lengths
# ---------------------------------------------------------------------------

def test_d20_summary_matches_change_list_lengths():
    """For a diff with multiple change types, every summary count equals its change list length."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT DROP [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    summary = result["summary"]
    changes = result["changes"]
    for key in ("tables_added", "tables_removed", "chains_added", "chains_removed",
                "policy_changes", "rules_added", "rules_removed", "rules_repositioned"):
        assert summary[key] == len(changes[key]), (
            f"summary[{key}]={summary[key]} != len(changes[{key}])={len(changes[key])}"
        )


def test_d20_summary_matches_with_table_addition():
    """Summary count consistency holds for non-zero tables_added and chains_added counts."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        "*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    summary = result["summary"]
    changes = result["changes"]
    for key in ("tables_added", "tables_removed", "chains_added", "chains_removed",
                "policy_changes", "rules_added", "rules_removed", "rules_repositioned"):
        assert summary[key] == len(changes[key]), (
            f"summary[{key}]={summary[key]} != len(changes[{key}])={len(changes[key])}"
        )
    assert summary["tables_added"] == 1
    assert summary["chains_added"] == 2


# ---------------------------------------------------------------------------
# AC-D21 — parse_warnings passed through; does not affect drift
# ---------------------------------------------------------------------------

def test_d21_parse_warnings_passthrough():
    """current has parse_warnings; drift_detected reflects only rule/chain/policy changes, not warnings."""
    baseline = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current = parse("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    current["parse_warnings"] = ["Table 'filter' block ended without COMMIT"]
    result = diff_rulesets(baseline, current)
    assert result["current_parse_warnings"] == ["Table 'filter' block ended without COMMIT"]
    assert result["baseline_parse_warnings"] == []
    # Identical rule content → no drift despite the warning
    assert result["drift_detected"] is False


# ---------------------------------------------------------------------------
# AC-D22 — Empty baseline, non-empty current
# ---------------------------------------------------------------------------

def test_d22_empty_baseline():
    """baseline is empty ruleset (tables: {}); all current tables in tables_added; rules_added empty."""
    baseline = {"family": "ipv4", "tables": {}, "parsed_at": None, "parse_warnings": []}
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert result["drift_detected"] is True
    assert "filter" in result["changes"]["tables_added"]
    chains_added = result["changes"]["chains_added"]
    added_names = {c["chain"] for c in chains_added if c["table"] == "filter"}
    assert added_names == {"INPUT", "FORWARD", "OUTPUT"}
    # No double-counting
    assert result["changes"]["rules_added"] == []


# ---------------------------------------------------------------------------
# AC-D23 — IPv6 diff
# ---------------------------------------------------------------------------

def test_d23_ipv6_diff():
    """Two IPv6 rulesets, one rule difference → family ipv6, ::1/128 preserved verbatim in identity."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT ! -d ::1/128 -j ACCEPT\n"
        "COMMIT\n",
        family="ipv6",
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT ! -d ::1/128 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n",
        family="ipv6",
    )
    result = diff_rulesets(baseline, current)
    assert result["family"] == "ipv6"
    assert result["drift_detected"] is True
    # Only the new tcp rule is added; the ::1/128 rule is unchanged
    added = result["changes"]["rules_added"]
    assert len(added) == 1
    assert added[0]["dst_port"] == "22"
    # ::1/128 rule not in any change list
    v6_in_added = [r for r in result["changes"]["rules_added"] if r.get("destination") == "::1/128"]
    assert v6_in_added == []


# ---------------------------------------------------------------------------
# AC-D24 — rules_repositioned rule sub-object contains only identity fields
# ---------------------------------------------------------------------------

def test_d24_repositioned_rule_has_only_identity_fields():
    """rule sub-object in every rules_repositioned entry contains exactly _RULE_IDENTITY_FIELDS."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -j LOG\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -j LOG\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    assert len(result["changes"]["rules_repositioned"]) > 0
    expected_fields = set(_RULE_IDENTITY_FIELDS)
    for entry in result["changes"]["rules_repositioned"]:
        rule = entry["rule"]
        assert set(rule.keys()) == expected_fields, (
            f"Unexpected keys in rule sub-object: {set(rule.keys()) ^ expected_fields}"
        )
        for absent in ("position", "packet_count", "byte_count", "raw_rule",
                       "target_stops_chain_traversal"):
            assert absent not in rule, f"'{absent}' must not appear in repositioned rule sub-object"


# ---------------------------------------------------------------------------
# AC-D25 — Output is always valid JSON
# ---------------------------------------------------------------------------

def test_d25_output_is_valid_json():
    """diff_rulesets result serialises to JSON and round-trips cleanly; all top-level keys present."""
    baseline = parse(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    current = parse(
        "*filter\n:INPUT DROP [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -j DROP\n"
        "COMMIT\n"
    )
    result = diff_rulesets(baseline, current)
    serialised = json.dumps(result)
    deserialised = json.loads(serialised)
    required_keys = (
        "diff_at", "family", "baseline_parsed_at", "current_parsed_at",
        "baseline_parse_warnings", "current_parse_warnings",
        "drift_detected", "has_critical_changes", "summary", "changes",
    )
    for key in required_keys:
        assert key in deserialised, f"Missing top-level key: {key}"
    # Verify parsed_at values are taken from the correct input dict, not swapped or fabricated
    assert result["baseline_parsed_at"] == baseline.get("parsed_at")
    assert result["current_parsed_at"] == current.get("parsed_at")
