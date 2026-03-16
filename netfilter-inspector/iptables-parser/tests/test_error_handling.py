"""
AC-EH01 through AC-EH06: error handling criteria.

All tests use synthetic inputs. Each test verifies that malformed or unusual
input produces a specific parse_warning, does not crash, and still returns
valid output for the well-formed parts of the input.
"""
from parser_helpers import parse


def test_eh01_missing_commit():
    """AC-EH01: Table block without COMMIT → parse_warning, partial results still returned."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
"""
    # No COMMIT line
    d = parse(text)

    assert len(d["parse_warnings"]) >= 1
    warning_text = " ".join(d["parse_warnings"]).lower()
    assert "commit" in warning_text and "filter" in warning_text, (
        f"Expected warning mentioning both 'commit' and 'filter', got: {d['parse_warnings']}"
    )

    # Partial results still present
    assert "filter" in d["tables"]
    assert len(d["tables"]["filter"]["chains"]["INPUT"]["rules"]) == 1


def test_eh01_missing_commit_other_tables_unaffected():
    """AC-EH01: Other tables with valid COMMIT are still fully parsed."""
    text = """\
*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE
COMMIT
"""
    d = parse(text)

    # filter has no COMMIT → warning
    has_commit_warning = any("commit" in w.lower() for w in d["parse_warnings"])
    assert has_commit_warning

    # nat has COMMIT → fully parsed
    assert "nat" in d["tables"]
    assert len(d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"]) == 1


def test_eh02_unknown_target():
    """AC-EH02 (SHOULD): Unknown target → target preserved, conditional traversal, warning."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 8080 -j CUSTOM_TARGET
COMMIT
"""
    d = parse(text)

    rule = d["tables"]["filter"]["chains"]["INPUT"]["rules"][0]
    assert rule["target"] == "CUSTOM_TARGET"
    assert rule["target_stops_chain_traversal"] == "conditional"
    assert rule["raw_rule"] != ""

    # Both a parse_warning AND an unresolved_chain_reference entry must be present
    unresolved = d["diagnostics"]["unresolved_chain_references"]
    assert len(unresolved) >= 1, "Expected unresolved_chain_references entry for unknown target"
    assert unresolved[0]["target_chain"] == "CUSTOM_TARGET"
    assert any("CUSTOM_TARGET" in w for w in d["parse_warnings"]), (
        "Expected parse_warning mentioning CUSTOM_TARGET"
    )


def test_eh03_invalid_chain_policy():
    """AC-EH03: REJECT as chain policy → warning, chain included with default_policy: null."""
    text = """\
*filter
:INPUT REJECT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
    d = parse(text)

    # Warning about the invalid policy
    assert len(d["parse_warnings"]) >= 1
    assert any("REJECT" in w and "INPUT" in w for w in d["parse_warnings"])

    # Chain is present with null policy — not silently skipped
    chains = d["tables"]["filter"]["chains"]
    assert "INPUT" in chains
    assert chains["INPUT"]["default_policy"] is None

    # Rule appended to the chain is accessible
    assert len(chains["INPUT"]["rules"]) == 1
    assert chains["INPUT"]["rules"][0]["target"] == "ACCEPT"

    # Other chains parsed normally
    assert chains["FORWARD"]["default_policy"] == "DROP"
    assert chains["OUTPUT"]["default_policy"] == "ACCEPT"


def test_eh04_unresolved_chain_reference():
    """AC-EH04 (SHOULD): Jump to undeclared chain → unresolved_chain_references + warning."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j UNDEFINED_CHAIN
COMMIT
"""
    d = parse(text)

    unresolved = d["diagnostics"]["unresolved_chain_references"]
    assert len(unresolved) >= 1
    entry = unresolved[0]
    assert entry["target_chain"] == "UNDEFINED_CHAIN"
    assert entry["referenced_from"]["table"] == "filter"
    assert entry["referenced_from"]["chain"] == "INPUT"

    # Warning recorded too
    assert any("UNDEFINED_CHAIN" in w for w in d["parse_warnings"])

    # Rule still in output
    rule = d["tables"]["filter"]["chains"]["INPUT"]["rules"][0]
    assert rule["target"] == "UNDEFINED_CHAIN"
    assert rule["target_stops_chain_traversal"] == "conditional"


def test_eh05_malformed_rule_missing_j():
    """AC-EH05: Rule line without -j → clear 'no -j target' warning, raw_rule preserved."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80
-A INPUT -i lo -j ACCEPT
COMMIT
"""
    d = parse(text)

    # Warning specifically about missing -j target
    warnings = d["parse_warnings"]
    assert len(warnings) >= 1
    malformed_warning = next(
        (w for w in warnings if "no -j target" in w or "malformed" in w.lower()), None
    )
    assert malformed_warning is not None, (
        f"Expected 'no -j target' warning, got: {warnings}"
    )

    # Parser continues — the valid rule is still parsed
    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    valid_rules = [r for r in rules if r["target"] == "ACCEPT"]
    assert len(valid_rules) == 1

    # Malformed rule record is present in output with raw_rule preserved
    assert len(rules) == 2, f"Expected 2 rules (malformed + valid), got {len(rules)}"
    malformed = next(r for r in rules if r["target"] == "")
    assert malformed["raw_rule"] != "", "raw_rule must be preserved on malformed rule"
    assert "-A INPUT -p tcp --dport 80" in malformed["raw_rule"]


def test_eh06_inconsistent_counter_prefixes():
    """AC-EH06: Mixed counter/no-counter rules in same chain → parse_warning per chain."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
[5:300] -A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
    d = parse(text)

    # Warning about inconsistent prefixes
    assert len(d["parse_warnings"]) >= 1
    assert any("inconsistent" in w.lower() for w in d["parse_warnings"])
    # input_format is set to counters because at least one rule has a counter prefix
    assert d["input_format"] == "iptables-save-counters"

    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    assert len(rules) == 2

    # Rule with counter prefix: packet_count and byte_count are integers
    counter_rule = next(r for r in rules if r["packet_count"] is not None)
    assert counter_rule["packet_count"] == 5
    assert counter_rule["byte_count"] == 300

    # Rule without counter prefix: null
    no_counter_rule = next(r for r in rules if r["packet_count"] is None)
    assert no_counter_rule["byte_count"] is None
