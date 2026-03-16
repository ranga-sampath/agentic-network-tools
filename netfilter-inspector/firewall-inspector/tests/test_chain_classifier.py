"""
Tests for chain_classifier.py (Module 6)

Coverage:
  CC-01 to CC-06   classify_chain() — tier assignment
  CC-07            classify_chain() — ephemeral checked before structural
  CC-08 to CC-09   classify_chain() — user-defined default
  CC-10 to CC-14   classify_diff() — ephemeral rule suppression
  CC-15 to CC-16   classify_diff() — user-defined and structural rules preserved
  CC-17            classify_diff() — summary counts updated after suppression
  CC-18            classify_diff() — input dict not mutated
  CC-19            classify_diff() — chain_classifications key present
  CC-20            classify_diff() — ephemeral_summary counts correct
  CC-21            classify_diff() — policy_changes for ephemeral chain NOT suppressed
  CC-22            extensibility: classify_chain honours new patterns without code change
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import chain_classifier as cc
from chain_classifier import classify_chain, classify_diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(table: str = "filter", chain: str = "INPUT", position: int = 1, target: str = "ACCEPT") -> dict:
    return {
        "table": table, "chain": chain, "position": position,
        "target": target, "protocol": None, "protocol_negated": False,
        "source": None, "source_negated": False,
        "destination": None, "destination_negated": False,
        "in_interface": None, "in_interface_negated": False,
        "out_interface": None, "out_interface_negated": False,
        "dst_port": None, "dst_port_negated": False,
        "src_port": None, "src_port_negated": False,
        "target_params": None, "match_extensions": [], "opaque_extensions": [],
        "packet_count": 0, "byte_count": 0, "raw_rule": "",
        "target_stops_chain_traversal": True,
    }


def _empty_diff() -> dict:
    return {
        "drift_detected": False,
        "has_critical_changes": False,
        "summary": {
            "tables_added": 0, "tables_removed": 0,
            "chains_added": 0, "chains_removed": 0,
            "policy_changes": 0, "rules_added": 0,
            "rules_removed": 0, "rules_repositioned": 0,
        },
        "changes": {
            "tables_added": [], "tables_removed": [],
            "chains_added": [], "chains_removed": [],
            "policy_changes": [],
            "rules_added": [], "rules_removed": [], "rules_repositioned": [],
        },
    }


# ---------------------------------------------------------------------------
# CC-01 to CC-09: classify_chain()
# ---------------------------------------------------------------------------

def test_cc01_kube_sep_is_ephemeral():
    assert classify_chain("KUBE-SEP-ABCD1234") == "ephemeral"


def test_cc02_kube_svc_is_ephemeral():
    assert classify_chain("KUBE-SVC-XYZ") == "ephemeral"


def test_cc03_kube_fw_is_ephemeral():
    assert classify_chain("KUBE-FW-SOMEID") == "ephemeral"


def test_cc04_docker_is_structural():
    assert classify_chain("DOCKER") == "structural"


def test_cc05_f2b_chain_is_structural():
    assert classify_chain("f2b-sshd") == "structural"


def test_cc06_ufw_chain_is_structural():
    assert classify_chain("ufw-before-input") == "structural"


def test_cc07_ephemeral_wins_over_structural_if_prefix_matches_both():
    """If a chain matches both lists, ephemeral (checked first) takes priority."""
    import re
    # Temporarily add a structural pattern that would also match KUBE-SEP-*
    original = cc._STRUCTURAL_PATTERNS[:]
    cc._STRUCTURAL_PATTERNS.append(re.compile(r"^KUBE-"))
    try:
        assert classify_chain("KUBE-SEP-XXXX") == "ephemeral"
    finally:
        cc._STRUCTURAL_PATTERNS[:] = original


def test_cc08_input_is_user_defined():
    assert classify_chain("INPUT") == "user-defined"


def test_cc09_custom_chain_is_user_defined():
    assert classify_chain("BLOCK-LIST") == "user-defined"


# ---------------------------------------------------------------------------
# CC-10 to CC-14: classify_diff() — ephemeral suppression
# ---------------------------------------------------------------------------

def test_cc10_ephemeral_rules_added_suppressed():
    """rules_added entries for ephemeral chains are removed from changes."""
    d = _empty_diff()
    d["changes"]["rules_added"] = [_make_rule(chain="KUBE-SEP-XXXX", target="DNAT")]
    d["summary"]["rules_added"] = 1
    d["drift_detected"] = True
    result = classify_diff(d)
    assert result["changes"]["rules_added"] == []
    assert result["summary"]["rules_added"] == 0


def test_cc11_ephemeral_rules_removed_suppressed():
    d = _empty_diff()
    d["changes"]["rules_removed"] = [_make_rule(chain="KUBE-SVC-ABC", target="ACCEPT")]
    d["summary"]["rules_removed"] = 1
    d["drift_detected"] = True
    result = classify_diff(d)
    assert result["changes"]["rules_removed"] == []
    assert result["summary"]["rules_removed"] == 0


def test_cc12_ephemeral_rules_repositioned_suppressed():
    d = _empty_diff()
    d["changes"]["rules_repositioned"] = [{
        "table": "filter", "chain": "KUBE-SEP-XXXX",
        "baseline_position": 1, "current_position": 2,
        "rule": _make_rule(chain="KUBE-SEP-XXXX"),
    }]
    d["summary"]["rules_repositioned"] = 1
    result = classify_diff(d)
    assert result["changes"]["rules_repositioned"] == []
    assert result["summary"]["rules_repositioned"] == 0


def test_cc13_mixed_diff_only_ephemeral_suppressed():
    """Non-ephemeral rules in the same diff are not suppressed."""
    d = _empty_diff()
    d["changes"]["rules_added"] = [
        _make_rule(chain="KUBE-SEP-XXXX", target="DNAT"),   # ephemeral → suppressed
        _make_rule(chain="INPUT",         target="DROP"),    # user-defined → kept
    ]
    d["summary"]["rules_added"] = 2
    d["drift_detected"] = True
    result = classify_diff(d)
    assert len(result["changes"]["rules_added"]) == 1
    assert result["changes"]["rules_added"][0]["chain"] == "INPUT"
    assert result["summary"]["rules_added"] == 1


def test_cc18_input_dict_not_mutated():
    """classify_diff() must not modify its input argument."""
    d = _empty_diff()
    d["changes"]["rules_added"] = [_make_rule(chain="KUBE-SEP-XXXX")]
    import copy
    original = copy.deepcopy(d)
    classify_diff(d)
    assert d == original


# ---------------------------------------------------------------------------
# CC-15 to CC-16: user-defined and structural preserved
# ---------------------------------------------------------------------------

def test_cc15_user_defined_rules_not_suppressed():
    d = _empty_diff()
    d["changes"]["rules_added"] = [_make_rule(chain="INPUT", target="DROP")]
    d["summary"]["rules_added"] = 1
    result = classify_diff(d)
    assert len(result["changes"]["rules_added"]) == 1


def test_cc16_structural_rules_not_suppressed():
    d = _empty_diff()
    d["changes"]["rules_added"] = [_make_rule(chain="DOCKER", target="ACCEPT")]
    d["summary"]["rules_added"] = 1
    result = classify_diff(d)
    assert len(result["changes"]["rules_added"]) == 1


# ---------------------------------------------------------------------------
# CC-17: summary updated after suppression
# ---------------------------------------------------------------------------

def test_cc17_summary_counts_match_filtered_lists():
    """After classify_diff(), all summary counts match len(changes[key])."""
    d = _empty_diff()
    d["changes"]["rules_added"] = [
        _make_rule(chain="KUBE-SEP-1"),
        _make_rule(chain="KUBE-SEP-2"),
        _make_rule(chain="INPUT"),
    ]
    d["summary"]["rules_added"] = 3
    result = classify_diff(d)
    assert result["summary"]["rules_added"] == len(result["changes"]["rules_added"])


# ---------------------------------------------------------------------------
# CC-19: chain_classifications key present
# ---------------------------------------------------------------------------

def test_cc19_chain_classifications_key_present():
    d = _empty_diff()
    d["changes"]["rules_added"] = [
        _make_rule(chain="INPUT"),
        _make_rule(chain="KUBE-SEP-XXXX"),
        _make_rule(chain="DOCKER"),
    ]
    result = classify_diff(d)
    cc_map = result["chain_classifications"]
    assert cc_map["INPUT"]        == "user-defined"
    assert cc_map["KUBE-SEP-XXXX"] == "ephemeral"
    assert cc_map["DOCKER"]       == "structural"


# ---------------------------------------------------------------------------
# CC-20: ephemeral_summary counts
# ---------------------------------------------------------------------------

def test_cc20_ephemeral_summary_counts():
    """ephemeral_summary records correct added/removed counts per ephemeral chain."""
    d = _empty_diff()
    d["changes"]["rules_added"]   = [_make_rule(chain="KUBE-SEP-A"), _make_rule(chain="KUBE-SEP-A")]
    d["changes"]["rules_removed"] = [_make_rule(chain="KUBE-SEP-B")]
    result = classify_diff(d)
    summary = result["ephemeral_summary"]
    assert summary["KUBE-SEP-A"]["current_rule_count"]  == 2
    assert summary["KUBE-SEP-B"]["baseline_rule_count"] == 1


# ---------------------------------------------------------------------------
# CC-21: policy changes for ephemeral chains are NOT suppressed
# ---------------------------------------------------------------------------

def test_cc21_policy_changes_not_suppressed_for_ephemeral():
    """Policy changes apply to any chain — even ephemeral — and must not be suppressed."""
    d = _empty_diff()
    d["changes"]["policy_changes"] = [{
        "table": "filter", "chain": "KUBE-SEP-XXXX",
        "baseline_policy": "ACCEPT", "current_policy": "DROP",
    }]
    d["summary"]["policy_changes"] = 1
    result = classify_diff(d)
    assert len(result["changes"]["policy_changes"]) == 1


# ---------------------------------------------------------------------------
# CC-22: extensibility — new structural pattern
# ---------------------------------------------------------------------------

def test_cc22_new_pattern_added_without_code_change():
    """Adding a pattern to _STRUCTURAL_PATTERNS is sufficient to classify new chains."""
    import re
    original = cc._STRUCTURAL_PATTERNS[:]
    cc._STRUCTURAL_PATTERNS.append(re.compile(r"^tun-vpn-"))
    try:
        assert classify_chain("tun-vpn-client0") == "structural"
        assert classify_chain("INPUT")           == "user-defined"  # unchanged
    finally:
        cc._STRUCTURAL_PATTERNS[:] = original
