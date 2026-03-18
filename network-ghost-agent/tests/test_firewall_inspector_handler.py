"""
test_firewall_inspector_handler.py — Layer 3 integration tests for
_run_firewall_inspector_handler() in ghost_agent.py.

What these tests verify
-----------------------
The handler reads a drift JSON artifact produced by firewall_inspector.py,
routes field extraction on family == "nft" vs iptables, and builds a
condensed result for the Brain to consume.

Mock boundary
-------------
subprocess.run is mocked for all compare-mode tests. The mock's side_effect
writes a synthetic drift artifact to audit_dir so the handler's mtime-based
file discovery returns the expected file. This isolates the handler's data-
processing logic from the SSH/probe pipeline already covered by E2E tests.

Test IDs
--------
GA-NF01  nftables rules_added → nftables field names in condensed output
GA-NF02  nftables rules_added → iptables field names absent from condensed output
GA-NF03  iptables rules_added → iptables field names in condensed output
GA-NF04  iptables rules_added → nftables field names absent from condensed output
GA-NF05  top-level drift_detected=True when nft family has drift
GA-NF06  top-level drift_detected=False when no drift in any family
GA-NF07  top-level has_critical_changes=True when nft family critical
GA-NF08  family with "error" key excluded from top-level flag computation
GA-NF09  mixed nft+ipv4 families → correct field routing per family
GA-NF10  policy_changes/chains_added/chains_removed forwarded correctly
GA-NF11  baseline mode → status="success", mode="baseline", session_id returned
GA-NF12  neither is_baseline nor compare_session_id → error, no subprocess call
GA-NF13  rules_added absent from fam_result when rules list is empty
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# conftest.py has already stubbed google.genai / safe_exec_shell / cloud_orchestrator
# and imported ghost_agent — importing it here is safe.
import ghost_agent
from ghost_agent import _run_firewall_inspector_handler


# ===========================================================================
# Shared fixtures
# ===========================================================================

@pytest.fixture()
def ghost_cfg(tmp_path):
    """Minimal ghost_cfg dict pointing at tmp_path as AUDIT_DIR."""
    return {
        "AUDIT_DIR":        str(tmp_path),
        "FW_TARGET_VM_IP":  "192.168.2.7",
        "FW_SSH_KEY_PATH":  "/tmp/test_key",
        "FW_SSH_USER":      "ubuntu",
    }


@pytest.fixture()
def compare_args():
    """tool_args for a compare-baseline call."""
    return {
        "provider":           "ssh",
        "compare_session_id": "fw_nft_base",
    }


def _make_proc(returncode: int = 0) -> SimpleNamespace:
    """Return a minimal subprocess.CompletedProcess stand-in."""
    return SimpleNamespace(returncode=returncode)


def _write_drift(audit_dir: str, payload: dict, name: str = "fw_nft_compare_drift.json"):
    """Write payload as a drift JSON file to audit_dir."""
    Path(audit_dir).mkdir(parents=True, exist_ok=True)
    path = Path(audit_dir) / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _subprocess_side_effect(audit_dir: str, payload: dict):
    """Return a side_effect callable that writes the drift file then returns proc."""
    def _inner(*args, **kwargs):
        _write_drift(audit_dir, payload)
        return _make_proc(0)
    return _inner


# ===========================================================================
# Synthetic drift payloads
# ===========================================================================

_NFT_RULE_DROP = {
    "table":    "inet/filter",
    "chain":    "input",
    "verdict":  "drop",
    "protocol": "tcp",
    "dst_port": 8080,
    "src_port": None,
    "src_addr": "10.0.0.0/24",
    "dst_addr": None,
    "comment":  "block-http-alt",
}

_IPT_RULE_DROP = {
    "table":    "filter",
    "chain":    "INPUT",
    "target":   "DROP",
    "protocol": "tcp",
    "dst_port": "80",
    "src_port": None,
    "source":   "0.0.0.0/0",
    "raw_rule": "-A INPUT -p tcp --dport 80 -j DROP",
}

_SUMMARY_ONE_ADDED = {
    "tables_added": 0, "tables_removed": 0,
    "chains_added": 0, "chains_removed": 0,
    "policy_changes": 0,
    "rules_added": 1, "rules_removed": 0,
    "rules_repositioned": 0, "rules_recreated": 0,
}

_CHANGES_EMPTY = {
    "tables_added": [], "tables_removed": [],
    "chains_added": [], "chains_removed": [],
    "policy_changes": [],
    "rules_added": [], "rules_removed": [],
    "rules_repositioned": [], "rules_recreated": [],
}


def _nft_drift_payload(
    drift_detected=True,
    has_critical=True,
    rules_added=None,
    rules_removed=None,
    policy_changes=None,
    chains_added=None,
    chains_removed=None,
):
    changes = dict(_CHANGES_EMPTY)
    if rules_added is not None:
        changes["rules_added"] = rules_added
    if rules_removed is not None:
        changes["rules_removed"] = rules_removed
    if policy_changes is not None:
        changes["policy_changes"] = policy_changes
    if chains_added is not None:
        changes["chains_added"] = chains_added
    if chains_removed is not None:
        changes["chains_removed"] = chains_removed
    return {
        "drift_by_family": {
            "nft": {
                "drift_detected":     drift_detected,
                "has_critical_changes": has_critical,
                "summary":            _SUMMARY_ONE_ADDED,
                "changes":            changes,
            }
        }
    }


def _ipt_drift_payload(drift_detected=True, has_critical=True, rules_added=None):
    changes = dict(_CHANGES_EMPTY)
    if rules_added is not None:
        changes["rules_added"] = rules_added
    return {
        "drift_by_family": {
            "ipv4": {
                "drift_detected":       drift_detected,
                "has_critical_changes": has_critical,
                "summary":              _SUMMARY_ONE_ADDED,
                "changes":              changes,
            }
        }
    }


# ===========================================================================
# GA-NF01: nftables rules_added → nftables field names in condensed output
# ===========================================================================

def test_ga_nf01_nftables_rules_added_uses_nft_field_names(ghost_cfg, compare_args):
    """GA-NF01: nft family → condensed rules_added uses verdict/src_addr/dst_addr/comment."""
    payload = _nft_drift_payload(rules_added=[_NFT_RULE_DROP])

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["status"] == "success"
    rules = result["nft"]["rules_added"]
    assert len(rules) == 1
    r = rules[0]
    assert r["verdict"]  == "drop"
    assert r["src_addr"] == "10.0.0.0/24"
    assert r["dst_addr"] is None
    assert r["comment"]  == "block-http-alt"
    assert r["table"]    == "inet/filter"
    assert r["chain"]    == "input"
    assert r["protocol"] == "tcp"
    assert r["dst_port"] == 8080


# ===========================================================================
# GA-NF02: nftables rules_added → iptables field names absent
# ===========================================================================

def test_ga_nf02_nftables_rules_added_excludes_iptables_fields(ghost_cfg, compare_args):
    """GA-NF02: nft family → condensed rules must NOT contain target/source/raw_rule."""
    payload = _nft_drift_payload(rules_added=[_NFT_RULE_DROP])

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    r = result["nft"]["rules_added"][0]
    assert "target"   not in r, "iptables 'target' field must not appear in nftables condensed rule"
    assert "source"   not in r, "iptables 'source' field must not appear in nftables condensed rule"
    assert "raw_rule" not in r, "iptables 'raw_rule' field must not appear in nftables condensed rule"


# ===========================================================================
# GA-NF03: iptables rules_added → iptables field names in condensed output
# ===========================================================================

def test_ga_nf03_iptables_rules_added_uses_ipt_field_names(ghost_cfg, compare_args):
    """GA-NF03: ipv4 family → condensed rules_added uses target/source/raw_rule."""
    payload = _ipt_drift_payload(rules_added=[_IPT_RULE_DROP])
    compare_args["compare_session_id"] = "fw_ipt_base"

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["status"] == "success"
    rules = result["ipv4"]["rules_added"]
    assert len(rules) == 1
    r = rules[0]
    assert r["target"]   == "DROP"
    assert r["source"]   == "0.0.0.0/0"
    assert r["raw_rule"] == "-A INPUT -p tcp --dport 80 -j DROP"
    assert r["table"]    == "filter"
    assert r["chain"]    == "INPUT"


# ===========================================================================
# GA-NF04: iptables rules_added → nftables field names absent
# ===========================================================================

def test_ga_nf04_iptables_rules_added_excludes_nft_fields(ghost_cfg, compare_args):
    """GA-NF04: ipv4 family → condensed rules must NOT contain verdict/src_addr/dst_addr/comment."""
    payload = _ipt_drift_payload(rules_added=[_IPT_RULE_DROP])

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    r = result["ipv4"]["rules_added"][0]
    assert "verdict"  not in r, "nftables 'verdict' field must not appear in iptables condensed rule"
    assert "src_addr" not in r, "nftables 'src_addr' field must not appear in iptables condensed rule"
    assert "dst_addr" not in r, "nftables 'dst_addr' field must not appear in iptables condensed rule"
    assert "comment"  not in r, "nftables 'comment' field must not appear in iptables condensed rule"


# ===========================================================================
# GA-NF05: top-level drift_detected=True when nft family has drift
# ===========================================================================

def test_ga_nf05_top_level_drift_detected_true_for_nft_drift(ghost_cfg, compare_args):
    """GA-NF05: drift_detected=True at top level when nft family reports drift."""
    payload = _nft_drift_payload(drift_detected=True, rules_added=[_NFT_RULE_DROP])

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["drift_detected"] is True


# ===========================================================================
# GA-NF06: top-level drift_detected=False when no drift in any family
# ===========================================================================

def test_ga_nf06_top_level_drift_detected_false_when_no_drift(ghost_cfg, compare_args):
    """GA-NF06: drift_detected=False at top level when nft family has no drift."""
    payload = _nft_drift_payload(drift_detected=False, has_critical=False)

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["drift_detected"] is False


# ===========================================================================
# GA-NF07: top-level has_critical_changes=True when nft family critical
# ===========================================================================

def test_ga_nf07_top_level_has_critical_changes_true_for_nft(ghost_cfg, compare_args):
    """GA-NF07: has_critical_changes=True at top level when nft family is critical."""
    payload = _nft_drift_payload(has_critical=True, rules_added=[_NFT_RULE_DROP])

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["has_critical_changes"] is True


# ===========================================================================
# GA-NF08: family with "error" key excluded from top-level flag computation
# ===========================================================================

def test_ga_nf08_error_family_excluded_from_top_level_flags(ghost_cfg, compare_args):
    """GA-NF08: A family dict containing "error" must not count toward drift_detected
    or has_critical_changes even if those keys happen to be present in the error dict.
    """
    payload = {
        "drift_by_family": {
            "nft": {
                "error": "Cannot diff: ruleset unavailable",
                "drift_detected": True,       # must NOT count — error family
                "has_critical_changes": True,  # must NOT count — error family
            }
        }
    }

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    assert result["drift_detected"] is False, (
        "drift_detected must be False when the only family has an error"
    )
    assert result["has_critical_changes"] is False, (
        "has_critical_changes must be False when the only family has an error"
    )


# ===========================================================================
# GA-NF09: mixed nft+ipv4 families → correct field routing per family
# ===========================================================================

def test_ga_nf09_mixed_families_route_fields_independently(ghost_cfg, compare_args):
    """GA-NF09: When drift_by_family has both "nft" and "ipv4" families,
    each gets the correct field set independently (no cross-contamination).
    """
    payload = {
        "drift_by_family": {
            "nft": {
                "drift_detected": True,
                "has_critical_changes": True,
                "summary": _SUMMARY_ONE_ADDED,
                "changes": {**_CHANGES_EMPTY, "rules_added": [_NFT_RULE_DROP]},
            },
            "ipv4": {
                "drift_detected": True,
                "has_critical_changes": True,
                "summary": _SUMMARY_ONE_ADDED,
                "changes": {**_CHANGES_EMPTY, "rules_added": [_IPT_RULE_DROP]},
            },
        }
    }

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    # nft family: nftables fields present, iptables fields absent
    nft_rule = result["nft"]["rules_added"][0]
    assert "verdict"  in nft_rule
    assert "src_addr" in nft_rule
    assert "target"   not in nft_rule
    assert "raw_rule" not in nft_rule

    # ipv4 family: iptables fields present, nftables fields absent
    ipt_rule = result["ipv4"]["rules_added"][0]
    assert "target"   in ipt_rule
    assert "raw_rule" in ipt_rule
    assert "verdict"  not in ipt_rule
    assert "src_addr" not in ipt_rule

    # top-level flags: True because both families have drift
    assert result["drift_detected"] is True
    assert result["has_critical_changes"] is True


# ===========================================================================
# GA-NF10: policy_changes / chains_added / chains_removed forwarded
# ===========================================================================

def test_ga_nf10_policy_changes_and_chain_changes_forwarded(ghost_cfg, compare_args):
    """GA-NF10: policy_changes, chains_added, chains_removed pass through to fam_result."""
    policy_change = {
        "table": "inet/filter", "chain": "input",
        "old_policy": "accept", "new_policy": "drop",
    }
    chain_added = {
        "table": "inet/filter", "chain": "forward",
        "handle": 2, "is_base_chain": True, "rule_count": 0,
    }
    payload = _nft_drift_payload(
        drift_detected=True,
        has_critical=True,
        policy_changes=[policy_change],
        chains_added=[chain_added],
    )

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    fam = result["nft"]
    assert fam["policy_changes"] == [policy_change]
    assert fam["chains_added"]   == [chain_added]


# ===========================================================================
# GA-NF11: baseline mode → status="success", mode="baseline", session_id
# ===========================================================================

def test_ga_nf11_baseline_mode_returns_session_id(ghost_cfg, tmp_path):
    """GA-NF11: is_baseline=True → status="success", mode="baseline", session_id extracted
    from snapshot filename written during the mocked subprocess run.
    """
    session_id = "fw_nft_20260317_040000"
    snap_name  = f"{session_id}_snapshot.json"
    audit_dir  = ghost_cfg["AUDIT_DIR"]

    def _write_snapshot_and_return(*args, **kwargs):
        Path(audit_dir).mkdir(parents=True, exist_ok=True)
        (Path(audit_dir) / snap_name).write_text("{}", encoding="utf-8")
        return _make_proc(0)

    tool_args = {"provider": "ssh", "is_baseline": True}

    with patch("subprocess.run", side_effect=_write_snapshot_and_return):
        result = _run_firewall_inspector_handler(ghost_cfg, tool_args)

    assert result["status"]     == "success"
    assert result["mode"]       == "baseline"
    assert result["session_id"] == session_id


# ===========================================================================
# GA-NF12: neither is_baseline nor compare_session_id → error, no subprocess
# ===========================================================================

def test_ga_nf12_missing_mode_returns_error_without_subprocess(ghost_cfg):
    """GA-NF12: Omitting both is_baseline and compare_session_id returns an error dict
    and must never invoke subprocess.run.
    """
    tool_args = {"provider": "ssh"}  # no is_baseline, no compare_session_id

    with patch("subprocess.run") as mock_proc:
        result = _run_firewall_inspector_handler(ghost_cfg, tool_args)

    assert result["status"] == "error"
    assert "is_baseline" in result["error"] or "compare_session_id" in result["error"]
    mock_proc.assert_not_called()


# ===========================================================================
# GA-NF13: rules_added absent from fam_result when rules list is empty
# ===========================================================================

def test_ga_nf13_empty_rules_list_not_included_in_fam_result(ghost_cfg, compare_args):
    """GA-NF13: When rules_added is empty, the key must not appear in fam_result.
    The handler only populates rules_added/rules_removed when the list is non-empty,
    keeping the Brain's result payload minimal.
    """
    payload = _nft_drift_payload(drift_detected=False, has_critical=False)
    # rules_added defaults to [] in _nft_drift_payload

    with patch("subprocess.run",
               side_effect=_subprocess_side_effect(ghost_cfg["AUDIT_DIR"], payload)):
        result = _run_firewall_inspector_handler(ghost_cfg, compare_args)

    fam = result["nft"]
    assert "rules_added"   not in fam, "Empty rules_added must not appear in fam_result"
    assert "rules_removed" not in fam, "Empty rules_removed must not appear in fam_result"
