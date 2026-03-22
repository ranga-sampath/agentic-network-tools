"""
iptables_diff.py — Diff Engine for the iptables-parser module

Compares two parse_iptables_save() outputs and produces a structured diff.
Counter changes (packet_count, byte_count) are excluded from drift detection.

Usage:
    python3 iptables_diff.py baseline.json current.json
    python3 iptables_diff.py baseline.json current.json --indent 2
    cat current.json | python3 iptables_diff.py baseline.json -
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Rule identity
# ---------------------------------------------------------------------------

# Frozen field list — defines what makes two rules "the same rule".
# Explicitly enumerated; never derived dynamically from the rule record.
# Changes to this list invalidate previously captured baselines.
_RULE_IDENTITY_FIELDS = (
    "table", "chain",
    "protocol", "protocol_negated",
    "source", "source_negated",
    "destination", "destination_negated",
    "in_interface", "in_interface_negated",
    "out_interface", "out_interface_negated",
    "dst_port", "dst_port_negated",
    "src_port", "src_port_negated",
    "target", "target_params",
    "match_extensions", "opaque_extensions",
)

# Targets whose addition or removal constitutes a critical change
_CRITICAL_TARGETS = frozenset({"DROP", "REJECT"})


def _identity_hash(rule: dict) -> str:
    try:
        identity = {f: rule[f] for f in _RULE_IDENTITY_FIELDS}
    except KeyError as exc:
        raise KeyError(
            f"Rule missing identity field {exc} "
            f"(table={rule.get('table')!r}, chain={rule.get('chain')!r}, "
            f"position={rule.get('position')!r})"
        ) from None
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True).encode()
    ).hexdigest()


def _identity_fields(rule: dict) -> dict:
    """Return a dict containing only the identity fields of a rule."""
    try:
        return {f: rule[f] for f in _RULE_IDENTITY_FIELDS}
    except KeyError as exc:
        raise KeyError(
            f"Rule missing identity field {exc} "
            f"(table={rule.get('table')!r}, chain={rule.get('chain')!r}, "
            f"position={rule.get('position')!r})"
        ) from None


def _chain_rules(entry: dict, tables: dict) -> list[dict]:
    """Return the rule list for a chains_added / chains_removed entry."""
    return (
        tables
        .get(entry["table"], {})
        .get("chains", {})
        .get(entry["chain"], {})
        .get("rules", [])
    )


def _rules_by_hash(rules: list[dict]) -> dict[str, list[dict]]:
    """
    Group rules by identity hash.
    Each group is sorted ascending by position.
    """
    result: dict[str, list[dict]] = {}
    for r in rules:
        h = _identity_hash(r)
        result.setdefault(h, []).append(r)
    for group in result.values():
        group.sort(key=lambda r: r["position"])
    return result


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate(d: Any, label: str) -> None:
    if not isinstance(d, dict):
        raise ValueError(f"{label} must be a dict")
    for key in ("family", "tables"):
        if key not in d:
            raise ValueError(
                f"{label} is not a valid parse_iptables_save() output: "
                f"missing '{key}'"
            )
    if not isinstance(d["tables"], dict):
        raise ValueError(
            f"{label} is not a valid parse_iptables_save() output: "
            f"'tables' must be a dict, got {type(d['tables']).__name__}"
        )


# ---------------------------------------------------------------------------
# Main diff function
# ---------------------------------------------------------------------------

def diff_rulesets(baseline: dict, current: dict) -> dict:
    """
    Compare two parse_iptables_save() outputs and return a structured diff.

    Raises ValueError for invalid inputs or cross-family comparison.
    """
    _validate(baseline, "baseline")
    _validate(current, "current")

    if baseline["family"] != current["family"]:
        raise ValueError(
            f"Cannot diff across address families: "
            f"baseline is {baseline['family']!r}, current is {current['family']!r}"
        )

    family = baseline["family"]
    b_tables = baseline["tables"]
    c_tables = current["tables"]

    b_table_names = set(b_tables)
    c_table_names = set(c_tables)

    tables_added:       list[str]  = sorted(c_table_names - b_table_names)
    tables_removed:     list[str]  = sorted(b_table_names - c_table_names)
    chains_added:       list[dict] = []
    chains_removed:     list[dict] = []
    policy_changes:     list[dict] = []
    rules_added:        list[dict] = []
    rules_removed:      list[dict] = []
    rules_repositioned: list[dict] = []

    # --- Chains from entirely new tables → chains_added ---
    # Their rules do NOT also appear in rules_added (no double-counting).
    # Include the rule list so explain_diff can describe their contents without
    # requiring a separate snapshot lookup.
    for tname in tables_added:
        for cname, cdata in c_tables[tname]["chains"].items():
            chains_added.append({
                "table":      tname,
                "chain":      cname,
                "type":       cdata["type"],
                "rule_count": len(cdata["rules"]),
                "rules":      [{"position": r.get("position"),
                                "target":   r.get("target"),
                                "protocol": r.get("protocol"),
                                "source":   r.get("source"),
                                "raw_rule": r.get("raw_rule")}
                               for r in cdata["rules"]],
            })

    # --- Chains from entirely removed tables → chains_removed ---
    for tname in tables_removed:
        for cname, cdata in b_tables[tname]["chains"].items():
            chains_removed.append({
                "table":      tname,
                "chain":      cname,
                "type":       cdata["type"],
                "rule_count": len(cdata["rules"]),
                "rules":      [{"position": r.get("position"),
                                "target":   r.get("target"),
                                "protocol": r.get("protocol"),
                                "source":   r.get("source"),
                                "raw_rule": r.get("raw_rule")}
                               for r in cdata["rules"]],
            })

    # --- Tables present in both: chain-level and rule-level diff ---
    for tname in sorted(b_table_names & c_table_names):
        b_chains = b_tables[tname]["chains"]
        c_chains = c_tables[tname]["chains"]
        b_chain_names = set(b_chains)
        c_chain_names = set(c_chains)

        # Chains added within this table
        for cname in sorted(c_chain_names - b_chain_names):
            cdata = c_chains[cname]
            chains_added.append({
                "table":      tname,
                "chain":      cname,
                "type":       cdata["type"],
                "rule_count": len(cdata["rules"]),
                "rules":      [{"position": r.get("position"),
                                "target":   r.get("target"),
                                "protocol": r.get("protocol"),
                                "source":   r.get("source"),
                                "raw_rule": r.get("raw_rule")}
                               for r in cdata["rules"]],
            })

        # Chains removed within this table
        for cname in sorted(b_chain_names - c_chain_names):
            cdata = b_chains[cname]
            chains_removed.append({
                "table":      tname,
                "chain":      cname,
                "type":       cdata["type"],
                "rule_count": len(cdata["rules"]),
                "rules":      [{"position": r.get("position"),
                                "target":   r.get("target"),
                                "protocol": r.get("protocol"),
                                "source":   r.get("source"),
                                "raw_rule": r.get("raw_rule")}
                               for r in cdata["rules"]],
            })

        # Chains present in both
        for cname in sorted(b_chain_names & c_chain_names):
            b_chain = b_chains[cname]
            c_chain = c_chains[cname]

            # Policy diff (counter fields ignored)
            if b_chain["default_policy"] != c_chain["default_policy"]:
                policy_changes.append({
                    "table":           tname,
                    "chain":           cname,
                    "baseline_policy": b_chain["default_policy"],
                    "current_policy":  c_chain["default_policy"],
                })

            # Rule diff
            b_by_hash = _rules_by_hash(b_chain["rules"])
            c_by_hash = _rules_by_hash(c_chain["rules"])
            b_counts = Counter({h: len(rs) for h, rs in b_by_hash.items()})
            c_counts = Counter({h: len(rs) for h, rs in c_by_hash.items()})

            for h in sorted(set(b_counts) | set(c_counts)):
                b_count = b_counts[h]   # 0 if hash absent from baseline
                c_count = c_counts[h]   # 0 if hash absent from current
                min_count = min(b_count, c_count)

                # min_count rules exist in both sides — check for reposition
                if min_count > 0:
                    b_pos = [r["position"] for r in b_by_hash[h]][:min_count]
                    c_pos = [r["position"] for r in c_by_hash[h]][:min_count]
                    for bp, cp in zip(b_pos, c_pos):
                        if bp != cp:
                            rules_repositioned.append({
                                "table":            tname,
                                "chain":            cname,
                                "baseline_position": bp,
                                "current_position":  cp,
                                # All rules sharing this hash have identical identity
                                # fields by definition; [0] is representative for all
                                # duplicates in the group.
                                "rule": _identity_fields(b_by_hash[h][0]),
                            })

                # Excess in baseline → removed
                # (b_count > min_count implies b_count > c_count, so h is in b_by_hash)
                if b_count > min_count:
                    for r in b_by_hash[h][min_count:]:
                        rules_removed.append(r)

                # Excess in current → added
                # (c_count > min_count implies c_count > b_count, so h is in c_by_hash)
                if c_count > min_count:
                    for r in c_by_hash[h][min_count:]:
                        rules_added.append(r)

    # Sort all change lists for deterministic output
    chains_added.sort(key=lambda x: (x["table"], x["chain"]))
    chains_removed.sort(key=lambda x: (x["table"], x["chain"]))
    policy_changes.sort(key=lambda x: (x["table"], x["chain"]))
    rules_added.sort(key=lambda x: (x["table"], x["chain"], x["position"]))
    rules_removed.sort(key=lambda x: (x["table"], x["chain"], x["position"]))
    rules_repositioned.sort(
        key=lambda x: (x["table"], x["chain"], x["baseline_position"])
    )

    drift_detected = any([
        tables_added, tables_removed,
        chains_added, chains_removed,
        policy_changes,
        rules_added, rules_removed, rules_repositioned,
    ])

    has_critical_changes = (
        bool(policy_changes)
        or any(r["target"] in _CRITICAL_TARGETS for r in rules_added)
        or any(r["target"] in _CRITICAL_TARGETS for r in rules_removed)
        or any(
            r["target"] in _CRITICAL_TARGETS
            for e in chains_added
            for r in _chain_rules(e, c_tables)
        )
        or any(
            r["target"] in _CRITICAL_TARGETS
            for e in chains_removed
            for r in _chain_rules(e, b_tables)
        )
    )

    summary = {
        "tables_added":       len(tables_added),
        "tables_removed":     len(tables_removed),
        "chains_added":       len(chains_added),
        "chains_removed":     len(chains_removed),
        "policy_changes":     len(policy_changes),
        "rules_added":        len(rules_added),
        "rules_removed":      len(rules_removed),
        "rules_repositioned": len(rules_repositioned),
    }

    return {
        "diff_at":                 datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "family":                  family,
        "baseline_parsed_at":      baseline.get("parsed_at"),
        "current_parsed_at":       current.get("parsed_at"),
        "baseline_parse_warnings": baseline.get("parse_warnings", []),
        "current_parse_warnings":  current.get("parse_warnings", []),
        "drift_detected":          drift_detected,
        "has_critical_changes":    has_critical_changes,
        "summary":                 summary,
        "changes": {
            "tables_added":       tables_added,
            "tables_removed":     tables_removed,
            "chains_added":       chains_added,
            "chains_removed":     chains_removed,
            "policy_changes":     policy_changes,
            "rules_added":        rules_added,
            "rules_removed":      rules_removed,
            "rules_repositioned": rules_repositioned,
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Diff two parse_iptables_save() JSON outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "baseline",
        help="Path to baseline JSON file (output of iptables_parser.py)",
    )
    parser.add_argument(
        "current",
        help="Path to current JSON file, or '-' to read from stdin",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation (default: 2)",
    )
    args = parser.parse_args()

    with open(args.baseline, "r", encoding="utf-8") as fh:
        baseline = json.load(fh)

    if args.current == "-":
        current = json.load(sys.stdin)
    else:
        with open(args.current, "r", encoding="utf-8") as fh:
            current = json.load(fh)

    result = diff_rulesets(baseline, current)
    print(json.dumps(result, indent=args.indent))


if __name__ == "__main__":
    main()
