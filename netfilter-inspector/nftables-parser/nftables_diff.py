#!/usr/bin/env python3
"""
nftables_diff.py — Diff engine for the nftables-parser module.

Compares two parse_nft_ruleset() outputs and produces a structured diff.
Counter changes (inline packet/byte counts) are excluded from drift detection.

Usage:
    python3 nftables_diff.py baseline.json current.json
    python3 nftables_diff.py baseline.json current.json --indent 2
    python3 nftables_diff.py baseline.json current.json --summary
    python3 nftables_diff.py baseline.json current.json --summary --verbose
    cat current.json | python3 nftables_diff.py baseline.json -
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Rule identity — fields included in repositioned rule's identity sub-dict.
# Frozen: any change to this list invalidates stored baselines.
# ---------------------------------------------------------------------------
_RULE_IDENTITY_FIELDS = (
    # ── v1 fields (original) ─────────────────────────────────────────────
    "table", "chain",
    "protocol", "protocol_negated",
    "src_addr", "src_addr_negated",
    "dst_addr", "dst_addr_negated",
    "src_port", "src_port_negated",
    "dst_port", "dst_port_negated",
    "in_interface", "in_interface_negated",
    "out_interface", "out_interface_negated",
    "ct_state",
    "verdict",
    "jump_target", "goto_target",
    "expression_hash",
    # ── v2 fields (added: ICMP, extended ct, comment) ────────────────────
    # NOTE: adding fields here invalidates stored baselines taken with an
    # earlier parser version — new fields will simply be absent (None) in
    # old baselines and populated in current captures.
    "icmp_type", "icmp_type_negated",
    "icmp_code", "icmp_code_negated",
    "ct_mark", "ct_mark_negated",
    "ct_direction",
    "ct_zone",
    "comment",
)

_CRITICAL_VERDICTS = frozenset({"drop", "reject"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_critical_verdict(rule: dict) -> bool:
    """True if the rule has a drop or reject verdict."""
    return rule.get("verdict") in _CRITICAL_VERDICTS


def _policy_is_critical(policy: Any) -> bool:
    """True if policy == 'drop'."""
    return policy == "drop"


def _chain_rules(entry: dict, tables: dict) -> list[dict]:
    """Return the rule list for a chains_added / chains_removed entry."""
    return (
        tables
        .get(entry["table"], {})
        .get("chains", {})
        .get(entry["chain"], {})
        .get("rules", [])
    )


def _rules_by_handle(rules: list[dict]) -> dict[int, dict]:
    """
    Index rules by handle. Raises ValueError on duplicate handles
    (indicates malformed parser output).
    """
    result: dict[int, dict] = {}
    for rule in rules:
        h = rule["handle"]
        if h in result:
            raise ValueError(
                f"Duplicate handle {h} in chain "
                f"{rule.get('table')}/{rule.get('chain')} "
                f"— indicates malformed parser output"
            )
        result[h] = rule
    return result


def _rules_by_hash(rules: list[dict]) -> dict[str, list[dict]]:
    """Index rules by expression_hash. Multiple rules with the same hash are grouped."""
    result: dict[str, list[dict]] = {}
    for rule in rules:
        h = rule["expression_hash"]
        result.setdefault(h, []).append(rule)
    return result


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate(d: Any, label: str) -> None:
    """Validate that d is a dict with input_format and tables fields."""
    if not isinstance(d, dict):
        raise ValueError(f"{label} must be a dict")
    for key in ("input_format", "tables"):
        if key not in d:
            raise ValueError(
                f"{label} is not a valid parse_nft_ruleset() output: "
                f"missing '{key}'"
            )
    if not isinstance(d["tables"], dict):
        raise ValueError(
            f"{label} is not a valid parse_nft_ruleset() output: "
            f"'tables' must be a dict, got {type(d['tables']).__name__}"
        )


# ---------------------------------------------------------------------------
# Main diff function
# ---------------------------------------------------------------------------

def diff_rulesets(baseline: dict, current: dict) -> dict:
    """
    Compare two parse_nft_ruleset() outputs and return a structured diff.

    Raises ValueError for invalid inputs or cross-format comparison.
    """
    _validate(baseline, "baseline")
    _validate(current, "current")

    b_fmt = baseline["input_format"]
    c_fmt = current["input_format"]
    if b_fmt != "nft-json" or c_fmt != "nft-json":
        raise ValueError(
            f"Cannot diff {b_fmt} baseline against {c_fmt} current"
        )

    # Carry forward current parse warnings; append schema mismatch warning if needed
    current_parse_warnings: list[str] = list(current.get("parse_warnings", []))
    b_schema = baseline.get("json_schema_version")
    c_schema = current.get("json_schema_version")
    if b_schema is not None and c_schema is not None and b_schema != c_schema:
        current_parse_warnings.append(
            f"json_schema_version changed (baseline: {b_schema}, current: {c_schema}) "
            f"— expression structure may differ across nft versions"
        )

    b_tables = baseline["tables"]
    c_tables = current["tables"]

    b_table_keys = set(b_tables)
    c_table_keys = set(c_tables)

    tables_added:       list[str]  = sorted(c_table_keys - b_table_keys)
    tables_removed:     list[str]  = sorted(b_table_keys - c_table_keys)
    chains_added:       list[dict] = []
    chains_removed:     list[dict] = []
    policy_changes:     list[dict] = []
    rules_added:        list[dict] = []
    rules_removed:      list[dict] = []
    rules_repositioned: list[dict] = []
    rules_recreated:    list[dict] = []

    # --- Chains from entirely new tables → chains_added ---
    # Their rules do NOT also appear in rules_added (no double-counting).
    for tkey in tables_added:
        for cname, cdata in c_tables[tkey]["chains"].items():
            chains_added.append({
                "table":         tkey,
                "chain":         cname,
                "handle":        cdata.get("handle"),
                "is_base_chain": cdata.get("is_base_chain", False),
                "rule_count":    len(cdata.get("rules", [])),
            })

    # --- Chains from entirely removed tables → chains_removed ---
    for tkey in tables_removed:
        for cname, cdata in b_tables[tkey]["chains"].items():
            chains_removed.append({
                "table":         tkey,
                "chain":         cname,
                "handle":        cdata.get("handle"),
                "is_base_chain": cdata.get("is_base_chain", False),
                "rule_count":    len(cdata.get("rules", [])),
            })

    # --- Tables present in both: chain-level and rule-level diff ---
    for tkey in sorted(b_table_keys & c_table_keys):
        b_chains = b_tables[tkey]["chains"]
        c_chains = c_tables[tkey]["chains"]
        b_chain_names = set(b_chains)
        c_chain_names = set(c_chains)

        # Chains added within this table
        for cname in sorted(c_chain_names - b_chain_names):
            cdata = c_chains[cname]
            chains_added.append({
                "table":         tkey,
                "chain":         cname,
                "handle":        cdata.get("handle"),
                "is_base_chain": cdata.get("is_base_chain", False),
                "rule_count":    len(cdata.get("rules", [])),
            })

        # Chains removed within this table
        for cname in sorted(b_chain_names - c_chain_names):
            cdata = b_chains[cname]
            chains_removed.append({
                "table":         tkey,
                "chain":         cname,
                "handle":        cdata.get("handle"),
                "is_base_chain": cdata.get("is_base_chain", False),
                "rule_count":    len(cdata.get("rules", [])),
            })

        # Chains present in both
        for cname in sorted(b_chain_names & c_chain_names):
            b_chain = b_chains[cname]
            c_chain = c_chains[cname]

            # Policy diff
            if b_chain.get("policy") != c_chain.get("policy"):
                policy_changes.append({
                    "table":           tkey,
                    "chain":           cname,
                    "baseline_policy": b_chain.get("policy"),
                    "current_policy":  c_chain.get("policy"),
                })

            # Priority diff (affects enforcement order)
            if b_chain.get("priority") != c_chain.get("priority"):
                policy_changes.append({
                    "table":             tkey,
                    "chain":             cname,
                    "baseline_priority": b_chain.get("priority"),
                    "current_priority":  c_chain.get("priority"),
                    "note":              "Chain priority changed — enforcement order affected",
                })

            # Type diff
            if b_chain.get("type") != c_chain.get("type"):
                policy_changes.append({
                    "table":         tkey,
                    "chain":         cname,
                    "baseline_type": b_chain.get("type"),
                    "current_type":  c_chain.get("type"),
                    "note":          "Chain type changed",
                })

            # --- Rule diff: handle-based primary pass ---
            b_by_handle = _rules_by_handle(b_chain.get("rules", []))
            c_by_handle = _rules_by_handle(c_chain.get("rules", []))

            b_handles = set(b_by_handle)
            c_handles = set(c_by_handle)

            candidate_removed: list[dict] = []
            candidate_added:   list[dict] = []

            # Handles only in baseline → candidate removed
            for h in sorted(b_handles - c_handles):
                candidate_removed.append(b_by_handle[h])

            # Handles only in current → candidate added
            for h in sorted(c_handles - b_handles):
                candidate_added.append(c_by_handle[h])

            # Handles in both → check hash stability and position
            for h in sorted(b_handles & c_handles):
                b_rule = b_by_handle[h]
                c_rule = c_by_handle[h]

                if b_rule["expression_hash"] != c_rule["expression_hash"]:
                    # Same handle, different hash — nftables does not allow
                    # in-place rule modification; this indicates a parser bug
                    # or malformed input. Record as remove + add.
                    current_parse_warnings.append(
                        f"Handle {h} in {tkey}/{cname} has different "
                        f"expression_hash between baseline and current — "
                        f"possible parser bug or malformed input; "
                        f"recording as remove+add"
                    )
                    candidate_removed.append(b_rule)
                    candidate_added.append(c_rule)

                elif b_rule["position"] != c_rule["position"]:
                    rules_repositioned.append({
                        "table":             tkey,
                        "chain":             cname,
                        "handle":            h,
                        "baseline_position": b_rule["position"],
                        "current_position":  c_rule["position"],
                        "rule": {
                            f: b_rule[f]
                            for f in _RULE_IDENTITY_FIELDS
                            if f in b_rule
                        },
                    })

            # --- Rule diff: expression_hash secondary pass (recreation detection) ---
            b_hash_idx = _rules_by_hash(candidate_removed)
            c_hash_idx = _rules_by_hash(candidate_added)

            matched_b_handles: set[int] = set()
            matched_c_handles: set[int] = set()

            for expr_hash in set(b_hash_idx) & set(c_hash_idx):
                b_group = b_hash_idx[expr_hash]
                c_group = c_hash_idx[expr_hash]
                for i in range(min(len(b_group), len(c_group))):
                    b_rule = b_group[i]
                    c_rule = c_group[i]
                    rules_recreated.append({
                        "baseline_rule": b_rule,
                        "current_rule":  c_rule,
                        "note": (
                            "Semantically equivalent rule: same expression_hash, "
                            "different handle. Rule was deleted and re-added."
                        ),
                    })
                    matched_b_handles.add(b_rule["handle"])
                    matched_c_handles.add(c_rule["handle"])

            # Remaining unpaired candidates → final removed / added lists
            for rule in candidate_removed:
                if rule["handle"] not in matched_b_handles:
                    rules_removed.append(rule)

            for rule in candidate_added:
                if rule["handle"] not in matched_c_handles:
                    rules_added.append(rule)

    # --- Sort all change lists for deterministic output ---
    chains_added.sort(key=lambda x: (x["table"], x["chain"]))
    chains_removed.sort(key=lambda x: (x["table"], x["chain"]))
    policy_changes.sort(key=lambda x: (x["table"], x["chain"]))
    rules_added.sort(key=lambda x: (x["table"], x["chain"], x["handle"]))
    rules_removed.sort(key=lambda x: (x["table"], x["chain"], x["handle"]))
    rules_repositioned.sort(key=lambda x: (x["table"], x["chain"], x["handle"]))
    rules_recreated.sort(
        key=lambda x: (
            x["baseline_rule"]["table"],
            x["baseline_rule"]["chain"],
            x["baseline_rule"]["handle"],
        )
    )

    # --- drift_detected ---
    drift_detected = any([
        tables_added, tables_removed,
        chains_added, chains_removed,
        policy_changes,
        rules_added, rules_removed, rules_repositioned, rules_recreated,
    ])

    # --- has_critical_changes per design §2 ---
    has_critical_changes = (
        any(_policy_is_critical(pc.get("current_policy")) for pc in policy_changes)
        or any(_is_critical_verdict(r) for r in rules_added)
        or any(_is_critical_verdict(r) for r in rules_removed)
        or any(
            _is_critical_verdict(r)
            for e in chains_added
            for r in _chain_rules(e, c_tables)
        )
        or any(
            _is_critical_verdict(r)
            for e in chains_removed
            for r in _chain_rules(e, b_tables)
        )
        or any(
            _is_critical_verdict(e["baseline_rule"]) or _is_critical_verdict(e["current_rule"])
            for e in rules_recreated
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
        "rules_recreated":    len(rules_recreated),
    }

    return {
        "diff_at":                 datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_format":            "nft-json",
        "baseline_parsed_at":      baseline.get("parsed_at"),
        "current_parsed_at":       current.get("parsed_at"),
        "baseline_parse_warnings": baseline.get("parse_warnings", []),
        "current_parse_warnings":  current_parse_warnings,
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
            "rules_recreated":    rules_recreated,
        },
    }


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------

def _rule_summary_lines(rule: dict, *, verbose: bool, indent: str = "  ") -> list[str]:
    """Return bullet lines describing a single rule record."""
    lines: list[str] = []
    if verbose:
        lines.append(f"{indent}- `{json.dumps(rule, default=str)}`")
        return lines

    _fields = (
        "comment", "protocol", "icmp_type", "src_addr", "dst_addr",
        "src_port", "dst_port", "in_interface", "out_interface",
        "ct_state", "ct_mark", "ct_direction", "ct_zone",
        "jump_target", "goto_target",
    )
    parts: list[str] = []
    for f in _fields:
        v = rule.get(f)
        if v is None or v is False:
            continue
        if isinstance(v, list):
            parts.append(f"{f}: [{', '.join(str(x) for x in v)}]")
        else:
            neg_key = f"{f}_negated"
            prefix = "!= " if rule.get(neg_key) else ""
            parts.append(f"{f}: {prefix}{v}")
    if parts:
        lines.append(f"{indent}- " + ", ".join(parts))
    return lines


def _critical_label(rule: dict) -> str:
    return "  ⚠ CRITICAL" if _is_critical_verdict(rule) else ""


def summary_diff(diff: dict, *, verbose: bool = False) -> str:
    """
    Produce a human-readable Markdown summary of a diff_rulesets() result.

    Parameters
    ----------
    diff    : dict returned by diff_rulesets()
    verbose : if True, include the full rule dict for each change entry;
              default shows the most discriminating fields only.

    Returns
    -------
    Markdown string suitable for printing or writing to a .md file.
    """
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────
    lines.append(f"## nftables Ruleset Diff — {diff.get('diff_at', 'unknown')}")
    lines.append("")

    drift = diff.get("drift_detected", False)
    critical = diff.get("has_critical_changes", False)
    if not drift:
        lines.append("No drift detected.")
        lines.append("")
        _append_warnings(lines, diff)
        return "\n".join(lines)

    if critical:
        lines.append("**Drift detected. ⚠ Critical changes present.**")
    else:
        lines.append("**Drift detected.**")
    lines.append("")

    # ── Summary table ──────────────────────────────────────────────────────
    s = diff.get("summary", {})
    lines.append("### Summary")
    lines.append("| Category           | Count |")
    lines.append("|--------------------|-------|")
    rows = [
        ("Tables added",        "tables_added"),
        ("Tables removed",      "tables_removed"),
        ("Chains added",        "chains_added"),
        ("Chains removed",      "chains_removed"),
        ("Policy changes",      "policy_changes"),
        ("Rules added",         "rules_added"),
        ("Rules removed",       "rules_removed"),
        ("Rules repositioned",  "rules_repositioned"),
        ("Rules recreated",     "rules_recreated"),
    ]
    for label, key in rows:
        count = s.get(key, 0)
        if count:
            lines.append(f"| {label:<18} | {count:<5} |")
    lines.append("")

    changes = diff.get("changes", {})

    # ── Tables added / removed ─────────────────────────────────────────────
    if changes.get("tables_added"):
        lines.append("### Tables Added")
        for t in changes["tables_added"]:
            lines.append(f"- `{t}`")
        lines.append("")

    if changes.get("tables_removed"):
        lines.append("### Tables Removed")
        for t in changes["tables_removed"]:
            lines.append(f"- `{t}`")
        lines.append("")

    # ── Chains added / removed ─────────────────────────────────────────────
    if changes.get("chains_added"):
        lines.append("### Chains Added")
        for e in changes["chains_added"]:
            kind = "base chain" if e.get("is_base_chain") else "regular chain"
            lines.append(
                f"- `{e['table']}` **{e['chain']}** ({kind}, {e.get('rule_count', 0)} rules)"
            )
        lines.append("")

    if changes.get("chains_removed"):
        lines.append("### Chains Removed")
        for e in changes["chains_removed"]:
            kind = "base chain" if e.get("is_base_chain") else "regular chain"
            lines.append(
                f"- `{e['table']}` **{e['chain']}** ({kind}, {e.get('rule_count', 0)} rules)"
            )
        lines.append("")

    # ── Policy changes ─────────────────────────────────────────────────────
    if changes.get("policy_changes"):
        lines.append("### Policy Changes")
        for e in changes["policy_changes"]:
            if "current_policy" in e and "baseline_policy" in e:
                is_crit = _policy_is_critical(e.get("current_policy"))
                crit = "  ⚠ CRITICAL (chain now drops by default)" if is_crit else ""
                lines.append(
                    f"- `{e['table']}` **{e['chain']}**: "
                    f"policy `{e['baseline_policy']}` → `{e['current_policy']}`{crit}"
                )
            elif "current_priority" in e:
                lines.append(
                    f"- `{e['table']}` **{e['chain']}**: "
                    f"priority `{e.get('baseline_priority')}` → `{e.get('current_priority')}` "
                    f"— enforcement order affected"
                )
            elif "current_type" in e:
                lines.append(
                    f"- `{e['table']}` **{e['chain']}**: "
                    f"type `{e.get('baseline_type')}` → `{e.get('current_type')}`"
                )
        lines.append("")

    # ── Rules added ───────────────────────────────────────────────────────
    if changes.get("rules_added"):
        has_crit = any(_is_critical_verdict(r) for r in changes["rules_added"])
        section_crit = "  ⚠ includes critical" if has_crit else ""
        lines.append(f"### Rules Added{section_crit}")
        for r in changes["rules_added"]:
            verdict = r.get("verdict") or "—"
            lines.append(
                f"- `{r['table']}` **{r['chain']}** handle {r['handle']} "
                f"— verdict: **{verdict}**{_critical_label(r)}"
            )
            lines.extend(_rule_summary_lines(r, verbose=verbose))
        lines.append("")

    # ── Rules removed ─────────────────────────────────────────────────────
    if changes.get("rules_removed"):
        has_crit = any(_is_critical_verdict(r) for r in changes["rules_removed"])
        section_crit = "  ⚠ includes critical" if has_crit else ""
        lines.append(f"### Rules Removed{section_crit}")
        for r in changes["rules_removed"]:
            verdict = r.get("verdict") or "—"
            lines.append(
                f"- `{r['table']}` **{r['chain']}** handle {r['handle']} "
                f"— verdict: **{verdict}**{_critical_label(r)}"
            )
            lines.extend(_rule_summary_lines(r, verbose=verbose))
        lines.append("")

    # ── Rules repositioned ────────────────────────────────────────────────
    if changes.get("rules_repositioned"):
        lines.append("### Rules Repositioned")
        for e in changes["rules_repositioned"]:
            lines.append(
                f"- `{e['table']}` **{e['chain']}** handle {e['handle']}: "
                f"position {e['baseline_position']} → {e['current_position']}"
            )
        lines.append("")

    # ── Rules recreated ───────────────────────────────────────────────────
    if changes.get("rules_recreated"):
        lines.append("### Rules Recreated (deleted + re-added with new handle)")
        for e in changes["rules_recreated"]:
            b = e["baseline_rule"]
            c = e["current_rule"]
            verdict = b.get("verdict") or "—"
            crit = _critical_label(b) or _critical_label(c)
            lines.append(
                f"- `{b['table']}` **{b['chain']}**: "
                f"handle {b['handle']} → {c['handle']} "
                f"— verdict: **{verdict}**{crit}"
            )
            lines.extend(_rule_summary_lines(b, verbose=verbose))
        lines.append("")

    # ── Footer ────────────────────────────────────────────────────────────
    baseline_at = diff.get("baseline_parsed_at") or "—"
    current_at  = diff.get("current_parsed_at")  or "—"
    lines.append("---")
    lines.append(f"*Baseline: {baseline_at}  |  Current: {current_at}*")

    _append_warnings(lines, diff)
    return "\n".join(lines)


def _append_warnings(lines: list[str], diff: dict) -> None:
    """Append parse warning sections if non-empty."""
    b_warns = diff.get("baseline_parse_warnings", [])
    c_warns = diff.get("current_parse_warnings",  [])
    if b_warns:
        lines.append("")
        lines.append("#### Baseline Parse Warnings")
        for w in b_warns:
            lines.append(f"- {w}")
    if c_warns:
        lines.append("")
        lines.append("#### Current Parse Warnings")
        for w in c_warns:
            lines.append(f"- {w}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Diff two parse_nft_ruleset() JSON outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "baseline",
        help="Path to baseline JSON file (output of nftables_parser.py)",
    )
    ap.add_argument(
        "current",
        help="Path to current JSON file, or '-' to read from stdin",
    )
    ap.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation (default: 2)",
    )
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Print a human-readable Markdown summary instead of raw JSON",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="With --summary: include full rule dicts for each change entry",
    )
    args = ap.parse_args()

    if args.verbose and not args.summary:
        print(
            "Warning: --verbose has no effect without --summary",
            file=sys.stderr,
        )

    try:
        with open(args.baseline, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error reading baseline: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.current == "-":
            current = json.load(sys.stdin)
        else:
            with open(args.current, "r", encoding="utf-8") as fh:
                current = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error reading current: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        result = diff_rulesets(baseline, current)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.summary:
        print(summary_diff(result, verbose=args.verbose))
    else:
        print(json.dumps(result, indent=args.indent))


if __name__ == "__main__":
    main()
