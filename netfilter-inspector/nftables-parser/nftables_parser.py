#!/usr/bin/env python3
"""
nftables_parser.py — Parse nft --json list ruleset output into structured JSON.

Usage:
    python3 nftables_parser.py [file] [--indent N]          # parse to JSON (stdout)
    python3 nftables_parser.py [file] --explain             # parse + LLM explanation
    python3 nftables_parser.py [file] --explain-diff FILE2  # diff two files + LLM explanation
    python3 nftables_parser.py -                            # explicit stdin
    python3 nftables_parser.py --help

For --explain and --explain-diff:
    Requires GEMINI_API_KEY environment variable.
    Optional: NFTABLES_EXPLAIN_MODEL (default: gemini-2.0-flash)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Named priority map: nft string priority name → integer
# Ref: nftables standard priority values (net/netfilter/nf_tables_core.c)
# ---------------------------------------------------------------------------
_PRIORITY_MAP: dict[str, int] = {
    "raw":        -300,
    "conntrack":  -200,
    "mangle":     -150,
    "dstnat":     -100,
    "filter":        0,
    "security":     50,
    "srcnat":      100,
}


# ---------------------------------------------------------------------------
# Internal parse accumulator
# ---------------------------------------------------------------------------

@dataclass
class _ParseState:
    tables:   dict[str, dict] = field(default_factory=dict)
    warnings: list[str]       = field(default_factory=list)


# ---------------------------------------------------------------------------
# Expression hash
# ---------------------------------------------------------------------------

def _expression_hash(exprs: list) -> str:
    """
    SHA-256 of canonical JSON of the expression list, sorted keys, no whitespace.

    Inline counter expressions are excluded before hashing.  Counter packet/byte
    values increment on every capture, so including them would produce a different
    hash on every diff even when the rule policy is unchanged — causing the diff
    engine to emit a false-positive same-handle/different-hash warning for every
    counter-bearing rule.  raw_expressions always preserves the original counter
    so the active_drop_rules diagnostic is unaffected.
    """
    canonical_exprs = [
        e for e in exprs
        if not (isinstance(e, dict) and "counter" in e)
    ]
    canonical = json.dumps(canonical_exprs, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Right-hand side normaliser
# ---------------------------------------------------------------------------

def _right_to_str(right: Any) -> str:
    """Convert the right-hand side of a match expression to a display string."""
    if isinstance(right, int):
        return str(right)
    if isinstance(right, str):
        return right
    if isinstance(right, dict):
        if "prefix" in right:
            p = right["prefix"]
            return f"{p.get('addr', '')}/{p.get('len', '')}"
        if "range" in right:
            r = right["range"]
            return f"{r[0]}-{r[1]}"
        return json.dumps(right, sort_keys=True)
    return str(right)


# ---------------------------------------------------------------------------
# Match field extractor
# ---------------------------------------------------------------------------

def _extract_match_fields(match: dict, record: dict, warnings: list[str]) -> None:
    """
    Extract normalized fields from a match expression dict.
    Mutates record in-place. Appends to record["_opaque"] for unrecognized patterns.
    """
    try:
        op    = match.get("op", "==")
        left  = match.get("left", {})
        right = match.get("right")

        # Set reference: @setname in the right-hand side
        if isinstance(right, str) and right.startswith("@"):
            setname = right[1:]
            if setname not in record["set_references"]:
                record["set_references"].append(setname)
            # Cannot normalize a set-reference match to a specific address field
            record["_opaque"].append({"match": match})
            return

        # --- payload: ip/ip6 addresses ---
        if isinstance(left, dict) and "payload" in left:
            payload = left["payload"]
            proto   = payload.get("protocol", "")
            fld     = payload.get("field", "")

            if proto in ("ip", "ip6") and fld == "saddr":
                record["src_addr"] = _right_to_str(right)
                record["src_addr_negated"] = (op == "!=")
                return

            if proto in ("ip", "ip6") and fld == "daddr":
                record["dst_addr"] = _right_to_str(right)
                record["dst_addr_negated"] = (op == "!=")
                return

            if proto == "tcp" and fld == "dport":
                record["protocol"] = "tcp"
                record["dst_port"] = _right_to_str(right)
                record["dst_port_negated"] = (op == "!=")
                return

            if proto == "tcp" and fld == "sport":
                record["protocol"] = "tcp"
                record["src_port"] = _right_to_str(right)
                record["src_port_negated"] = (op == "!=")
                return

            if proto == "udp" and fld == "dport":
                record["protocol"] = "udp"
                record["dst_port"] = _right_to_str(right)
                record["dst_port_negated"] = (op == "!=")
                return

            if proto == "udp" and fld == "sport":
                record["protocol"] = "udp"
                record["src_port"] = _right_to_str(right)
                record["src_port_negated"] = (op == "!=")
                return

            # ICMP / ICMPv6 type and code
            if proto in ("icmp", "icmpv6") and fld == "type":
                record["protocol"] = proto
                record["icmp_type"] = _right_to_str(right)
                record["icmp_type_negated"] = (op == "!=")
                return

            if proto in ("icmp", "icmpv6") and fld == "code":
                record["protocol"] = proto
                record["icmp_code"] = _right_to_str(right)
                record["icmp_code_negated"] = (op == "!=")
                return

        # --- meta key ---
        if isinstance(left, dict) and "meta" in left:
            key = left["meta"].get("key", "")

            if key == "l4proto":
                record["protocol"] = _right_to_str(right)
                record["protocol_negated"] = (op == "!=")
                return

            if key == "iifname":
                record["in_interface"] = _right_to_str(right)
                record["in_interface_negated"] = (op == "!=")
                return

            if key == "oifname":
                record["out_interface"] = _right_to_str(right)
                record["out_interface_negated"] = (op == "!=")
                return

        # --- ct fields ---
        if isinstance(left, dict) and "ct" in left:
            ct_key = left["ct"].get("key")

            if ct_key == "state":
                if isinstance(right, list):
                    record["ct_state"] = right
                else:
                    record["ct_state"] = [str(right)]
                return

            if ct_key == "mark":
                record["ct_mark"] = _right_to_str(right)
                record["ct_mark_negated"] = (op == "!=")
                return

            if ct_key == "direction":
                record["ct_direction"] = _right_to_str(right)
                return

            if ct_key == "zone":
                record["ct_zone"] = _right_to_str(right)
                return

        # Unrecognized match pattern
        record["_opaque"].append({"match": match})

    except (KeyError, TypeError, AttributeError) as exc:
        warnings.append(f"Match field extraction error ({exc}): {match!r}")
        record["_opaque"].append({"match": match})


# ---------------------------------------------------------------------------
# Verdict extractor
# ---------------------------------------------------------------------------

def _extract_verdict(expr: dict) -> tuple[str | None, bool]:
    """
    Extract (verdict_str, verdict_stops_chain) from a single expression object.
    Returns (None, False) if the expression is not a terminal verdict.
    """
    if "accept" in expr:
        return ("accept", True)
    if "drop" in expr:
        return ("drop", True)
    if "reject" in expr:
        return ("reject", True)
    if "return" in expr:
        return ("return", False)
    return (None, False)


# ---------------------------------------------------------------------------
# Expression normaliser
# ---------------------------------------------------------------------------

def _normalize_expressions(exprs: list, warnings: list[str]) -> dict:
    """
    Walk the expression list and extract normalized fields.
    Returns a dict of extracted fields + _opaque (private) for unrecognised entries.
    """
    record: dict[str, Any] = {
        "verdict":               None,
        "verdict_stops_chain":   False,
        "protocol":              None,
        "dst_port":              None,
        "src_port":              None,
        "src_addr":              None,
        "dst_addr":              None,
        "in_interface":          None,
        "out_interface":         None,
        "ct_state":              None,
        "protocol_negated":      False,
        "src_addr_negated":      False,
        "dst_addr_negated":      False,
        "src_port_negated":      False,
        "dst_port_negated":      False,
        "in_interface_negated":  False,
        "out_interface_negated": False,
        # ICMP / ICMPv6 type and code (item 3)
        "icmp_type":             None,
        "icmp_type_negated":     False,
        "icmp_code":             None,
        "icmp_code_negated":     False,
        # Extended conntrack fields (item 4)
        "ct_mark":               None,
        "ct_mark_negated":       False,
        "ct_direction":          None,
        "ct_zone":               None,
        "is_log":                False,
        "log_prefix":            None,
        "jump_target":           None,
        "goto_target":           None,
        "set_references":        [],
        "_opaque":               [],
    }

    verdict_seen = False

    for expr in exprs:
        if not isinstance(expr, dict):
            warnings.append(f"Non-dict expression skipped: {expr!r}")
            continue

        try:
            # --- Terminal verdicts ---
            v, stops = _extract_verdict(expr)
            if v is not None:
                if verdict_seen:
                    warnings.append(
                        f"Multiple terminal verdicts in rule — subsequent verdict moved to "
                        f"opaque_expressions: {expr!r}"
                    )
                    record["_opaque"].append(expr)
                else:
                    record["verdict"] = v
                    record["verdict_stops_chain"] = stops
                    verdict_seen = True
                continue

            # --- Match ---
            if "match" in expr:
                _extract_match_fields(expr["match"], record, warnings)
                continue

            # --- Jump / Goto ---
            if "jump" in expr:
                record["jump_target"] = expr["jump"].get("target")
                continue

            if "goto" in expr:
                record["goto_target"] = expr["goto"].get("target")
                continue

            # --- Log ---
            if "log" in expr:
                record["is_log"] = True
                log_obj = expr["log"]
                if isinstance(log_obj, dict) and "prefix" in log_obj:
                    record["log_prefix"] = log_obj["prefix"]
                continue

            # --- Inline counter (non-terminal; packet/byte counts accessed via raw_expressions) ---
            if "counter" in expr:
                continue

            # --- Non-terminal known expressions (not opaque) ---
            if "limit" in expr or "quota" in expr:
                continue

            # --- Unrecognised ---
            top_key = next(iter(expr), "<empty>")
            warnings.append(
                f"Unrecognised expression type '{top_key}' moved to opaque_expressions"
            )
            record["_opaque"].append(expr)

        except (KeyError, TypeError, AttributeError) as exc:
            warnings.append(f"Expression processing error ({exc}): {expr!r}")
            record["_opaque"].append(expr)

    return record


# ---------------------------------------------------------------------------
# Object parsers
# ---------------------------------------------------------------------------

def _parse_table(obj: dict, state: _ParseState) -> None:
    """Register a table entry. Mutates state.tables."""
    family = obj.get("family")
    name   = obj.get("name")
    handle = obj.get("handle")

    if not family or not name:
        state.warnings.append(
            f"Table object missing 'family' or 'name' — skipped: {obj!r}"
        )
        return

    key = f"{family}/{name}"
    if key not in state.tables:
        state.tables[key] = {
            "family": family,
            "name":   name,
            "handle": handle,
            "chains": {},
            "sets":   {},
        }


def _parse_chain(obj: dict, state: _ParseState) -> None:
    """Register a chain under its table. Mutates state.tables."""
    family = obj.get("family")
    table  = obj.get("table")
    name   = obj.get("name")
    handle = obj.get("handle")

    if not family or not table or not name:
        state.warnings.append(
            f"Chain object missing required fields — skipped: {obj!r}"
        )
        return

    table_key = f"{family}/{table}"
    if table_key not in state.tables:
        state.warnings.append(
            f"Chain '{name}' references undeclared table '{table_key}' — table created implicitly"
        )
        state.tables[table_key] = {
            "family": family,
            "name":   table,
            "handle": None,
            "chains": {},
            "sets":   {},
        }

    hook   = obj.get("hook")
    c_type = obj.get("type")
    prio   = obj.get("prio")
    policy = obj.get("policy")

    # Normalise named priority string → integer
    if isinstance(prio, str):
        if prio in _PRIORITY_MAP:
            priority: Any = _PRIORITY_MAP[prio]
        else:
            state.warnings.append(
                f"Unknown chain priority string '{prio}' for chain '{name}' in "
                f"'{table_key}' — stored as-is"
            )
            priority = prio
    else:
        priority = prio

    is_base = hook is not None

    state.tables[table_key]["chains"][name] = {
        "name":          name,
        "handle":        handle,
        "is_base_chain": is_base,
        "type":          c_type if is_base else None,
        "hook":          hook,
        "priority":      priority if is_base else None,
        "policy":        policy if is_base else None,
        "rules":         [],
    }


def _parse_rule(obj: dict, state: _ParseState) -> None:
    """Parse a rule entry. Calls _normalize_expressions(). Appends to its chain."""
    family = obj.get("family")
    table  = obj.get("table")
    chain  = obj.get("chain")
    handle = obj.get("handle")

    if not family or not table or not chain:
        state.warnings.append(
            f"Rule missing 'family', 'table', or 'chain' — skipped: {obj!r}"
        )
        return

    if handle is None:
        state.warnings.append(
            f"Rule in {family}/{table}/{chain} has no 'handle' — skipped "
            f"(handle is required for diff identity)"
        )
        return

    table_key = f"{family}/{table}"
    if table_key not in state.tables:
        state.warnings.append(
            f"Rule references undeclared table '{table_key}' — table created implicitly"
        )
        state.tables[table_key] = {
            "family": family,
            "name":   table,
            "handle": None,
            "chains": {},
            "sets":   {},
        }

    if chain not in state.tables[table_key]["chains"]:
        state.warnings.append(
            f"Rule references undeclared chain '{chain}' in '{table_key}' — "
            f"chain created implicitly"
        )
        state.tables[table_key]["chains"][chain] = {
            "name":          chain,
            "handle":        None,
            "is_base_chain": False,
            "type":          None,
            "hook":          None,
            "priority":      None,
            "policy":        None,
            "rules":         [],
        }

    chain_obj = state.tables[table_key]["chains"][chain]
    if "expr" not in obj:
        state.warnings.append(
            f"Rule handle={obj.get('handle')} in '{table_key}/{chain}' "
            f"has no 'expr' field — included with verdict=null, raw_expressions=[]"
        )
    raw_exprs = obj.get("expr", [])

    # position: 1-based, assigned in parse order
    position = len(chain_obj["rules"]) + 1

    # expression_hash: SHA-256 of canonical JSON of raw_expressions
    expr_hash = _expression_hash(raw_exprs)

    # Normalise expressions
    norm = _normalize_expressions(raw_exprs, state.warnings)

    # Extract private accumulation fields before spreading norm into rule record
    opaque = norm.pop("_opaque")

    rule_record: dict[str, Any] = {
        "table":                 table_key,
        "chain":                 chain,
        "handle":                handle,
        "position":              position,
        "comment":               obj.get("comment"),   # set via nft add rule ... comment "text"
        **norm,
        "opaque_expressions":    opaque if opaque else None,
        "expression_hash":       expr_hash,
        "raw_expressions":       raw_exprs if raw_exprs else [],
    }

    chain_obj["rules"].append(rule_record)


def _parse_set(obj: dict, state: _ParseState, *, is_map: bool) -> None:
    # is_map: True when called for a "map" object; sets and maps share this
    # handler but produce different "type" values ("map" vs "set").
    # Design signature is _parse_set(obj, state) → None; is_map is an
    # implementation detail that avoids duplicating identical logic.
    """Register a named set (or map) under its table."""
    family = obj.get("family")
    table  = obj.get("table")
    name   = obj.get("name")
    handle = obj.get("handle")

    if not family or not table or not name:
        state.warnings.append(
            f"Set/map object missing required fields — skipped: {obj!r}"
        )
        return

    table_key = f"{family}/{table}"
    if table_key not in state.tables:
        state.warnings.append(
            f"Set '{name}' references undeclared table '{table_key}' — table created implicitly"
        )
        state.tables[table_key] = {
            "family": family,
            "name":   table,
            "handle": None,
            "chains": {},
            "sets":   {},
        }

    raw_elem = obj.get("elem")
    elements: Any = None if raw_elem is None else [_right_to_str(e) for e in raw_elem]

    state.tables[table_key]["sets"][name] = {
        "name":     name,
        "handle":   handle,
        "type":     obj.get("type"),
        "is_map":   is_map,
        "elements": elements,
        "flags":    obj.get("flags", []),
        "timeout":  obj.get("timeout"),
    }


# ---------------------------------------------------------------------------
# Diagnostics pass
# ---------------------------------------------------------------------------

def _get_inline_packet_count(raw_exprs: list) -> int | None:
    """Extract packet count from an inline counter expression in a rule."""
    for expr in raw_exprs:
        if isinstance(expr, dict) and "counter" in expr:
            ctr = expr["counter"]
            if isinstance(ctr, dict):
                return ctr.get("packets")
    return None


def _run_diagnostics(tables: dict) -> dict:
    """Compute the diagnostics section from the fully populated tables dict."""
    drop_policy_chains:     list[str]  = []
    accept_policy_chains:   list[str]  = []
    active_drop_rules:      list[dict] = []
    unresolved_chain_jumps: list[dict] = []
    inet_tables:            list[str]  = []
    sets_referenced:        dict[str, dict] = {}

    # Build per-table chain name sets for unresolved jump detection
    chain_names_by_table: dict[str, set[str]] = {
        tk: set(td["chains"].keys()) for tk, td in tables.items()
    }

    for table_key, table_data in sorted(tables.items()):
        if table_data["family"] == "inet":
            inet_tables.append(table_key)

        for chain_name, chain_data in sorted(table_data["chains"].items()):
            policy     = chain_data.get("policy")
            chain_path = f"{table_key}/{chain_name}"

            if policy == "drop":
                drop_policy_chains.append(chain_path)
            elif policy == "accept":
                accept_policy_chains.append(chain_path)

            for rule in chain_data["rules"]:
                # active_drop_rules: verdict=drop AND inline counter packets > 0
                if rule.get("verdict") == "drop":
                    pkt = _get_inline_packet_count(rule.get("raw_expressions", []))
                    if pkt is not None and pkt > 0:
                        active_drop_rules.append(rule)

                # unresolved_chain_jumps
                for target_field in ("jump_target", "goto_target"):
                    target = rule.get(target_field)
                    if target is not None:
                        if target not in chain_names_by_table.get(table_key, set()):
                            entry: dict[str, Any] = {
                                "table":    table_key,
                                "chain":    chain_name,
                                "handle":   rule["handle"],
                                "position": rule["position"],
                            }
                            entry[target_field] = target
                            unresolved_chain_jumps.append(entry)

                # sets_referenced_in_rules
                for setname in rule.get("set_references", []):
                    if setname not in sets_referenced:
                        found = setname in table_data.get("sets", {})
                        sets_referenced[setname] = {
                            "table": table_key,
                            "found": found,
                        }

    return {
        "drop_policy_chains":       drop_policy_chains,
        "accept_policy_chains":     accept_policy_chains,
        "active_drop_rules":        active_drop_rules,
        "unresolved_chain_jumps":   unresolved_chain_jumps,
        "inet_tables":              inet_tables,
        "sets_referenced_in_rules": sets_referenced,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_nft_ruleset(text: str) -> dict:
    """
    Parse complete nft --json list ruleset text into structured dict.

    Raises ValueError for:
      - Non-JSON input
      - Missing 'nftables' key
      - 'nftables' value is not a list
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Input is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict) or "nftables" not in raw:
        raise ValueError(
            "Input is not nft --json list ruleset output: missing 'nftables' key"
        )

    nft_list = raw["nftables"]
    if not isinstance(nft_list, list):
        raise ValueError("'nftables' must be a list")

    state           = _ParseState()
    nft_version     = None
    json_schema_ver = None
    metainfo_seen   = False

    if not nft_list:
        state.warnings.append("nftables list is empty — no tables configured")

    for idx, obj in enumerate(nft_list):
        if not isinstance(obj, dict):
            state.warnings.append(
                f"Non-dict entry at index {idx} — skipped: {obj!r}"
            )
            continue

        if not obj:
            state.warnings.append(f"Empty object at index {idx} — skipped")
            continue

        obj_type = next(iter(obj))

        if obj_type == "metainfo":
            meta            = obj["metainfo"]
            nft_version     = meta.get("version")
            json_schema_ver = meta.get("json_schema_version")
            metainfo_seen   = True

        elif obj_type == "table":
            _parse_table(obj["table"], state)

        elif obj_type == "chain":
            _parse_chain(obj["chain"], state)

        elif obj_type == "rule":
            _parse_rule(obj["rule"], state)

        elif obj_type == "set":
            _parse_set(obj["set"], state, is_map=False)

        elif obj_type == "map":
            _parse_set(obj["map"], state, is_map=True)

        elif obj_type in ("counter", "quota", "limit"):
            state.warnings.append(
                f"Named '{obj_type}' object encountered — captured as metadata only "
                f"(name={obj[obj_type].get('name')!r})"
            )

        elif obj_type == "flowtable":
            # Structural capture only per design §6
            ft       = obj["flowtable"]
            family   = ft.get("family")
            table_n  = ft.get("table")
            ft_name  = ft.get("name")
            if family and table_n:
                tkey = f"{family}/{table_n}"
                if tkey in state.tables:
                    state.tables[tkey].setdefault("flowtables", {})[ft_name] = {
                        "name":   ft_name,
                        "handle": ft.get("handle"),
                        "hook":   ft.get("hook"),
                    }

        else:
            state.warnings.append(
                f"Unknown nftables object type at index {idx}: "
                f"keys={list(obj.keys())!r}"
            )

    if not metainfo_seen:
        state.warnings.append(
            "metainfo object not found in nftables list — "
            "nft_version and json_schema_version will be null"
        )

    diagnostics = _run_diagnostics(state.tables)

    return {
        "parsed_at":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_format":        "nft-json",
        "nft_version":         nft_version,
        "json_schema_version": json_schema_ver,
        "tables":              state.tables,
        "diagnostics":         diagnostics,
        "parse_warnings":      state.warnings,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse nft --json list ruleset output into structured JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "file",
        nargs="?",
        help="Path to nft --json list ruleset JSON file. Reads stdin if omitted or '-'. "
             "Required when using --explain or --explain-diff.",
    )
    ap.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation for output (default: 2)",
    )
    ap.add_argument(
        "--explain",
        action="store_true",
        help="Generate an LLM-powered explanation of the parsed firewall state. "
             "Requires GEMINI_API_KEY. Writes snapshot JSON to "
             "<input>_snapshot.json; explanation goes to stdout (or --output).",
    )
    ap.add_argument(
        "--explain-diff",
        metavar="FILE2",
        dest="explain_diff",
        help="Compare FILE (baseline) with FILE2 (current) and generate an "
             "LLM-powered explanation of what changed. Requires GEMINI_API_KEY. "
             "Writes both snapshot JSONs and the diff JSON to disk; explanation "
             "goes to stdout (or --output).",
    )
    ap.add_argument(
        "--output",
        metavar="PATH",
        help="Write explanation to PATH instead of stdout. "
             "Only valid with --explain or --explain-diff.",
    )
    args = ap.parse_args()

    # ---- Validate flag combinations ----
    if args.output and not (args.explain or args.explain_diff):
        ap.error("--output is only valid with --explain or --explain-diff")

    if (args.explain or args.explain_diff) and (not args.file or args.file == "-"):
        ap.error("--explain and --explain-diff require a FILE argument (stdin not supported)")

    # ---- Read primary input ----
    try:
        if args.file and args.file != "-":
            with open(args.file, "r", encoding="utf-8") as fh:
                text = fh.read()
            input_path = Path(args.file)
        else:
            text = sys.stdin.read()
            input_path = None
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_nft_ruleset(text)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # ---- explain-diff mode ----
    if args.explain_diff:
        from nftables_explain import explain_diff as _explain_diff
        from nftables_diff import diff_rulesets

        current_path = Path(args.explain_diff)
        try:
            with open(current_path, "r", encoding="utf-8") as fh:
                text2 = fh.read()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        try:
            result2 = parse_nft_ruleset(text2)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        snap1_path = input_path.with_name(input_path.stem + "_snapshot.json")
        snap2_path = current_path.with_name(current_path.stem + "_snapshot.json")
        diff_path = input_path.with_name(
            f"{input_path.stem}_vs_{current_path.stem}_diff.json"
        )

        snap1_path.write_text(json.dumps(result, indent=args.indent), encoding="utf-8")
        snap2_path.write_text(json.dumps(result2, indent=args.indent), encoding="utf-8")

        diff_result = diff_rulesets(result, result2)
        diff_path.write_text(json.dumps(diff_result, indent=args.indent), encoding="utf-8")

        print(f"Baseline snapshot: {snap1_path}", file=sys.stderr)
        print(f"Current snapshot:  {snap2_path}", file=sys.stderr)
        print(f"Diff JSON:         {diff_path}", file=sys.stderr)

        explanation = _explain_diff(diff_result)
        _write_explanation(explanation, args.output)
        return

    # ---- explain mode ----
    if args.explain:
        from nftables_explain import explain_snapshot as _explain_snapshot

        snap_path = input_path.with_name(input_path.stem + "_snapshot.json")
        snap_path.write_text(json.dumps(result, indent=args.indent), encoding="utf-8")
        print(f"Snapshot JSON: {snap_path}", file=sys.stderr)

        explanation = _explain_snapshot(result)
        _write_explanation(explanation, args.output)
        return

    # ---- normal mode: JSON to stdout ----
    print(json.dumps(result, indent=args.indent))


def _write_explanation(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        print(f"Explanation:   {output_path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
