#!/usr/bin/env python3
"""
iptables_parser.py — Parse iptables-save output into structured JSON.

Usage:
    python3 iptables_parser.py [file]      # reads file or stdin
    python3 iptables_parser.py --help
    python3 iptables_parser.py --indent N  # JSON indentation (default 2)
"""
from __future__ import annotations

import sys
import json
import argparse
import re
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict, Set

# ---------------------------------------------------------------------------
# Known targets that terminate chain traversal
# ---------------------------------------------------------------------------
TERMINATING_TARGETS = {
    "ACCEPT", "DROP", "REJECT", "RETURN", "NFQUEUE",
    "MASQUERADE", "SNAT", "DNAT",
}
NON_TERMINATING_TARGETS = {
    "LOG", "NFLOG", "MARK", "CONNMARK",
}
BUILTIN_TARGETS = TERMINATING_TARGETS | NON_TERMINATING_TARGETS

# Built-in chain names per table (for type detection)
BUILTIN_CHAINS = {
    "filter": {"INPUT", "FORWARD", "OUTPUT"},
    "nat":    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
    "mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
    "raw":    {"PREROUTING", "OUTPUT"},
    "security": {"INPUT", "FORWARD", "OUTPUT"},
}


# ---------------------------------------------------------------------------
# Tokenizer — handles quoted strings
# ---------------------------------------------------------------------------
def tokenize(line: str) -> tuple[list[str], bool]:
    """Split a rule line into tokens, preserving quoted strings as single tokens.

    Returns (tokens, had_unclosed_quote). If a quoted string was never closed,
    the partial content is flushed as a bare token and had_unclosed_quote is True.
    """
    tokens = []
    current = []
    in_quotes = False
    quote_char = None
    i = 0
    while i < len(line):
        c = line[i]
        if in_quotes:
            if c == quote_char:
                in_quotes = False
                # Keep the full quoted token (quotes will be stripped by caller)
                tokens.append(quote_char + "".join(current) + quote_char)
                current = []
            else:
                current.append(c)
        else:
            if c in ('"', "'"):
                if current:
                    # flush any partial token before quote start
                    tokens.append("".join(current))
                    current = []
                in_quotes = True
                quote_char = c
            elif c == " " or c == "\t":
                if current:
                    tokens.append("".join(current))
                    current = []
            else:
                current.append(c)
        i += 1
    if current:
        tokens.append("".join(current))
    # in_quotes=True means the string ended before the closing quote was found
    return tokens, in_quotes


def strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


# ---------------------------------------------------------------------------
# Rule parser
# ---------------------------------------------------------------------------

def _make_rule_record(table: str, chain: str, position: int) -> dict:
    return {
        "table": table,
        "chain": chain,
        "position": position,
        "protocol": None,
        "protocol_negated": False,
        "source": None,
        "source_negated": False,
        "destination": None,
        "destination_negated": False,
        "in_interface": None,
        "in_interface_negated": False,
        "out_interface": None,
        "out_interface_negated": False,
        "dst_port": None,
        "dst_port_negated": False,
        "src_port": None,
        "src_port_negated": False,
        "target": "",
        "target_params": None,
        "target_stops_chain_traversal": False,
        "match_extensions": {},
        "opaque_extensions": None,
        "raw_rule": "",
        "packet_count": None,
        "byte_count": None,
    }


def _stops_traversal(target: str, all_chain_names: set[str]) -> Any:
    if target in TERMINATING_TARGETS:
        return True
    if target in NON_TERMINATING_TARGETS:
        return False
    # Jump to user-defined chain or unknown target => conditional
    return "conditional"


def parse_rule_line(
    raw_line: str,
    table: str,
    chain_positions: dict[str, int],
    all_chain_names: set[str],
    parse_warnings: list[str],
    family: str = "ipv4",
) -> dict | None:
    """Parse a single -A rule line and return a rule record."""
    line = raw_line.strip()

    # Strip leading counter [pkts:bytes]
    packet_count = None
    byte_count = None
    if line.startswith("["):
        m = re.match(r"^\[(\d+):(\d+)\]\s*", line)
        if m:
            packet_count = int(m.group(1))
            byte_count = int(m.group(2))
            line = line[m.end():]

    tokens, unclosed_quote = tokenize(line)
    if unclosed_quote:
        parse_warnings.append(
            f"Unclosed quoted string in table '{table}' rule — partial content flushed: {line!r}"
        )
    if not tokens or tokens[0] != "-A":
        return None

    # tokens[1] is chain name
    if len(tokens) < 2:
        return None
    chain = tokens[1]

    chain_positions[chain] = chain_positions.get(chain, 0) + 1
    position = chain_positions[chain]

    record = _make_rule_record(table, chain, position)
    record["raw_rule"] = raw_line.rstrip("\n")
    record["packet_count"] = packet_count
    record["byte_count"] = byte_count

    # Parse remaining tokens
    i = 2
    opaque_parts = []

    while i < len(tokens):
        tok = tokens[i]

        # Negation prefix (modern style: ! before flag)
        negate_next = False
        if tok == "!":
            negate_next = True
            i += 1
            if i >= len(tokens):
                break
            tok = tokens[i]

        # ---- Protocol ----
        if tok in ("-p", "--protocol"):
            # old-style negation: -p ! tcp  (advance only 1 so tokens[i+1] reads the value)
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["protocol_negated"] = True
                i += 1
            else:
                record["protocol_negated"] = negate_next
            if i + 1 < len(tokens):
                record["protocol"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        # ---- Source ----
        elif tok in ("-s", "--source", "--src"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["source_negated"] = True
                i += 1
            else:
                record["source_negated"] = negate_next
            if i + 1 < len(tokens):
                record["source"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        # ---- Destination ----
        elif tok in ("-d", "--destination", "--dst"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["destination_negated"] = True
                i += 1
            else:
                record["destination_negated"] = negate_next
            if i + 1 < len(tokens):
                record["destination"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        # ---- In interface ----
        elif tok in ("-i", "--in-interface"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["in_interface_negated"] = True
                i += 1
            else:
                record["in_interface_negated"] = negate_next
            if i + 1 < len(tokens):
                record["in_interface"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        # ---- Out interface ----
        elif tok in ("-o", "--out-interface"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["out_interface_negated"] = True
                i += 1
            else:
                record["out_interface_negated"] = negate_next
            if i + 1 < len(tokens):
                record["out_interface"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        # ---- Match module ----
        elif tok == "-m":
            i += 1
            if i < len(tokens):
                module = tokens[i]
                i += 1
                i = _parse_match_module(
                    module, tokens, i, record, parse_warnings
                )
            # negate_next consumed by module (or ignored)

        # ---- Jump target ----
        elif tok in ("-j", "--jump"):
            i += 1
            if i < len(tokens):
                record["target"] = tokens[i]
                i += 1
                i = _parse_target_params(record["target"], tokens, i, record, parse_warnings, family)

        # ---- goto (treat like jump for our purposes) ----
        elif tok in ("-g", "--goto"):
            i += 1
            if i < len(tokens):
                record["target"] = tokens[i]
                i += 1

        # ---- dst-port shorthand (from -p tcp -m tcp --dport) ----
        # These are handled inside the tcp/udp module parser, but if they
        # appear outside a -m context (shouldn't normally happen):
        elif tok in ("--dport", "--destination-port"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["dst_port_negated"] = True
                i += 1
            else:
                record["dst_port_negated"] = negate_next
            if i + 1 < len(tokens):
                record["dst_port"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        elif tok in ("--sport", "--source-port"):
            if i + 1 < len(tokens) and tokens[i + 1] == "!":
                record["src_port_negated"] = True
                i += 1
            else:
                record["src_port_negated"] = negate_next
            if i + 1 < len(tokens):
                record["src_port"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        else:
            # Unknown flag — collect as opaque
            opaque_parts.append(tok)
            i += 1

    if opaque_parts:
        existing = record["opaque_extensions"] or ""
        record["opaque_extensions"] = (existing + " " if existing else "") + " ".join(opaque_parts)
        parse_warnings.append(
            f"Unknown token(s) in {table}/{chain} rule {position}: {' '.join(opaque_parts)}"
        )

    # EH05: warn if -j was never encountered
    if record["target"] == "":
        parse_warnings.append(
            f"Rule in {table}/{chain} at position {position} has no -j target "
            f"(malformed rule) — raw: {record['raw_rule'].strip()}"
        )

    # Determine target_stops_chain_traversal
    target = record["target"]
    record["target_stops_chain_traversal"] = _stops_traversal(target, all_chain_names)

    return record


def _parse_match_module(
    module: str,
    tokens: list[str],
    i: int,
    record: dict,
    parse_warnings: list[str],
) -> int:
    """Parse match module flags starting at tokens[i]. Returns new i."""
    ext = record["match_extensions"]

    if module == "conntrack":
        ct = ext.setdefault("conntrack", {"ctstates": [], "negated": False})
        while i < len(tokens):
            t = tokens[i]
            if t == "!":
                ct["negated"] = True
                i += 1
            elif t in ("--ctstate", "--ctstates"):
                i += 1
                if i < len(tokens):
                    ct["ctstates"] = tokens[i].split(",")
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "state":
        st = ext.setdefault("state", {"states": [], "negated": False})
        while i < len(tokens):
            t = tokens[i]
            if t == "!":
                st["negated"] = True
                i += 1
            elif t == "--state":
                i += 1
                if i < len(tokens):
                    st["states"] = tokens[i].split(",")
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "multiport":
        mp = ext.setdefault("multiport", {})
        while i < len(tokens):
            t = tokens[i]
            neg = False
            if t == "!":
                neg = True
                i += 1
                if i >= len(tokens):
                    break
                t = tokens[i]
            if t in ("--dports", "--destination-ports"):
                i += 1
                if i < len(tokens):
                    mp["destination_ports"] = tokens[i].split(",")
                    mp["destination_ports_negated"] = neg
                    i += 1
            elif t in ("--sports", "--source-ports"):
                i += 1
                if i < len(tokens):
                    mp["source_ports"] = tokens[i].split(",")
                    mp["source_ports_negated"] = neg
                    i += 1
            elif t == "--ports":
                i += 1
                if i < len(tokens):
                    mp["ports"] = tokens[i].split(",")
                    mp["ports_negated"] = neg
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "tcp":
        tc = {}
        while i < len(tokens):
            t = tokens[i]
            neg = False
            if t == "!":
                neg = True
                i += 1
                if i >= len(tokens):
                    break
                t = tokens[i]
            if t in ("--dport", "--destination-port"):
                i += 1
                if i < len(tokens):
                    record["dst_port"] = tokens[i]
                    record["dst_port_negated"] = neg
                    i += 1
            elif t in ("--sport", "--source-port"):
                i += 1
                if i < len(tokens):
                    record["src_port"] = tokens[i]
                    record["src_port_negated"] = neg
                    i += 1
            elif t == "--tcp-flags":
                # two args: mask match
                i += 1
                if i + 1 < len(tokens):
                    tc["flags_mask"] = tokens[i]
                    tc["flags_match"] = tokens[i + 1]
                    i += 2
            elif t == "--syn":
                tc["flags_mask"] = "SYN,RST,ACK,FIN"
                tc["flags_match"] = "SYN"
                i += 1
            elif t.startswith("-"):
                break
            else:
                break
        if tc:
            ext["tcp"] = tc
        return i

    elif module == "udp":
        while i < len(tokens):
            t = tokens[i]
            neg = False
            if t == "!":
                neg = True
                i += 1
                if i >= len(tokens):
                    break
                t = tokens[i]
            if t in ("--dport", "--destination-port"):
                i += 1
                if i < len(tokens):
                    record["dst_port"] = tokens[i]
                    record["dst_port_negated"] = neg
                    i += 1
            elif t in ("--sport", "--source-port"):
                i += 1
                if i < len(tokens):
                    record["src_port"] = tokens[i]
                    record["src_port_negated"] = neg
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "icmp":
        ic = ext.setdefault("icmp", {"icmp_type": None, "negated": False})
        while i < len(tokens):
            t = tokens[i]
            if t == "!":
                ic["negated"] = True
                i += 1
            elif t in ("--icmp-type",):
                i += 1
                if i < len(tokens):
                    ic["icmp_type"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module in ("icmp6", "ipv6-icmp"):
        ic = ext.setdefault("icmp6", {"icmpv6_type": None, "negated": False})
        while i < len(tokens):
            t = tokens[i]
            if t == "!":
                ic["negated"] = True
                i += 1
            elif t == "--icmpv6-type":
                i += 1
                if i < len(tokens):
                    ic["icmpv6_type"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "addrtype":
        at = ext.setdefault("addrtype", {})
        while i < len(tokens):
            t = tokens[i]
            neg = False
            if t == "!":
                neg = True
                i += 1
                if i >= len(tokens):
                    break
                t = tokens[i]
            if t == "--dst-type":
                i += 1
                if i < len(tokens):
                    at["dst_type"] = tokens[i]
                    at["dst_type_negated"] = neg
                    i += 1
            elif t == "--src-type":
                i += 1
                if i < len(tokens):
                    at["src_type"] = tokens[i]
                    at["src_type_negated"] = neg
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "owner":
        ow = ext.setdefault("owner", {})
        while i < len(tokens):
            t = tokens[i]
            if t == "--uid-owner":
                i += 1
                if i < len(tokens):
                    ow["uid_owner"] = tokens[i]
                    i += 1
            elif t == "--gid-owner":
                i += 1
                if i < len(tokens):
                    ow["gid_owner"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "limit":
        lm = ext.setdefault("limit", {})
        while i < len(tokens):
            t = tokens[i]
            if t == "--limit":
                i += 1
                if i < len(tokens):
                    lm["rate"] = tokens[i]
                    i += 1
            elif t == "--limit-burst":
                i += 1
                if i < len(tokens):
                    lm["burst"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "comment":
        cm = ext.setdefault("comment", {})
        while i < len(tokens):
            t = tokens[i]
            if t == "--comment":
                i += 1
                if i < len(tokens):
                    cm["comment_text"] = strip_quotes(tokens[i])
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "mark":
        # match extension (different from MARK target)
        mk = ext.setdefault("mark", {"mark_value": None, "mask": "0xffffffff", "negated": False})
        while i < len(tokens):
            t = tokens[i]
            if t == "!":
                mk["negated"] = True
                i += 1
            elif t == "--mark":
                i += 1
                if i < len(tokens):
                    val = tokens[i]
                    i += 1
                    if "/" in val:
                        parts = val.split("/", 1)
                        mk["mark_value"] = parts[0]
                        mk["mask"] = parts[1]
                    else:
                        mk["mark_value"] = val
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "iprange":
        ir = ext.setdefault("iprange", {})
        while i < len(tokens):
            t = tokens[i]
            neg = False
            if t == "!":
                neg = True
                i += 1
                if i >= len(tokens):
                    break
                t = tokens[i]
            if t == "--src-range":
                i += 1
                if i < len(tokens):
                    ir["src_range"] = tokens[i]
                    ir["src_range_negated"] = neg
                    i += 1
            elif t == "--dst-range":
                i += 1
                if i < len(tokens):
                    ir["dst_range"] = tokens[i]
                    ir["dst_range_negated"] = neg
                    i += 1
            elif t.startswith("-"):
                break
            else:
                break
        return i

    elif module == "set":
        # ipset module — parse as opaque
        opaque = [f"-m {module}"]
        while i < len(tokens) and (tokens[i].startswith("--") or not tokens[i].startswith("-")):
            opaque.append(tokens[i])
            i += 1
        existing = record["opaque_extensions"] or ""
        record["opaque_extensions"] = (existing + " " if existing else "") + " ".join(opaque)
        parse_warnings.append(
            f"Unrecognized match module '{module}' stored in opaque_extensions"
        )
        return i

    else:
        # Unknown module — consume flags that look like --xxx val
        opaque_parts = [f"-m {module}"]
        while i < len(tokens):
            t = tokens[i]
            if t.startswith("--"):
                opaque_parts.append(t)
                i += 1
                # consume next token if it doesn't start with -
                if i < len(tokens) and not tokens[i].startswith("-"):
                    opaque_parts.append(tokens[i])
                    i += 1
            elif t == "!":
                opaque_parts.append(t)
                i += 1
            elif t.startswith("-"):
                break
            else:
                # bare value — consume
                opaque_parts.append(t)
                i += 1
        record["opaque_extensions"] = (
            (record["opaque_extensions"] + " " if record["opaque_extensions"] else "")
            + " ".join(opaque_parts)
        )
        parse_warnings.append(
            f"Unrecognized match module '{module}' stored in opaque_extensions"
        )
        return i


def _parse_target_params(
    target: str,
    tokens: list[str],
    i: int,
    record: dict,
    parse_warnings: list[str],
    family: str = "ipv4",
) -> int:
    """Parse target-specific parameters. Returns new i."""

    if target == "REJECT":
        default_reject = "icmp-port-unreachable" if family == "ipv4" else "icmp6-port-unreachable"
        params = {"reject_with": default_reject}
        while i < len(tokens):
            t = tokens[i]
            if t == "--reject-with":
                i += 1
                if i < len(tokens):
                    params["reject_with"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params
        return i

    elif target == "SNAT":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--to-source":
                i += 1
                if i < len(tokens):
                    params["to_source"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params or None
        return i

    elif target == "DNAT":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--to-destination":
                i += 1
                if i < len(tokens):
                    params["to_destination"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params or None
        return i

    elif target == "MASQUERADE":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--to-ports":
                i += 1
                if i < len(tokens):
                    params["to_ports"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params if params else None
        return i

    elif target == "NFQUEUE":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--queue-num":
                i += 1
                if i < len(tokens):
                    params["queue_num"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params or None
        return i

    elif target == "LOG":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--log-prefix":
                i += 1
                if i < len(tokens):
                    params["log_prefix"] = strip_quotes(tokens[i])
                    i += 1
            elif t == "--log-level":
                i += 1
                if i < len(tokens):
                    params["log_level"] = tokens[i]
                    i += 1
            elif t == "--log-tcp-sequence":
                params["log_tcp_sequence"] = True
                i += 1
            elif t == "--log-tcp-options":
                params["log_tcp_options"] = True
                i += 1
            elif t == "--log-ip-options":
                params["log_ip_options"] = True
                i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params if params else None
        return i

    elif target == "MARK":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--set-xmark":
                i += 1
                if i < len(tokens):
                    val = tokens[i]
                    i += 1
                    if "/" in val:
                        parts = val.split("/", 1)
                        params["set_xmark_value"] = parts[0]
                        params["set_xmark_mask"] = parts[1]
                    else:
                        params["set_xmark_value"] = val
                        params["set_xmark_mask"] = "0xffffffff"
            elif t == "--set-mark":
                i += 1
                if i < len(tokens):
                    val = tokens[i]
                    i += 1
                    if "/" in val:
                        parts = val.split("/", 1)
                        params["set_xmark_value"] = parts[0]
                        params["set_xmark_mask"] = parts[1]
                    else:
                        params["set_xmark_value"] = val
                        params["set_xmark_mask"] = "0xffffffff"
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params or None
        return i

    elif target == "CONNMARK":
        params = {}
        while i < len(tokens):
            t = tokens[i]
            if t == "--save-mark":
                params["save_mark"] = True
                i += 1
            elif t == "--restore-mark":
                params["restore_mark"] = True
                i += 1
            elif t == "--set-xmark":
                i += 1
                if i < len(tokens):
                    params["set_xmark"] = tokens[i]
                    i += 1
            elif t.startswith("-"):
                break
            else:
                i += 1
        record["target_params"] = params or None
        return i

    else:
        # Unknown target — no params to parse (return chain jump has no params either)
        return i


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_iptables_save(text: str, family: str = "ipv4") -> dict:
    if family not in ("ipv4", "ipv6"):
        raise ValueError(f"Invalid family {family!r}: must be 'ipv4' or 'ipv6'")
    lines = text.splitlines()
    parse_warnings: list[str] = []
    tables: dict[str, Any] = {}

    current_table: str | None = None
    # chain_meta: {chain_name: {type, default_policy, policy_packet_count, policy_byte_count, rules}}
    chain_meta: dict[str, dict] = {}
    # chain_positions tracks 1-based position within each chain
    chain_positions: dict[str, int] = {}
    base_format = "ip6tables-save" if family == "ipv6" else "iptables-save"
    input_format = base_format
    commit_seen = False

    def flush_table():
        nonlocal current_table, chain_meta, chain_positions, commit_seen
        if current_table is not None:
            if not commit_seen:
                parse_warnings.append(
                    f"Table '{current_table}' block ended without COMMIT — including partial results"
                )
            tables[current_table] = {"chains": chain_meta}
        current_table = None
        chain_meta = {}
        chain_positions = {}
        commit_seen = False

    for line_raw in lines:
        line = line_raw.strip()

        # Skip blanks and comments
        if not line or line.startswith("#"):
            continue

        # Table header
        if line.startswith("*"):
            flush_table()
            current_table = line[1:].strip()
            commit_seen = False
            continue

        # COMMIT
        if line == "COMMIT":
            commit_seen = True
            flush_table()
            continue

        # Chain definition: :CHAIN POLICY [pkts:bytes]
        if line.startswith(":"):
            if current_table is None:
                parse_warnings.append(f"Chain definition outside table block: {line}")
                continue
            m = re.match(r"^:(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]", line)
            if not m:
                parse_warnings.append(f"Could not parse chain definition: {line}")
                continue
            cname = m.group(1)
            policy_str = m.group(2)
            pkt_count = int(m.group(3))
            byte_count = int(m.group(4))

            # Determine policy — REJECT is not a valid chain policy
            if policy_str == "REJECT":
                parse_warnings.append(
                    f"Invalid chain policy 'REJECT' for chain '{cname}' in table '{current_table}'"
                    f" — chain included with default_policy: null"
                )
                default_policy = None
            elif policy_str == "-":
                default_policy = None
            else:
                default_policy = policy_str

            # Determine builtin vs user-defined
            table_builtins = BUILTIN_CHAINS.get(current_table, set())
            chain_type = "builtin" if cname in table_builtins else "user-defined"

            chain_meta[cname] = {
                "type": chain_type,
                "default_policy": default_policy,
                "policy_packet_count": pkt_count,
                "policy_byte_count": byte_count,
                "rules": [],
            }
            continue

        # Rule line: -A ... or [pkts:bytes] -A ...
        if line.startswith("-A") or line.startswith("["):
            if current_table is None:
                parse_warnings.append(f"Rule outside table block: {line}")
                continue

            # Detect format — any rule with a counter prefix marks the file as counters format
            if line.startswith("["):
                input_format = base_format + "-counters"

            all_chain_names = set(chain_meta.keys())
            record = parse_rule_line(
                line_raw, current_table, chain_positions, all_chain_names, parse_warnings, family
            )
            if record is None:
                parse_warnings.append(f"Could not parse rule line: {line}")
                continue

            chain = record["chain"]
            if chain not in chain_meta:
                # Implicitly create chain if not yet declared
                parse_warnings.append(
                    f"Rule references undeclared chain '{chain}' in table '{current_table}' — creating implicitly"
                )
                table_builtins = BUILTIN_CHAINS.get(current_table, set())
                chain_type = "builtin" if chain in table_builtins else "user-defined"
                chain_meta[chain] = {
                    "type": chain_type,
                    "default_policy": None,
                    "policy_packet_count": 0,
                    "policy_byte_count": 0,
                    "rules": [],
                }

            chain_meta[chain]["rules"].append(record)
            continue

        # Anything else
        parse_warnings.append(f"Unrecognized line: {line}")

    # Final flush if file ended without COMMIT
    if current_table is not None:
        flush_table()

    # EH06: warn on inconsistent counter prefixes within any chain
    for tname, tdata in tables.items():
        for cname, cdata in tdata["chains"].items():
            rules = cdata["rules"]
            with_counters = [r for r in rules if r["packet_count"] is not None]
            without_counters = [r for r in rules if r["packet_count"] is None]
            if with_counters and without_counters:
                parse_warnings.append(
                    f"Table '{tname}', chain '{cname}': inconsistent counter prefixes — "
                    f"{len(with_counters)} rule(s) have counters, "
                    f"{len(without_counters)} rule(s) do not. "
                    f"Rules without counters have packet_count/byte_count set to null."
                )

    # -----------------------------------------------------------------------
    # Diagnostics pass
    # -----------------------------------------------------------------------
    drop_policy_chains: list[str] = []
    accept_policy_chains: list[str] = []

    for tname, tdata in tables.items():
        for cname, cdata in tdata["chains"].items():
            pol = cdata["default_policy"]
            if pol == "DROP":
                drop_policy_chains.append(f"{tname}/{cname}")
            elif pol == "ACCEPT":
                accept_policy_chains.append(f"{tname}/{cname}")

    # conntrack_position_warnings
    conntrack_position_warnings = []
    for tname in ("filter",):
        if tname not in tables:
            continue
        for cname in ("INPUT", "FORWARD"):
            if cname not in tables[tname]["chains"]:
                continue
            rules = tables[tname]["chains"][cname]["rules"]
            for rule in rules:
                ext = rule.get("match_extensions", {})
                is_ct = False
                ct_states = []
                if "conntrack" in ext:
                    ct_states = ext["conntrack"].get("ctstates", [])
                    is_ct = True
                elif "state" in ext:
                    ct_states = ext["state"].get("states", [])
                    is_ct = True

                if is_ct and rule["target"] == "ACCEPT":
                    interested = {"ESTABLISHED", "RELATED"}
                    if interested & set(ct_states):
                        # Check for DROP/REJECT rules at lower positions
                        preceding_drops = [
                            {"position": r["position"], "raw_rule": r["raw_rule"]}
                            for r in rules
                            if r["position"] < rule["position"]
                            and r["target"] in ("DROP", "REJECT")
                        ]
                        if preceding_drops:
                            conntrack_position_warnings.append({
                                "table": tname,
                                "chain": cname,
                                "conntrack_rule_position": rule["position"],
                                "conntrack_raw_rule": rule["raw_rule"],
                                "preceding_drop_rules": preceding_drops,
                            })

    # active_drop_rules — rules with DROP/REJECT that have a non-zero hit counter.
    # Always empty for files captured without --counters (packet_count is null in that case).
    active_drop_rules = [
        r
        for tdata in tables.values()
        for cdata in tdata["chains"].values()
        for r in cdata["rules"]
        if r["target"] in ("DROP", "REJECT")
        and r["packet_count"] is not None
        and r["packet_count"] > 0
    ]

    # nat_summary
    masquerade_rules = []
    dnat_rules = []
    snat_rules = []
    if "nat" in tables:
        for cdata in tables["nat"]["chains"].values():
            for r in cdata["rules"]:
                if r["target"] == "MASQUERADE":
                    masquerade_rules.append(r)
                elif r["target"] == "DNAT":
                    dnat_rules.append(r)
                elif r["target"] == "SNAT":
                    snat_rules.append(r)

    # user_defined_chains and unresolved_chain_references
    user_defined_chains: dict[str, dict] = {}
    unresolved_chain_references = []

    for tname, tdata in tables.items():
        # collect all chain names in this table
        table_chain_names = set(tdata["chains"].keys())
        # collect user-defined chains in this table
        ud_chains = {
            cname for cname, cdata in tdata["chains"].items()
            if cdata["type"] == "user-defined"
        }
        for cname, cdata in tdata["chains"].items():
            for rule in cdata["rules"]:
                target = rule["target"]
                if target in BUILTIN_TARGETS:
                    continue
                ref = {"table": tname, "chain": cname, "position": rule["position"]}
                if target in table_chain_names:
                    # resolved user-defined chain jump
                    if target not in user_defined_chains:
                        user_defined_chains[target] = {"referenced_from": []}
                    user_defined_chains[target]["referenced_from"].append(ref)
                else:
                    # unresolved
                    unresolved_chain_references.append(
                        {"target_chain": target, "referenced_from": ref}
                    )
                    parse_warnings.append(
                        f"Unresolved chain reference: target '{target}' in {tname}/{cname} position {rule['position']}"
                    )

    diagnostics = {
        "drop_policy_chains": drop_policy_chains,
        "accept_policy_chains": accept_policy_chains,
        "conntrack_position_warnings": conntrack_position_warnings,
        "active_drop_rules": active_drop_rules,
        "nat_summary": {
            "masquerade_rules": masquerade_rules,
            "dnat_rules": dnat_rules,
            "snat_rules": snat_rules,
        },
        "user_defined_chains": user_defined_chains,
        "unresolved_chain_references": unresolved_chain_references,
    }

    return {
        "parsed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "family": family,
        "input_format": input_format,
        "tables": tables,
        "diagnostics": diagnostics,
        "parse_warnings": parse_warnings,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse iptables-save output into structured JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to iptables-save output file. Reads stdin if omitted.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation (default: 2)",
    )
    parser.add_argument(
        "--family",
        choices=["ipv4", "ipv6"],
        default="ipv4",
        help="Address family of the input (default: ipv4)",
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    result = parse_iptables_save(text, family=args.family)
    print(json.dumps(result, indent=args.indent))


if __name__ == "__main__":
    main()
