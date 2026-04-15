#!/usr/bin/env python3
"""
nsg_preprocessor.py — Azure Security Rule Resolver preprocessor

Parses the JSON output of:
    az network nic list-effective-nsg --resource-group <RG> --name <NIC> -o json

and produces a structured, analysis-ready document for Claude to evaluate.

The output separates rules into gates (subnet-nsg vs nic-nsg), sorts each gate's
rules by priority (ascending — lower number = higher priority = evaluated first),
and flags shadowed rules where a higher-priority rule makes a lower-priority rule
unreachable.

Usage:
    python3 nsg_preprocessor.py <effective-nsg.json>
    python3 nsg_preprocessor.py <effective-nsg.json> --indent 4

Output: JSON to stdout. Exit 0 on success, 1 on error.
"""

import json
import sys
import argparse
from typing import Any


# ---------------------------------------------------------------------------
# Resource ID helpers
# ---------------------------------------------------------------------------

def _last_segment(resource_id: str) -> str:
    """Return the last path segment of an Azure resource ID."""
    if not resource_id:
        return ""
    return resource_id.rstrip("/").split("/")[-1]


# ---------------------------------------------------------------------------
# Port and address normalisation
# ---------------------------------------------------------------------------

def _port_list(rule: dict, range_key: str, single_key: str) -> list[str]:
    """Return the effective port list for a rule field."""
    ranges = rule.get(range_key) or []
    if ranges:
        return [str(p) for p in ranges]
    single = rule.get(single_key) or ""
    return [single] if single else ["*"]


def _address(rule: dict, prefix_key: str, prefixes_key: str, expanded_key: str) -> str:
    """Return the effective address representation for a rule field."""
    expanded = rule.get(expanded_key) or []
    if expanded:
        return ", ".join(sorted(str(x) for x in expanded))
    prefixes = rule.get(prefixes_key) or []
    if prefixes:
        return ", ".join(sorted(str(x) for x in prefixes))
    return str(rule.get(prefix_key) or "*")


def _normalize_rule(raw: dict) -> dict:
    """Convert a raw Azure effective security rule object to normalised form."""
    priority = int(raw.get("priority", 0))

    dst_ports = _port_list(raw, "destinationPortRanges", "destinationPortRange")
    src_ports  = _port_list(raw, "sourcePortRanges",      "sourcePortRange")

    src_addr = _address(
        raw,
        "sourceAddressPrefix",
        "sourceAddressPrefixes",
        "expandedSourceAddressPrefix",
    )
    dst_addr = _address(
        raw,
        "destinationAddressPrefix",
        "destinationAddressPrefixes",
        "expandedDestinationAddressPrefix",
    )

    return {
        "name":                raw.get("name", ""),
        "priority":            priority,
        "direction":           raw.get("direction", ""),
        "access":              raw.get("access", ""),
        "protocol":            raw.get("protocol") or "*",
        "source_address":      src_addr,
        "source_ports":        src_ports,
        "destination_address": dst_addr,
        "destination_ports":   dst_ports,
        "is_default":          priority >= 65000,
        "shadowed_by":         None,   # filled in by _detect_shadows()
    }


# ---------------------------------------------------------------------------
# Shadow detection
# ---------------------------------------------------------------------------

def _protocols_overlap(p1: str, p2: str) -> bool:
    """True if the two protocol values could match the same packet.

    Azure uses both "*" and "All" to mean match-any-protocol in effective
    security rules. Treat both as wildcards.
    """
    _WILDCARDS = {"*", "all"}
    if p1.lower() in _WILDCARDS or p2.lower() in _WILDCARDS:
        return True
    return p1.lower() == p2.lower()


def _ports_overlap(ports_a: list[str], ports_b: list[str]) -> bool:
    """
    True if the two port lists could match the same destination port.

    Handles:
    - "*"          → matches everything
    - "443"        → single port
    - "8080-8090"  → range
    """
    if "*" in ports_a or "*" in ports_b:
        return True

    def _to_range(spec: str) -> tuple[int, int]:
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return int(lo), int(hi)
        v = int(spec)
        return v, v

    for a in ports_a:
        try:
            a_lo, a_hi = _to_range(a)
        except ValueError:
            continue
        for b in ports_b:
            try:
                b_lo, b_hi = _to_range(b)
            except ValueError:
                continue
            if a_lo <= b_hi and b_lo <= a_hi:
                return True
    return False


def _address_is_wildcard(addr: str) -> bool:
    """True if the address is a catch-all wildcard.

    Azure effective rules use "*" for wildcard addresses. Some API versions
    and CLI output variants return "Any" for the same meaning. Both are
    treated as wildcards here.
    """
    return addr.strip().lower() in ("*", "any", "0.0.0.0/0", "::/0")


def _is_protocol_wildcard(proto: str) -> bool:
    """True if the protocol value matches all protocols."""
    return proto.lower() in {"*", "all"}


def _is_port_wildcard(ports: list[str]) -> bool:
    """True if the port list represents all possible ports."""
    return "*" in ports or "0-65535" in ports


def _detect_shadows(rules: list[dict]) -> list[dict]:
    """
    Mark rules that are definitively shadowed by a higher-priority rule.

    A rule at index i is shadowed by rule at index j (j < i, i.e. higher priority)
    when the earlier rule is a complete wildcard match:
      - Opposite access (one Allow, one Deny)
      - Wildcard protocol ("*" or "All")
      - Wildcard destination ports ("*" or "0-65535")
      - Wildcard source address ("*", "0.0.0.0/0", etc.)
      - Wildcard destination address

    ALL four wildcard conditions must hold. A rule with specific protocol or port
    (e.g., Tcp/443) only partially covers traffic — rules after it that handle
    different protocols/ports are still reachable and are NOT flagged as shadowed.
    This prevents false positives from partial-overlap cases.
    """
    for i in range(len(rules)):
        for j in range(i):          # j always has higher priority (lower number)
            earlier = rules[j]
            current = rules[i]
            # Direction check is redundant since _detect_shadows is called on
            # pre-filtered inbound/outbound lists, but left for safety.
            if earlier["direction"] != current["direction"]:
                continue
            if earlier["access"] == current["access"]:
                continue            # same action — not a shadow
            if not _is_protocol_wildcard(earlier["protocol"]):
                continue            # partial protocol match — not a definitive shadow
            if not _is_port_wildcard(earlier["destination_ports"]):
                continue            # specific port — not a definitive shadow
            if _address_is_wildcard(earlier["source_address"]) and \
               _address_is_wildcard(earlier["destination_address"]):
                current["shadowed_by"] = earlier["name"]
                break
    return rules


# ---------------------------------------------------------------------------
# NSG group extraction
# ---------------------------------------------------------------------------

_FALLBACK_GATE_NAMES = ["subnet-nsg", "nic-nsg", "nsg-3", "nsg-4"]


def _extract_gate(entry: dict, fallback_gate: str) -> dict:
    """
    Extract one NSG gate from a single entry in the az CLI response.

    Identifies the gate type (subnet-nsg vs nic-nsg) from the 'association'
    field when present, falling back to positional labelling.
    """
    nsg       = entry.get("networkSecurityGroup") or {}
    nsg_id    = nsg.get("id", "")
    nsg_name  = _last_segment(nsg_id) or "unknown-nsg"

    # Determine gate type from association
    association = entry.get("association") or {}
    if "subnet" in association:
        gate             = "subnet-nsg"
        association_type = "subnet"
        association_id   = ((association.get("subnet") or {}).get("id") or "")
    elif "networkInterface" in association:
        gate             = "nic-nsg"
        association_type = "networkInterface"
        association_id   = ((association.get("networkInterface") or {}).get("id") or "")
    else:
        gate             = fallback_gate
        association_type = "unknown"
        association_id   = ""

    raw_rules  = entry.get("effectiveSecurityRules") or []
    normalised = [_normalize_rule(r) for r in raw_rules if isinstance(r, dict)]

    inbound  = sorted(
        [r for r in normalised if r["direction"].lower() == "inbound"],
        key=lambda r: r["priority"],
    )
    outbound = sorted(
        [r for r in normalised if r["direction"].lower() == "outbound"],
        key=lambda r: r["priority"],
    )

    inbound  = _detect_shadows(inbound)
    outbound = _detect_shadows(outbound)

    return {
        "gate":             gate,
        "nsg_name":         nsg_name,
        "nsg_id":           nsg_id,
        "association_type": association_type,
        "association_id":   association_id,
        "inbound_rules":    inbound,
        "outbound_rules":   outbound,
    }


# ---------------------------------------------------------------------------
# Envelope parsing
# ---------------------------------------------------------------------------

def _unwrap(data: Any) -> tuple[list[dict], list[str]]:
    """
    Unwrap the top-level az CLI envelope and return (entries, warnings).

    Handles four observed formats:
      1. {"value": [{networkSecurityGroup: ..., effectiveSecurityRules: [...]}, ...]}
      2. {"networkSecurityGroups": [{effectiveSecurityRules: [...]}, ...]}
      3. [{...}, ...]  — raw list (e.g., from az --query flattening)
      4. {"effectiveSecurityRules": [...]}  — single NSG, no wrapper
    """
    warnings: list[str] = []
    entries:  list[dict] = []

    if isinstance(data, list):
        entries = [e for e in data if isinstance(e, dict)]

    elif isinstance(data, dict):
        if "value" in data:
            entries = [e for e in (data["value"] or []) if isinstance(e, dict)]
        elif "networkSecurityGroups" in data:
            entries = [e for e in (data["networkSecurityGroups"] or []) if isinstance(e, dict)]
        elif "effectiveSecurityRules" in data:
            entries = [data]
        else:
            warnings.append(
                "Unrecognised envelope: no 'value', 'networkSecurityGroups', "
                "or 'effectiveSecurityRules' key found at the top level."
            )

    if not entries:
        warnings.append("No NSG entries found in the input.")

    return entries, warnings


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def preprocess(path: str) -> dict:
    """Full preprocessing pipeline. Returns the structured output dict."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON in {path}: {exc}"}

    entries, warnings = _unwrap(data)

    gates = []
    for i, entry in enumerate(entries):
        fallback = _FALLBACK_GATE_NAMES[i] if i < len(_FALLBACK_GATE_NAMES) else f"nsg-{i + 1}"
        try:
            gates.append(_extract_gate(entry, fallback))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Failed to process entry {i} ({fallback}): {exc}")

    # Warn if association type could not be determined for any gate
    for g in gates:
        if g["association_type"] == "unknown":
            warnings.append(
                f"Gate '{g['nsg_name']}' has no 'association' field — "
                f"labelled by position as '{g['gate']}'. "
                f"Verify this is the correct gate type."
            )

    return {
        "gate_count":     len(gates),
        "gates":          gates,
        "parse_warnings": warnings,
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Preprocess az network nic list-effective-nsg JSON "
            "for the azure-security-rule-resolver skill."
        )
    )
    ap.add_argument("file", help="Path to the az network nic list-effective-nsg JSON output")
    ap.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON output indentation (default: 2)",
    )
    args = ap.parse_args()

    result = preprocess(args.file)
    print(json.dumps(result, indent=args.indent))

    if "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
