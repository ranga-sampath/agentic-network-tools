"""
diff.py — Normalization and diff engine for the Effective Network Inspector.

Public API
----------
extract_routes(json_str)     -> list[dict]
    Parse raw az network nic show-effective-route-table JSON into a stable
    list of normalized route dicts. addressPrefix and nextHopIpAddress are
    preserved as sorted lists.

extract_nsg_rules(json_str)  -> list[dict]
    Parse raw az network nic list-effective-nsg JSON into a stable list of
    normalized security rule dicts. expandedSourceAddressPrefix is preserved
    for use by the diff engine.

compute_diff(baseline, compare) -> dict
    Diff two ENI snapshots. Returns the diff artifact dict with:
        drift_detected, changes_count, changes_by_category, nic_diffs, skipped_nics

Change categories
-----------------
    bgp_route_change      route with source VirtualNetworkGateway added or removed
    udr_route_change      route with source User added or removed
    system_route_change   route with source Default added or removed; also used for
                          unknown source values (defensive fallback)
    security_rule_change  effective NSG rule added or removed

All changes are expressed as "added" or "removed" pairs. There is no "changed"
change type. A route whose next-hop changes produces one "removed" (old) and one
"added" (new) change object.
"""

from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Route normalization
# ---------------------------------------------------------------------------

def _normalize_route(raw: dict) -> dict:
    """
    Normalize a single az effective-route-table entry to a stable canonical form.

    addressPrefix and nextHopIpAddress are preserved as sorted lists.
    az returns these as lists; string values (older API responses) are coerced
    to single-element lists for consistency.
    """
    prefix = raw.get("addressPrefix", [])
    if isinstance(prefix, str):
        prefix = [prefix] if prefix else []

    hop = raw.get("nextHopIpAddress") or []
    if isinstance(hop, str):
        hop = [hop] if hop else []

    return {
        "addressPrefix":    sorted(prefix),
        "nextHopType":      raw.get("nextHopType", ""),
        "nextHopIpAddress": sorted(hop),
        "source":           raw.get("source", ""),
        "state":            raw.get("state", "Active"),
    }


def extract_routes(json_str: str) -> list[dict]:
    """
    Parse raw az network nic show-effective-route-table JSON.

    The az output wraps routes in {"value": [...]} regardless of scope.
    Returns a list of normalized route dicts sorted by addressPrefix.
    Returns [] for empty or unparseable input.
    """
    if not json_str or not json_str.strip():
        return []
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return []

    raw_routes: list = []
    if isinstance(data, list):
        raw_routes = data
    elif isinstance(data, dict):
        raw_routes = data.get("value", [])

    normalized = [_normalize_route(r) for r in raw_routes if isinstance(r, dict)]
    return sorted(normalized, key=lambda r: r["addressPrefix"])


# ---------------------------------------------------------------------------
# NSG rule normalization
# ---------------------------------------------------------------------------

def _normalize_nsg_rule(raw: dict) -> dict:
    """
    Normalize a single effective security rule to a stable canonical form.

    Sorts list-valued fields so that rule order within lists does not produce
    false diffs. Preserves expandedSourceAddressPrefix and
    expandedDestinationAddressPrefix for use by the diff engine.
    """
    return {
        "name":                              raw.get("name", ""),
        "priority":                          int(raw.get("priority", 0)),
        "direction":                         raw.get("direction", ""),
        "access":                            raw.get("access", ""),
        "protocol":                          raw.get("protocol", ""),
        "sourceAddressPrefix":               raw.get("sourceAddressPrefix") or "",
        "sourceAddressPrefixes":             sorted(raw.get("sourceAddressPrefixes") or []),
        "expandedSourceAddressPrefix":       sorted(raw.get("expandedSourceAddressPrefix") or []),
        "destinationAddressPrefix":          raw.get("destinationAddressPrefix") or "",
        "destinationAddressPrefixes":        sorted(raw.get("destinationAddressPrefixes") or []),
        "expandedDestinationAddressPrefix":  sorted(raw.get("expandedDestinationAddressPrefix") or []),
        "destinationPortRange":              raw.get("destinationPortRange") or "",
        "destinationPortRanges":             sorted(raw.get("destinationPortRanges") or []),
    }


def extract_nsg_rules(json_str: str) -> list[dict]:
    """
    Parse raw az network nic list-effective-nsg JSON.

    Handles three possible az envelope formats:
        1. Raw list of rules
        2. {"networkSecurityGroups": [{..., "effectiveSecurityRules": [...]}]}
        3. {"value": [{..., "effectiveSecurityRules": [...]}]}

    Returns a list of normalized rule dicts sorted by (direction, priority).
    Returns [] for empty or unparseable input.
    """
    if not json_str or not json_str.strip():
        return []
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return []

    raw_rules: list = []

    if isinstance(data, list):
        raw_rules = data

    elif isinstance(data, dict):
        if "networkSecurityGroups" in data:
            for nsg in data["networkSecurityGroups"]:
                raw_rules.extend(nsg.get("effectiveSecurityRules", []))
        elif "value" in data:
            for entry in data["value"]:
                nsg = entry.get("networkSecurityGroup", {})
                raw_rules.extend(nsg.get("effectiveSecurityRules", []))
                raw_rules.extend(entry.get("effectiveSecurityRules", []))
        else:
            raw_rules = data.get("effectiveSecurityRules", [])

    normalized = [_normalize_nsg_rule(r) for r in raw_rules if isinstance(r, dict)]
    return sorted(normalized, key=lambda r: (r["direction"], r["priority"]))


# ---------------------------------------------------------------------------
# Diff engine — route and NSG rule canonicalization for comparison
# ---------------------------------------------------------------------------

def _route_key(route: dict) -> tuple:
    """Identity key for route matching: (sorted addressPrefix as tuple, source)."""
    prefix = route.get("addressPrefix", [])
    if isinstance(prefix, str):
        prefix = [prefix] if prefix else []
    return (tuple(sorted(prefix)), route.get("source", ""))


def _canonicalise_route(route: dict) -> dict:
    """Return a stable comparison dict from a route (handles both string and list addressPrefix)."""
    prefix = route.get("addressPrefix", [])
    if isinstance(prefix, str):
        prefix = [prefix] if prefix else []

    hop = route.get("nextHopIpAddress") or []
    if isinstance(hop, str):
        hop = [hop] if hop else []

    return {
        "addressPrefix":    sorted(prefix),
        "nextHopType":      route.get("nextHopType", ""),
        "nextHopIpAddress": sorted(hop),
        "source":           route.get("source", ""),
        "state":            route.get("state", "Active"),
    }


def _nsg_key(rule: dict) -> tuple:
    """Identity key for NSG rule matching: (name, direction)."""
    return (rule.get("name", ""), rule.get("direction", ""))


def _canonicalise_nsg_rule(rule: dict) -> dict:
    """
    Return a stable comparison dict from an NSG rule.

    Uses expandedSourceAddressPrefix when non-empty (resolved CIDRs from service tags).
    Falls back to sourceAddressPrefixes when expanded is empty.
    Same logic for destination.
    """
    expanded_src = rule.get("expandedSourceAddressPrefix") or []
    src = sorted(expanded_src) if expanded_src else sorted(rule.get("sourceAddressPrefixes") or [])

    expanded_dst = rule.get("expandedDestinationAddressPrefix") or []
    dst = sorted(expanded_dst) if expanded_dst else sorted(rule.get("destinationAddressPrefixes") or [])

    return {
        "name":                       rule.get("name", ""),
        "priority":                   int(rule.get("priority", 0)),
        "direction":                  rule.get("direction", ""),
        "access":                     rule.get("access", ""),
        "protocol":                   rule.get("protocol", ""),
        "sourceAddressPrefixes":      src,
        "destinationAddressPrefixes": dst,
        "destinationPortRanges":      sorted(rule.get("destinationPortRanges") or []),
    }


# ---------------------------------------------------------------------------
# Diff engine — change categorisation
# ---------------------------------------------------------------------------

_ROUTE_SOURCE_TO_CATEGORY = {
    "VirtualNetworkGateway": "bgp_route_change",
    "User":                  "udr_route_change",
    "Default":               "system_route_change",
}


def _categorize_route_change(route: dict) -> str:
    source = route.get("source", "")
    return _ROUTE_SOURCE_TO_CATEGORY.get(source, "system_route_change")


# ---------------------------------------------------------------------------
# Per-NIC diff
# ---------------------------------------------------------------------------

def _diff_nic(
    baseline_nic: dict | None,
    compare_nic: dict,
) -> list[dict]:
    """
    Produce a list of change dicts for a single NIC.

    baseline_nic is None when the NIC is new (no baseline entry).
    In that case all compare entries are treated as "added".

    All changes are expressed as "added" or "removed". A modified route or rule
    (same identity key, different content) produces a "removed" (old) + "added"
    (new) pair. There is no "changed" change type.
    """
    changes: list[dict] = []

    # ----- Routes -----
    b_routes: dict[tuple, dict] = {}
    if baseline_nic:
        for r in (baseline_nic.get("effective_routes") or []):
            b_routes[_route_key(r)] = _canonicalise_route(r)

    c_routes: dict[tuple, dict] = {}
    for r in (compare_nic.get("effective_routes") or []):
        c_routes[_route_key(r)] = _canonicalise_route(r)

    # Removed routes (in baseline, not in compare)
    for key, route in b_routes.items():
        if key not in c_routes:
            changes.append({
                "change_type": "removed",
                "category":    _categorize_route_change(route),
                "route":       route,
            })

    # Added routes (in compare, not in baseline)
    for key, route in c_routes.items():
        if key not in b_routes:
            changes.append({
                "change_type": "added",
                "category":    _categorize_route_change(route),
                "route":       route,
            })

    # Modified routes (same key, different content) → removed + added pair
    for key in b_routes:
        if key in c_routes and b_routes[key] != c_routes[key]:
            changes.append({
                "change_type": "removed",
                "category":    _categorize_route_change(b_routes[key]),
                "route":       b_routes[key],
            })
            changes.append({
                "change_type": "added",
                "category":    _categorize_route_change(c_routes[key]),
                "route":       c_routes[key],
            })

    # ----- NSG rules -----
    b_rules: dict[tuple, dict] = {}
    if baseline_nic:
        for r in (baseline_nic.get("effective_nsg_rules") or []):
            b_rules[_nsg_key(r)] = _canonicalise_nsg_rule(r)

    c_rules: dict[tuple, dict] = {}
    for r in (compare_nic.get("effective_nsg_rules") or []):
        c_rules[_nsg_key(r)] = _canonicalise_nsg_rule(r)

    # Removed rules
    for key, rule in b_rules.items():
        if key not in c_rules:
            changes.append({
                "change_type": "removed",
                "category":    "security_rule_change",
                "rule":        rule,
            })

    # Added rules
    for key, rule in c_rules.items():
        if key not in b_rules:
            changes.append({
                "change_type": "added",
                "category":    "security_rule_change",
                "rule":        rule,
            })

    # Modified rules (same key, different content) → removed + added pair
    for key in b_rules:
        if key in c_rules and b_rules[key] != c_rules[key]:
            changes.append({
                "change_type": "removed",
                "category":    "security_rule_change",
                "rule":        b_rules[key],
            })
            changes.append({
                "change_type": "added",
                "category":    "security_rule_change",
                "rule":        c_rules[key],
            })

    return changes


def compute_diff(baseline_snapshot: dict, compare_snapshot: dict) -> dict:
    """
    Diff two ENI snapshots and produce the diff artifact.

    NICs are matched by name.
    - NIC present in compare but absent in baseline: all its routes and rules
      are "added" changes.
    - NIC present in baseline but absent in compare: all its routes and rules
      are "removed" changes (detached or renamed NIC is treated as drift).
    - NIC errored in either snapshot: excluded from diff, added to skipped_nics.

    Returns a dict matching the diff artifact schema:
    {
        "baseline_session_id": str,
        "compare_session_id":  str,
        "drift_detected":      bool,
        "changes_count":       int,
        "changes_by_category": {category: count, ...},
        "skipped_nics":        [nic_name, ...],
        "nic_diffs":           [{nic_name, changes: [...]}, ...]
    }
    """
    baseline_nics: dict[str, dict] = {
        n["nic_name"]: n for n in baseline_snapshot.get("nics", [])
    }
    compare_nics: dict[str, dict] = {
        n["nic_name"]: n for n in compare_snapshot.get("nics", [])
    }

    # Preserve ordering: baseline NICs first, then new NICs from compare
    all_nic_names: list[str] = list(dict.fromkeys(
        [n["nic_name"] for n in baseline_snapshot.get("nics", [])] +
        [n["nic_name"] for n in compare_snapshot.get("nics", [])]
    ))

    nic_diffs: list[dict] = []
    changes_by_category: dict[str, int] = {}
    skipped_nics: list[str] = []

    for nic_name in all_nic_names:
        b_nic = baseline_nics.get(nic_name)
        c_nic = compare_nics.get(nic_name)

        # Skip if either side has an error — don't false-positive on missing data
        b_errored = b_nic is not None and b_nic.get("error")
        c_errored = c_nic is not None and c_nic.get("error")
        if b_errored or c_errored:
            skipped_nics.append(nic_name)
            continue

        if c_nic is None:
            # NIC present in baseline but absent from compare → fully removed
            empty_compare = {
                "nic_name":            nic_name,
                "effective_routes":    [],
                "effective_nsg_rules": [],
                "error":               None,
            }
            nic_changes = _diff_nic(b_nic, empty_compare)
        else:
            nic_changes = _diff_nic(b_nic, c_nic)

        if nic_changes:
            nic_diffs.append({"nic_name": nic_name, "changes": nic_changes})
            for ch in nic_changes:
                cat = ch["category"]
                changes_by_category[cat] = changes_by_category.get(cat, 0) + 1

    total_changes = sum(changes_by_category.values())

    return {
        "baseline_session_id": baseline_snapshot.get("session_id", ""),
        "compare_session_id":  compare_snapshot.get("session_id", ""),
        "drift_detected":      total_changes > 0,
        "changes_count":       total_changes,
        "changes_by_category": changes_by_category,
        "skipped_nics":        skipped_nics,
        "nic_diffs":           nic_diffs,
    }
