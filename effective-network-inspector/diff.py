"""
diff.py — Normalization and diff engine for the Effective Network Inspector.

Public API
----------
extract_routes(json_str)     -> list[dict]
    Parse raw az network nic show-effective-route-table JSON into a stable
    list of normalized route dicts.

extract_nsg_rules(json_str)  -> list[dict]
    Parse raw az network nic list-effective-nsg JSON into a stable list of
    normalized security rule dicts.

compute_diff(baseline, compare) -> dict
    Diff two ENI snapshots. Returns the diff artifact dict with:
        drift_detected, changes_count, changes_by_category, nic_diffs

Change categories
-----------------
    bgp_route_change      route with source VirtualNetworkGateway added or removed
    udr_route_change      route with source User added, removed, or changed
    system_route_change   route with source Default added, removed, or changed
    security_rule_change  effective NSG rule added, removed, or changed
"""

from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Route normalization
# ---------------------------------------------------------------------------

def _normalize_route(raw: dict) -> dict:
    """
    Normalize a single az effective-route-table entry to a stable canonical form.

    az returns addressPrefix and nextHopIpAddress as lists; we collapse to
    scalars. Unknown / null values are normalised to empty string or None.
    """
    # addressPrefix: list ["10.0.0.0/16"] or string "10.0.0.0/16"
    prefix_raw = raw.get("addressPrefix", "")
    if isinstance(prefix_raw, list):
        address_prefix = prefix_raw[0] if prefix_raw else ""
    else:
        address_prefix = prefix_raw or ""

    # nextHopIpAddress: list ["1.2.3.4"] or [] or null
    hop_raw = raw.get("nextHopIpAddress")
    if isinstance(hop_raw, list):
        next_hop: str | None = hop_raw[0] if hop_raw else None
    else:
        next_hop = hop_raw or None

    return {
        "addressPrefix":    address_prefix,
        "nextHopType":      raw.get("nextHopType", ""),
        "nextHopIpAddress": next_hop,
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

    Sorts list-valued fields (destinationPortRanges, sourceAddressPrefixes, etc.)
    so that rule order within lists does not produce false diffs.
    """
    return {
        "name":                       raw.get("name", ""),
        "priority":                   int(raw.get("priority", 0)),
        "direction":                  raw.get("direction", ""),
        "access":                     raw.get("access", ""),
        "protocol":                   raw.get("protocol", ""),
        "sourceAddressPrefix":        raw.get("sourceAddressPrefix") or "",
        "sourceAddressPrefixes":      sorted(raw.get("sourceAddressPrefixes") or []),
        "destinationAddressPrefix":   raw.get("destinationAddressPrefix") or "",
        "destinationAddressPrefixes": sorted(raw.get("destinationAddressPrefixes") or []),
        "destinationPortRange":       raw.get("destinationPortRange") or "",
        "destinationPortRanges":      sorted(raw.get("destinationPortRanges") or []),
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
            # Fallback: treat as single object containing rules list
            raw_rules = data.get("effectiveSecurityRules", [])

    normalized = [_normalize_nsg_rule(r) for r in raw_rules if isinstance(r, dict)]
    return sorted(normalized, key=lambda r: (r["direction"], r["priority"]))


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

_ROUTE_SOURCE_TO_CATEGORY = {
    "VirtualNetworkGateway": "bgp_route_change",
    "User":                  "udr_route_change",
    "Default":               "system_route_change",
}


def _categorize_route_change(route: dict) -> str:
    source = route.get("source", "")
    return _ROUTE_SOURCE_TO_CATEGORY.get(source, "udr_route_change")


def _diff_nic(
    baseline_nic: dict | None,
    compare_nic: dict,
) -> list[dict]:
    """
    Produce a list of change dicts for a single NIC.

    baseline_nic is None when the NIC is new (no baseline entry).
    In that case all compare entries are treated as "added".
    """
    changes: list[dict] = []

    # ----- Routes -----
    # Key: addressPrefix. Tracks the full route for change detection.
    b_routes: dict[str, dict] = {}
    if baseline_nic:
        for r in baseline_nic.get("effective_routes", []):
            b_routes[r["addressPrefix"]] = r

    c_routes: dict[str, dict] = {}
    for r in compare_nic.get("effective_routes", []):
        c_routes[r["addressPrefix"]] = r

    # Removed routes (in baseline, not in compare)
    for prefix, route in b_routes.items():
        if prefix not in c_routes:
            changes.append({
                "change_type": "removed",
                "category":    _categorize_route_change(route),
                "route":       route,
            })

    # Added routes (in compare, not in baseline)
    for prefix, route in c_routes.items():
        if prefix not in b_routes:
            changes.append({
                "change_type": "added",
                "category":    _categorize_route_change(route),
                "route":       route,
            })

    # Changed routes (in both, but properties differ)
    for prefix in b_routes:
        if prefix in c_routes and b_routes[prefix] != c_routes[prefix]:
            changes.append({
                "change_type": "changed",
                "category":    _categorize_route_change(c_routes[prefix]),
                "route_before": b_routes[prefix],
                "route_after":  c_routes[prefix],
            })

    # ----- NSG rules -----
    # Key: (name, direction). Names are unique within the effective NSG scope.
    b_rules: dict[tuple, dict] = {}
    if baseline_nic:
        for r in baseline_nic.get("effective_nsg_rules", []):
            b_rules[(r["name"], r["direction"])] = r

    c_rules: dict[tuple, dict] = {}
    for r in compare_nic.get("effective_nsg_rules", []):
        c_rules[(r["name"], r["direction"])] = r

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

    # Changed rules (key matches but content differs)
    for key in b_rules:
        if key in c_rules and b_rules[key] != c_rules[key]:
            changes.append({
                "change_type": "changed",
                "category":    "security_rule_change",
                "rule_before": b_rules[key],
                "rule_after":  c_rules[key],
            })

    return changes


def compute_diff(baseline_snapshot: dict, compare_snapshot: dict) -> dict:
    """
    Diff two ENI snapshots and produce the diff artifact.

    NICs are matched by name. A NIC present in compare but absent in baseline
    is treated as fully added (all its routes and rules are "added" changes).
    A NIC present in baseline but absent in compare is noted but not expanded
    (the NIC itself may have been detached — treat as a warning, not a change).

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
        n["nic_name"]: n
        for n in baseline_snapshot.get("nics", [])
    }

    nic_diffs: list[dict] = []
    changes_by_category: dict[str, int] = {}
    skipped_nics: list[str] = []

    for nic in compare_snapshot.get("nics", []):
        nic_name = nic["nic_name"]
        b_nic    = baseline_nics.get(nic_name)

        # Skip if either side has an error — don't false-positive on missing data
        if nic.get("error") or (b_nic is not None and b_nic.get("error")):
            skipped_nics.append(nic_name)
            continue

        nic_changes = _diff_nic(b_nic, nic)

        if nic_changes:
            nic_diffs.append({"nic_name": nic_name, "changes": nic_changes})
            for ch in nic_changes:
                cat = ch["category"]
                changes_by_category[cat] = changes_by_category.get(cat, 0) + 1

    # Also skip NICs that were in baseline but not in compare (detached NIC — not drift)
    compare_nic_names = {n["nic_name"] for n in compare_snapshot.get("nics", [])}
    for nic_name, b_nic in baseline_nics.items():
        if nic_name not in compare_nic_names and b_nic.get("error"):
            skipped_nics.append(nic_name)

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
