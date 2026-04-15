#!/usr/bin/env python3
"""
route_preprocessor.py — Azure Effective Route Table JSON normaliser.

Reads the output of:
    az network nic show-effective-route-table -o json > routes.json

Emits a normalised JSON structure to stdout — one row per prefix — ready
for Claude Code's analysis framework.

Exit codes:
    0  success (JSON written to stdout)
    1  error (JSON with "error" key written to stdout)

Usage:
    python3 route_preprocessor.py <routes.json>
"""

import json
import sys
import ipaddress
from typing import Optional, List, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_state(raw: object) -> str:
    """
    Normalise the state field to title-case ("Active", "Invalid").

    Returns "Unknown" for absent, null, or unrecognised values and emits no
    warning here — the caller is responsible for deciding whether to warn.
    """
    if raw is None:
        return "Unknown"
    s = str(raw).strip()
    if not s:
        return "Unknown"
    # Title-case so downstream comparisons are always consistent.
    return s[0].upper() + s[1:].lower()


def _normalise_hop_ip(raw: Optional[List], warnings: list) -> Optional[str]:
    """
    Return the first element of nextHopIpAddress, or None if empty/absent.

    Emits a parse_warning when more than one address is present (ECMP paths
    on some VirtualNetworkGateway routes) so the engineer knows to verify the
    full set at the gateway.
    """
    if not raw:
        return None
    if isinstance(raw, str):
        # Some az CLI versions or custom serializers return a bare string instead of
        # a one-element array. Normalize to a list so the rest of the logic is uniform.
        warnings.append(
            f"nextHopIpAddress was a bare string '{raw}', not an array; "
            "normalized to single entry."
        )
        raw = [raw]
    if len(raw) > 1:
        warnings.append(
            f"nextHopIpAddress contains {len(raw)} addresses {raw}. "
            "Only the first is recorded here; verify the full ECMP set at the gateway."
        )
    first = str(raw[0]).strip()
    return first if first else None


def _extract_routes(data: object) -> Tuple[list, list]:
    """
    Accept any of the four envelope variants Azure CLI / SDK may return:
      - {"value": [...]}               standard az output
      - {"effectiveRoutes": [...]}     alternative field name
      - [...]                          raw array
      - {...}                          single route object

    Returns (raw_entries, warnings).
    """
    warnings = []

    if isinstance(data, list):
        if not data:
            warnings.append(
                "Input is a valid JSON array but it is empty. "
                "The effective route table contains no routes."
            )
        return data, warnings

    if isinstance(data, dict):
        for key in ("value", "effectiveRoutes"):
            if key in data and isinstance(data[key], list):
                entries = data[key]
                if not entries:
                    warnings.append(
                        f"'{key}' array is present but empty. "
                        "The effective route table contains no routes."
                    )
                return entries, warnings

        # Single object wrapped in braces — treat as one-element list
        if "addressPrefix" in data or "nextHopType" in data:
            warnings.append(
                "Input appears to be a single route object rather than a list. "
                "Wrapping it for processing."
            )
            return [data], warnings

    return [], [
        "Could not find a route list in the input. "
        "Expected output of: az network nic show-effective-route-table -o json"
    ]


def _expand_entry(entry: dict, warnings: list) -> List[dict]:
    """
    Expand one raw entry into one normalised row per prefix.

    A single entry can carry multiple CIDRs in addressPrefix — common for
    VNet peering entries that aggregate address spaces.
    """
    raw_prefixes = entry.get("addressPrefix")
    if isinstance(raw_prefixes, str):
        # Some az CLI versions or custom serializers return a bare string instead of
        # a one-element array. Normalize so the prefix iteration loop is not derailed.
        warnings.append(
            f"addressPrefix was a bare string '{raw_prefixes}', not an array; "
            "normalized to single entry."
        )
        raw_prefixes = [raw_prefixes]
    elif not raw_prefixes:
        raw_prefixes = []
    if not raw_prefixes:
        warnings.append(
            f"Entry with nextHopType={entry.get('nextHopType')} has no addressPrefix; skipped."
        )
        return []

    # next_hop_type — warn and use "Unknown" if absent or empty
    raw_hop_type = entry.get("nextHopType")
    if raw_hop_type is None or str(raw_hop_type).strip() == "":
        warnings.append(
            "An entry has no nextHopType field. Recording as 'Unknown'. "
            "This route will not trigger NVA or blackhole detection."
        )
        next_hop_type = "Unknown"
    else:
        next_hop_type = str(raw_hop_type).strip()

    next_hop_ip = _normalise_hop_ip(entry.get("nextHopIpAddress"), warnings)
    source = str(entry.get("source") or "Unknown").strip()

    # state — warn and use "Unknown" if absent or null; never default to Active
    raw_state = entry.get("state")
    state = _normalise_state(raw_state)
    if state == "Unknown":
        warnings.append(
            f"An entry with nextHopType={next_hop_type} has no state field. "
            "Recording as 'Unknown' — this route will be excluded from selection "
            "to avoid promoting an unverified route to Active."
        )

    route_name = entry.get("name") or None
    if isinstance(route_name, str):
        route_name = route_name.strip() or None

    rows = []
    for raw_prefix in raw_prefixes:
        prefix = str(raw_prefix).strip()

        # Validate CIDR
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            prefix = str(network)          # normalise representation
            prefix_len = network.prefixlen
        except ValueError:
            warnings.append(f"Invalid CIDR '{prefix}'; skipped.")
            continue

        rows.append({
            "prefix": prefix,
            "prefix_length": prefix_len,
            "next_hop_type": next_hop_type,
            "next_hop_ip": next_hop_ip,
            "source": source,
            "state": state,
            "route_name": route_name,
            "is_zero_route": (prefix == "0.0.0.0/0"),
        })

    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def preprocess(path: str) -> dict:
    """Parse the file at *path* and return the normalised structure."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except json.JSONDecodeError as exc:
        return {"error": f"File is not valid JSON: {exc}"}

    raw_entries, warnings = _extract_routes(data)

    if not raw_entries and any("Could not find" in w for w in warnings):
        return {"error": warnings[0]}

    routes = []
    invalid_count = 0

    for entry in raw_entries:
        rows = _expand_entry(entry, warnings)
        for row in rows:
            if row["state"] == "Invalid":
                invalid_count += 1
            routes.append(row)

    if not routes and not warnings:
        return {
            "error": (
                "No routes could be parsed from the file. "
                "Ensure it is the output of: az network nic show-effective-route-table -o json"
            )
        }

    if not routes:
        # Warnings already explain why (empty array, all CIDRs invalid, etc.)
        return {
            "error": (
                "No routes could be parsed from the file. "
                "Ensure it is the output of: az network nic show-effective-route-table -o json"
            ),
            "parse_warnings": warnings,
        }

    return {
        "route_count": len(routes),
        "routes": routes,
        "invalid_route_count": invalid_count,
        "parse_warnings": warnings,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print(
            json.dumps(
                {"error": "Usage: route_preprocessor.py <routes.json>"},
                indent=2,
            )
        )
        sys.exit(1)

    result = preprocess(sys.argv[1])
    print(json.dumps(result, indent=2))

    if "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
