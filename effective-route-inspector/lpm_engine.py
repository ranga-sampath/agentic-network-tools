"""
lpm_engine.py — Pure-function Azure route selection algorithm.

All functions are deterministic, side-effect-free, and I/O-free.
Input: normalised route list from route_preprocessor.py.
"""

import ipaddress

SOURCE_TIER = {
    "User": 1,
    "VirtualNetworkGateway": 2,
    "Default": 3,
}


def select_route(routes: list, dst_ip: str) -> dict:
    """
    Apply the Azure route selection algorithm for a destination IP.

    Receives the full normalised route list (Active + Invalid + Unknown).
    Returns a SingleTargetVerdict dict without identity fields.
    """
    dst = ipaddress.ip_address(dst_ip)

    # Step 1: CIDR containment filter — Active routes only
    candidates = [
        r for r in routes
        if r["state"] == "Active"
        and dst in ipaddress.ip_network(r["prefix"], strict=False)
    ]

    if not candidates:
        return {
            "mode": "single-target",
            "dst_ip": dst_ip,
            "result": "NO_ROUTE",
            "winning_route": None,
            "selection_reason": "NO_ROUTE",
            "tied_routes": None,
            "shadowed_candidates": [],
            "anomaly_warnings": [],
            "parse_warnings": [],
        }

    # Step 2: Longest Prefix Match
    max_len = max(r["prefix_length"] for r in candidates)
    lpm_winners = [r for r in candidates if r["prefix_length"] == max_len]
    shadowed = [r for r in candidates if r["prefix_length"] < max_len]

    # Step 3: Source precedence (only when >1 lpm winner)
    if len(lpm_winners) > 1:
        tier = lambda r: SOURCE_TIER.get(r["source"], 4)
        min_tier = min(tier(r) for r in lpm_winners)
        final_winners = [r for r in lpm_winners if tier(r) == min_tier]
        shadowed += [r for r in lpm_winners if tier(r) > min_tier]
    else:
        final_winners = lpm_winners

    # Step 4: BGP tie-break
    if len(final_winners) > 1:
        all_vgw = all(r["source"] == "VirtualNetworkGateway" for r in final_winners)
        parse_warnings = [] if all_vgw else [
            "Tie involves routes of unknown source type, not BGP routes — unexpected Azure state"
        ]
        return {
            "mode": "single-target",
            "dst_ip": dst_ip,
            "result": "TIED_BGP",
            "winning_route": None,
            "selection_reason": "TIED_BGP",
            "tied_routes": final_winners,
            "shadowed_candidates": shadowed,
            "anomaly_warnings": [],
            "parse_warnings": parse_warnings,
        }

    # Step 5: Single winner — anomaly checks
    winner = final_winners[0]
    selection_reason = "LPM_ONLY" if len(lpm_winners) == 1 else "SOURCE_PRECEDENCE"
    anomaly_warnings = _check_anomalies(winner, routes, dst_ip)

    return {
        "mode": "single-target",
        "dst_ip": dst_ip,
        "result": "WINNER",
        "winning_route": winner,
        "selection_reason": selection_reason,
        "tied_routes": None,
        "shadowed_candidates": shadowed,
        "anomaly_warnings": anomaly_warnings,
        "parse_warnings": [],
    }


def _check_anomalies(winner: dict, all_routes: list, dst_ip: str) -> list:
    """
    Run all three anomaly checks against the winning route.
    Returns a list of warning strings (empty if none).
    """
    warnings = []
    dst = ipaddress.ip_address(dst_ip)

    # Blackhole: next_hop_type is the string "None", not Python None
    if winner["next_hop_type"] == "None":
        warnings.append(
            f"BLACKHOLE_WARNING: winning route {winner['prefix']} has next_hop_type 'None'"
            " — Azure will silently drop traffic"
        )

    # Invalid shadow: route is Invalid AND dst_ip falls within its prefix AND it would have
    # taken precedence over the winner if it were Active (longer prefix, or same prefix with
    # higher source priority). Skip the winner itself to avoid self-comparison.
    winner_tier = SOURCE_TIER.get(winner["source"], 4)
    for r in all_routes:
        if r["state"] != "Invalid":
            continue
        if not (dst in ipaddress.ip_network(r["prefix"], strict=False)):
            continue
        longer_prefix = r["prefix_length"] > winner["prefix_length"]
        same_prefix_higher_priority = (
            r["prefix_length"] == winner["prefix_length"]
            and SOURCE_TIER.get(r["source"], 4) < winner_tier
        )
        if longer_prefix:
            warnings.append(
                f"INVALID_SHADOW_WARNING: route {r['prefix']} has longer prefix than winner"
                " but is Invalid — traffic falls to less specific path"
            )
        elif same_prefix_higher_priority:
            warnings.append(
                f"INVALID_SHADOW_WARNING: route {r['prefix']} (source {r['source']}) has same"
                f" prefix as winner but is Invalid — it would have taken source precedence"
                f" (tier {SOURCE_TIER.get(r['source'], 4)} vs winner tier {winner_tier})"
                " — verify whether the intended path is an NVA or gateway"
            )

    # NVA: next_hop_type is VirtualAppliance on the winner
    if winner["next_hop_type"] == "VirtualAppliance":
        nh = winner.get("next_hop_ip") or "unknown"
        warnings.append(
            f"NVA_WARNING: winning route {winner['prefix']} points to a Virtual Appliance"
            f" ({nh}) — verify IP forwarding is enabled and return path is symmetric"
        )

    return warnings


def audit_routes(routes: list) -> dict:
    """
    Produce a full route table audit without a destination IP.
    Returns an AuditVerdict dict without identity fields.
    """
    active = [r for r in routes if r["state"] == "Active"]
    invalid = [r for r in routes if r["state"] == "Invalid"]
    sorted_all = sorted(routes, key=lambda r: r["prefix_length"], reverse=True)

    # User-defined routes with nextHopType=None are operator-configured blackholes —
    # these are the concerning cases (accidental or intentional silent drops).
    # Default-sourced routes with nextHopType=None are Azure system behaviour: Azure
    # intentionally blocks certain infrastructure and RFC 1918 prefixes from routing.
    # Counting them as blackholes produces noisy, misleading audit output.
    user_blackhole = [
        r for r in active
        if r["next_hop_type"] == "None" and r["source"] == "User"
    ]
    system_blocked = [
        r for r in active
        if r["next_hop_type"] == "None" and r["source"] != "User"
    ]

    findings = {
        "blackhole_routes": user_blackhole,
        "system_blocked_routes": system_blocked,
        "nva_routes": [r for r in active if r["next_hop_type"] == "VirtualAppliance"],
        "bgp_routes": [r for r in active if r["source"] == "VirtualNetworkGateway"],
        "default_route_present": any(r["is_zero_route"] for r in active),
        "default_route_source": next(
            (r["source"] for r in active if r["is_zero_route"]), None
        ),
    }

    return {
        "mode": "audit",
        "route_count": len(routes),
        "invalid_route_count": len(invalid),
        "routes_by_prefix_length": sorted_all,
        "invalid_routes": sorted(invalid, key=lambda r: r["prefix_length"], reverse=True),
        "findings": findings,
        "parse_warnings": [],
    }
