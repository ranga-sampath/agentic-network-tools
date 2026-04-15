#!/usr/bin/env python3
"""
effective_route_inspector.py — CLI entry point for Azure VM effective route inspection.

Stages:
  1. Validate — parse and validate CLI args
  2. Collect  — query Azure CLI for effective route table
  3. Preprocess — normalise raw JSON to route objects
  4. Analyze  — apply LPM algorithm or full audit
  5. Output   — render human-readable table to stdout

Artifacts written to audit_dir:
  {session_id}_raw.json     — raw az CLI output (Stage 2)
  {session_id}_verdict.json — analysis result (Stage 4)

Exit codes:
  0 — success (verdict written and rendered)
  2 — any failure (no verdict or partial state)
  1 — never emitted
"""

import argparse
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

import lpm_engine
import route_preprocessor
from providers import (
    AzureRouteProvider,
    ProviderError,
    RouteProvider,
)


# ---------------------------------------------------------------------------
# Session ID helpers
# ---------------------------------------------------------------------------

def _enforce_session_prefix(session_id: str) -> str:
    return session_id if session_id.startswith("rt_") else "rt_" + session_id


def _generate_session_id() -> str:
    return "rt_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# Audit directory
# ---------------------------------------------------------------------------

def _ensure_audit_dir(audit_dir: str) -> Path:
    path = Path(audit_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(f"Cannot create audit directory: {path}: {e}\n")
        sys.exit(2)
    return path


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(args: argparse.Namespace, provider: "RouteProvider | None" = None) -> int:
    audit_path: Path = args.audit_path
    session_id: str = args.session_id

    # Stage 2 — Collect
    if provider is None:
        provider = AzureRouteProvider(subscription_id=args.subscription_id)

    try:
        if args.nic_name:
            nic_name = args.nic_name
        else:
            nic_name = provider.get_nic_name(args.vm_name, args.resource_group)

        print(f"Querying effective routes for {nic_name}...")
        raw_dict = provider.get_effective_routes(nic_name, args.resource_group)
    except ProviderError as e:
        sys.stderr.write(f"{e}\n")
        return 2

    raw_file_path = audit_path / f"{session_id}_raw.json"
    try:
        raw_file_path.write_text(json.dumps(raw_dict, indent=2), encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"Cannot write raw artifact {raw_file_path}: {e}\n")
        return 2

    # Stage 3 — Preprocess
    result = route_preprocessor.preprocess(str(raw_file_path))
    if "error" in result:
        sys.stderr.write(f"{result['error']}\n")
        return 2

    routes = result["routes"]
    parse_warnings = result.get("parse_warnings") or []

    # Stage 4 — Analyze
    if args.dst_ip:
        verdict = lpm_engine.select_route(routes, args.dst_ip)
    else:
        verdict = lpm_engine.audit_routes(routes)

    # Enrich with identity fields
    verdict["session_id"] = session_id
    verdict["vm_name"] = args.vm_name
    verdict["resource_group"] = args.resource_group
    verdict["nic_name"] = nic_name

    # Merge preprocessor parse_warnings
    existing = verdict.get("parse_warnings") or []
    verdict["parse_warnings"] = existing + parse_warnings

    verdict_path = audit_path / f"{session_id}_verdict.json"
    try:
        verdict_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"Cannot write verdict artifact {verdict_path}: {e}\n")
        return 2

    # Stage 5 — Output
    print(_render_table(verdict))
    return 0


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def _render_table(verdict: dict) -> str:
    lines = []
    mode = verdict.get("mode", "unknown")
    vm = verdict.get("vm_name", "n/a")
    nic = verdict.get("nic_name", "n/a")

    if mode == "single-target":
        dst = verdict.get("dst_ip", "n/a")
        result = verdict.get("result", "n/a")
        reason = verdict.get("selection_reason", "n/a")
        warnings = verdict.get("anomaly_warnings") or []
        shadowed = verdict.get("shadowed_candidates") or []
        tied = verdict.get("tied_routes") or []

        lines.append(f"VM: {vm}   NIC: {nic}   Destination: {dst}")
        lines.append(f"Result:   {result}")

        if result == "WINNER":
            wr = verdict.get("winning_route") or {}
            prefix = wr.get("prefix", "n/a")
            hop_type = wr.get("next_hop_type", "n/a")
            source = wr.get("source", "n/a")
            state = wr.get("state", "n/a")
            lines.append(f"Winner:   {prefix} → {hop_type} [{source}] {state}")
        elif result == "TIED_BGP":
            lines.append("Winner:   (unresolvable BGP tie)")
            for r in tied:
                lines.append(f"  Tied:   {r.get('prefix', 'n/a')} → {r.get('next_hop_type', 'n/a')} [{r.get('source', 'n/a')}]")
        else:
            lines.append("Winner:   No active route matches destination")

        lines.append(f"Reason:   {reason}")
        if warnings:
            lines.append("Warnings:")
            for warning in warnings:
                lines.append(f"  {warning}")
        else:
            lines.append("Warnings: none")
        lines.append(f"Shadowed: {len(shadowed)} route(s)")

        parse_warnings = verdict.get("parse_warnings") or []
        if parse_warnings:
            lines.append("")
            for pw in parse_warnings:
                lines.append(f"[parse warning] {pw}")

    elif mode == "audit":
        route_count = verdict.get("route_count", 0)
        invalid_count = verdict.get("invalid_route_count", 0)
        routes_sorted = verdict.get("routes_by_prefix_length") or []
        findings = verdict.get("findings") or {}

        lines.append(f"VM: {vm}   NIC: {nic}   Mode: audit")
        lines.append(f"Routes: {route_count} total  ({invalid_count} invalid)")
        lines.append("")
        lines.append(f"  {'Len':>3}  {'Prefix':<22}  {'NextHopType':<24}  {'Source':<24}  State")
        lines.append("  " + "-" * 90)
        for r in routes_sorted:
            pl = str(r.get("prefix_length", "?"))
            prefix = r.get("prefix", "n/a")
            hop = r.get("next_hop_type", "n/a")
            src = r.get("source", "n/a")
            state = r.get("state", "n/a")
            lines.append(f"  {pl:>3}  {prefix:<22}  {hop:<24}  {src:<24}  {state}")

        lines.append("")
        lines.append("Findings:")
        lines.append(f"  User blackholes  : {len(findings.get('blackhole_routes') or [])}  (User-defined routes → None — investigate)")
        lines.append(f"  System blocked   : {len(findings.get('system_blocked_routes') or [])}  (Azure Default routes → None — normal behaviour)")
        lines.append(f"  NVA routes       : {len(findings.get('nva_routes') or [])}")
        lines.append(f"  BGP routes       : {len(findings.get('bgp_routes') or [])}")
        default_present = findings.get("default_route_present", False)
        default_src = findings.get("default_route_source") or "n/a"
        lines.append(f"  Default route    : {'present' if default_present else 'absent'} ({default_src})")

        parse_warnings = verdict.get("parse_warnings") or []
        if parse_warnings:
            lines.append("")
            for pw in parse_warnings:
                lines.append(f"[parse warning] {pw}")
    else:
        lines.append(f"[unknown verdict mode: {mode}]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect effective route table for an Azure VM."
    )
    parser.add_argument("--vm-name", required=True, help="Azure VM name")
    parser.add_argument("--resource-group", required=True, help="Azure resource group")
    parser.add_argument("--dst-ip", default=None, help="Destination IP (single-target mode)")
    parser.add_argument("--nic-name", default=None, help="Override primary NIC lookup")
    parser.add_argument("--subscription-id", default=None, help="Azure subscription ID")
    parser.add_argument("--session-id", default=None, help="Session ID (rt_ prefix enforced)")
    parser.add_argument("--audit-dir", default="./audit", help="Artifact output directory")

    args = parser.parse_args()

    if args.dst_ip is not None:
        try:
            ipaddress.ip_address(args.dst_ip)
        except ValueError:
            sys.stderr.write(f"Invalid destination IP: {args.dst_ip}\n")
            sys.exit(2)

    args.session_id = _enforce_session_prefix(args.session_id or _generate_session_id())
    args.audit_path = _ensure_audit_dir(args.audit_dir)

    sys.exit(_run_pipeline(args))


if __name__ == "__main__":
    main()
