#!/usr/bin/env python3
"""
security_rule_inspector.py — CLI entry point for Azure VM NSG effective rule inspection.

Stages:
  1. Validate — parse and validate CLI args
  2. Collect  — query Azure CLI for effective NSG
  3. Preprocess — normalise raw JSON to gate/rule objects
  4. Evaluate — apply dual-gate model or full audit
  5. Output   — render human-readable table to stdout

Artifacts written to audit_dir:
  {session_id}_raw.json     — raw az CLI output (Stage 2)
  {session_id}_verdict.json — verdict result (Stage 4, verdict mode)
  {session_id}_audit.json   — audit result (Stage 4, audit mode)

Exit codes:
  0 — success (artifact written and rendered)
  2 — any failure (no artifact or partial state)
  1 — never emitted
"""

from __future__ import annotations

import argparse
import glob as glob_module
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

import nsg_engine
import nsg_preprocessor
from nsg_engine import TrafficTuple
from providers import (
    AzureNSGProvider,
    NSGProvider,
    NICResolutionError,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    VMNotFoundError,
)


# ---------------------------------------------------------------------------
# Session ID helpers
# ---------------------------------------------------------------------------

def _enforce_session_prefix(session_id: str) -> str:
    return session_id if session_id.startswith("nsg_") else "nsg_" + session_id


def _generate_session_id() -> str:
    return "nsg_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")


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
# Mode detection
# ---------------------------------------------------------------------------

def _detect_mode(args: argparse.Namespace) -> str:
    traffic_flags = [args.src_ip, args.dst_ip, args.dst_port, args.proto, args.direction]
    provided = sum(1 for f in traffic_flags if f is not None)

    if provided == 5:
        return "verdict"
    if provided == 0:
        return "audit"

    # Inbound verdict: --dst-ip may be omitted — derived from the VM's NIC IP after resolution.
    # All other four flags must be present, and direction must be "inbound".
    if (provided == 4
            and args.src_ip is not None
            and args.dst_ip is None
            and args.dst_port is not None
            and args.proto is not None
            and (args.direction or "").lower() == "inbound"):
        return "verdict"

    sys.stderr.write(
        "Verdict mode requires --src-ip, --dst-ip, --dst-port, --proto, --direction\n"
        "(--dst-ip may be omitted for inbound — it is then derived from the VM's NIC IP)\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Session ID collision check
# ---------------------------------------------------------------------------

def _check_collision(session_id: str, audit_dir: Path) -> None:
    pattern = str(audit_dir / f"{session_id}_*.json")
    matches = glob_module.glob(pattern)
    if matches:
        sys.stderr.write(
            f"Session ID {session_id} already has artifacts in {audit_dir} "
            "— supply a new --session-id\n"
        )
        sys.exit(2)


# ---------------------------------------------------------------------------
# Traffic tuple validation
# ---------------------------------------------------------------------------

def _validate_traffic_tuple(args: argparse.Namespace) -> TrafficTuple:
    # src_ip
    try:
        ipaddress.ip_address(args.src_ip)
    except ValueError:
        sys.stderr.write(f"Invalid IP address: {args.src_ip}\n")
        sys.exit(2)

    # dst_ip
    try:
        ipaddress.ip_address(args.dst_ip)
    except ValueError:
        sys.stderr.write(f"Invalid IP address: {args.dst_ip}\n")
        sys.exit(2)

    # dst_port — already an int (argparse type=int); validate range only
    dst_port = args.dst_port
    if not (1 <= dst_port <= 65535):
        sys.stderr.write(f"Invalid port: {args.dst_port} — must be 1–65535\n")
        sys.exit(2)

    # proto
    proto_map = {"tcp": "Tcp", "udp": "Udp", "icmp": "Icmp", "*": "*"}
    proto_norm = proto_map.get((args.proto or "").lower())
    if proto_norm is None:
        sys.stderr.write(f"Invalid protocol: {args.proto} — must be tcp, udp, icmp, or *\n")
        sys.exit(2)

    # direction
    direction_map = {"inbound": "Inbound", "outbound": "Outbound"}
    direction_norm = direction_map.get((args.direction or "").lower())
    if direction_norm is None:
        sys.stderr.write(f"Invalid direction: {args.direction} — must be inbound or outbound\n")
        sys.exit(2)

    return TrafficTuple(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        dst_port=dst_port,
        protocol=proto_norm,
        direction=direction_norm,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(args: argparse.Namespace, provider: "NSGProvider | None" = None) -> int:
    audit_path: Path = args.audit_path
    session_id: str = args.session_id
    mode: str = args.mode

    # Stage 2 — Collect
    if provider is None:
        provider = AzureNSGProvider(subscription_id=args.subscription_id)

    try:
        if args.nic_name:
            nic_name = args.nic_name
            print(f"Using NIC override: {nic_name}")
        else:
            print(f"Resolving primary NIC for {args.vm_name}...")
            nic_name = provider.get_nic_name(args.vm_name, args.resource_group)

        # For inbound verdict mode where --dst-ip was omitted, derive it from the NIC's
        # own private IP.  This is always correct: for inbound traffic at a VM's NIC,
        # the destination is always the NIC's own IP.
        # Guard: args.traffic is None only when main() deferred building the tuple
        # (i.e. dst_ip was absent from the CLI flags).  Tests that build args.traffic
        # directly are not affected.
        if mode == "verdict" and args.traffic is None:
            print(f"Deriving dst_ip from NIC {nic_name}...")
            args.dst_ip = provider.get_nic_ip(nic_name, args.resource_group)
            args.traffic = _validate_traffic_tuple(args)

        print(f"Querying effective NSG for {nic_name}...")
        raw_dict = provider.get_effective_nsg(nic_name, args.resource_group)

    except RBACError as e:
        sys.stderr.write(
            f"ERROR: Authorization failed.\n"
            f"  Missing permission: {e.permission}\n"
            f"  Required for:       {e.operation}\n"
            f"  Grant 'Network Contributor' or a custom role with this action on the resource group.\n"
        )
        return 2
    except VMNotFoundError as e:
        sys.stderr.write(
            f"VM '{args.vm_name}' not found in resource group '{args.resource_group}': {e}\n"
        )
        return 2
    except NICResolutionError as e:
        sys.stderr.write(f"NIC resolution failed for VM '{args.vm_name}': {e}\n")
        return 2
    except ThrottleExhausted as e:
        sys.stderr.write(
            f"Azure API throttled. Attempts: {e.attempts}, last wait: {e.last_wait_seconds:.1f}s\n"
        )
        return 2
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
    result = nsg_preprocessor.preprocess(str(raw_file_path))

    if "error" in result:
        sys.stderr.write(f"{result['error']}\n")
        return 2

    if result["gate_count"] == 0:
        sys.stderr.write(f"No NSG entries found in {raw_file_path}\n")
        for pw in result.get("parse_warnings") or []:
            sys.stderr.write(f"{pw}\n")
        return 2

    rule_sets = result

    # Stage 4 — Evaluate
    if mode == "verdict":
        evaluated = nsg_engine.evaluate_verdict(rule_sets, args.traffic)
    else:
        evaluated = nsg_engine.audit(rule_sets)

    # Enrich with identity fields
    evaluated["session_id"] = session_id
    evaluated["vm_name"] = args.vm_name
    evaluated["resource_group"] = args.resource_group
    evaluated["nic_name"] = nic_name

    if mode == "verdict":
        artifact_path = audit_path / f"{session_id}_verdict.json"
    else:
        artifact_path = audit_path / f"{session_id}_audit.json"

    try:
        artifact_path.write_text(json.dumps(evaluated, indent=2), encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"Cannot write artifact {artifact_path}: {e}\n")
        return 2

    # Stage 5 — Output
    if mode == "verdict":
        print(_render_verdict_table(evaluated))
    else:
        print(_render_audit_table(evaluated))

    print(f"\nArtifact: {artifact_path}")

    for pw in evaluated.get("parse_warnings") or []:
        print(f"Warning: {pw}")

    return 0


# ---------------------------------------------------------------------------
# Render — verdict mode
# ---------------------------------------------------------------------------

def _render_verdict_table(verdict: dict) -> str:
    lines = []
    traffic = verdict.get("traffic") or {}
    vm = verdict.get("vm_name", "n/a")
    rg = verdict.get("resource_group", "n/a")
    nic = verdict.get("nic_name", "n/a")
    src = traffic.get("src_ip", "n/a")
    dst = traffic.get("dst_ip", "n/a")
    port = traffic.get("dst_port", "n/a")
    proto = traffic.get("protocol", "n/a")
    direction = traffic.get("direction", "n/a")

    lines.append(f"VM:  {vm}  ({rg})")
    lines.append(f"NIC: {nic}")
    lines.append(f"Traffic:        {src} → {dst}:{port} {proto} {direction.lower()}")
    lines.append("")

    gate_order = verdict.get("gate_order") or []
    gate1 = verdict.get("gate1") or {}
    gate2 = verdict.get("gate2") or {}

    def _gate_label(gate_name: str, position: str, direction: str) -> str:
        nsg_type = "Subnet NSG" if gate_name == "subnet" else "NIC NSG"
        return f"Gate {position} ({nsg_type} — evaluated {'first' if position == '1' else 'second'} for {direction.lower()})"

    def _render_gate_section(gate_result: dict, position: str, direction: str) -> list:
        section = []
        gate_name = gate_result.get("gate", "unknown")
        label = _gate_label(gate_name, position, direction)
        section.append(f"{label}:")

        if not gate_result.get("evaluated", True):
            skip = gate_result.get("skip_reason", "")
            reason = "prior gate DENY" if skip == "PRIOR_GATE_DENY" else "prior gate INDETERMINATE"
            section.append(f"  Gate {position}:         Not evaluated ({reason})")
            return section

        gate_verdict = gate_result.get("verdict")
        decisive = gate_result.get("decisive_rule")
        unresolvable = gate_result.get("unresolvable_rule")

        if decisive is None and unresolvable is None and gate_verdict == "ALLOW":
            section.append("  No NSG associated — gate imposes no restriction")
            section.append(f"  Decision:       ALLOW")
        elif unresolvable is not None:
            name = unresolvable.get("name", "unknown")
            priority = unresolvable.get("priority", "?")
            src_addr = unresolvable.get("source_address", "")
            dst_addr = unresolvable.get("destination_address", "")
            section.append(f"  Rule halted:    {name} (priority {priority})")
            if src_addr and not _is_plain_cidr(src_addr):
                section.append(f"    source: {src_addr!r} — service tag or ASG, not expanded to CIDRs")
            if dst_addr and not _is_plain_cidr(dst_addr):
                section.append(f"    destination: {dst_addr!r} — service tag or ASG, not expanded to CIDRs")
            section.append(f"  Decision:       INDETERMINATE")
        elif decisive is not None:
            name = decisive.get("name", "unknown")
            priority = decisive.get("priority", "?")
            section.append(f"  Rule matched:   {name} (priority {priority})")
            section.append(f"  Decision:       {gate_verdict}")
        else:
            section.append(f"  Decision:       {gate_verdict}")

        return section

    lines.extend(_render_gate_section(gate1, "1", direction))
    lines.append("")
    lines.extend(_render_gate_section(gate2, "2", direction))
    lines.append("")

    final = verdict.get("final_verdict", "n/a")
    lines.append(f"Final verdict:  {final}")
    lines.append("")

    shadowed = verdict.get("shadowed_rules") or []
    if shadowed:
        lines.append("Shadowed rules:")
        for sr in shadowed:
            rule = sr.get("rule") or {}
            by = sr.get("shadowed_by") or {}
            gate = sr.get("gate", "?")
            direction_s = sr.get("direction", "?")
            lines.append(
                f"  [{gate.capitalize()} NSG / {direction_s}] "
                f"{rule.get('name', '?')} (priority {rule.get('priority', '?')})"
            )
            lines.append(
                f"    shadowed by: {by.get('name', '?')} (priority {by.get('priority', '?')}) "
                "— superset on all dimensions"
            )
    else:
        lines.append("Shadowed rules: (none)")

    lines.append("")

    unresolvable_rules = verdict.get("unresolvable_rules") or []
    if unresolvable_rules:
        lines.append("Unresolvable:")
        for ur in unresolvable_rules:
            name = ur.get("name", "?")
            priority = ur.get("priority", "?")
            src_addr = ur.get("source_address", "")
            dst_addr = ur.get("destination_address", "")
            lines.append(f"  {name} (priority {priority})")
            if src_addr and not _is_plain_cidr(src_addr):
                lines.append(f"    source: {src_addr!r} — service tag or ASG not expanded")
            if dst_addr and not _is_plain_cidr(dst_addr):
                lines.append(f"    destination: {dst_addr!r} — service tag or ASG not expanded")
    else:
        lines.append("Unresolvable:   (none)")

    lines.append("────────────────────────────────────────────────────────")

    return "\n".join(lines)


def _is_plain_cidr(value: str) -> bool:
    """Return True if value is a wildcard or valid CIDR (not a service tag)."""
    if value.strip().lower() in ("*", "any", "0.0.0.0/0", "::/0"):
        return True
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Render — audit mode
# ---------------------------------------------------------------------------

def _render_audit_table(audit: dict) -> str:
    lines = []
    vm = audit.get("vm_name", "n/a")
    rg = audit.get("resource_group", "n/a")
    nic = audit.get("nic_name", "n/a")

    lines.append(f"VM:   {vm}  ({rg})")
    lines.append(f"NIC:  {nic}")
    lines.append("")

    rule_sets = audit.get("rule_sets") or {}
    findings = audit.get("findings") or {}

    def _render_rule_set(gate_label: str, position_label: str, direction: str, rules: list) -> list:
        section = []
        nsg_type = "Subnet NSG" if gate_label == "subnet" else "NIC NSG"
        section.append(f"{nsg_type} (evaluated {position_label} for {direction.lower()}):")
        if not rules:
            section.append("  (No NSG associated)")
            return section
        header = f"  {'Priority':<10}{'Name':<30}{'Action':<8}{'Protocol':<10}{'Source':<22}{'Destination':<22}Port"
        section.append(header)
        section.append("  " + "-" * 110)
        for r in rules:
            priority = str(r.get("priority", "?"))
            name = r.get("name", "?")
            access = r.get("access", "?")
            proto = r.get("protocol", "?")
            src = r.get("source_address", "?")
            dst = r.get("destination_address", "?")
            ports = ", ".join(r.get("destination_ports") or ["?"])
            default_tag = "  [default]" if r.get("is_default") else ""
            shadowed_tag = "  [SHADOWED]" if r.get("shadowed_by") else ""
            section.append(
                f"  {priority:<10}{name:<30}{access:<8}{proto:<10}"
                f"{src:<22}{dst:<22}{ports}{default_tag}{shadowed_tag}"
            )
        return section

    # Inbound
    lines.append("─── INBOUND " + "─" * 68)
    lines.append("")
    inbound = rule_sets.get("inbound") or {}
    g1 = inbound.get("gate1") or {}
    g2 = inbound.get("gate2") or {}
    lines.extend(_render_rule_set(g1.get("gate", "subnet"), "first",  "Inbound", g1.get("rules") or []))
    lines.append("")
    lines.extend(_render_rule_set(g2.get("gate", "nic"),    "second", "Inbound", g2.get("rules") or []))
    lines.append("")

    # Outbound
    lines.append("─── OUTBOUND " + "─" * 67)
    lines.append("")
    outbound = rule_sets.get("outbound") or {}
    g1 = outbound.get("gate1") or {}
    g2 = outbound.get("gate2") or {}
    lines.extend(_render_rule_set(g1.get("gate", "nic"),    "first",  "Outbound", g1.get("rules") or []))
    lines.append("")
    lines.extend(_render_rule_set(g2.get("gate", "subnet"), "second", "Outbound", g2.get("rules") or []))
    lines.append("")

    # Findings
    lines.append("─── FINDINGS " + "─" * 67)
    lines.append("")

    shadowed_rules = findings.get("shadowed_rules") or []
    lines.append("Shadowed rules:")
    if shadowed_rules:
        for sr in shadowed_rules:
            rule = sr.get("rule") or {}
            by = sr.get("shadowed_by") or {}
            gate = sr.get("gate", "?")
            direction_s = sr.get("direction", "?")
            nsg_type = "Subnet NSG" if gate == "subnet" else "NIC NSG"
            lines.append(
                f"  [{nsg_type} / {direction_s}] "
                f"{rule.get('name', '?')} (priority {rule.get('priority', '?')})"
            )
            lines.append(
                f"    shadowed by: {by.get('name', '?')} (priority {by.get('priority', '?')}) "
                "— superset on all dimensions"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    permissive_rules = findings.get("permissive_rules") or []
    lines.append("Overly permissive rules:")
    if permissive_rules:
        for pr in permissive_rules:
            rule = pr.get("rule") or {}
            gate = pr.get("gate", "?")
            direction_s = pr.get("direction", "?")
            dims = pr.get("wildcard_dimensions") or []
            nsg_type = "Subnet NSG" if gate == "subnet" else "NIC NSG"
            lines.append(
                f"  [{nsg_type} / {direction_s}] "
                f"{rule.get('name', '?')} (priority {rule.get('priority', '?')})"
            )
            lines.append(f"    wildcard dimensions: {', '.join(dims)}")
    else:
        lines.append("  (none)")
    lines.append("")

    default_only_gates = findings.get("default_only_gates") or []
    lines.append("Default-only gates:")
    if default_only_gates:
        for dog in default_only_gates:
            gate = dog.get("gate", "?")
            direction_s = dog.get("direction", "?")
            nsg_absent = dog.get("nsg_absent", False)
            nsg_type = "Subnet NSG" if gate == "subnet" else "NIC NSG"
            if nsg_absent:
                lines.append(f"  {nsg_type} / {direction_s} — no NSG associated")
            else:
                lines.append(f"  {nsg_type} / {direction_s} — NSG present, no custom rules")
    else:
        lines.append("  (none)")
    lines.append("")

    # Posture summary — derived from findings
    posture_lines = _derive_posture_summary(rule_sets, findings)
    lines.append("Posture summary:")
    for pl in posture_lines:
        lines.append(f"  {pl}")

    lines.append("────────────────────────────────────────────────────────")

    return "\n".join(lines)


def _derive_posture_summary(rule_sets: dict, findings: dict) -> list:
    """
    Derive a brief posture summary from rule sets and findings.

    Identifies whether any direction is effectively blocked by a high-priority
    deny rule in Gate 1 that covers all traffic.
    """
    summary = []

    def _check_gate1_block(gate1_rules: list, direction: str, gate1_label: str) -> str | None:
        nsg_type = "Subnet NSG" if gate1_label == "subnet" else "NIC NSG"
        for rule in gate1_rules:
            if rule.get("access", "").lower() != "deny":
                continue
            proto = rule.get("protocol", "")
            src = rule.get("source_address", "")
            dst = rule.get("destination_address", "")
            ports = rule.get("destination_ports") or []
            if (
                _is_protocol_wildcard_str(proto)
                and _is_wildcard_addr_str(src)
                and _is_wildcard_addr_str(dst)
                and _is_port_wildcard_list(ports)
            ):
                name = rule.get("name", "?")
                priority = rule.get("priority", "?")
                return (
                    f"{direction} traffic is blocked by {name} at priority {priority} "
                    f"in the {nsg_type}. "
                    f"No {direction.lower()} traffic can reach this VM regardless of the other gate's rules."
                )
        return None

    inbound = rule_sets.get("inbound") or {}
    outbound = rule_sets.get("outbound") or {}

    g1_inbound = inbound.get("gate1") or {}
    g1_outbound = outbound.get("gate1") or {}

    block_in = _check_gate1_block(
        g1_inbound.get("rules") or [], "Inbound", g1_inbound.get("gate", "subnet")
    )
    if block_in:
        summary.append(block_in)

    block_out = _check_gate1_block(
        g1_outbound.get("rules") or [], "Outbound", g1_outbound.get("gate", "nic")
    )
    if block_out:
        summary.append(block_out)

    if not summary:
        summary.append("No all-traffic deny rule detected at Gate 1 in either direction.")

    return summary


def _is_protocol_wildcard_str(proto: str) -> bool:
    return proto.lower() in ("*", "all")


def _is_wildcard_addr_str(addr: str) -> bool:
    return addr.strip().lower() in ("*", "any", "0.0.0.0/0", "::/0")


def _is_port_wildcard_list(ports: list) -> bool:
    return "*" in ports or "0-65535" in ports


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect effective NSG rules for an Azure VM."
    )
    parser.add_argument("--vm-name", required=True, help="Azure VM name")
    parser.add_argument("--resource-group", required=True, help="Azure resource group")
    parser.add_argument("--src-ip", default=None, help="Source IP (verdict mode)")
    parser.add_argument("--dst-ip", default=None, help="Destination IP (verdict mode)")
    parser.add_argument("--dst-port", default=None, type=int, help="Destination port (verdict mode)")
    parser.add_argument("--proto", default=None, help="Protocol: tcp, udp, icmp, or * (verdict mode)")
    parser.add_argument("--direction", default=None, help="inbound or outbound (verdict mode)")
    parser.add_argument("--nic-name", default=None, help="Override primary NIC lookup")
    parser.add_argument("--subscription-id", default=None, help="Azure subscription ID")
    parser.add_argument("--session-id", default=None, help="Session ID (nsg_ prefix enforced)")
    parser.add_argument("--audit-dir", default="./audit", help="Artifact output directory")

    args = parser.parse_args()

    args.mode = _detect_mode(args)

    if args.mode == "verdict" and args.dst_ip is not None:
        # All five flags present — validate eagerly so bad inputs fail before any API call.
        args.traffic = _validate_traffic_tuple(args)
    else:
        # Either audit mode, or inbound verdict with dst_ip deferred to NIC resolution
        # in _run_pipeline.
        args.traffic = None

    args.session_id = _enforce_session_prefix(args.session_id or _generate_session_id())
    args.audit_path = _ensure_audit_dir(args.audit_dir)
    _check_collision(args.session_id, args.audit_path)

    sys.exit(_run_pipeline(args))


if __name__ == "__main__":
    main()
