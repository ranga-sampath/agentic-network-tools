"""
nsg_engine.py — Pure evaluation engine for security-rule-inspector.

No I/O. No side effects. All functions are deterministic for identical inputs.

Public interface:
    evaluate_verdict(rule_sets: dict, traffic: TrafficTuple) -> dict
    audit(rule_sets: dict) -> dict
"""

from __future__ import annotations

import ipaddress
from typing import NamedTuple


# ---------------------------------------------------------------------------
# TrafficTuple
# ---------------------------------------------------------------------------

class TrafficTuple(NamedTuple):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str   # "Tcp", "Udp", "Icmp", or "*"
    direction: str  # "Inbound" or "Outbound"


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def _is_wildcard_address(value: str) -> bool:
    return value.strip().lower() in ("*", "any", "0.0.0.0/0", "::/0")


def _is_unresolvable(value: str) -> bool:
    if _is_wildcard_address(value):
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return False
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------

def _match_rule(rule: dict, traffic: TrafficTuple) -> bool | None:
    """
    Return True (match), False (definitive no-match), or None (UNRESOLVABLE).
    """
    # Protocol check
    rule_proto = (rule.get("protocol") or "*").lower()
    if rule_proto not in ("*", "all"):
        if rule_proto != traffic.protocol.lower():
            return False

    # Source address check (OR semantics across comma-separated values)
    src_addr_field = rule.get("source_address") or "*"
    src_values = [v.strip() for v in src_addr_field.split(", ")]
    src_matched = False
    for value in src_values:
        if _is_wildcard_address(value):
            src_matched = True
            break
        if _is_unresolvable(value):
            return None
        try:
            network = ipaddress.ip_network(value, strict=False)
            if ipaddress.ip_address(traffic.src_ip) in network:
                src_matched = True
                break
        except ValueError:
            return None

    if not src_matched:
        return False

    # Destination address check (OR semantics)
    dst_addr_field = rule.get("destination_address") or "*"
    dst_values = [v.strip() for v in dst_addr_field.split(", ")]
    dst_matched = False
    for value in dst_values:
        if _is_wildcard_address(value):
            dst_matched = True
            break
        if _is_unresolvable(value):
            return None
        try:
            network = ipaddress.ip_network(value, strict=False)
            if ipaddress.ip_address(traffic.dst_ip) in network:
                dst_matched = True
                break
        except ValueError:
            return None

    if not dst_matched:
        return False

    # Source port — always treated as matching (ephemeral, not in traffic description)

    # Destination port check (OR semantics)
    dst_ports = rule.get("destination_ports") or ["*"]
    for port_spec in dst_ports:
        port_spec = str(port_spec).strip()
        if port_spec in ("*", "0-65535"):
            return True
        if "-" in port_spec:
            try:
                low, high = port_spec.split("-", 1)
                if int(low) <= traffic.dst_port <= int(high):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(port_spec) == traffic.dst_port:
                    return True
            except ValueError:
                continue

    return False


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------

def _evaluate_gate(rules: list, traffic: TrafficTuple) -> dict:
    """
    Evaluate a single gate's sorted rule list against traffic.

    Returns a GateResult dict.
    """
    if not rules:
        return {
            "verdict": "ALLOW",
            "decisive_rule": None,
            "unresolvable_rule": None,
            "evaluated": True,
            "skip_reason": None,
        }

    for rule in rules:
        match = _match_rule(rule, traffic)
        if match is True:
            access = rule.get("access", "")
            verdict = "ALLOW" if access.lower() == "allow" else "DENY"
            return {
                "verdict": verdict,
                "decisive_rule": rule,
                "unresolvable_rule": None,
                "evaluated": True,
                "skip_reason": None,
            }
        if match is None:
            return {
                "verdict": "INDETERMINATE",
                "decisive_rule": None,
                "unresolvable_rule": rule,
                "evaluated": True,
                "skip_reason": None,
            }
        # match is False — continue

    # Exhausted all rules without a match or UNRESOLVABLE hit.
    # Should not occur in practice — Azure always injects DenyAll at priority 65500
    # which matches every packet. If it does occur (malformed preprocessor output),
    # the design requires a parse warning here, but _evaluate_gate has no warning
    # list parameter and GateResult has no parse_warnings field. The DENY is correct;
    # the missing warning is a known gap for this unreachable path.
    return {
        "verdict": "DENY",
        "decisive_rule": None,
        "unresolvable_rule": None,
        "evaluated": True,
        "skip_reason": None,
    }


# ---------------------------------------------------------------------------
# Gate lookup
# ---------------------------------------------------------------------------

def _find_gate(gates: list, association_type: str) -> dict | None:
    for g in gates:
        if g.get("association_type") == association_type:
            return g
    return None


# ---------------------------------------------------------------------------
# Shadow collection
# ---------------------------------------------------------------------------

def _collect_shadows(
    rules: list,
    gate: str,
    direction: str,
    warnings: list | None = None,
) -> list:
    """
    Convert preprocessor-populated shadowed_by fields into ShadowedRule objects.
    """
    result = []
    name_index = {r["name"]: r for r in rules}

    for rule in rules:
        shadowed_by_name = rule.get("shadowed_by")
        if shadowed_by_name is None:
            continue
        shadower = name_index.get(shadowed_by_name)
        if shadower is None:
            if warnings is not None:
                warnings.append(
                    f"Shadow reference '{shadowed_by_name}' not found in {gate}/{direction} "
                    f"rule list — skipping shadow entry for '{rule['name']}'."
                )
            continue
        result.append({
            "rule": rule,
            "shadowed_by": shadower,
            "gate": gate,
            "direction": direction,
        })

    return result


# ---------------------------------------------------------------------------
# Permissive rule detection
# ---------------------------------------------------------------------------

def _detect_permissive(rules: list, gate: str, direction: str) -> list:
    """
    Return list of PermissiveRule dicts for custom ALLOW rules with wildcard dimensions.
    """
    result = []
    for rule in rules:
        if rule.get("access", "").lower() != "allow":
            continue
        if rule.get("is_default", True):
            continue

        wildcard_dimensions = []
        # Azure expands "*" to "0.0.0.0/0, ::/0" in effective NSG output.
        # Split on commas and treat the address as a wildcard if ANY component is.
        src_components = [v.strip() for v in (rule.get("source_address") or "").split(",")]
        if any(_is_wildcard_address(v) for v in src_components):
            wildcard_dimensions.append("source")
        dst_components = [v.strip() for v in (rule.get("destination_address") or "").split(",")]
        if any(_is_wildcard_address(v) for v in dst_components):
            wildcard_dimensions.append("destination")
        dst_ports = rule.get("destination_ports") or []
        if "*" in dst_ports or "0-65535" in dst_ports:
            wildcard_dimensions.append("port")

        if wildcard_dimensions:
            result.append({
                "rule": rule,
                "gate": gate,
                "direction": direction,
                "wildcard_dimensions": wildcard_dimensions,
            })

    return result


# ---------------------------------------------------------------------------
# evaluate_verdict — dual-gate model
# ---------------------------------------------------------------------------

def evaluate_verdict(rule_sets: dict, traffic: TrafficTuple) -> dict:
    """
    Apply the Azure dual-gate model; return a complete verdict structure.

    Identity fields (session_id, vm_name, resource_group, nic_name) are NOT
    included — the orchestrator adds them before writing the artifact.
    """
    gates = rule_sets.get("gates") or []
    parse_warnings = list(rule_sets.get("parse_warnings") or [])

    direction = traffic.direction  # "Inbound" or "Outbound"
    rule_key = "inbound_rules" if direction.lower() == "inbound" else "outbound_rules"

    # Gate assignment by direction
    if direction.lower() == "inbound":
        gate1_assoc = "subnet"
        gate2_assoc = "networkInterface"
        gate1_label = "subnet"
        gate2_label = "nic"
    else:
        gate1_assoc = "networkInterface"
        gate2_assoc = "subnet"
        gate1_label = "nic"
        gate2_label = "subnet"

    gate_order = [gate1_label, gate2_label]

    # Extract Gate 1 rules
    gate1_entry = _find_gate(gates, gate1_assoc)
    gate1_rules = gate1_entry[rule_key] if gate1_entry else []
    if gate1_entry is None:
        parse_warnings.append(
            f"No {gate1_label} NSG gate found — treating as empty (no restriction)."
        )

    # Evaluate Gate 1
    gate1_result = _evaluate_gate(gate1_rules, traffic)
    gate1_result["gate"] = gate1_label

    # Collect Gate 1 shadow warnings
    shadow_warnings: list = []
    gate1_shadows = _collect_shadows(gate1_rules, gate1_label, direction, shadow_warnings)
    parse_warnings.extend(shadow_warnings)

    # Gate 2 evaluation
    if gate1_result["verdict"] == "DENY":
        gate2_result = {
            "gate": gate2_label,
            "verdict": None,
            "decisive_rule": None,
            "unresolvable_rule": None,
            "evaluated": False,
            "skip_reason": "PRIOR_GATE_DENY",
        }
        gate2_rules = []
    elif gate1_result["verdict"] == "INDETERMINATE":
        gate2_result = {
            "gate": gate2_label,
            "verdict": None,
            "decisive_rule": None,
            "unresolvable_rule": None,
            "evaluated": False,
            "skip_reason": "PRIOR_GATE_INDETERMINATE",
        }
        gate2_rules = []
    else:
        # Gate 1 = ALLOW — evaluate Gate 2
        gate2_entry = _find_gate(gates, gate2_assoc)
        gate2_rules = gate2_entry[rule_key] if gate2_entry else []
        if gate2_entry is None:
            parse_warnings.append(
                f"No {gate2_label} NSG gate found — treating as empty (no restriction)."
            )
        gate2_result = _evaluate_gate(gate2_rules, traffic)
        gate2_result["gate"] = gate2_label

    # Collect Gate 2 shadows (even when Gate 2 not evaluated)
    shadow_warnings2: list = []
    gate2_shadows = _collect_shadows(gate2_rules, gate2_label, direction, shadow_warnings2)
    parse_warnings.extend(shadow_warnings2)

    shadowed_rules = gate1_shadows + gate2_shadows

    # INDETERMINATE propagation table (architecture D15)
    g1v = gate1_result["verdict"]
    g2v = gate2_result["verdict"]

    if g1v == "DENY":
        final_verdict = "DENY"
    elif g1v == "INDETERMINATE":
        final_verdict = "INDETERMINATE"
    elif g1v == "ALLOW":
        if g2v == "ALLOW":
            final_verdict = "ALLOW"
        elif g2v == "DENY":
            final_verdict = "DENY"
        elif g2v == "INDETERMINATE":
            final_verdict = "INDETERMINATE"
        else:
            # Gate 2 verdict is None — should not occur when Gate 1 = ALLOW.
            # Fail-closed: unknown state is INDETERMINATE, not ALLOW.
            final_verdict = "INDETERMINATE"
    else:
        final_verdict = "INDETERMINATE"

    # Collect unresolvable rules
    unresolvable_rules = []
    if gate1_result.get("unresolvable_rule"):
        unresolvable_rules.append(gate1_result["unresolvable_rule"])
    if gate2_result.get("unresolvable_rule"):
        unresolvable_rules.append(gate2_result["unresolvable_rule"])

    return {
        "mode": "verdict",
        "traffic": {
            "src_ip": traffic.src_ip,
            "dst_ip": traffic.dst_ip,
            "dst_port": traffic.dst_port,
            "protocol": traffic.protocol,
            "direction": traffic.direction,
        },
        "gate_order": gate_order,
        "gate1": gate1_result,
        "gate2": gate2_result,
        "final_verdict": final_verdict,
        "shadowed_rules": shadowed_rules,
        "unresolvable_rules": unresolvable_rules,
        "parse_warnings": parse_warnings,
    }


# ---------------------------------------------------------------------------
# audit — full rule inventory and findings
# ---------------------------------------------------------------------------

def audit(rule_sets: dict) -> dict:
    """
    Produce full rule inventory and findings across both gates and both directions.

    Identity fields are NOT included — the orchestrator adds them.
    """
    gates = rule_sets.get("gates") or []
    parse_warnings = list(rule_sets.get("parse_warnings") or [])

    subnet_entry = _find_gate(gates, "subnet")
    nic_entry = _find_gate(gates, "networkInterface")

    subnet_inbound  = subnet_entry["inbound_rules"]  if subnet_entry else []
    subnet_outbound = subnet_entry["outbound_rules"] if subnet_entry else []
    nic_inbound     = nic_entry["inbound_rules"]     if nic_entry else []
    nic_outbound    = nic_entry["outbound_rules"]    if nic_entry else []

    # Collect shadows across all four rule sets
    shadow_warnings: list = []
    shadowed_rules = (
        _collect_shadows(subnet_inbound,  "subnet", "Inbound",  shadow_warnings) +
        _collect_shadows(subnet_outbound, "subnet", "Outbound", shadow_warnings) +
        _collect_shadows(nic_inbound,     "nic",    "Inbound",  shadow_warnings) +
        _collect_shadows(nic_outbound,    "nic",    "Outbound", shadow_warnings)
    )
    parse_warnings.extend(shadow_warnings)

    # Collect permissive rules
    permissive_rules = (
        _detect_permissive(subnet_inbound,  "subnet", "Inbound") +
        _detect_permissive(subnet_outbound, "subnet", "Outbound") +
        _detect_permissive(nic_inbound,     "nic",    "Inbound") +
        _detect_permissive(nic_outbound,    "nic",    "Outbound")
    )

    # Default-only gates
    default_only_gates = []

    def _is_default_only(rules: list, entry_present: bool) -> bool:
        if not entry_present:
            return True
        if not rules:
            return True
        return all(r.get("is_default", False) for r in rules)

    for gate_label, entry, inbound, outbound in [
        ("subnet", subnet_entry, subnet_inbound,  subnet_outbound),
        ("nic",    nic_entry,    nic_inbound,      nic_outbound),
    ]:
        entry_present = entry is not None
        for direction, rules in [("Inbound", inbound), ("Outbound", outbound)]:
            if _is_default_only(rules, entry_present):
                default_only_gates.append({
                    "gate": gate_label,
                    "direction": direction,
                    "nsg_absent": not entry_present,
                })

    # Inbound: Gate 1 = subnet, Gate 2 = nic
    # Outbound: Gate 1 = nic, Gate 2 = subnet
    result = {
        "mode": "audit",
        "rule_sets": {
            "inbound": {
                "gate1": {
                    "gate": "subnet",
                    "rules": subnet_inbound,
                },
                "gate2": {
                    "gate": "nic",
                    "rules": nic_inbound,
                },
            },
            "outbound": {
                "gate1": {
                    "gate": "nic",
                    "rules": nic_outbound,
                },
                "gate2": {
                    "gate": "subnet",
                    "rules": subnet_outbound,
                },
            },
        },
        "findings": {
            "shadowed_rules": shadowed_rules,
            "permissive_rules": permissive_rules,
            "default_only_gates": default_only_gates,
        },
        "parse_warnings": parse_warnings,
    }

    return result
