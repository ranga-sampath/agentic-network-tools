"""
chain_classifier.py — Module 6 of the VM Firewall Inspector

Classifies iptables chains by drift significance and annotates a diff_rulesets()
output to suppress rule-level noise from ephemeral chains.

Three-tier classification:
    user-defined  — operator-created chains; full rule diff always reported
    structural    — service-managed chains (Docker, fail2ban, ufw); full diff
    ephemeral     — high-churn per-connection/per-endpoint chains (kube-proxy);
                    rule-level diff suppressed; count-only summary in output

Extensibility: add new patterns to _EPHEMERAL_PATTERNS or _STRUCTURAL_PATTERNS.
No changes to classify_chain() or classify_diff() are required.

Public API:
    classify_chain(chain_name: str) -> str
    classify_diff(diff_result: dict) -> dict
"""

from __future__ import annotations

import re
from copy import deepcopy

# ---------------------------------------------------------------------------
# Classification pattern lists
# ---------------------------------------------------------------------------
# Checked in order: ephemeral first, structural second, user-defined fallback.
# To add VPN chain patterns (OpenVPN, WireGuard, strongSwan):
#   append re.compile(r"^tun_") etc. to _STRUCTURAL_PATTERNS.
# To add a new ephemeral category: append to _EPHEMERAL_PATTERNS.
# No other code changes required.

_EPHEMERAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"^KUBE-SEP-"),   # kube-proxy: per-endpoint chains
    re.compile(r"^KUBE-SVC-"),   # kube-proxy: per-service chains
    re.compile(r"^KUBE-FW-"),    # kube-proxy: external LoadBalancer
    re.compile(r"^KUBE-XLB-"),   # kube-proxy: external LB hairpin
]

_STRUCTURAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"^DOCKER"),      # Docker bridge and NAT rules
    re.compile(r"^f2b-"),        # fail2ban per-service jail chains
    re.compile(r"^ufw-"),        # UFW generated chains
    re.compile(r"^LIBVIRT_"),    # libvirt bridge chains
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_chain(chain_name: str) -> str:
    """
    Classify a chain name by drift significance.

    Returns:
        "ephemeral"    — high-churn; rule-level diff suppressed in classify_diff()
        "structural"   — service-managed; full diff reported
        "user-defined" — operator-created; full diff reported (default)
    """
    for pattern in _EPHEMERAL_PATTERNS:
        if pattern.match(chain_name):
            return "ephemeral"
    for pattern in _STRUCTURAL_PATTERNS:
        if pattern.match(chain_name):
            return "structural"
    return "user-defined"


def classify_diff(diff_result: dict) -> dict:
    """
    Annotate a diff_rulesets() output with chain classifications.

    For ephemeral-tier chains:
      - Rule-level entries (rules_added, rules_removed, rules_repositioned)
        are removed from the changes dict.
      - A count-only summary is added under "ephemeral_summary".

    For user-defined and structural chains, the diff is unchanged.

    Returns a new dict (deep copy — the input is not modified) with two
    additional top-level keys:
        "chain_classifications": {chain_name: "user-defined"|"structural"|"ephemeral"}
        "ephemeral_summary":     {chain_name: {"baseline_rule_count": int,
                                               "current_rule_count": int}}

    The "drift_detected" and "has_critical_changes" flags are NOT modified.
    Ephemeral-chain policy changes are included in the output because a default
    policy change on any chain is operationally significant regardless of tier.
    """
    result = deepcopy(diff_result)

    changes = result.get("changes", {})
    all_chain_names: set[str] = set()

    # Collect all chain names touched by this diff
    for key in ("chains_added", "chains_removed"):
        for entry in changes.get(key, []):
            all_chain_names.add(entry["chain"])
    for key in ("rules_added", "rules_removed", "rules_repositioned"):
        for entry in changes.get(key, []):
            all_chain_names.add(entry["chain"])
    for entry in changes.get("policy_changes", []):
        all_chain_names.add(entry["chain"])

    # Build classification index
    chain_classifications: dict[str, str] = {
        name: classify_chain(name) for name in sorted(all_chain_names)
    }

    # Identify ephemeral chain names
    ephemeral_chains = {
        name for name, cls in chain_classifications.items() if cls == "ephemeral"
    }

    # Build ephemeral summary (baseline and current rule counts)
    ephemeral_summary: dict[str, dict] = {}

    # Count rules added per ephemeral chain
    current_counts: dict[str, int] = {}
    baseline_counts: dict[str, int] = {}
    for r in changes.get("rules_added", []):
        if r["chain"] in ephemeral_chains:
            current_counts[r["chain"]] = current_counts.get(r["chain"], 0) + 1
    for r in changes.get("rules_removed", []):
        if r["chain"] in ephemeral_chains:
            baseline_counts[r["chain"]] = baseline_counts.get(r["chain"], 0) + 1

    for chain_name in ephemeral_chains:
        ephemeral_summary[chain_name] = {
            "baseline_rule_count": baseline_counts.get(chain_name, 0),
            "current_rule_count":  current_counts.get(chain_name, 0),
        }

    # Suppress rule-level entries for ephemeral chains
    for key in ("rules_added", "rules_removed", "rules_repositioned"):
        changes[key] = [
            r for r in changes.get(key, [])
            if r["chain"] not in ephemeral_chains
        ]

    # Update summary counts to reflect suppressed rules
    summary = result.get("summary", {})
    for key in ("rules_added", "rules_removed", "rules_repositioned"):
        summary[key] = len(changes[key])

    result["chain_classifications"] = chain_classifications
    result["ephemeral_summary"] = ephemeral_summary
    return result
