"""
framework_detector.py — Module 4 of the VM Firewall Inspector

Detects the active netfilter framework on a VM from version strings returned by
the probe script. Pure function — no I/O, no shell calls.

Public API:
    detect_framework(version_strings: dict) -> dict
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Regex patterns for version string parsing
# ---------------------------------------------------------------------------

# iptables --version output patterns
# "iptables v1.8.7 (nf_tables)" → iptables-nft backend
# "iptables v1.8.7 (legacy)"    → legacy xtables backend
# "iptables v1.4.21"            → no backend tag → assume legacy
_IPTABLES_NFT_RE    = re.compile(r"\(nf_tables\)", re.IGNORECASE)
_IPTABLES_LEGACY_RE = re.compile(r"\(legacy\)",    re.IGNORECASE)

# update-alternatives --query iptables output
# The "Value:" line shows which binary /usr/sbin/iptables currently points to.
_UA_VALUE_RE = re.compile(r"^Value:\s*(.+)$", re.MULTILINE)

# nft version line: "nftables v0.9.8 (Liffey)"
_NFT_VERSION_RE = re.compile(r"nftables\s+v\d", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _check_update_alternatives(ua_output: str) -> str | None:
    """
    Parse update-alternatives --query iptables output.
    Returns "iptables-nft", "iptables-legacy", or None if indeterminate.
    """
    if not ua_output:
        return None
    m = _UA_VALUE_RE.search(ua_output)
    if not m:
        return None
    current_value = m.group(1).strip()
    if "iptables-nft" in current_value:
        return "iptables-nft"
    if "iptables-legacy" in current_value:
        return "iptables-legacy"
    return None


def _check_iptables_version(version_output: str) -> str | None:
    """
    Parse iptables --version output.
    Returns "iptables-nft", "iptables-legacy", or None if indeterminate.
    """
    if not version_output:
        return None
    if _IPTABLES_NFT_RE.search(version_output):
        return "iptables-nft"
    if _IPTABLES_LEGACY_RE.search(version_output):
        return "iptables-legacy"
    return None


def _nft_available(nft_output: str) -> bool:
    """Return True if the nft --version output indicates nftables is present."""
    return bool(nft_output and _NFT_VERSION_RE.search(nft_output))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_framework(version_strings: dict[str, Any]) -> dict:
    """
    Detect the active netfilter framework from version strings.

    Args:
        version_strings: dict with zero or more of the following keys:
            "iptables"             — stdout of `iptables --version`
            "iptables_legacy"      — stdout of `iptables-legacy --version`
            "nft"                  — stdout of `nft --version`
            "update_alternatives"  — stdout of `update-alternatives --query iptables`
        Any key may be absent or its value may be an empty string / None —
        these are treated identically as "command not available."

    Returns:
        {
            "framework":       "iptables-legacy" | "iptables-nft" |
                               "nftables-native" | "mixed" | "unknown",
            "iptables_cmd":    "iptables-save" | "iptables-legacy-save" | None,
            "nft_available":   bool,
            "confidence":      "high" | "low",
            "parse_warnings":  list[str],
        }

    "mixed" returns framework="unknown" with a parse_warning.
    "nftables-native" now returns framework="nftables" (Module 3 implemented).
    """
    iptables_vs   = str(version_strings.get("iptables")            or "").strip()
    iptables_leg  = str(version_strings.get("iptables_legacy")     or "").strip()
    nft_vs        = str(version_strings.get("nft")                 or "").strip()
    ua_output     = str(version_strings.get("update_alternatives") or "").strip()

    warnings: list[str] = []
    nft_present = _nft_available(nft_vs)

    # ---------------------------------------------------------------------------
    # Step 1: update-alternatives is the most reliable source (Debian/Ubuntu)
    # ---------------------------------------------------------------------------
    ua_result = _check_update_alternatives(ua_output)
    if ua_result == "iptables-nft":
        return {
            "framework":      "iptables-nft",
            "iptables_cmd":   "iptables-save",
            "nft_available":  nft_present,
            "confidence":     "high",
            "parse_warnings": warnings,
        }
    if ua_result == "iptables-legacy":
        return {
            "framework":      "iptables-legacy",
            "iptables_cmd":   "iptables-legacy-save" if iptables_leg else "iptables-save",
            "nft_available":  nft_present,
            "confidence":     "high",
            "parse_warnings": warnings,
        }

    # ---------------------------------------------------------------------------
    # Step 2: iptables --version backend tag
    # ---------------------------------------------------------------------------
    ipv_result = _check_iptables_version(iptables_vs)
    if ipv_result == "iptables-nft":
        return {
            "framework":      "iptables-nft",
            "iptables_cmd":   "iptables-save",
            "nft_available":  nft_present,
            "confidence":     "high",
            "parse_warnings": warnings,
        }
    if ipv_result == "iptables-legacy":
        return {
            "framework":      "iptables-legacy",
            "iptables_cmd":   "iptables-legacy-save" if iptables_leg else "iptables-save",
            "nft_available":  nft_present,
            "confidence":     "high",
            "parse_warnings": warnings,
        }

    # ---------------------------------------------------------------------------
    # Step 3: iptables --version present but no backend tag — likely older kernel
    # ---------------------------------------------------------------------------
    if iptables_vs and not ipv_result:
        # Older iptables (e.g., v1.4.x) had no backend tag — always legacy.
        # iptables-legacy --version also present strengthens this.
        confidence = "high" if iptables_leg else "low"
        warnings.append(
            "iptables --version has no backend tag; assuming iptables-legacy. "
            "Confirm with 'update-alternatives --query iptables' if possible."
        )
        return {
            "framework":      "iptables-legacy",
            "iptables_cmd":   "iptables-legacy-save" if iptables_leg else "iptables-save",
            "nft_available":  nft_present,
            "confidence":     confidence,
            "parse_warnings": warnings,
        }

    # ---------------------------------------------------------------------------
    # Step 4: iptables-legacy version string available but no iptables main
    # ---------------------------------------------------------------------------
    if iptables_leg and not iptables_vs:
        warnings.append(
            "iptables-legacy --version present but iptables --version absent; "
            "assuming iptables-legacy backend."
        )
        return {
            "framework":      "iptables-legacy",
            "iptables_cmd":   "iptables-legacy-save",
            "nft_available":  nft_present,
            "confidence":     "low",
            "parse_warnings": warnings,
        }

    # ---------------------------------------------------------------------------
    # ---------------------------------------------------------------------------
    # Step 5: only nft present — nftables-native
    # ---------------------------------------------------------------------------
    if nft_present and not iptables_vs and not iptables_leg:
        return {
            "framework":      "nftables",
            "iptables_cmd":   None,
            "nft_available":  True,
            "confidence":     "high",
            "parse_warnings": warnings,
        }

    # ---------------------------------------------------------------------------
    # Step 6: no recognisable version strings — unknown
    # ---------------------------------------------------------------------------
    warnings.append(
        "Could not determine netfilter framework from available version strings. "
        "Ensure the probe script ran correctly and iptables is installed."
    )
    return {
        "framework":      "unknown",
        "iptables_cmd":   None,
        "nft_available":  nft_present,
        "confidence":     "low",
        "parse_warnings": warnings,
    }
