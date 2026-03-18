"""
Tests for framework_detector.py (Module 4)

Coverage:
  FD-01 to FD-04  update-alternatives detection (high confidence)
  FD-05 to FD-08  iptables --version backend tag detection
  FD-09 to FD-10  legacy fallback when no backend tag
  FD-11           iptables-legacy only (no iptables main)
  FD-12           nftables-native only → nftables (Module 3)
  FD-13 to FD-14  empty / missing version strings → unknown
  FD-15           nft_available flag set correctly
  FD-16           parse_warnings populated when expected
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from framework_detector import detect_framework


# ---------------------------------------------------------------------------
# Fixtures — representative version string dicts
# ---------------------------------------------------------------------------

def _vs(
    iptables: str            = "",
    iptables_legacy: str     = "",
    nft: str                 = "",
    update_alternatives: str = "",
) -> dict:
    return {
        "iptables":            iptables,
        "iptables_legacy":     iptables_legacy,
        "nft":                 nft,
        "update_alternatives": update_alternatives,
    }


UA_NFT    = "Name: iptables\nLink: /usr/sbin/iptables\nStatus: manual\nValue: /usr/sbin/iptables-nft\n"
UA_LEGACY = "Name: iptables\nLink: /usr/sbin/iptables\nStatus: manual\nValue: /usr/sbin/iptables-legacy\n"

IPT_NFT    = "iptables v1.8.7 (nf_tables)"
IPT_LEGACY = "iptables v1.8.7 (legacy)"
IPT_OLD    = "iptables v1.4.21"          # no backend tag
IPT_LEG_V  = "iptables-legacy v1.8.7 (legacy)"
NFT_V      = "nftables v0.9.8 (Liffey)"


# ---------------------------------------------------------------------------
# update-alternatives detection
# ---------------------------------------------------------------------------

def test_fd01_ua_detects_nft():
    """update-alternatives Value pointing to iptables-nft → iptables-nft, high."""
    r = detect_framework(_vs(iptables=IPT_NFT, update_alternatives=UA_NFT))
    assert r["framework"]  == "iptables-nft"
    assert r["confidence"] == "high"
    assert r["iptables_cmd"] == "iptables-save"


def test_fd02_ua_detects_legacy():
    """update-alternatives Value pointing to iptables-legacy → iptables-legacy, high."""
    r = detect_framework(_vs(iptables=IPT_LEGACY, update_alternatives=UA_LEGACY))
    assert r["framework"]  == "iptables-legacy"
    assert r["confidence"] == "high"


def test_fd03_ua_legacy_cmd_uses_legacy_save_when_available():
    """When UA says legacy AND iptables-legacy version string present → iptables-legacy-save."""
    r = detect_framework(_vs(iptables=IPT_LEGACY, iptables_legacy=IPT_LEG_V, update_alternatives=UA_LEGACY))
    assert r["iptables_cmd"] == "iptables-legacy-save"


def test_fd04_ua_legacy_cmd_falls_back_to_iptables_save_when_no_legacy_binary():
    """UA says legacy but no iptables-legacy version → iptables-save (best available)."""
    r = detect_framework(_vs(iptables=IPT_LEGACY, update_alternatives=UA_LEGACY))
    assert r["iptables_cmd"] == "iptables-save"


# ---------------------------------------------------------------------------
# iptables --version backend tag
# ---------------------------------------------------------------------------

def test_fd05_version_tag_nft():
    """iptables --version with '(nf_tables)' → iptables-nft, high."""
    r = detect_framework(_vs(iptables=IPT_NFT))
    assert r["framework"]    == "iptables-nft"
    assert r["confidence"]   == "high"
    assert r["iptables_cmd"] == "iptables-save"


def test_fd06_version_tag_legacy():
    """iptables --version with '(legacy)' → iptables-legacy, high."""
    r = detect_framework(_vs(iptables=IPT_LEGACY))
    assert r["framework"]  == "iptables-legacy"
    assert r["confidence"] == "high"


def test_fd07_version_tag_nft_case_insensitive():
    """Backend tag matching is case-insensitive."""
    r = detect_framework(_vs(iptables="iptables v1.8.7 (NF_TABLES)"))
    assert r["framework"] == "iptables-nft"


def test_fd08_version_tag_legacy_case_insensitive():
    r = detect_framework(_vs(iptables="iptables v1.8.7 (LEGACY)"))
    assert r["framework"] == "iptables-legacy"


# ---------------------------------------------------------------------------
# Fallback: iptables present but no backend tag (older kernels)
# ---------------------------------------------------------------------------

def test_fd09_old_version_no_tag_with_legacy_binary():
    """Old iptables (no tag) + iptables-legacy binary present → iptables-legacy, high."""
    r = detect_framework(_vs(iptables=IPT_OLD, iptables_legacy=IPT_LEG_V))
    assert r["framework"]  == "iptables-legacy"
    assert r["confidence"] == "high"
    assert len(r["parse_warnings"]) == 1


def test_fd10_old_version_no_tag_without_legacy_binary():
    """Old iptables (no tag), no legacy binary → iptables-legacy, low + warning."""
    r = detect_framework(_vs(iptables=IPT_OLD))
    assert r["framework"]  == "iptables-legacy"
    assert r["confidence"] == "low"
    assert len(r["parse_warnings"]) == 1


# ---------------------------------------------------------------------------
# iptables-legacy version only (no iptables main)
# ---------------------------------------------------------------------------

def test_fd11_legacy_binary_only():
    """Only iptables-legacy --version present → iptables-legacy, low."""
    r = detect_framework(_vs(iptables_legacy=IPT_LEG_V))
    assert r["framework"]    == "iptables-legacy"
    assert r["iptables_cmd"] == "iptables-legacy-save"
    assert r["confidence"]   == "low"
    assert len(r["parse_warnings"]) == 1


# ---------------------------------------------------------------------------
# nftables-native (Module 3 — implemented)
# ---------------------------------------------------------------------------

def test_fd12_nft_only_returns_nftables():
    """Only nft present, no iptables → framework='nftables', high confidence."""
    r = detect_framework(_vs(nft=NFT_V))
    assert r["framework"]      == "nftables"
    assert r["iptables_cmd"]   is None
    assert r["nft_available"]  is True
    assert r["confidence"]     == "high"
    assert r["parse_warnings"] == []


# ---------------------------------------------------------------------------
# Empty / missing inputs
# ---------------------------------------------------------------------------

def test_fd13_all_empty_strings():
    """All version strings empty → unknown, low."""
    r = detect_framework(_vs())
    assert r["framework"]  == "unknown"
    assert r["confidence"] == "low"
    assert len(r["parse_warnings"]) >= 1


def test_fd14_missing_keys():
    """Empty dict (no keys at all) → unknown, low."""
    r = detect_framework({})
    assert r["framework"]  == "unknown"
    assert r["confidence"] == "low"


# ---------------------------------------------------------------------------
# nft_available flag
# ---------------------------------------------------------------------------

def test_fd15_nft_available_true_when_nft_present():
    """nft_available=True when nft --version output is present."""
    r = detect_framework(_vs(iptables=IPT_LEGACY, nft=NFT_V))
    assert r["nft_available"] is True


def test_fd15b_nft_available_false_when_no_nft():
    """nft_available=False when nft version string absent."""
    r = detect_framework(_vs(iptables=IPT_LEGACY))
    assert r["nft_available"] is False


# ---------------------------------------------------------------------------
# parse_warnings field
# ---------------------------------------------------------------------------

def test_fd16_no_warnings_for_clean_high_confidence():
    """Clean high-confidence detection via update-alternatives produces no warnings."""
    r = detect_framework(_vs(iptables=IPT_NFT, update_alternatives=UA_NFT))
    assert r["parse_warnings"] == []


def test_fd16b_warnings_for_ambiguous_detection():
    """Ambiguous detection (old iptables, no backup evidence) produces at least one warning."""
    r = detect_framework(_vs(iptables=IPT_OLD))
    assert len(r["parse_warnings"]) >= 1
