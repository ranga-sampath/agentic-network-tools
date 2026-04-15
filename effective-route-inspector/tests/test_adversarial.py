"""
test_adversarial.py — Regression tests for adversarial fixture failures.

Each test class documents the production scenario, the original failure mode,
and what the fix must guarantee.
"""

import json
import sys
import tempfile
import os
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import lpm_engine
import route_preprocessor

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _preprocess(fixture_name: str) -> dict:
    path = FIXTURES / fixture_name
    with open(path) as f:
        data = json.load(f)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(data, tmp)
        tmp_path = tmp.name
    try:
        return route_preprocessor.preprocess(tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# ADV-01: INVALID_SHADOW same-prefix false negative
# ---------------------------------------------------------------------------

class TestAdv01InvalidShadowSamePrefix(unittest.TestCase):
    """
    Scenario: A UDR (User) for 172.16.10.0/24 pointing to an NVA becomes Invalid
    because the NVA was deleted. Azure's Default VnetLocal route for the same /24
    prefix takes over as winner. The original INVALID_SHADOW check used
    `prefix_length > winner["prefix_length"]`, which misses same-prefix Invalid
    routes.

    Fix: Expand the check to `prefix_length >= winner["prefix_length"]` for cases
    where the Invalid route would have taken source precedence (lower tier number).
    """

    def setUp(self):
        self.result = _preprocess("fx-adv-01-invalid-udr-same-prefix.json")
        self.routes = self.result["routes"]

    def test_preprocessor_parses_all_routes(self):
        self.assertEqual(self.result["route_count"], 4)
        self.assertNotIn("error", self.result)

    def test_winner_is_default_vnetlocal(self):
        verdict = lpm_engine.select_route(self.routes, "172.16.10.5")
        self.assertEqual(verdict["result"], "WINNER")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "172.16.10.0/24")
        self.assertEqual(wr["source"], "Default")
        self.assertEqual(wr["next_hop_type"], "VnetLocal")

    def test_invalid_shadow_warning_fires_for_same_prefix_udr(self):
        """
        ADV-01 regression: the Invalid User /24 UDR must trigger INVALID_SHADOW
        even though its prefix_length equals the winner's prefix_length.
        """
        verdict = lpm_engine.select_route(self.routes, "172.16.10.5")
        warnings = verdict["anomaly_warnings"]
        shadow_warnings = [w for w in warnings if "INVALID_SHADOW_WARNING" in w]
        self.assertTrue(
            shadow_warnings,
            "Expected INVALID_SHADOW_WARNING for same-prefix Invalid UDR; got none.\n"
            f"All anomaly_warnings: {warnings}"
        )

    def test_invalid_shadow_warning_mentions_source_precedence(self):
        verdict = lpm_engine.select_route(self.routes, "172.16.10.5")
        warnings = " ".join(verdict["anomaly_warnings"])
        # The warning must explain WHY it matters — source precedence
        self.assertIn("tier", warnings)
        self.assertIn("User", warnings)

    def test_no_false_positive_when_invalid_route_has_lower_priority(self):
        """
        Inverse: an Invalid route with LOWER source priority than the winner
        should NOT trigger INVALID_SHADOW (it would not have won anyway).
        """
        # Construct routes where winner is User and Invalid is Default (tier 3 > tier 1)
        routes = [
            {
                "prefix": "10.0.0.0/24",
                "prefix_length": 24,
                "next_hop_type": "VirtualAppliance",
                "next_hop_ip": "10.0.0.4",
                "source": "User",
                "state": "Active",
                "route_name": "udr",
                "is_zero_route": False,
            },
            {
                "prefix": "10.0.0.0/24",
                "prefix_length": 24,
                "next_hop_type": "VnetLocal",
                "next_hop_ip": None,
                "source": "Default",
                "state": "Invalid",
                "route_name": None,
                "is_zero_route": False,
            },
            {
                "prefix": "0.0.0.0/0",
                "prefix_length": 0,
                "next_hop_type": "Internet",
                "next_hop_ip": None,
                "source": "Default",
                "state": "Active",
                "route_name": None,
                "is_zero_route": True,
            },
        ]
        verdict = lpm_engine.select_route(routes, "10.0.0.5")
        self.assertEqual(verdict["result"], "WINNER")
        shadow_warnings = [w for w in verdict["anomaly_warnings"] if "INVALID_SHADOW_WARNING" in w]
        self.assertFalse(
            shadow_warnings,
            f"False positive INVALID_SHADOW fired for lower-priority Invalid route: {shadow_warnings}"
        )


# ---------------------------------------------------------------------------
# ADV-02: nextHopIpAddress as bare string
# ---------------------------------------------------------------------------

class TestAdv02NextHopIpAsString(unittest.TestCase):
    """
    Scenario: az CLI or custom serializer returns nextHopIpAddress as a bare
    string "10.4.0.1" instead of a one-element array ["10.4.0.1"]. The original
    _normalise_hop_ip() treated the string as an iterable, taking raw[0] = "1"
    (the first character) as the hop IP. The NVA warning then reported
    "Virtual Appliance (1)" — meaningless and potentially misleading.

    Fix: isinstance check in _normalise_hop_ip — if raw is a str, wrap in a list
    before processing and emit a parse_warning.
    """

    def setUp(self):
        self.result = _preprocess("fx-adv-02-nexthopip-as-string.json")
        self.routes = self.result["routes"]

    def test_preprocessor_parses_all_routes(self):
        self.assertEqual(self.result["route_count"], 4)
        self.assertNotIn("error", self.result)

    def test_parse_warning_emitted_for_string_nexthopip(self):
        """ADV-02 regression: bare-string nextHopIpAddress must produce a parse_warning."""
        warnings = self.result["parse_warnings"]
        string_warnings = [w for w in warnings if "bare string" in w and "nextHopIpAddress" in w]
        self.assertTrue(
            string_warnings,
            f"Expected parse_warning about bare-string nextHopIpAddress; got: {warnings}"
        )

    def test_nva_route_hop_ip_is_correct(self):
        """ADV-02 regression: next_hop_ip must be the full IP, not the first character."""
        nva_routes = [r for r in self.routes if r["next_hop_type"] == "VirtualAppliance"]
        self.assertTrue(nva_routes, "Expected at least one VirtualAppliance route")
        for r in nva_routes:
            self.assertEqual(
                r["next_hop_ip"],
                "10.4.0.1",
                f"next_hop_ip was {r['next_hop_ip']!r}, expected '10.4.0.1'. "
                "Bare-string nextHopIpAddress was not normalized correctly."
            )

    def test_nva_warning_contains_correct_hop_ip(self):
        verdict = lpm_engine.select_route(self.routes, "172.16.10.5")
        nva_warnings = [w for w in verdict["anomaly_warnings"] if "NVA_WARNING" in w]
        self.assertTrue(nva_warnings, "Expected NVA_WARNING for VirtualAppliance winner")
        self.assertIn(
            "10.4.0.1",
            nva_warnings[0],
            f"NVA_WARNING does not contain correct hop IP. Got: {nva_warnings[0]}"
        )
        # Guard against the original bug where first character was used
        self.assertNotIn(
            "Virtual Appliance (1)",
            nva_warnings[0],
            "NVA_WARNING contains '(1)' — bare-string first-character bug regressed"
        )

    def test_string_nexthopip_not_confused_with_ecmp(self):
        """A bare string must NOT trigger the multi-address ECMP warning."""
        warnings = self.result["parse_warnings"]
        ecmp_warnings = [w for w in warnings if "addresses" in w and "ECMP" in w]
        self.assertFalse(
            ecmp_warnings,
            f"Bare-string nextHopIpAddress incorrectly triggered ECMP warning: {ecmp_warnings}"
        )


# ---------------------------------------------------------------------------
# ADV-03: addressPrefix as bare string — UDR silently dropped
# ---------------------------------------------------------------------------

class TestAdv03AddressPrefixAsString(unittest.TestCase):
    """
    Scenario: addressPrefix field is returned as a bare string "0.0.0.0/0" instead
    of a one-element array ["0.0.0.0/0"]. The original code did:
        raw_prefixes = entry.get("addressPrefix") or []
    A non-empty string is truthy, so raw_prefixes became the string itself. Iterating
    over it yielded individual characters ('0', '.', '0', ...). Each character failed
    CIDR validation and was silently skipped. The entire route was dropped.

    In this fixture the dropped route is a User UDR (0.0.0.0/0 → VirtualAppliance)
    that forces all egress through an NVA firewall. With it dropped, the Default
    Internet route wins for 8.8.8.8 — an NVA bypass that the tool reported as
    a clean WINNER with no anomalies.

    Fix: isinstance check in _expand_entry — if addressPrefix is a str, wrap in a
    list and emit a parse_warning.
    """

    def setUp(self):
        self.result = _preprocess("fx-adv-03-addressprefix-as-string.json")
        self.routes = self.result["routes"]

    def test_preprocessor_does_not_drop_the_udr(self):
        """ADV-03 regression: route count must be 4, not 3."""
        self.assertEqual(
            self.result["route_count"],
            4,
            f"Expected 4 routes (User /0 UDR must be preserved); got {self.result['route_count']}"
        )
        self.assertNotIn("error", self.result)

    def test_parse_warning_emitted_for_string_addressprefix(self):
        """ADV-03 regression: bare-string addressPrefix must produce a parse_warning."""
        warnings = self.result["parse_warnings"]
        string_warnings = [w for w in warnings if "bare string" in w and "addressPrefix" in w]
        self.assertTrue(
            string_warnings,
            f"Expected parse_warning about bare-string addressPrefix; got: {warnings}"
        )

    def test_no_invalid_cidr_character_warnings(self):
        """
        ADV-03 regression: must not emit 9+ 'Invalid CIDR' warnings for individual
        characters of the string.
        """
        char_warnings = [
            w for w in self.result["parse_warnings"]
            if w.startswith("Invalid CIDR '") and len(w) < 25
        ]
        self.assertFalse(
            char_warnings,
            f"Bare-string addressPrefix produced per-character CIDR warnings: {char_warnings}"
        )

    def test_user_udr_is_winner_for_external_ip(self):
        """
        ADV-03 regression: with the User UDR preserved, 8.8.8.8 must route through
        the NVA (VirtualAppliance), not Internet.
        """
        verdict = lpm_engine.select_route(self.routes, "8.8.8.8")
        self.assertEqual(verdict["result"], "WINNER")
        wr = verdict["winning_route"]
        self.assertEqual(
            wr["source"],
            "User",
            f"Expected User UDR to win for 8.8.8.8; got {wr['source']} {wr['next_hop_type']}. "
            "User UDR was probably silently dropped."
        )
        self.assertEqual(wr["next_hop_type"], "VirtualAppliance")

    def test_nva_warning_fires_not_suppressed(self):
        verdict = lpm_engine.select_route(self.routes, "8.8.8.8")
        nva_warnings = [w for w in verdict["anomaly_warnings"] if "NVA_WARNING" in w]
        self.assertTrue(
            nva_warnings,
            "NVA_WARNING must fire when User UDR → VirtualAppliance wins; tool was silent."
        )


# ---------------------------------------------------------------------------
# Cross-cutting: normalise_hop_ip edge cases
# ---------------------------------------------------------------------------

class TestNormaliseHopIpEdgeCases(unittest.TestCase):
    """Unit tests for _normalise_hop_ip edge cases independent of fixtures."""

    def _call(self, raw):
        warnings = []
        result = route_preprocessor._normalise_hop_ip(raw, warnings)
        return result, warnings

    def test_none_returns_none(self):
        result, warnings = self._call(None)
        self.assertIsNone(result)
        self.assertEqual(warnings, [])

    def test_empty_list_returns_none(self):
        result, warnings = self._call([])
        self.assertIsNone(result)
        self.assertEqual(warnings, [])

    def test_single_element_list(self):
        result, warnings = self._call(["10.0.0.1"])
        self.assertEqual(result, "10.0.0.1")
        self.assertEqual(warnings, [])

    def test_bare_string_normalized(self):
        result, warnings = self._call("10.0.0.1")
        self.assertEqual(result, "10.0.0.1")
        self.assertTrue(any("bare string" in w for w in warnings))

    def test_bare_string_does_not_trigger_ecmp_warning(self):
        _, warnings = self._call("10.0.0.1")
        ecmp = [w for w in warnings if "ECMP" in w]
        self.assertFalse(ecmp)

    def test_multi_element_list_triggers_ecmp_warning(self):
        result, warnings = self._call(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(result, "10.0.0.1")
        self.assertTrue(any("ECMP" in w for w in warnings))


# ---------------------------------------------------------------------------
# Cross-cutting: expand_entry with string addressPrefix
# ---------------------------------------------------------------------------

class TestExpandEntryStringAddressPrefix(unittest.TestCase):
    """Unit tests for _expand_entry with bare-string addressPrefix."""

    def _call(self, entry):
        warnings = []
        rows = route_preprocessor._expand_entry(entry, warnings)
        return rows, warnings

    def test_string_prefix_produces_one_route(self):
        entry = {
            "addressPrefix": "10.0.0.0/16",
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": "Active",
        }
        rows, warnings = self._call(entry)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["prefix"], "10.0.0.0/16")

    def test_string_prefix_emits_parse_warning(self):
        entry = {
            "addressPrefix": "10.0.0.0/16",
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": "Active",
        }
        _, warnings = self._call(entry)
        self.assertTrue(any("bare string" in w for w in warnings))

    def test_list_prefix_still_works(self):
        entry = {
            "addressPrefix": ["10.0.0.0/16"],
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": "Active",
        }
        rows, warnings = self._call(entry)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["prefix"], "10.0.0.0/16")
        string_warnings = [w for w in warnings if "bare string" in w]
        self.assertFalse(string_warnings)

    def test_none_prefix_produces_no_routes(self):
        entry = {
            "addressPrefix": None,
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": "Active",
        }
        rows, _ = self._call(entry)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestAdv01InvalidShadowSamePrefix,
        TestAdv02NextHopIpAsString,
        TestAdv03AddressPrefixAsString,
        TestNormaliseHopIpEdgeCases,
        TestExpandEntryStringAddressPrefix,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed
    print(f"\nResults: {passed} PASSED  {failed} FAILED  ({total} total)")
    sys.exit(0 if failed == 0 else 1)
