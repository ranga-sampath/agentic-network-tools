"""
test_lpm_engine.py — Unit tests for lpm_engine.py.

Covers test plan §5 (select_route and audit_routes).
All fixtures loaded through route_preprocessor.preprocess() as specified in §5 setup.

Adversarial cases (same-prefix INVALID_SHADOW, CIDR guard DANGER) live in
test_adversarial.py and are NOT duplicated here.
"""

import json
import sys
import tempfile
import os
import unittest
from pathlib import Path

# Add parent dir to sys.path so tests can import the source modules directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import lpm_engine
import route_preprocessor

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(fixture_name: str) -> list:
    """Load a fixture through the preprocessor and return the route list."""
    path = FIXTURES / fixture_name
    with open(path) as f:
        data = json.load(f)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(data, tmp)
        tmp_path = tmp.name
    try:
        result = route_preprocessor.preprocess(tmp_path)
    finally:
        os.unlink(tmp_path)
    assert "error" not in result, f"preprocess failed on {fixture_name}: {result.get('error')}"
    return result["routes"]


# ---------------------------------------------------------------------------
# §5.1 select_route()
# ---------------------------------------------------------------------------

class TestSelectRouteLPM(unittest.TestCase):

    def test_T_LPM_01_basic_vnet_lpm_selects_24_over_16_and_0(self):
        routes = _load("fx-01-basic-vnet-local.json")
        verdict = lpm_engine.select_route(routes, "10.0.1.50")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.0.1.0/24")
        self.assertEqual(wr["next_hop_type"], "VnetLocal")
        self.assertEqual(wr["source"], "Default")
        shadowed = verdict["shadowed_candidates"]
        self.assertEqual(len(shadowed), 2)
        shadowed_prefixes = {r["prefix"] for r in shadowed}
        self.assertIn("10.0.0.0/16", shadowed_prefixes)
        self.assertIn("0.0.0.0/0", shadowed_prefixes)
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_02_source_precedence_udr_beats_default_at_equal_24(self):
        routes = _load("fx-02-udr-same-prefix.json")
        verdict = lpm_engine.select_route(routes, "172.16.10.20")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "SOURCE_PRECEDENCE")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "172.16.10.0/24")
        self.assertEqual(wr["source"], "User")
        self.assertEqual(wr["next_hop_type"], "VirtualAppliance")
        # 3 shadowed: Default /24 (lost at step 3), /16 and /0 (lost at step 2)
        self.assertEqual(len(verdict["shadowed_candidates"]), 3)
        self.assertTrue(
            any("NVA_WARNING" in w for w in verdict["anomaly_warnings"]),
            "Expected NVA_WARNING for VirtualAppliance winner"
        )

    def test_T_LPM_03_lpm_absolute_vnetpeering_16_beats_udr_0(self):
        """DANGER: LPM is applied unconditionally before source precedence."""
        routes = _load("fx-03-lpm-beats-udr.json")
        verdict = lpm_engine.select_route(routes, "10.2.5.10")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.2.0.0/16")
        self.assertEqual(wr["source"], "Default")
        self.assertEqual(wr["next_hop_type"], "VnetPeering")
        self.assertEqual(verdict["anomaly_warnings"], [])
        shadowed_prefixes = {r["prefix"] for r in verdict["shadowed_candidates"]}
        self.assertIn("0.0.0.0/0", shadowed_prefixes)

    def test_T_LPM_04_nva_udr_winner_emits_nva_warning(self):
        routes = _load("fx-04-nva-udr.json")
        verdict = lpm_engine.select_route(routes, "192.168.5.10")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "192.168.0.0/16")
        self.assertEqual(wr["source"], "User")
        self.assertTrue(
            any("NVA_WARNING" in w for w in verdict["anomaly_warnings"])
        )

    def test_T_LPM_05a_minimal_catch_all_wins_for_public_dst(self):
        routes = _load("fx-05-minimal-routes.json")
        verdict = lpm_engine.select_route(routes, "8.8.8.8")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "0.0.0.0/0")
        self.assertTrue(wr["is_zero_route"])
        self.assertEqual(verdict["shadowed_candidates"], [])
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_05b_minimal_vnetlocal_24_beats_0_for_private_dst(self):
        routes = _load("fx-05-minimal-routes.json")
        verdict = lpm_engine.select_route(routes, "10.0.1.50")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        self.assertEqual(verdict["winning_route"]["prefix"], "10.0.1.0/24")
        shadowed_prefixes = {r["prefix"] for r in verdict["shadowed_candidates"]}
        self.assertIn("0.0.0.0/0", shadowed_prefixes)

    def test_T_LPM_06_bgp_beats_default_at_equal_16_no_blackhole_warning(self):
        """DANGER: BLACKHOLE check must run only on winner, not shadowed routes."""
        routes = _load("fx-06-bgp-vs-system.json")
        verdict = lpm_engine.select_route(routes, "10.100.5.30")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "SOURCE_PRECEDENCE")
        wr = verdict["winning_route"]
        self.assertEqual(wr["source"], "VirtualNetworkGateway")
        self.assertNotEqual(wr["next_hop_type"], "None")
        # None-hop Default is shadowed — must NOT trigger BLACKHOLE_WARNING
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_06b_bgp_24_beats_16_candidates_for_dst_in_24(self):
        routes = _load("fx-06-bgp-vs-system.json")
        verdict = lpm_engine.select_route(routes, "10.100.50.10")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.100.50.0/24")
        self.assertEqual(wr["source"], "VirtualNetworkGateway")
        shadowed_prefixes = {r["prefix"] for r in verdict["shadowed_candidates"]}
        self.assertIn("10.100.0.0/16", shadowed_prefixes)
        self.assertIn("0.0.0.0/0", shadowed_prefixes)
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_07a_invalid_route_excluded_invalid_shadow_warning_fires(self):
        routes = _load("fx-07-invalid-route.json")
        verdict = lpm_engine.select_route(routes, "10.200.1.50")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["winning_route"]["prefix"], "0.0.0.0/0")
        warnings = verdict["anomaly_warnings"]
        shadow_warnings = [w for w in warnings if "INVALID_SHADOW_WARNING" in w]
        # Both 10.200.0.0/16 (/16>0) and 10.200.1.0/24 (/24>0) contain 10.200.1.50
        self.assertEqual(len(shadow_warnings), 2,
            f"Expected 2 INVALID_SHADOW_WARNINGs, got {len(shadow_warnings)}: {warnings}")

    def test_T_LPM_07b_invalid_shadow_cidr_guard_no_false_positive(self):
        """DANGER: unrelated Invalid route must NOT fire for 8.8.8.8."""
        routes = _load("fx-07-invalid-route.json")
        verdict = lpm_engine.select_route(routes, "8.8.8.8")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["winning_route"]["prefix"], "0.0.0.0/0")
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_08_host_route_32_wins_unconditionally(self):
        routes = _load("fx-08-host-route-slash32.json")
        verdict = lpm_engine.select_route(routes, "10.5.10.100")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.5.10.100/32")
        self.assertEqual(wr["prefix_length"], 32)
        self.assertTrue(any("NVA_WARNING" in w for w in verdict["anomaly_warnings"]))
        self.assertEqual(len(verdict["shadowed_candidates"]), 3)

    def test_T_LPM_09_no_matching_route_returns_no_route(self):
        """DANGER: must not fabricate a default route."""
        routes = _load("fx-09-no-matching-route.json")
        verdict = lpm_engine.select_route(routes, "203.0.113.1")
        self.assertEqual(verdict["result"], "NO_ROUTE")
        self.assertEqual(verdict["selection_reason"], "NO_ROUTE")
        self.assertIsNone(verdict["winning_route"])
        self.assertEqual(verdict["shadowed_candidates"], [])
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_10_blackhole_none_hop_winner_emits_blackhole_warning(self):
        routes = _load("fx-10-blackhole-none-hop.json")
        verdict = lpm_engine.select_route(routes, "10.30.0.50")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.30.0.0/16")
        # next_hop_type is the string "None", not Python None
        self.assertEqual(wr["next_hop_type"], "None")
        self.assertTrue(any("BLACKHOLE_WARNING" in w for w in verdict["anomaly_warnings"]))

    def test_T_LPM_11_multi_prefix_24_beats_16_after_expansion(self):
        routes = _load("fx-11-multi-prefix-entry.json")
        # Verify expansion happened: must be 7 routes
        self.assertEqual(len(routes), 7)
        verdict = lpm_engine.select_route(routes, "172.20.5.10")
        self.assertEqual(verdict["winning_route"]["prefix"], "172.20.5.0/24")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")

    def test_T_LPM_12a_hub_spoke_bgp_24_beats_bgp_16_and_udr_0(self):
        routes = _load("fx-12-hub-spoke-production.json")
        verdict = lpm_engine.select_route(routes, "192.168.10.50")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "192.168.10.0/24")
        self.assertEqual(wr["source"], "VirtualNetworkGateway")
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_12b_hub_spoke_udr_0_nva_wins_for_internet_dst(self):
        routes = _load("fx-12-hub-spoke-production.json")
        verdict = lpm_engine.select_route(routes, "8.8.8.8")
        self.assertEqual(verdict["winning_route"]["prefix"], "0.0.0.0/0")
        self.assertEqual(verdict["winning_route"]["source"], "User")
        self.assertTrue(any("NVA_WARNING" in w for w in verdict["anomaly_warnings"]))

    def test_T_LPM_12c_hub_spoke_bgp_16_wins_for_dst_outside_24(self):
        routes = _load("fx-12-hub-spoke-production.json")
        verdict = lpm_engine.select_route(routes, "192.168.5.30")
        self.assertEqual(verdict["winning_route"]["prefix"], "192.168.0.0/16")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")

    def test_T_LPM_13a_invalid_24_excluded_shadow_fires_for_10_3_5_20(self):
        routes = _load("fx-13-vnet-peering-routes.json")
        verdict = lpm_engine.select_route(routes, "10.3.5.20")
        self.assertEqual(verdict["winning_route"]["prefix"], "10.3.0.0/16")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        warnings = verdict["anomaly_warnings"]
        shadow_warnings = [w for w in warnings if "INVALID_SHADOW_WARNING" in w]
        self.assertEqual(len(shadow_warnings), 1,
            f"Expected exactly 1 INVALID_SHADOW_WARNING; got {len(shadow_warnings)}: {warnings}")
        self.assertIn("10.3.5.0/24", shadow_warnings[0])

    def test_T_LPM_13b_invalid_shadow_cidr_containment_no_warning_for_unrelated_invalid(self):
        routes = _load("fx-13-vnet-peering-routes.json")
        verdict = lpm_engine.select_route(routes, "10.4.5.20")
        warnings = verdict["anomaly_warnings"]
        shadow_warnings = [w for w in warnings if "INVALID_SHADOW_WARNING" in w]
        self.assertEqual(len(shadow_warnings), 1)
        self.assertIn("10.4.0.0/16", shadow_warnings[0])
        self.assertNotIn("10.3.5.0/24", shadow_warnings[0])

    def test_T_LPM_14a_bgp_tie_two_identical_vgw_24_routes_tied_bgp(self):
        """DANGER: must not pick the first route arbitrarily."""
        routes = _load("fx-14-bgp-tie-same-prefix.json")
        verdict = lpm_engine.select_route(routes, "10.50.0.100")
        self.assertEqual(verdict["result"], "TIED_BGP")
        self.assertEqual(verdict["selection_reason"], "TIED_BGP")
        self.assertIsNone(verdict["winning_route"])
        tied = verdict["tied_routes"]
        self.assertEqual(len(tied), 2)
        for r in tied:
            self.assertEqual(r["prefix"], "10.50.0.0/24")
        # /16 and /0 must be in shadowed_candidates
        shadowed_prefixes = {r["prefix"] for r in verdict["shadowed_candidates"]}
        self.assertIn("10.50.0.0/16", shadowed_prefixes)
        self.assertIn("0.0.0.0/0", shadowed_prefixes)
        self.assertEqual(verdict["anomaly_warnings"], [])

    def test_T_LPM_14b_bgp_tie_does_not_affect_16_for_dst_outside_24(self):
        routes = _load("fx-14-bgp-tie-same-prefix.json")
        verdict = lpm_engine.select_route(routes, "10.50.5.10")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        self.assertEqual(verdict["winning_route"]["prefix"], "10.50.0.0/16")
        shadowed_prefixes = {r["prefix"] for r in verdict["shadowed_candidates"]}
        self.assertIn("0.0.0.0/0", shadowed_prefixes)

    def test_T_LPM_15a_overlapping_udrs_28_wins_for_dst_in_28_range(self):
        routes = _load("fx-15-overlapping-udrs.json")
        verdict = lpm_engine.select_route(routes, "10.0.1.130")
        self.assertEqual(verdict["result"], "WINNER")
        self.assertEqual(verdict["selection_reason"], "LPM_ONLY")
        wr = verdict["winning_route"]
        self.assertEqual(wr["prefix"], "10.0.1.128/28")
        self.assertEqual(wr["next_hop_type"], "VnetLocal")
        self.assertEqual(verdict["anomaly_warnings"], [])
        self.assertEqual(len(verdict["shadowed_candidates"]), 4)

    def test_T_LPM_15b_overlapping_udrs_24_wins_for_dst_outside_28(self):
        routes = _load("fx-15-overlapping-udrs.json")
        verdict = lpm_engine.select_route(routes, "10.0.1.50")
        self.assertEqual(verdict["winning_route"]["prefix"], "10.0.1.0/24")
        self.assertEqual(verdict["winning_route"]["next_hop_type"], "VirtualAppliance")
        self.assertTrue(any("NVA_WARNING" in w for w in verdict["anomaly_warnings"]))


# ---------------------------------------------------------------------------
# §5.2 audit_routes()
# ---------------------------------------------------------------------------

class TestAuditRoutes(unittest.TestCase):

    def test_T_AUD_01_clean_system_table_all_findings_empty(self):
        routes = _load("fx-01-basic-vnet-local.json")
        verdict = lpm_engine.audit_routes(routes)
        self.assertEqual(verdict["mode"], "audit")
        self.assertEqual(verdict["route_count"], 5)
        self.assertEqual(verdict["invalid_route_count"], 0)
        findings = verdict["findings"]
        self.assertEqual(findings["blackhole_routes"], [])
        self.assertEqual(findings["nva_routes"], [])
        self.assertEqual(findings["bgp_routes"], [])
        self.assertTrue(findings["default_route_present"])
        self.assertEqual(findings["default_route_source"], "Default")
        # routes_by_prefix_length sorted descending; first must be a /24
        sorted_routes = verdict["routes_by_prefix_length"]
        self.assertEqual(sorted_routes[0]["prefix_length"], 24)

    def test_T_AUD_07_invalid_routes_listed_active_count_correct(self):
        routes = _load("fx-07-invalid-route.json")
        verdict = lpm_engine.audit_routes(routes)
        self.assertEqual(verdict["route_count"], 4)
        self.assertEqual(verdict["invalid_route_count"], 2)
        invalid_prefixes = {r["prefix"] for r in verdict["invalid_routes"]}
        self.assertIn("10.200.0.0/16", invalid_prefixes)
        self.assertIn("10.200.1.0/24", invalid_prefixes)
        self.assertEqual(len(verdict["routes_by_prefix_length"]), 4)
        # Invalid routes are excluded from active findings
        self.assertEqual(verdict["findings"]["blackhole_routes"], [])

    def test_T_AUD_10_default_none_route_goes_to_system_blocked_not_blackhole(self):
        """
        fx-10 has a Default-sourced nextHopType=None route (10.30.0.0/16).
        Default None routes are Azure system behaviour — blocked infrastructure prefixes.
        They must land in system_blocked_routes, NOT blackhole_routes.
        Only User-sourced None routes are operator-configured blackholes.
        """
        routes = _load("fx-10-blackhole-none-hop.json")
        verdict = lpm_engine.audit_routes(routes)
        findings = verdict["findings"]
        # Default None → system_blocked, not a user blackhole
        self.assertEqual(findings["blackhole_routes"], [],
            "Default-sourced None route must not appear in blackhole_routes")
        self.assertEqual(len(findings["system_blocked_routes"]), 1)
        self.assertEqual(findings["system_blocked_routes"][0]["prefix"], "10.30.0.0/16")
        self.assertEqual(findings["nva_routes"], [])
        self.assertEqual(findings["bgp_routes"], [])
        self.assertTrue(findings["default_route_present"])
        self.assertEqual(findings["default_route_source"], "Default")

    def test_T_AUD_10b_user_none_route_classified_as_blackhole(self):
        """
        A User-sourced nextHopType=None route is an operator-configured blackhole —
        accidental or intentional. It must appear in blackhole_routes, not system_blocked_routes.
        """
        routes = [
            {
                "prefix": "10.0.2.4/32", "prefix_length": 32,
                "next_hop_type": "None", "next_hop_ip": None,
                "source": "User", "state": "Active",
                "route_name": "blackhole-dest-vm", "is_zero_route": False,
            },
            {
                "prefix": "10.0.0.0/16", "prefix_length": 16,
                "next_hop_type": "VnetLocal", "next_hop_ip": None,
                "source": "Default", "state": "Active",
                "route_name": None, "is_zero_route": False,
            },
            {
                "prefix": "10.0.0.0/8", "prefix_length": 8,
                "next_hop_type": "None", "next_hop_ip": None,
                "source": "Default", "state": "Active",
                "route_name": None, "is_zero_route": False,
            },
            {
                "prefix": "0.0.0.0/0", "prefix_length": 0,
                "next_hop_type": "Internet", "next_hop_ip": None,
                "source": "Default", "state": "Active",
                "route_name": None, "is_zero_route": True,
            },
        ]
        verdict = lpm_engine.audit_routes(routes)
        findings = verdict["findings"]
        # Only the User /32 → None is a blackhole
        self.assertEqual(len(findings["blackhole_routes"]), 1)
        self.assertEqual(findings["blackhole_routes"][0]["prefix"], "10.0.2.4/32")
        self.assertEqual(findings["blackhole_routes"][0]["source"], "User")
        # The Default /8 → None is system behaviour, not a blackhole
        self.assertEqual(len(findings["system_blocked_routes"]), 1)
        self.assertEqual(findings["system_blocked_routes"][0]["prefix"], "10.0.0.0/8")

    def test_T_AUD_12_hub_spoke_nva_and_bgp_routes_detected(self):
        routes = _load("fx-12-hub-spoke-production.json")
        verdict = lpm_engine.audit_routes(routes)
        findings = verdict["findings"]
        self.assertEqual(len(findings["nva_routes"]), 1)
        self.assertEqual(findings["nva_routes"][0]["prefix"], "0.0.0.0/0")
        self.assertEqual(len(findings["bgp_routes"]), 2)
        bgp_prefixes = {r["prefix"] for r in findings["bgp_routes"]}
        self.assertIn("192.168.0.0/16", bgp_prefixes)
        self.assertIn("192.168.10.0/24", bgp_prefixes)
        self.assertTrue(findings["default_route_present"])
        self.assertEqual(findings["default_route_source"], "User")
        self.assertEqual(findings["blackhole_routes"], [])

    def test_T_AUD_14_bgp_tie_all_three_vgw_routes_in_bgp_findings(self):
        routes = _load("fx-14-bgp-tie-same-prefix.json")
        verdict = lpm_engine.audit_routes(routes)
        findings = verdict["findings"]
        self.assertEqual(len(findings["bgp_routes"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
