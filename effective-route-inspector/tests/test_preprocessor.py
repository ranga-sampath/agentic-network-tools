"""
test_preprocessor.py — Unit tests for route_preprocessor.py.

Covers test plan §6.
Adversarial cases (bare-string addressPrefix, bare-string nextHopIpAddress) live in
test_adversarial.py and are NOT duplicated here.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import route_preprocessor

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Mapping: fixture filename → expected normalised route count after expansion
FIXTURE_ROUTE_COUNTS = {
    "fx-01-basic-vnet-local.json": 5,
    "fx-02-udr-same-prefix.json": 4,
    "fx-03-lpm-beats-udr.json": 4,
    "fx-04-nva-udr.json": 4,
    "fx-05-minimal-routes.json": 2,
    "fx-06-bgp-vs-system.json": 5,
    "fx-07-invalid-route.json": 4,
    "fx-08-host-route-slash32.json": 5,
    "fx-09-no-matching-route.json": 3,
    "fx-10-blackhole-none-hop.json": 4,
    "fx-11-multi-prefix-entry.json": 7,  # expansion: 4 raw → 7
    "fx-12-hub-spoke-production.json": 6,
    "fx-13-vnet-peering-routes.json": 7,
    "fx-14-bgp-tie-same-prefix.json": 5,
    "fx-15-overlapping-udrs.json": 5,
}

REQUIRED_ROUTE_KEYS = {
    "prefix", "prefix_length", "next_hop_type", "source", "state",
    "next_hop_ip", "route_name", "is_zero_route",
}


def _preprocess_file(fixture_name: str) -> dict:
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


def _preprocess_string(content: str) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        return route_preprocessor.preprocess(tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# T-PP-01 through T-PP-15: all fixtures parse cleanly
# ---------------------------------------------------------------------------

class TestAllFixturesParsing(unittest.TestCase):
    """Each fixture must parse without error and contain well-formed RouteObjects."""

    def _assert_fixture_clean(self, fixture_name: str, expected_count: int):
        result = _preprocess_file(fixture_name)
        self.assertNotIn("error", result,
            f"{fixture_name} returned error: {result.get('error')}")
        self.assertGreater(result["route_count"], 0)
        routes = result["routes"]
        self.assertIsInstance(routes, list)
        self.assertGreater(len(routes), 0)
        self.assertEqual(result["route_count"], expected_count,
            f"{fixture_name}: expected {expected_count} routes, got {result['route_count']}")
        self.assertIsInstance(result["parse_warnings"], list)
        for r in routes:
            for key in REQUIRED_ROUTE_KEYS:
                self.assertIn(key, r,
                    f"{fixture_name}: route missing key '{key}': {r}")

    def test_T_PP_01_fx_01_basic_vnet_local(self):
        self._assert_fixture_clean("fx-01-basic-vnet-local.json", 5)

    def test_T_PP_02_fx_02_udr_same_prefix(self):
        self._assert_fixture_clean("fx-02-udr-same-prefix.json", 4)

    def test_T_PP_03_fx_03_lpm_beats_udr(self):
        self._assert_fixture_clean("fx-03-lpm-beats-udr.json", 4)

    def test_T_PP_04_fx_04_nva_udr(self):
        self._assert_fixture_clean("fx-04-nva-udr.json", 4)

    def test_T_PP_05_fx_05_minimal_routes(self):
        self._assert_fixture_clean("fx-05-minimal-routes.json", 2)

    def test_T_PP_06_fx_06_bgp_vs_system(self):
        self._assert_fixture_clean("fx-06-bgp-vs-system.json", 5)

    def test_T_PP_07_fx_07_invalid_route(self):
        self._assert_fixture_clean("fx-07-invalid-route.json", 4)

    def test_T_PP_08_fx_08_host_route_slash32(self):
        self._assert_fixture_clean("fx-08-host-route-slash32.json", 5)

    def test_T_PP_09_fx_09_no_matching_route(self):
        self._assert_fixture_clean("fx-09-no-matching-route.json", 3)

    def test_T_PP_10_fx_10_blackhole_none_hop(self):
        self._assert_fixture_clean("fx-10-blackhole-none-hop.json", 4)

    def test_T_PP_11_fx_11_multi_prefix_entry(self):
        self._assert_fixture_clean("fx-11-multi-prefix-entry.json", 7)

    def test_T_PP_12_fx_12_hub_spoke_production(self):
        self._assert_fixture_clean("fx-12-hub-spoke-production.json", 6)

    def test_T_PP_13_fx_13_vnet_peering_routes(self):
        self._assert_fixture_clean("fx-13-vnet-peering-routes.json", 7)

    def test_T_PP_14_fx_14_bgp_tie_same_prefix(self):
        self._assert_fixture_clean("fx-14-bgp-tie-same-prefix.json", 5)

    def test_T_PP_15_fx_15_overlapping_udrs(self):
        self._assert_fixture_clean("fx-15-overlapping-udrs.json", 5)


# ---------------------------------------------------------------------------
# T-PP-11a and T-PP-11b: multi-prefix expansion
# ---------------------------------------------------------------------------

class TestMultiPrefixExpansion(unittest.TestCase):

    def setUp(self):
        self.result = _preprocess_file("fx-11-multi-prefix-entry.json")
        self.routes = self.result["routes"]

    def test_T_PP_11a_two_prefix_entry_expands_to_two_route_objects(self):
        """Raw entry with ["172.20.0.0/16", "172.20.5.0/24"] → 2 RouteObjects."""
        prefixes = [r["prefix"] for r in self.routes]
        self.assertIn("172.20.0.0/16", prefixes)
        self.assertIn("172.20.5.0/24", prefixes)
        r16 = next(r for r in self.routes if r["prefix"] == "172.20.0.0/16")
        r24 = next(r for r in self.routes if r["prefix"] == "172.20.5.0/24")
        # Both expanded from the same entry — same source/type/state
        self.assertEqual(r16["next_hop_type"], r24["next_hop_type"])
        self.assertEqual(r16["source"], r24["source"])
        self.assertEqual(r16["state"], r24["state"])

    def test_T_PP_11b_three_prefix_entry_expands_to_three_route_objects(self):
        """Raw entry with [10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16] → 3 RouteObjects."""
        three = [r for r in self.routes
                 if r["prefix"] in {"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"}]
        self.assertEqual(len(three), 3)
        sources = {r["source"] for r in three}
        types = {r["next_hop_type"] for r in three}
        states = {r["state"] for r in three}
        self.assertEqual(len(sources), 1)
        self.assertEqual(len(types), 1)
        self.assertEqual(len(states), 1)
        # Total: 4 raw entries → 7 normalised (1 + 2 + 3 + 1)
        self.assertEqual(self.result["route_count"], 7)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestPreprocessorErrorPaths(unittest.TestCase):

    def test_T_PP_ERR_01_file_not_found_returns_error_dict(self):
        result = route_preprocessor.preprocess("/tmp/this_file_does_not_exist_ever.json")
        self.assertIn("error", result)
        self.assertNotIn("routes", result)

    def test_T_PP_ERR_02_invalid_json_returns_error_dict(self):
        result = _preprocess_string("not valid json {{{")
        self.assertIn("error", result)

    def test_T_PP_ERR_03_valid_json_no_routes_returns_error_dict(self):
        result = _preprocess_string('{"unrelated": "structure"}')
        self.assertIn("error", result)
        self.assertNotIn("routes", result)


# ---------------------------------------------------------------------------
# State normalisation
# ---------------------------------------------------------------------------

class TestStateNormalisation(unittest.TestCase):

    def _make_entry(self, state_value) -> dict:
        entry = {
            "addressPrefix": ["10.0.0.0/24"],
            "nextHopType": "VnetLocal",
            "source": "Default",
        }
        if state_value is not None:
            entry["state"] = state_value
        # state_value=None means the key is absent
        return entry

    def test_T_PP_STATE_absent_state_normalised_to_unknown(self):
        warnings = []
        rows = route_preprocessor._expand_entry(self._make_entry(None), warnings)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "Unknown")

    def test_T_PP_STATE_null_state_normalised_to_unknown(self):
        entry = {
            "addressPrefix": ["10.0.0.0/24"],
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": None,
        }
        warnings = []
        rows = route_preprocessor._expand_entry(entry, warnings)
        self.assertEqual(rows[0]["state"], "Unknown")

    def test_T_PP_STATE_active_string_preserved(self):
        entry = {
            "addressPrefix": ["10.0.0.0/24"],
            "nextHopType": "VnetLocal",
            "source": "Default",
            "state": "Active",
        }
        warnings = []
        rows = route_preprocessor._expand_entry(entry, warnings)
        self.assertEqual(rows[0]["state"], "Active")

    def test_T_PP_STATE_unknown_state_excluded_from_active_candidates(self):
        """Routes with state Unknown must not become LPM candidates."""
        content = json.dumps({
            "value": [
                {
                    "addressPrefix": ["10.0.0.0/16"],
                    "nextHopType": "VnetLocal",
                    "source": "Default",
                    # state key absent → Unknown
                },
                {
                    "addressPrefix": ["0.0.0.0/0"],
                    "nextHopType": "Internet",
                    "source": "Default",
                    "state": "Active",
                },
            ]
        })
        result = _preprocess_string(content)
        self.assertNotIn("error", result)
        import lpm_engine
        verdict = lpm_engine.select_route(result["routes"], "10.0.0.1")
        # Unknown-state /16 must not win; Active /0 wins instead
        self.assertEqual(verdict["winning_route"]["prefix"], "0.0.0.0/0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
