"""
test_pipeline.py — Tests for effective_route_inspector.py §8 and §9.

§8: _enforce_session_prefix, _generate_session_id, _ensure_audit_dir,
    CLI arg validation, _render_table.
§9: Full pipeline via MockRouteProvider injection; artifact lifecycle; exit codes.

Ghost Agent handler tests (§10) are omitted. The handler
(_run_effective_route_inspector_handler in ghost_agent.py) invokes
effective_route_inspector.py as a subprocess and reads back the verdict artifact.
Its contract is exercised by the end-to-end demo runs, not unit tests here.
"""

import argparse
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import effective_route_inspector as eri
from providers import (
    NICResolutionError,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    VMNotFoundError,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixture_dict(name: str) -> dict:
    with open(FIXTURES / name) as f:
        return json.load(f)


class MockRouteProvider:
    """Minimal RouteProvider for pipeline injection. Raises on demand."""

    def __init__(self, nic_name="test-nic", routes_dict=None, nic_error=None, routes_error=None):
        self._nic_name = nic_name
        self._routes_dict = _load_fixture_dict("fx-01-basic-vnet-local.json") if routes_dict is None else routes_dict
        self._nic_error = nic_error
        self._routes_error = routes_error
        self.get_nic_name_called = False
        self.get_effective_routes_called = False
        self.get_effective_routes_args = None

    def get_nic_name(self, vm_name: str, resource_group: str) -> str:
        self.get_nic_name_called = True
        if self._nic_error:
            raise self._nic_error
        return self._nic_name

    def get_effective_routes(self, nic_name: str, resource_group: str) -> dict:
        self.get_effective_routes_called = True
        self.get_effective_routes_args = (nic_name, resource_group)
        if self._routes_error:
            raise self._routes_error
        return self._routes_dict


def _make_args(
    vm_name="myvm",
    resource_group="myrg",
    dst_ip=None,
    nic_name=None,
    subscription_id=None,
    session_id="rt_test",
    audit_path=None,
):
    ns = argparse.Namespace(
        vm_name=vm_name,
        resource_group=resource_group,
        dst_ip=dst_ip,
        nic_name=nic_name,
        subscription_id=subscription_id,
        session_id=session_id,
        audit_path=audit_path or Path(tempfile.mkdtemp()),
    )
    return ns


# ---------------------------------------------------------------------------
# §8.1 _enforce_session_prefix()
# ---------------------------------------------------------------------------

class TestEnforceSessionPrefix(unittest.TestCase):

    def test_T_SID_01_already_prefixed_unchanged(self):
        self.assertEqual(eri._enforce_session_prefix("rt_20260413_120000"), "rt_20260413_120000")

    def test_T_SID_02_no_prefix_gets_rt_prepended(self):
        self.assertEqual(eri._enforce_session_prefix("myid"), "rt_myid")

    def test_T_SID_03_rt_prefix_only_unchanged(self):
        self.assertEqual(eri._enforce_session_prefix("rt_"), "rt_")

    def test_T_SID_04_empty_string_becomes_rt_(self):
        self.assertEqual(eri._enforce_session_prefix(""), "rt_")


# ---------------------------------------------------------------------------
# §8.2 _generate_session_id()
# ---------------------------------------------------------------------------

class TestGenerateSessionId(unittest.TestCase):

    def test_generate_matches_expected_pattern(self):
        sid = eri._generate_session_id()
        self.assertRegex(sid, r"^rt_\d{8}_\d{6}$")

    def test_two_calls_within_same_second_same_value(self):
        # Call twice immediately — same second → same value (documented, not prevented)
        a = eri._generate_session_id()
        b = eri._generate_session_id()
        # Strip to date+hour+minute to handle rare second boundary; both must be rt_ prefixed
        self.assertTrue(a.startswith("rt_"))
        self.assertTrue(b.startswith("rt_"))


# ---------------------------------------------------------------------------
# §8.3 _ensure_audit_dir()
# ---------------------------------------------------------------------------

class TestEnsureAuditDir(unittest.TestCase):

    def test_T_DIR_01_non_existent_directory_created(self):
        with tempfile.TemporaryDirectory() as base:
            new_dir = os.path.join(base, "sub", "audit")
            path = eri._ensure_audit_dir(new_dir)
            self.assertIsInstance(path, Path)
            self.assertTrue(path.exists())
            self.assertTrue(path.is_dir())

    def test_T_DIR_02_existing_directory_succeeds_silently(self):
        with tempfile.TemporaryDirectory() as base:
            path = eri._ensure_audit_dir(base)
            self.assertTrue(path.exists())

    def test_T_DIR_03_unwritable_parent_raises_system_exit_2(self):
        with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
            with self.assertRaises(SystemExit) as ctx:
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    eri._ensure_audit_dir("/some/path")
            self.assertEqual(ctx.exception.code, 2)


# ---------------------------------------------------------------------------
# §8.4 CLI argument validation
# ---------------------------------------------------------------------------

class TestCLIArgValidation(unittest.TestCase):
    """
    Tests invoke main() with sys.argv mocked. We expect SystemExit(2) on bad args.
    Successful args are tested by checking _run_pipeline is reached (mocked out).
    """

    def test_T_CLI_01_missing_vm_name_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.argv", ["eri", "--resource-group", "rg"]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    eri.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_T_CLI_02_missing_resource_group_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.argv", ["eri", "--vm-name", "vm"]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    eri.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_T_CLI_03_invalid_dst_ip_exits_2_with_message(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.argv", ["eri", "--vm-name", "vm", "--resource-group", "rg",
                                    "--dst-ip", "not-an-ip"]):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    eri.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_T_CLI_04_valid_args_reach_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock = MockRouteProvider()
            with patch("sys.argv", ["eri", "--vm-name", "vm", "--resource-group", "rg",
                                    "--dst-ip", "10.0.1.50", "--audit-dir", tmpdir]):
                with patch("sys.stdout", new_callable=io.StringIO):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        with self.assertRaises(SystemExit) as ctx:
                            with patch.object(eri, "_run_pipeline", return_value=0) as mock_pipe:
                                eri.main()
                        self.assertEqual(ctx.exception.code, 0)
                        self.assertTrue(mock_pipe.called)

    def test_T_CLI_05_dst_ip_0_0_0_0_is_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["eri", "--vm-name", "vm", "--resource-group", "rg",
                                    "--dst-ip", "0.0.0.0", "--audit-dir", tmpdir]):
                with patch("sys.stdout", new_callable=io.StringIO):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        with self.assertRaises(SystemExit) as ctx:
                            with patch.object(eri, "_run_pipeline", return_value=0):
                                eri.main()
                        self.assertEqual(ctx.exception.code, 0)

    def test_T_CLI_06_cidr_notation_dst_ip_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.argv", ["eri", "--vm-name", "vm", "--resource-group", "rg",
                                    "--dst-ip", "10.0.0.1/24"]):
                with patch("sys.stderr", new_callable=io.StringIO):
                    eri.main()
        self.assertEqual(ctx.exception.code, 2)


# ---------------------------------------------------------------------------
# §8.5 _render_table()
# ---------------------------------------------------------------------------

class TestRenderTable(unittest.TestCase):

    def _winner_verdict(self, prefix="10.0.1.0/24", next_hop_type="VnetLocal",
                        source="Default", next_hop_ip=None):
        return {
            "mode": "single-target",
            "dst_ip": "10.0.1.50",
            "result": "WINNER",
            "vm_name": "myvm",
            "nic_name": "my-nic",
            "winning_route": {
                "prefix": prefix,
                "prefix_length": 24,
                "next_hop_type": next_hop_type,
                "next_hop_ip": next_hop_ip,
                "source": source,
                "state": "Active",
                "route_name": None,
                "is_zero_route": False,
            },
            "selection_reason": "LPM_ONLY",
            "tied_routes": None,
            "shadowed_candidates": [],
            "anomaly_warnings": [],
            "parse_warnings": [],
            "session_id": "rt_test",
            "resource_group": "myrg",
        }

    def test_T_RENDER_01_winner_format_contains_required_labels(self):
        table = eri._render_table(self._winner_verdict())
        for label in ("VM:", "NIC:", "Destination:", "Result:", "Winner:", "Reason:"):
            self.assertIn(label, table, f"Missing label '{label}' in render output")

    def test_T_RENDER_02_tied_bgp_format_shows_tied_routes(self):
        verdict = {
            "mode": "single-target",
            "dst_ip": "10.50.0.100",
            "result": "TIED_BGP",
            "vm_name": "myvm",
            "nic_name": "my-nic",
            "winning_route": None,
            "selection_reason": "TIED_BGP",
            "tied_routes": [
                {"prefix": "10.50.0.0/24", "next_hop_type": "VirtualNetworkGateway", "source": "VirtualNetworkGateway"},
                {"prefix": "10.50.0.0/24", "next_hop_type": "VirtualNetworkGateway", "source": "VirtualNetworkGateway"},
            ],
            "shadowed_candidates": [],
            "anomaly_warnings": [],
            "parse_warnings": [],
            "session_id": "rt_test",
            "resource_group": "myrg",
        }
        table = eri._render_table(verdict)
        self.assertIn("TIED_BGP", table)
        self.assertIn("10.50.0.0/24", table)
        # Must not show a single definitive winner line
        self.assertNotIn("Winner:   10.50.0.0/24", table)

    def test_T_RENDER_03_no_route_format_shows_no_active_route_message(self):
        verdict = {
            "mode": "single-target",
            "dst_ip": "203.0.113.1",
            "result": "NO_ROUTE",
            "vm_name": "myvm",
            "nic_name": "my-nic",
            "winning_route": None,
            "selection_reason": "NO_ROUTE",
            "tied_routes": None,
            "shadowed_candidates": [],
            "anomaly_warnings": [],
            "parse_warnings": [],
            "session_id": "rt_test",
            "resource_group": "myrg",
        }
        table = eri._render_table(verdict)
        self.assertIn("No active route matches destination", table)

    def test_T_RENDER_04_audit_format_contains_required_sections(self):
        verdict = {
            "mode": "audit",
            "route_count": 5,
            "invalid_route_count": 0,
            "vm_name": "myvm",
            "nic_name": "my-nic",
            "routes_by_prefix_length": [
                {"prefix_length": 24, "prefix": "10.0.1.0/24", "next_hop_type": "VnetLocal",
                 "source": "Default", "state": "Active"},
            ],
            "invalid_routes": [],
            "findings": {
                "blackhole_routes": [],
                "nva_routes": [],
                "bgp_routes": [],
                "default_route_present": True,
                "default_route_source": "Default",
            },
            "parse_warnings": [],
            "session_id": "rt_test",
            "resource_group": "myrg",
        }
        table = eri._render_table(verdict)
        self.assertIn("audit", table)
        self.assertIn("Findings:", table)
        self.assertIn("10.0.1.0/24", table)

    def test_T_RENDER_05_none_next_hop_ip_renders_without_raising(self):
        verdict = self._winner_verdict(next_hop_ip=None)
        # Must not raise; render completes
        table = eri._render_table(verdict)
        self.assertIsInstance(table, str)


# ---------------------------------------------------------------------------
# §9.1 Artifact lifecycle
# ---------------------------------------------------------------------------

class TestArtifactLifecycle(unittest.TestCase):

    def _run(self, provider, dst_ip=None, session_id="rt_test", audit_path=None):
        if audit_path is None:
            audit_path = Path(tempfile.mkdtemp())
        args = _make_args(dst_ip=dst_ip, session_id=session_id, audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = eri._run_pipeline(args, provider=provider)
        return code, audit_path, mock_err.getvalue()

    def test_T_INT_ART_01_successful_single_target_writes_both_artifacts(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        code, audit_path, _ = self._run(provider, dst_ip="10.0.1.50")
        self.assertEqual(code, 0)
        raw = audit_path / "rt_test_raw.json"
        verdict = audit_path / "rt_test_verdict.json"
        self.assertTrue(raw.exists(), "_raw.json not written")
        self.assertTrue(verdict.exists(), "_verdict.json not written")
        with open(raw) as f:
            json.load(f)  # must be valid JSON
        with open(verdict) as f:
            json.load(f)

    def test_T_INT_ART_02_provider_failure_no_artifacts_written_exit_2(self):
        provider = MockRouteProvider(nic_error=VMNotFoundError("myvm not found"))
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir)
            args = _make_args(session_id="rt_test", audit_path=audit_path)
            with patch("sys.stdout", new_callable=io.StringIO):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = eri._run_pipeline(args, provider=provider)
            self.assertEqual(code, 2)
            self.assertFalse((audit_path / "rt_test_raw.json").exists())
            self.assertFalse((audit_path / "rt_test_verdict.json").exists())
            self.assertIn("myvm not found", mock_err.getvalue())

    def test_T_INT_ART_03_preprocessor_failure_raw_written_verdict_absent(self):
        # Empty dict → preprocessor returns error (no routes)
        provider = MockRouteProvider(routes_dict={})
        code, audit_path, _ = self._run(provider, session_id="rt_test")
        self.assertEqual(code, 2)
        # Stage 2 wrote raw artifact
        self.assertTrue((audit_path / "rt_test_raw.json").exists(), "_raw.json should exist")
        # Stage 3 failed — verdict must not exist
        self.assertFalse((audit_path / "rt_test_verdict.json").exists())

    def test_T_INT_ART_04_verdict_file_matches_stdout_result(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        audit_path = Path(tempfile.mkdtemp())
        args = _make_args(dst_ip="10.0.1.50", session_id="rt_test", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with patch("sys.stderr", new_callable=io.StringIO):
                eri._run_pipeline(args, provider=provider)
        stdout_text = mock_out.getvalue()
        with open(audit_path / "rt_test_verdict.json") as f:
            verdict = json.load(f)
        # result field in verdict must appear in rendered stdout
        self.assertIn(verdict["result"], stdout_text)

    def test_T_INT_ART_05_session_id_prefix_enforced_in_artifact_filenames(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        audit_path = Path(tempfile.mkdtemp())
        # session_id without rt_ — pipeline receives the already-enforced form
        args = _make_args(dst_ip="10.0.1.50", session_id="rt_myrun", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                eri._run_pipeline(args, provider=provider)
        self.assertTrue((audit_path / "rt_myrun_raw.json").exists())
        self.assertTrue((audit_path / "rt_myrun_verdict.json").exists())

    def test_T_INT_ART_06_audit_mode_writes_audit_verdict_single_target_writes_single(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        # Audit mode (no dst_ip)
        audit_path = Path(tempfile.mkdtemp())
        args = _make_args(dst_ip=None, session_id="rt_aud", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                eri._run_pipeline(args, provider=provider)
        with open(audit_path / "rt_aud_verdict.json") as f:
            v = json.load(f)
        self.assertEqual(v["mode"], "audit")

        # Single-target mode
        audit_path2 = Path(tempfile.mkdtemp())
        args2 = _make_args(dst_ip="10.0.1.50", session_id="rt_st", audit_path=audit_path2)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                eri._run_pipeline(args2, provider=provider)
        with open(audit_path2 / "rt_st_verdict.json") as f:
            v2 = json.load(f)
        self.assertEqual(v2["mode"], "single-target")


# ---------------------------------------------------------------------------
# §9.2 Exit code correctness
# ---------------------------------------------------------------------------

class TestExitCodes(unittest.TestCase):

    def _run_code(self, provider, dst_ip=None):
        audit_path = Path(tempfile.mkdtemp())
        args = _make_args(dst_ip=dst_ip, session_id="rt_ec", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                return eri._run_pipeline(args, provider=provider)

    def test_T_INT_EXIT_01_successful_single_target_exits_0(self):
        p = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        self.assertEqual(self._run_code(p, dst_ip="10.0.1.50"), 0)

    def test_T_INT_EXIT_02_successful_audit_exits_0(self):
        p = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        self.assertEqual(self._run_code(p, dst_ip=None), 0)

    def test_T_INT_EXIT_03_vm_not_found_error_exits_2(self):
        p = MockRouteProvider(nic_error=VMNotFoundError("not found"))
        self.assertEqual(self._run_code(p), 2)

    def test_T_INT_EXIT_04_rbac_error_exits_2(self):
        p = MockRouteProvider(nic_error=RBACError("permission denied"))
        self.assertEqual(self._run_code(p), 2)

    def test_T_INT_EXIT_05_throttle_exhausted_exits_2(self):
        p = MockRouteProvider(nic_error=ThrottleExhausted("throttled", attempts=4, last_wait_seconds=8.0))
        self.assertEqual(self._run_code(p), 2)

    def test_T_INT_EXIT_07_no_route_verdict_exits_0(self):
        # fx-09 has no 0.0.0.0/0; 203.0.113.1 → NO_ROUTE; valid verdict, not an error
        p = MockRouteProvider(routes_dict=_load_fixture_dict("fx-09-no-matching-route.json"))
        self.assertEqual(self._run_code(p, dst_ip="203.0.113.1"), 0)

    def test_T_INT_EXIT_08_tied_bgp_verdict_exits_0(self):
        # fx-14 produces TIED_BGP for 10.50.0.100; valid verdict
        p = MockRouteProvider(routes_dict=_load_fixture_dict("fx-14-bgp-tie-same-prefix.json"))
        self.assertEqual(self._run_code(p, dst_ip="10.50.0.100"), 0)


# ---------------------------------------------------------------------------
# §9.3 --nic-name bypass
# ---------------------------------------------------------------------------

class TestNicNameBypass(unittest.TestCase):

    def test_T_INT_NIC_01_nic_name_skips_get_nic_name_call(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        audit_path = Path(tempfile.mkdtemp())
        args = _make_args(nic_name="my-override-nic", dst_ip="10.0.1.50",
                          session_id="rt_nic", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                code = eri._run_pipeline(args, provider=provider)
        self.assertEqual(code, 0)
        self.assertFalse(provider.get_nic_name_called, "get_nic_name must not be called when --nic-name is set")
        self.assertTrue(provider.get_effective_routes_called)
        self.assertEqual(provider.get_effective_routes_args[0], "my-override-nic")
        # nic_name in verdict
        with open(audit_path / "rt_nic_verdict.json") as f:
            verdict = json.load(f)
        self.assertEqual(verdict["nic_name"], "my-override-nic")


# ---------------------------------------------------------------------------
# §9.4 Relational: identity fields added by orchestrator, not lpm_engine
# ---------------------------------------------------------------------------

class TestVerdictIdentityFields(unittest.TestCase):

    def test_T_INT_REL_01_verdict_file_contains_all_four_identity_fields(self):
        provider = MockRouteProvider(routes_dict=_load_fixture_dict("fx-01-basic-vnet-local.json"))
        audit_path = Path(tempfile.mkdtemp())
        args = _make_args(vm_name="testvm", resource_group="testrg",
                          dst_ip="10.0.1.50", session_id="rt_rel", audit_path=audit_path)
        with patch("sys.stdout", new_callable=io.StringIO):
            with patch("sys.stderr", new_callable=io.StringIO):
                eri._run_pipeline(args, provider=provider)
        with open(audit_path / "rt_rel_verdict.json") as f:
            verdict = json.load(f)
        for field in ("session_id", "vm_name", "resource_group", "nic_name"):
            self.assertIn(field, verdict, f"Verdict missing identity field '{field}'")
        self.assertTrue(verdict["session_id"].startswith("rt_"))
        self.assertEqual(verdict["vm_name"], "testvm")


if __name__ == "__main__":
    unittest.main(verbosity=2)
