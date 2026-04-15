"""
test_providers.py — Unit tests for providers.py.

Covers test plan §7 (is_throttle, LocalShell, AzureRouteProvider, retry, classify).
All subprocess calls mocked via unittest.mock.patch("subprocess.run").
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from providers import (
    AzureRouteProvider,
    LocalShell,
    NICResolutionError,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    VMNotFoundError,
    is_throttle,
)


def _completed(returncode=0, stdout="", stderr=""):
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


# ---------------------------------------------------------------------------
# §7.1 is_throttle()
# ---------------------------------------------------------------------------

class TestIsThrottle(unittest.TestCase):

    def test_T_THROT_01_throttling_keyword(self):
        self.assertTrue(is_throttle("Throttling: request limit"))

    def test_T_THROT_02_too_many_requests(self):
        self.assertTrue(is_throttle("Too Many Requests"))

    def test_T_THROT_03_rate_limit(self):
        self.assertTrue(is_throttle("rate limit exceeded"))

    def test_T_THROT_04_http_429(self):
        self.assertTrue(is_throttle("HTTP 429"))

    def test_T_THROT_05_authorization_failed_is_false(self):
        self.assertFalse(is_throttle("AuthorizationFailed"))

    def test_T_THROT_06_resource_not_found_is_false(self):
        self.assertFalse(is_throttle("ResourceNotFound"))

    def test_T_THROT_07_empty_string_is_false(self):
        self.assertFalse(is_throttle(""))

    def test_T_THROT_08_uppercase_throttling_is_true(self):
        self.assertTrue(is_throttle("THROTTLING"))


# ---------------------------------------------------------------------------
# §7.2 LocalShell.run()
# ---------------------------------------------------------------------------

class TestLocalShell(unittest.TestCase):

    @patch("subprocess.run")
    def test_T_LS_01_success_returns_stdout(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout="output text")
        shell = LocalShell()
        result = shell.run(["az", "vm", "show"])
        self.assertEqual(result, "output text")

    @patch("subprocess.run")
    def test_T_LS_02_non_zero_exit_raises_provider_error_with_stderr(self, mock_run):
        mock_run.return_value = _completed(returncode=1, stderr="VM not found")
        shell = LocalShell()
        with self.assertRaises(ProviderError) as ctx:
            shell.run(["az", "vm", "show"])
        self.assertIn("VM not found", str(ctx.exception))

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_T_LS_03_az_not_installed_raises_provider_error_with_install_message(self, _):
        shell = LocalShell()
        with self.assertRaises(ProviderError) as ctx:
            shell.run(["az", "vm", "show"])
        self.assertIn("az CLI not found", str(ctx.exception))

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="az", timeout=60))
    def test_T_LS_04_timeout_raises_provider_error_with_timeout_message(self, _):
        shell = LocalShell()
        with self.assertRaises(ProviderError) as ctx:
            shell.run(["az", "vm", "show"])
        self.assertIn("timed out after 60s", str(ctx.exception))

    @patch("subprocess.run")
    def test_T_LS_05_shell_true_never_used(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout="ok")
        shell = LocalShell()
        shell.run(["az", "vm", "show", "--name", "myvm"])
        call_kwargs = mock_run.call_args.kwargs if mock_run.call_args.kwargs else {}
        call_args = mock_run.call_args.args
        # shell=True must not appear in kwargs
        self.assertNotEqual(call_kwargs.get("shell"), True)
        # First positional argument must be a list, not a string
        if call_args:
            self.assertIsInstance(call_args[0], list)


# ---------------------------------------------------------------------------
# §7.3 AzureRouteProvider.get_nic_name()
# ---------------------------------------------------------------------------

class TestGetNicName(unittest.TestCase):

    NIC_RESOURCE_ID = (
        "/subscriptions/sub-id/resourceGroups/rg/providers/"
        "Microsoft.Network/networkInterfaces/my-nic-name\n"
    )

    @patch("subprocess.run")
    def test_T_NIC_01_success_extracts_last_segment(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout=self.NIC_RESOURCE_ID)
        provider = AzureRouteProvider()
        result = provider.get_nic_name("myvm", "myrg")
        self.assertEqual(result, "my-nic-name")

    @patch("subprocess.run")
    def test_T_NIC_02_empty_stdout_raises_vm_not_found_error(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout="")
        provider = AzureRouteProvider()
        with self.assertRaises(VMNotFoundError) as ctx:
            provider.get_nic_name("myvm", "myrg")
        self.assertIn("myvm", str(ctx.exception))
        self.assertIn("myrg", str(ctx.exception))

    @patch("subprocess.run")
    def test_T_NIC_03_literal_none_stdout_raises_vm_not_found_error(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout="None\n")
        provider = AzureRouteProvider()
        with self.assertRaises(VMNotFoundError):
            provider.get_nic_name("myvm", "myrg")

    @patch("subprocess.run")
    def test_T_NIC_04_rbac_failure_raises_rbac_error(self, mock_run):
        mock_run.return_value = _completed(returncode=1, stderr="AuthorizationFailed: caller lacks permission")
        provider = AzureRouteProvider()
        with self.assertRaises(RBACError) as ctx:
            provider.get_nic_name("myvm", "myrg")
        self.assertIn("effectiveRouteTable/action", str(ctx.exception))

    @patch("subprocess.run")
    def test_T_NIC_05_resource_not_found_context_get_nic_name_raises_vm_not_found_error(self, mock_run):
        mock_run.return_value = _completed(returncode=1, stderr="ResourceNotFound: VM myvm not found")
        provider = AzureRouteProvider()
        with self.assertRaises(VMNotFoundError):
            provider.get_nic_name("myvm", "myrg")

    @patch("subprocess.run")
    def test_T_NIC_06_subscription_id_appended_when_provided(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout=self.NIC_RESOURCE_ID)
        provider = AzureRouteProvider(subscription_id="my-sub-id")
        provider.get_nic_name("myvm", "myrg")
        args_vector = mock_run.call_args.args[0]
        self.assertIn("--subscription", args_vector)
        idx = args_vector.index("--subscription")
        self.assertEqual(args_vector[idx + 1], "my-sub-id")

    @patch("subprocess.run")
    def test_T_NIC_07_correct_jmespath_query_in_args(self, mock_run):
        """First call uses the primary-filter query; result returned without fallback."""
        mock_run.return_value = _completed(returncode=0, stdout=self.NIC_RESOURCE_ID)
        provider = AzureRouteProvider()
        provider.get_nic_name("myvm", "myrg")
        # Only one subprocess call when primary query succeeds
        self.assertEqual(mock_run.call_count, 1)
        args_vector = mock_run.call_args.args[0]
        self.assertIn("--query", args_vector)
        idx = args_vector.index("--query")
        self.assertEqual(
            args_vector[idx + 1],
            "networkProfile.networkInterfaces[?primary].id | [0]"
        )

    @patch("subprocess.run")
    def test_T_NIC_08_single_nic_vm_no_primary_flag_uses_fallback(self, mock_run):
        """
        Single-NIC VMs may omit the primary flag; [?primary] returns empty.
        get_nic_name must fall back to [0].id and still return the correct NIC name.
        """
        mock_run.side_effect = [
            _completed(returncode=0, stdout=""),           # primary query → empty
            _completed(returncode=0, stdout=self.NIC_RESOURCE_ID),  # fallback → resource ID
        ]
        provider = AzureRouteProvider()
        result = provider.get_nic_name("myvm", "myrg")
        self.assertEqual(result, "my-nic-name")
        self.assertEqual(mock_run.call_count, 2)
        # Second call must use the first-NIC fallback query
        fallback_args = mock_run.call_args_list[1].args[0]
        self.assertIn("--query", fallback_args)
        idx = fallback_args.index("--query")
        self.assertEqual(
            fallback_args[idx + 1],
            "networkProfile.networkInterfaces[0].id"
        )

    @patch("subprocess.run")
    def test_T_NIC_09_both_queries_empty_raises_vm_not_found(self, mock_run):
        """If both primary and fallback queries return empty, VMNotFoundError is raised."""
        mock_run.side_effect = [
            _completed(returncode=0, stdout=""),   # primary query → empty
            _completed(returncode=0, stdout=""),   # fallback → empty
        ]
        provider = AzureRouteProvider()
        with self.assertRaises(VMNotFoundError):
            provider.get_nic_name("missingvm", "myrg")


# ---------------------------------------------------------------------------
# §7.4 AzureRouteProvider.get_effective_routes()
# ---------------------------------------------------------------------------

class TestGetEffectiveRoutes(unittest.TestCase):

    SAMPLE_ROUTES = {"value": [{"addressPrefix": ["10.0.0.0/16"], "nextHopType": "VnetLocal"}]}

    @patch("subprocess.run")
    def test_T_ROUTES_01_success_returns_raw_dict(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout=json.dumps(self.SAMPLE_ROUTES))
        provider = AzureRouteProvider()
        result = provider.get_effective_routes("my-nic", "myrg")
        self.assertIsInstance(result, dict)
        self.assertIn("value", result)

    @patch("subprocess.run")
    def test_T_ROUTES_02_resource_not_found_context_get_effective_routes_raises_nic_error(self, mock_run):
        mock_run.return_value = _completed(returncode=1, stderr="ResourceNotFound: NIC not found")
        provider = AzureRouteProvider()
        with self.assertRaises(NICResolutionError):
            provider.get_effective_routes("my-nic", "myrg")

    @patch("subprocess.run")
    def test_T_ROUTES_03_non_json_response_raises_provider_error(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout="<html>service unavailable</html>")
        provider = AzureRouteProvider()
        with self.assertRaises(ProviderError) as ctx:
            provider.get_effective_routes("my-nic", "myrg")
        self.assertIn("non-JSON", str(ctx.exception))

    @patch("subprocess.run")
    def test_T_ROUTES_04_correct_az_command_vector(self, mock_run):
        mock_run.return_value = _completed(returncode=0, stdout=json.dumps(self.SAMPLE_ROUTES))
        provider = AzureRouteProvider()
        provider.get_effective_routes("my-nic", "myrg")
        args_vector = mock_run.call_args.args[0]
        self.assertEqual(args_vector[:4], ["az", "network", "nic", "show-effective-route-table"])
        self.assertIn("--name", args_vector)
        self.assertEqual(args_vector[args_vector.index("--name") + 1], "my-nic")
        self.assertIn("--resource-group", args_vector)
        self.assertEqual(args_vector[args_vector.index("--resource-group") + 1], "myrg")
        self.assertIn("--output", args_vector)
        self.assertEqual(args_vector[args_vector.index("--output") + 1], "json")
        # shell=True must never appear
        kwargs = mock_run.call_args.kwargs if mock_run.call_args.kwargs else {}
        self.assertNotEqual(kwargs.get("shell"), True)


# ---------------------------------------------------------------------------
# §7.5 _call_with_retry()
# ---------------------------------------------------------------------------

class TestRetryPolicy(unittest.TestCase):

    def _make_provider(self):
        return AzureRouteProvider()

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_01_throttle_first_then_success(self, mock_run, mock_sleep):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="Throttling"),
            _completed(returncode=0, stdout="ok"),
        ]
        provider = self._make_provider()
        result = provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")
        self.assertEqual(result, "ok")
        mock_sleep.assert_called_once()
        sleep_val = mock_sleep.call_args.args[0]
        self.assertLessEqual(sleep_val, 30)

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_02_throttle_all_4_attempts_raises_throttle_exhausted(self, mock_run, mock_sleep):
        mock_run.return_value = _completed(returncode=1, stderr="Throttling")
        provider = self._make_provider()
        with self.assertRaises(ThrottleExhausted) as ctx:
            provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")
        self.assertEqual(ctx.exception.attempts, 4)
        self.assertEqual(mock_sleep.call_count, 3)

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_03_throttle_3_then_success_on_4th(self, mock_run, mock_sleep):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="Throttling"),
            _completed(returncode=1, stderr="Throttling"),
            _completed(returncode=1, stderr="Throttling"),
            _completed(returncode=0, stdout="result"),
        ]
        provider = self._make_provider()
        result = provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")
        self.assertEqual(result, "result")
        self.assertEqual(mock_sleep.call_count, 3)

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_04_non_throttle_error_raises_immediately_no_retry(self, mock_run, mock_sleep):
        mock_run.return_value = _completed(returncode=1, stderr="AuthorizationFailed")
        provider = self._make_provider()
        with self.assertRaises(RBACError):
            provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")
        mock_sleep.assert_not_called()
        self.assertEqual(mock_run.call_count, 1)

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_05_backoff_formula_2_4_8(self, mock_run, mock_sleep):
        mock_run.return_value = _completed(returncode=1, stderr="Throttling")
        provider = self._make_provider()
        with self.assertRaises(ThrottleExhausted):
            provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")
        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list]
        self.assertEqual(sleep_calls, [2, 4, 8])

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_06_context_forwarded_to_classify_error_get_nic_name(self, mock_run, mock_sleep):
        mock_run.return_value = _completed(returncode=1, stderr="ResourceNotFound")
        provider = AzureRouteProvider()
        with self.assertRaises(VMNotFoundError):
            provider._call_with_retry(["az", "vm", "show"], context="get_nic_name")

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_T_RETRY_06b_context_forwarded_to_classify_error_get_effective_routes(self, mock_run, mock_sleep):
        mock_run.return_value = _completed(returncode=1, stderr="ResourceNotFound")
        provider = AzureRouteProvider()
        with self.assertRaises(NICResolutionError):
            provider._call_with_retry(["az", "network", "nic", "show-effective-route-table"],
                                      context="get_effective_routes")


# ---------------------------------------------------------------------------
# §7.6 _classify_error()
# ---------------------------------------------------------------------------

class TestClassifyError(unittest.TestCase):

    def _classify(self, stderr: str, context: str):
        provider = AzureRouteProvider()
        provider._classify_error(stderr, context)

    def test_T_CLS_01_authorization_failed_get_nic_name_raises_rbac(self):
        with self.assertRaises(RBACError):
            self._classify("AuthorizationFailed", "get_nic_name")

    def test_T_CLS_02_authorization_failed_lowercase_raises_rbac(self):
        with self.assertRaises(RBACError):
            self._classify("authorization_failed", "get_effective_routes")

    def test_T_CLS_03_resource_not_found_get_nic_name_raises_vm_not_found(self):
        with self.assertRaises(VMNotFoundError):
            self._classify("ResourceNotFound", "get_nic_name")

    def test_T_CLS_04_resource_not_found_get_effective_routes_raises_nic_error(self):
        with self.assertRaises(NICResolutionError):
            self._classify("resource not found", "get_effective_routes")

    def test_T_CLS_05_unknown_pattern_returns_without_raising(self):
        # Must return; caller (retry loop) will re-raise the original ProviderError
        self._classify("InternalError: backend failure", "get_nic_name")  # no exception

    def test_T_CLS_06_throttling_pattern_returns_without_raising(self):
        # Throttle handling is in _call_with_retry; _classify_error is never reached for throttle
        self._classify("Throttling: rate exceeded", "get_nic_name")  # no exception


if __name__ == "__main__":
    unittest.main(verbosity=2)
