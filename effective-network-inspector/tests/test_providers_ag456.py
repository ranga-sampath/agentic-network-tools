"""
test_providers_ag456.py — Tests for AG-4, AG-5, and AG-6 implementation.

AG-4: Typed exceptions (ProviderError, RBACError, ThrottleExhausted)
AG-5: Exponential backoff retry on HTTP 429
AG-6: ThreadPoolExecutor concurrent NIC queries

These supplement test_providers.py (which covers the existing command-vector
and RBAC-detection behaviour) and test_effective_network_inspector.py (which
covers the orchestrator pipeline).
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from providers import (
    AzureNetworkProvider,
    LocalShell,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    _is_throttled,
    _execute_with_retry,
)
from effective_network_inspector import InspectorConfig, run

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shell_ok(stdout="[]", output=None):
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "success", "stdout": stdout,
        "output": output if output is not None else stdout,
        "exit_code": 0, "audit_id": "local",
    }
    return shell


def _shell_error(output="error", exit_code=1):
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "error", "stdout": "", "output": output,
        "exit_code": exit_code, "audit_id": "local",
    }
    return shell


def _shell_throttle():
    """Shell that always returns a 429 throttle response."""
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "error", "stdout": "",
        "output": "(429) Too Many Requests. Retry after 30 seconds.",
        "exit_code": 1, "audit_id": "local",
    }
    return shell


def _provider(shell, rg="my-rg", sub=None):
    return AzureNetworkProvider(shell=shell, resource_group=rg, subscription_id=sub)


def _minimal_config(tmp_path, **kwargs) -> InspectorConfig:
    defaults = dict(
        session_id="eni_test",
        audit_dir=str(tmp_path),
        resource_group="my-rg",
        scope="vm",
        scope_target="my-vm",
        is_baseline=True,
    )
    defaults.update(kwargs)
    return InspectorConfig(**defaults)


# ---------------------------------------------------------------------------
# AG-4: Typed exception hierarchy
# ---------------------------------------------------------------------------

class TestTypedExceptions:

    def test_provider_error_is_runtime_error_subclass(self):
        """ProviderError must be a subclass of RuntimeError for backward compatibility."""
        assert issubclass(ProviderError, RuntimeError)

    def test_rbac_error_is_provider_error_subclass(self):
        """RBACError must be a subclass of ProviderError."""
        assert issubclass(RBACError, ProviderError)

    def test_throttle_exhausted_is_provider_error_subclass(self):
        """ThrottleExhausted must be a subclass of ProviderError."""
        assert issubclass(ThrottleExhausted, ProviderError)

    def test_rbac_error_caught_as_runtime_error(self):
        """RBACError can be caught with except RuntimeError (backward compat)."""
        with pytest.raises(RuntimeError):
            raise RBACError("auth failed")

    def test_rbac_error_caught_as_provider_error(self):
        """RBACError can be caught with except ProviderError."""
        with pytest.raises(ProviderError):
            raise RBACError("auth failed")

    def test_throttle_exhausted_caught_as_runtime_error(self):
        """ThrottleExhausted can be caught with except RuntimeError."""
        with pytest.raises(RuntimeError):
            raise ThrottleExhausted("throttled")

    def test_rbac_error_raised_on_authorization_failed(self):
        """get_effective_routes_json raises RBACError (not bare RuntimeError) on RBAC failure."""
        shell = _shell_error("AuthorizationFailed: policy denied")
        provider = _provider(shell)
        with patch("providers.time.sleep"):
            with pytest.raises(RBACError):
                provider.get_effective_routes_json("nic-a")

    def test_rbac_error_raised_on_nsg_authorization_failed(self):
        """get_effective_nsg_json raises RBACError on RBAC failure."""
        shell = _shell_error("AuthorizationFailed")
        provider = _provider(shell)
        with patch("providers.time.sleep"):
            with pytest.raises(RBACError):
                provider.get_effective_nsg_json("nic-a")

    def test_provider_error_raised_on_generic_failure(self):
        """A non-RBAC, non-throttle failure raises ProviderError (not bare RuntimeError)."""
        shell = _shell_error("ResourceNotFound: NIC nic-x not found")
        provider = _provider(shell)
        with patch("providers.time.sleep"):
            with pytest.raises(ProviderError):
                provider.get_effective_routes_json("nic-x")

    def test_provider_error_is_not_rbac_error_on_generic_failure(self):
        """A generic failure must NOT be classified as RBACError."""
        shell = _shell_error("ResourceNotFound: NIC nic-x not found")
        provider = _provider(shell)
        with patch("providers.time.sleep"):
            with pytest.raises(ProviderError) as exc_info:
                provider.get_effective_routes_json("nic-x")
        assert not isinstance(exc_info.value, RBACError)

    def test_empty_nic_list_raises_provider_error(self):
        """Empty NIC list from VM raises ProviderError."""
        shell = _shell_ok("[]")
        provider = _provider(shell)
        with pytest.raises(ProviderError):
            provider.get_nic_names_for_vm("my-vm")

    def test_nic_discovery_failure_raises_provider_error(self):
        """Non-zero exit from az vm nic list raises ProviderError."""
        shell = _shell_error("ResourceNotFound: VM not found")
        provider = _provider(shell)
        with patch("providers.time.sleep"):
            with pytest.raises(ProviderError):
                provider.get_nic_names_for_vm("missing-vm")


# ---------------------------------------------------------------------------
# AG-5: _is_throttled helper
# ---------------------------------------------------------------------------

class TestIsThrottled:

    @pytest.mark.parametrize("output", [
        "(429) Too Many Requests. Retry after 30 seconds.",
        "ERROR: (429) Rate limit exceeded.",
        "Too Many Requests",
        "ThrottlingException",
        "RequestThrottled",
    ])
    def test_throttle_markers_detected(self, output):
        """All known throttle marker strings are detected."""
        assert _is_throttled(output) is True

    @pytest.mark.parametrize("output", [
        "AuthorizationFailed",
        "ResourceNotFound",
        "Bad Request",
        "",
        "500 Internal Server Error",
    ])
    def test_non_throttle_not_detected(self, output):
        """Non-throttle errors are not misclassified as 429."""
        assert _is_throttled(output) is False


# ---------------------------------------------------------------------------
# AG-5: _execute_with_retry — retry behaviour
# ---------------------------------------------------------------------------

class TestExecuteWithRetry:

    def test_success_on_first_attempt_no_retry(self):
        """Successful response on first attempt — shell called exactly once."""
        shell = _shell_ok("{}")
        with patch("providers.time.sleep") as mock_sleep:
            result = _execute_with_retry(shell, {"command": ["az"]}, "test-op")
        assert result["exit_code"] == 0
        shell.execute.assert_called_once()
        mock_sleep.assert_not_called()

    def test_throttle_then_success_retries(self):
        """429 on first call, success on second — shell called twice, one sleep."""
        shell = MagicMock()
        shell.execute.side_effect = [
            {"status": "error", "stdout": "", "output": "(429) Too Many Requests",
             "exit_code": 1, "audit_id": "local"},
            {"status": "success", "stdout": "{}", "output": "{}",
             "exit_code": 0, "audit_id": "local"},
        ]
        with patch("providers.time.sleep") as mock_sleep:
            result = _execute_with_retry(shell, {"command": ["az"]}, "test-op",
                                         max_retries=3, base_delay=1.0)
        assert result["exit_code"] == 0
        assert shell.execute.call_count == 2
        mock_sleep.assert_called_once_with(1.0)  # base_delay * 2^0

    def test_exponential_backoff_delays(self):
        """Sleep durations follow base_delay * 2^attempt: 2, 4, 8 s."""
        shell = MagicMock()
        # Throttle three times, succeed on fourth
        throttle = {"status": "error", "stdout": "", "output": "(429) Too Many Requests",
                    "exit_code": 1, "audit_id": "local"}
        success  = {"status": "success", "stdout": "{}", "output": "{}",
                    "exit_code": 0, "audit_id": "local"}
        shell.execute.side_effect = [throttle, throttle, throttle, success]

        with patch("providers.time.sleep") as mock_sleep:
            result = _execute_with_retry(shell, {"command": ["az"]}, "test-op",
                                         max_retries=3, base_delay=2.0)

        assert result["exit_code"] == 0
        assert mock_sleep.call_count == 3
        assert mock_sleep.call_args_list == [call(2.0), call(4.0), call(8.0)]

    def test_throttle_exhausted_after_max_retries(self):
        """ThrottleExhausted raised when every attempt returns 429."""
        shell = _shell_throttle()
        with patch("providers.time.sleep"):
            with pytest.raises(ThrottleExhausted) as exc_info:
                _execute_with_retry(shell, {"command": ["az"]}, "test-op",
                                    max_retries=3, base_delay=1.0)
        # max_retries=3 means: initial + 3 retries = 4 total calls
        assert shell.execute.call_count == 4
        assert "429" in str(exc_info.value) or "throttle" in str(exc_info.value).lower()

    def test_non_throttle_error_not_retried(self):
        """Non-429 error is returned immediately without retry."""
        shell = _shell_error("ResourceNotFound")
        with patch("providers.time.sleep") as mock_sleep:
            result = _execute_with_retry(shell, {"command": ["az"]}, "test-op",
                                         max_retries=3, base_delay=1.0)
        assert result["exit_code"] == 1
        shell.execute.assert_called_once()
        mock_sleep.assert_not_called()

    def test_throttle_exhausted_message_mentions_operation(self):
        """ThrottleExhausted message identifies the failing operation."""
        shell = _shell_throttle()
        with patch("providers.time.sleep"):
            with pytest.raises(ThrottleExhausted, match="show-effective-route-table"):
                _execute_with_retry(
                    shell, {"command": ["az"]},
                    "az network nic show-effective-route-table for nic-a",
                    max_retries=1,
                )


# ---------------------------------------------------------------------------
# AG-5: Provider methods use retry
# ---------------------------------------------------------------------------

class TestProviderRetry:

    def test_get_effective_routes_retries_on_429(self):
        """get_effective_routes_json retries on 429 and succeeds on second attempt."""
        throttle_result = {
            "status": "error", "stdout": "", "exit_code": 1, "audit_id": "local",
            "output": "(429) Too Many Requests",
        }
        success_result = {
            "status": "success", "exit_code": 0, "audit_id": "local",
            "stdout": '{"value": []}', "output": '{"value": []}',
        }
        shell = MagicMock()
        shell.execute.side_effect = [throttle_result, success_result]
        provider = _provider(shell)

        with patch("providers.time.sleep"):
            result = provider.get_effective_routes_json("nic-a")

        assert result == '{"value": []}'
        assert shell.execute.call_count == 2

    def test_get_effective_nsg_retries_on_429(self):
        """get_effective_nsg_json retries on 429 and succeeds on second attempt."""
        throttle_result = {
            "status": "error", "stdout": "", "exit_code": 1, "audit_id": "local",
            "output": "Too Many Requests",
        }
        success_result = {
            "status": "success", "exit_code": 0, "audit_id": "local",
            "stdout": '{"value": []}', "output": '{"value": []}',
        }
        shell = MagicMock()
        shell.execute.side_effect = [throttle_result, success_result]
        provider = _provider(shell)

        with patch("providers.time.sleep"):
            result = provider.get_effective_nsg_json("nic-a")

        assert result == '{"value": []}'
        assert shell.execute.call_count == 2

    def test_get_effective_routes_raises_throttle_exhausted(self):
        """get_effective_routes_json raises ThrottleExhausted after exhausting retries."""
        shell = _shell_throttle()
        provider = _provider(shell)

        with patch("providers.time.sleep"):
            with pytest.raises(ThrottleExhausted):
                provider.get_effective_routes_json("nic-a")

    def test_get_effective_nsg_raises_throttle_exhausted(self):
        """get_effective_nsg_json raises ThrottleExhausted after exhausting retries."""
        shell = _shell_throttle()
        provider = _provider(shell)

        with patch("providers.time.sleep"):
            with pytest.raises(ThrottleExhausted):
                provider.get_effective_nsg_json("nic-a")

    def test_nic_discovery_retries_on_429(self):
        """get_nic_names_for_vm retries on 429 before succeeding."""
        from pathlib import Path
        ids_json = (FIXTURES / "vm_nic_ids.json").read_text()
        throttle_result = {
            "status": "error", "stdout": "", "exit_code": 1, "audit_id": "local",
            "output": "(429) Too Many Requests",
        }
        success_result = {
            "status": "success", "exit_code": 0, "audit_id": "local",
            "stdout": ids_json, "output": ids_json,
        }
        shell = MagicMock()
        shell.execute.side_effect = [throttle_result, success_result]
        provider = _provider(shell)

        with patch("providers.time.sleep"):
            names = provider.get_nic_names_for_vm("my-vm")

        assert names == ["nic-a", "nic-b"]
        assert shell.execute.call_count == 2


# ---------------------------------------------------------------------------
# AG-6: ThreadPoolExecutor — concurrent correctness
# ---------------------------------------------------------------------------

class TestConcurrentNicQueries:

    def _make_provider_mock(self, nic_names: list[str]) -> MagicMock:
        """Return a mock provider that succeeds for all NICs."""
        mock = MagicMock()
        mock.get_nic_names_for_vm.return_value = nic_names
        mock.get_effective_routes_json.return_value = '{"value": []}'
        mock.get_effective_nsg_json.return_value    = '{"value": []}'
        return mock

    def test_all_nics_appear_in_snapshot(self, tmp_path):
        """All NIC names from discovery appear as entries in the snapshot."""
        nic_names = ["nic-a", "nic-b", "nic-c", "nic-d"]
        mock_prov = self._make_provider_mock(nic_names)
        config = _minimal_config(tmp_path)

        result = run(config, mock_prov)

        returned_names = [n["nic_name"] for n in result["snapshot"]["nics"]]
        assert sorted(returned_names) == sorted(nic_names)

    def test_nic_order_is_deterministic(self, tmp_path):
        """NIC order in snapshot matches the discovery order, not completion order."""
        nic_names = ["nic-a", "nic-b", "nic-c"]
        mock_prov = self._make_provider_mock(nic_names)
        config = _minimal_config(tmp_path)

        result = run(config, mock_prov)

        snapshot_names = [n["nic_name"] for n in result["snapshot"]["nics"]]
        assert snapshot_names == nic_names

    def test_per_nic_error_isolated_in_thread_pool(self, tmp_path):
        """A failing NIC does not prevent other NICs from being snapshotted."""
        nic_names = ["nic-ok", "nic-fail", "nic-ok2"]
        mock_prov = MagicMock()
        mock_prov.get_nic_names_for_vm.return_value = nic_names

        def routes_side_effect(nic_name):
            if nic_name == "nic-fail":
                raise ProviderError("simulated failure")
            return '{"value": []}'

        mock_prov.get_effective_routes_json.side_effect = routes_side_effect
        mock_prov.get_effective_nsg_json.return_value   = '{"value": []}'

        config = _minimal_config(tmp_path)
        result = run(config, mock_prov)

        nics = {n["nic_name"]: n for n in result["snapshot"]["nics"]}
        assert nics["nic-ok"]["error"]  is None
        assert nics["nic-ok2"]["error"] is None
        assert nics["nic-fail"]["error"] is not None

    def test_max_workers_1_produces_same_result(self, tmp_path):
        """max_workers=1 (sequential) produces same snapshot as default concurrency."""
        nic_names = ["nic-a", "nic-b"]
        mock_prov = self._make_provider_mock(nic_names)

        config = _minimal_config(tmp_path, max_workers=1)
        result = run(config, mock_prov)

        snapshot_names = [n["nic_name"] for n in result["snapshot"]["nics"]]
        assert snapshot_names == nic_names

    def test_rbac_error_in_thread_recorded_per_nic(self, tmp_path):
        """RBACError raised in a worker thread is recorded in the NIC entry, not propagated."""
        nic_names = ["nic-a", "nic-b"]
        mock_prov = MagicMock()
        mock_prov.get_nic_names_for_vm.return_value = nic_names

        def routes_raise_rbac(nic_name):
            if nic_name == "nic-b":
                raise RBACError("RBAC error")
            return '{"value": []}'

        mock_prov.get_effective_routes_json.side_effect = routes_raise_rbac
        mock_prov.get_effective_nsg_json.return_value   = '{"value": []}'

        config = _minimal_config(tmp_path)
        # run() must not raise — RBAC error is per-NIC
        result = run(config, mock_prov)

        nics = {n["nic_name"]: n for n in result["snapshot"]["nics"]}
        assert nics["nic-a"]["error"] is None
        assert "RBAC" in nics["nic-b"]["error"]

    def test_throttle_exhausted_in_thread_recorded_per_nic(self, tmp_path):
        """ThrottleExhausted raised in a worker thread is recorded as per-NIC error."""
        nic_names = ["nic-a", "nic-throttled"]
        mock_prov = MagicMock()
        mock_prov.get_nic_names_for_vm.return_value = nic_names

        def routes_raise_throttle(nic_name):
            if nic_name == "nic-throttled":
                raise ThrottleExhausted("throttled")
            return '{"value": []}'

        mock_prov.get_effective_routes_json.side_effect = routes_raise_throttle
        mock_prov.get_effective_nsg_json.return_value   = '{"value": []}'

        config = _minimal_config(tmp_path)
        result = run(config, mock_prov)

        nics = {n["nic_name"]: n for n in result["snapshot"]["nics"]}
        assert nics["nic-a"]["error"] is None
        assert nics["nic-throttled"]["error"] is not None

    def test_nsg_not_queried_when_routes_fail_in_thread(self, tmp_path):
        """NSG is not queried for a NIC whose routes query failed, even in thread pool."""
        nic_names = ["nic-fail"]
        mock_prov = MagicMock()
        mock_prov.get_nic_names_for_vm.return_value = nic_names
        mock_prov.get_effective_routes_json.side_effect = ProviderError("routes failed")

        config = _minimal_config(tmp_path)
        run(config, mock_prov)

        mock_prov.get_effective_nsg_json.assert_not_called()

    def test_max_workers_config_key_parsed(self, tmp_path):
        """MAX_WORKERS in config file is parsed and applied to InspectorConfig."""
        from effective_network_inspector import _load_config_file

        cfg_file = tmp_path / "test.env"
        cfg_file.write_text(
            "RESOURCE_GROUP=my-rg\nSCOPE=vm\nVM_NAME=my-vm\nMAX_WORKERS=2\n"
        )
        defaults = _load_config_file(str(cfg_file))
        assert defaults.get("max_workers") == 2

    def test_progress_output_contains_all_nics(self, tmp_path, capsys):
        """Progress lines mention each NIC name (serialized through lock)."""
        nic_names = ["nic-a", "nic-b", "nic-c"]
        mock_prov = self._make_provider_mock(nic_names)
        config = _minimal_config(tmp_path)

        run(config, mock_prov)

        combined = capsys.readouterr().out + capsys.readouterr().err
        # Each NIC should appear in a "Snapshotting NIC N/3: nic-x" line
        for name in nic_names:
            assert name in combined

    def test_progress_format_shows_n_of_total(self, tmp_path, capsys):
        """Progress lines follow 'Snapshotting NIC {n}/{total}: {name}' format."""
        nic_names = ["nic-a", "nic-b"]
        mock_prov = self._make_provider_mock(nic_names)
        config = _minimal_config(tmp_path)

        run(config, mock_prov)

        stdout = capsys.readouterr().out
        assert "Snapshotting NIC" in stdout
        assert "/2:" in stdout
