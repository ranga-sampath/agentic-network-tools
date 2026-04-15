"""
test_providers.py — Unit tests for providers.py

Covers:
  T-PR-01 through T-PR-12  LocalShell, AzureNSGProvider, retry policy,
  error classification, is_throttle().
"""

import json
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

from providers import (
    AzureNSGProvider,
    LocalShell,
    NICResolutionError,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    VMNotFoundError,
    is_throttle,
)


# ---------------------------------------------------------------------------
# T-PR-01 — LocalShell.run() returns stdout on exit 0
# ---------------------------------------------------------------------------

def test_pr_01_local_shell_returns_stdout_on_success():
    """T-PR-01: LocalShell.run() returns stdout on exit 0 [PROVIDER]"""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"key": "value"}'
    mock_result.stderr = ""

    with patch("providers.subprocess.run", return_value=mock_result) as mock_run:
        shell = LocalShell()
        output = shell.run(["az", "vm", "show"])

    assert output == '{"key": "value"}'


# ---------------------------------------------------------------------------
# T-PR-02 — LocalShell.run() raises ProviderError on non-zero exit
# ---------------------------------------------------------------------------

def test_pr_02_local_shell_raises_on_nonzero_exit():
    """T-PR-02: LocalShell.run() raises ProviderError on non-zero exit [PROVIDER]"""
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "error message"

    with patch("providers.subprocess.run", return_value=mock_result):
        shell = LocalShell()
        with pytest.raises(ProviderError) as exc_info:
            shell.run(["az", "vm", "show"])

    assert "error message" in str(exc_info.value)


# ---------------------------------------------------------------------------
# T-PR-03 — LocalShell.run() raises ProviderError on timeout
# ---------------------------------------------------------------------------

def test_pr_03_local_shell_raises_on_timeout():
    """T-PR-03: LocalShell.run() raises ProviderError on timeout [PROVIDER]"""
    with patch(
        "providers.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["az"], timeout=60),
    ):
        shell = LocalShell()
        with pytest.raises(ProviderError) as exc_info:
            shell.run(["az", "vm", "show"])

    assert "timeout" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# T-PR-04 — LocalShell.run() uses argument vector, shell=False
# ---------------------------------------------------------------------------

def test_pr_04_local_shell_uses_argument_vector_not_shell_true():
    """T-PR-04: LocalShell.run() uses argument vector, never shell=True [PROVIDER]"""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "{}"
    mock_result.stderr = ""

    with patch("providers.subprocess.run", return_value=mock_result) as mock_run:
        shell = LocalShell()
        shell.run(["az", "vm", "show"])

    _, kwargs = mock_run.call_args
    assert kwargs.get("shell", False) is False


# ---------------------------------------------------------------------------
# T-PR-05 — is_throttle() — known patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stderr,expected", [
    ("Too Many Requests", True),
    ("429", True),
    ("throttling", True),
    ("rate limit exceeded", True),
    ("AuthorizationFailed", False),
    ("ResourceNotFound", False),
])
def test_pr_05_is_throttle_known_patterns(stderr, expected):
    """T-PR-05: is_throttle() recognises throttle patterns [PROVIDER]"""
    assert is_throttle(stderr) == expected


# ---------------------------------------------------------------------------
# T-PR-06 — _call_with_retry() retries on throttle, succeeds on 5th
# ---------------------------------------------------------------------------

def test_pr_06_call_with_retry_retries_on_throttle_succeeds_fifth():
    """T-PR-06: _call_with_retry() retries on throttle, succeeds on 5th call [PROVIDER]"""
    call_count = [0]

    def _fake_run(cmd, timeout=60):
        call_count[0] += 1
        if call_count[0] < 5:
            raise ProviderError("Too Many Requests (429)")
        return '{"ok": true}'

    provider = AzureNSGProvider()
    provider._shell = MagicMock()
    provider._shell.run.side_effect = _fake_run

    with patch("providers.time.sleep"), patch("providers.random.uniform", return_value=0.0):
        result = provider._call_with_retry(["az", "test"], context="test")

    assert result == '{"ok": true}'
    assert provider._shell.run.call_count == 5


# ---------------------------------------------------------------------------
# T-PR-07 — _call_with_retry() raises ThrottleExhausted after all attempts
# ---------------------------------------------------------------------------

def test_pr_07_call_with_retry_raises_throttle_exhausted():
    """T-PR-07: _call_with_retry() raises ThrottleExhausted after 6 total attempts [PROVIDER]

    The retry loop runs for range(max_retries + 1) = range(6), giving 6 total
    attempts before ThrottleExhausted is raised with attempts=6.
    """
    provider = AzureNSGProvider()
    provider._shell = MagicMock()
    provider._shell.run.side_effect = ProviderError("Too Many Requests (429)")

    with patch("providers.time.sleep"), patch("providers.random.uniform", return_value=0.0):
        with pytest.raises(ThrottleExhausted) as exc_info:
            provider._call_with_retry(["az", "test"], context="test")

    assert exc_info.value.attempts == 6  # max_retries + 1
    assert provider._shell.run.call_count == 6


# ---------------------------------------------------------------------------
# T-PR-08 — _classify_error() raises RBACError for AuthorizationFailed
# ---------------------------------------------------------------------------

def test_pr_08_classify_error_raises_rbac_error():
    """T-PR-08: _classify_error() raises RBACError for AuthorizationFailed [PROVIDER]"""
    provider = AzureNSGProvider()
    stderr = (
        "AuthorizationFailed: ... "
        "effectiveNetworkSecurityGroups/action is not allowed"
    )
    with pytest.raises(RBACError) as exc_info:
        provider._classify_error(stderr, context="get_effective_nsg")

    assert "effectiveNetworkSecurityGroups" in exc_info.value.permission or \
           "Network" in exc_info.value.permission


# ---------------------------------------------------------------------------
# T-PR-09 — _classify_error() raises VMNotFoundError for ResourceNotFound
# ---------------------------------------------------------------------------

def test_pr_09_classify_error_raises_vm_not_found_error():
    """T-PR-09: _classify_error() raises VMNotFoundError for ResourceNotFound [PROVIDER]"""
    provider = AzureNSGProvider()
    stderr = "ResourceNotFound: VM 'test-vm' not found"
    with pytest.raises(VMNotFoundError):
        provider._classify_error(stderr, context="get_nic_name")


# ---------------------------------------------------------------------------
# T-PR-10 — get_nic_name() selects NIC by primary=True
# ---------------------------------------------------------------------------

def test_pr_10_get_nic_name_selects_primary_nic():
    """T-PR-10: get_nic_name() selects NIC by primary=True [PROVIDER]"""
    vm_data = {
        "networkProfile": {
            "networkInterfaces": [
                {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-secondary",
                    "primary": False,
                },
                {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-primary",
                    "primary": True,
                },
            ]
        }
    }
    provider = AzureNSGProvider()
    provider._call_with_retry = MagicMock(return_value=json.dumps(vm_data))

    result = provider.get_nic_name("test-vm", "test-rg")
    assert result == "nic-primary"


# ---------------------------------------------------------------------------
# T-PR-11 — get_nic_name() falls back to single entry when no primary flag
# ---------------------------------------------------------------------------

def test_pr_11_get_nic_name_falls_back_to_single_entry():
    """T-PR-11: get_nic_name() falls back to single entry when no primary flag [PROVIDER]"""
    vm_data = {
        "networkProfile": {
            "networkInterfaces": [
                {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/only-nic",
                    # No "primary" key
                }
            ]
        }
    }
    provider = AzureNSGProvider()
    provider._call_with_retry = MagicMock(return_value=json.dumps(vm_data))

    result = provider.get_nic_name("test-vm", "test-rg")
    assert result == "only-nic"


# ---------------------------------------------------------------------------
# T-PR-12 — get_nic_name() raises NICResolutionError — multiple NICs, none primary
# ---------------------------------------------------------------------------

def test_pr_12_get_nic_name_raises_nic_resolution_error_multiple_nics_none_primary():
    """T-PR-12: get_nic_name() raises NICResolutionError — multiple NICs, none primary [PROVIDER]"""
    vm_data = {
        "networkProfile": {
            "networkInterfaces": [
                {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a",
                    "primary": False,
                },
                {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-b",
                    "primary": False,
                },
            ]
        }
    }
    provider = AzureNSGProvider()
    provider._call_with_retry = MagicMock(return_value=json.dumps(vm_data))

    with pytest.raises(NICResolutionError):
        provider.get_nic_name("test-vm", "test-rg")


# ---------------------------------------------------------------------------
# T-PR-13 — get_nic_ip() returns private IP for valid NIC
# ---------------------------------------------------------------------------

def test_pr_13_get_nic_ip_returns_private_ip():
    """T-PR-13: get_nic_ip() returns private IP when az CLI returns a valid address [PROVIDER]"""
    provider = AzureNSGProvider()
    provider._call_with_retry = MagicMock(return_value="10.0.1.5\n")

    result = provider.get_nic_ip("test-nic", "test-rg")

    assert result == "10.0.1.5"
    provider._call_with_retry.assert_called_once()
    call_args = provider._call_with_retry.call_args[0][0]
    assert "az" in call_args
    assert "network" in call_args
    assert "nic" in call_args
    assert "show" in call_args
    assert "test-nic" in call_args
    assert "test-rg" in call_args


# ---------------------------------------------------------------------------
# T-PR-14 — get_nic_ip() raises NICResolutionError on empty response
# ---------------------------------------------------------------------------

def test_pr_14_get_nic_ip_raises_nic_resolution_error_on_empty_response():
    """T-PR-14: get_nic_ip() raises NICResolutionError when az CLI returns empty output [PROVIDER]"""
    provider = AzureNSGProvider()
    provider._call_with_retry = MagicMock(return_value="   \n")

    with pytest.raises(NICResolutionError) as exc_info:
        provider.get_nic_ip("missing-nic", "test-rg")

    assert "missing-nic" in str(exc_info.value)
    assert "test-rg" in str(exc_info.value)
