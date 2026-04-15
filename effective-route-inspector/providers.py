"""
providers.py — Azure CLI boundary for effective-route-inspector.

Provides RouteProvider protocol, LocalShell, AzureRouteProvider, and
typed exception hierarchy.
"""

import json
import subprocess
import time
from typing import Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ProviderError(RuntimeError):
    pass


class RBACError(ProviderError):
    pass


class ThrottleExhausted(ProviderError):
    def __init__(self, message: str = "", attempts: int = 0, last_wait_seconds: float = 0.0):
        super().__init__(message)
        self.attempts = attempts
        self.last_wait_seconds = last_wait_seconds


class VMNotFoundError(ProviderError):
    pass


class NICResolutionError(ProviderError):
    pass


# ---------------------------------------------------------------------------
# Throttle detection (module-level for independent patching in tests)
# ---------------------------------------------------------------------------

def is_throttle(stderr: str) -> bool:
    lowered = stderr.lower()
    return (
        "throttling" in lowered
        or "too many requests" in lowered
        or "rate limit" in lowered
        or "429" in lowered
    )


# ---------------------------------------------------------------------------
# RouteProvider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class RouteProvider(Protocol):
    def get_nic_name(self, vm_name: str, resource_group: str) -> str: ...
    def get_effective_routes(self, nic_name: str, resource_group: str) -> dict: ...


# ---------------------------------------------------------------------------
# LocalShell
# ---------------------------------------------------------------------------

class LocalShell:
    def run(self, args: list) -> str:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            raise ProviderError("az CLI not found. Install the Azure CLI.")
        except subprocess.TimeoutExpired:
            raise ProviderError("az CLI timed out after 60s")

        if result.returncode != 0:
            raise ProviderError(result.stderr)

        return result.stdout


# ---------------------------------------------------------------------------
# AzureRouteProvider
# ---------------------------------------------------------------------------

class AzureRouteProvider:
    def __init__(self, subscription_id: Optional[str] = None):
        self._subscription_id = subscription_id
        self._shell = LocalShell()

    def get_nic_name(self, vm_name: str, resource_group: str) -> str:
        base_args = [
            "az", "vm", "show",
            "--name", vm_name,
            "--resource-group", resource_group,
            "--output", "tsv",
        ]
        if self._subscription_id:
            base_args += ["--subscription", self._subscription_id]

        # First attempt: NIC explicitly marked primary (multi-NIC VMs).
        # On single-NIC VMs Azure often omits the primary flag, so [?primary]
        # returns nothing even though the VM and NIC both exist.
        args = base_args + ["--query", "networkProfile.networkInterfaces[?primary].id | [0]"]
        stdout = self._call_with_retry(args, context="get_nic_name")
        resource_id = stdout.strip()

        if not resource_id or resource_id == "None":
            # Fallback: take the first NIC unconditionally (single-NIC VMs).
            args_fallback = base_args + ["--query", "networkProfile.networkInterfaces[0].id"]
            stdout = self._call_with_retry(args_fallback, context="get_nic_name")
            resource_id = stdout.strip()

        if not resource_id or resource_id == "None":
            raise VMNotFoundError(
                f"VM '{vm_name}' not found in resource group '{resource_group}'"
            )

        nic_name = resource_id.split("/")[-1]
        if not nic_name:
            raise NICResolutionError(
                f"Could not extract NIC name from resource ID: {resource_id}"
            )

        return nic_name

    def get_effective_routes(self, nic_name: str, resource_group: str) -> dict:
        args = [
            "az", "network", "nic", "show-effective-route-table",
            "--name", nic_name,
            "--resource-group", resource_group,
            "--output", "json",
        ]
        if self._subscription_id:
            args += ["--subscription", self._subscription_id]

        stdout = self._call_with_retry(args, context="get_effective_routes")

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            raise ProviderError(
                f"az CLI returned non-JSON output: {stdout[:200]}"
            )

    def _call_with_retry(self, args: list, context: str) -> str:
        last_sleep = 0.0
        for attempt in range(4):
            try:
                return self._shell.run(args)
            except ProviderError as e:
                stderr = str(e)
                if is_throttle(stderr):
                    if attempt == 3:
                        raise ThrottleExhausted(
                            f"Azure API throttled after 4 attempts during {context}.",
                            attempts=4,
                            last_wait_seconds=last_sleep,
                        )
                    last_sleep = min(2 ** (attempt + 1), 30)
                    time.sleep(last_sleep)
                    continue
                self._classify_error(stderr, context)
                raise

    def _classify_error(self, stderr: str, context: str) -> None:
        lowered = stderr.lower()

        if "authorizationfailed" in lowered or "authorization_failed" in lowered:
            raise RBACError(
                f"Authorization failed during {context}. Ensure the caller has "
                "'Microsoft.Network/networkInterfaces/effectiveRouteTable/action' "
                "and 'Microsoft.Compute/virtualMachines/read'."
            )

        if "resourcenotfound" in lowered or "resource not found" in lowered:
            if context == "get_nic_name":
                raise VMNotFoundError(
                    "VM not found during NIC lookup. Check VM name and resource group."
                )
            if context == "get_effective_routes":
                raise NICResolutionError(
                    "NIC not found when querying effective routes. Verify NIC name and resource group."
                )
