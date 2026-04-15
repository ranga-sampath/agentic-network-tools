"""
providers.py — Azure CLI boundary for security-rule-inspector.

Provides NSGProvider protocol, LocalShell, AzureNSGProvider, and
typed exception hierarchy.
"""

import json
import random
import subprocess
import time
from typing import Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ProviderError(RuntimeError):
    pass


class RBACError(ProviderError):
    def __init__(self, message: str = "", permission: str = "", operation: str = ""):
        super().__init__(message)
        self.permission = permission
        self.operation = operation


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
# NSGProvider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class NSGProvider(Protocol):
    def get_nic_name(self, vm_name: str, resource_group: str) -> str: ...
    def get_nic_ip(self, nic_name: str, resource_group: str) -> str: ...
    def get_effective_nsg(self, nic_name: str, resource_group: str) -> dict: ...


# ---------------------------------------------------------------------------
# LocalShell
# ---------------------------------------------------------------------------

class LocalShell:
    def run(self, cmd: list, timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ProviderError("az CLI not found. Install the Azure CLI.")
        except subprocess.TimeoutExpired:
            raise ProviderError(f"timeout after {timeout}s")

        if result.returncode != 0:
            raise ProviderError(result.stderr)

        return result.stdout


# ---------------------------------------------------------------------------
# AzureNSGProvider
# ---------------------------------------------------------------------------

class AzureNSGProvider:
    def __init__(self, subscription_id: Optional[str] = None):
        self._subscription_id = subscription_id
        self._shell = LocalShell()

    def get_nic_name(self, vm_name: str, resource_group: str) -> str:
        args = [
            "az", "vm", "show",
            "--resource-group", resource_group,
            "--name", vm_name,
            "--output", "json",
        ]
        if self._subscription_id:
            args += ["--subscription", self._subscription_id]

        stdout = self._call_with_retry(args, context="get_nic_name")

        try:
            vm_data = json.loads(stdout)
        except json.JSONDecodeError:
            raise ProviderError(
                f"az CLI returned non-JSON output for vm show: {stdout[:200]}"
            )

        if not vm_data:
            raise VMNotFoundError(
                f"VM '{vm_name}' not found in resource group '{resource_group}'"
            )

        network_profile = vm_data.get("networkProfile") or {}
        interfaces = network_profile.get("networkInterfaces") or []

        if not interfaces:
            raise NICResolutionError(
                f"VM '{vm_name}' has no network interfaces in resource group '{resource_group}'"
            )

        # Find primary NIC
        primary_entry = None
        for iface in interfaces:
            if iface.get("primary") is True:
                primary_entry = iface
                break

        # Fall back to single-entry list if no primary flag
        if primary_entry is None and len(interfaces) == 1:
            primary_entry = interfaces[0]

        if primary_entry is None:
            raise NICResolutionError(
                f"VM '{vm_name}' has multiple NICs but none is marked primary. "
                "Use --nic-name to specify the NIC directly."
            )

        resource_id = primary_entry.get("id", "")
        nic_name = resource_id.rstrip("/").split("/")[-1] if resource_id else ""

        if not nic_name:
            raise NICResolutionError(
                f"Could not extract NIC name from resource ID: {resource_id!r}"
            )

        return nic_name

    def get_nic_ip(self, nic_name: str, resource_group: str) -> str:
        args = [
            "az", "network", "nic", "show",
            "--resource-group", resource_group,
            "--name", nic_name,
            "--query", "ipConfigurations[0].privateIPAddress",
            "--output", "tsv",
        ]
        if self._subscription_id:
            args += ["--subscription", self._subscription_id]

        stdout = self._call_with_retry(args, context="get_nic_ip")
        ip = stdout.strip()
        if not ip:
            raise NICResolutionError(
                f"Could not resolve private IP for NIC '{nic_name}' in '{resource_group}'"
            )
        return ip

    def get_effective_nsg(self, nic_name: str, resource_group: str) -> dict:
        args = [
            "az", "network", "nic", "list-effective-nsg",
            "--name", nic_name,
            "--resource-group", resource_group,
            "--output", "json",
        ]
        if self._subscription_id:
            args += ["--subscription", self._subscription_id]

        stdout = self._call_with_retry(args, context="get_effective_nsg")

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            raise ProviderError(
                f"az CLI returned non-JSON output for list-effective-nsg: {stdout[:200]}"
            )

    def _call_with_retry(self, cmd: list, context: str) -> str:
        max_retries = 5
        initial_delay = 2.0
        multiplier = 2
        last_sleep = 0.0

        for attempt in range(max_retries + 1):
            try:
                return self._shell.run(cmd)
            except ProviderError as e:
                stderr = str(e)

                # RBAC error — do not retry
                if "authorizationfailed" in stderr.lower() or "authorization_failed" in stderr.lower():
                    self._classify_error(stderr, context)
                    raise  # _classify_error raises RBACError; this line is unreachable for RBAC

                # VM/resource not found — do not retry
                if "resourcenotfound" in stderr.lower() or "resource not found" in stderr.lower():
                    self._classify_error(stderr, context)
                    raise  # re-raises original ProviderError if _classify_error didn't match

                # Throttle — retry with exponential backoff + jitter
                if is_throttle(stderr):
                    if attempt == max_retries:
                        raise ThrottleExhausted(
                            f"Azure API throttled after {max_retries + 1} attempts during {context}.",
                            attempts=max_retries + 1,
                            last_wait_seconds=last_sleep,
                        )
                    delay = min(initial_delay * (multiplier ** attempt), 30)
                    jitter = random.uniform(-0.5, 0.5)
                    last_sleep = max(0.0, delay + jitter)
                    time.sleep(last_sleep)
                    continue

                # Any other error — raise immediately
                raise

        # Should not be reached
        raise ProviderError(f"Unexpected retry loop exit during {context}")

    def _classify_error(self, stderr: str, context: str) -> None:
        lowered = stderr.lower()

        if "authorizationfailed" in lowered or "authorization_failed" in lowered:
            if "effectivenetworksecuritygroups" in lowered:
                permission = "Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action"
                operation = "az network nic list-effective-nsg"
            elif "virtualmachines" in lowered:
                permission = "Microsoft.Compute/virtualMachines/read"
                operation = "az vm show (NIC resolution)"
            else:
                permission = stderr[:200]
                operation = "unknown operation"
            raise RBACError(
                f"Authorization failed during {context}.",
                permission=permission,
                operation=operation,
            )

        if "resourcenotfound" in lowered or "resource not found" in lowered:
            if context == "get_nic_name":
                raise VMNotFoundError(
                    "VM not found during NIC lookup. Check VM name and resource group."
                )
            if context == "get_effective_nsg":
                raise NICResolutionError(
                    "NIC not found when querying effective NSG. Verify NIC name and resource group."
                )
