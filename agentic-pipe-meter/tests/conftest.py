"""Shared fixtures and sys.modules stub for pipe_meter tests."""

import sys
import argparse
from unittest.mock import MagicMock
import pytest


# ---------------------------------------------------------------------------
# Stub safe_exec_shell BEFORE pipe_meter is imported by any test file
# ---------------------------------------------------------------------------

class _HitlDecision:
    def __init__(self, action: str):
        self.action = action


_shell_mod = MagicMock()
_shell_mod.HitlDecision = _HitlDecision
_shell_mod.SafeExecShell = MagicMock
sys.modules.setdefault("safe_exec_shell", _shell_mod)


# ---------------------------------------------------------------------------
# Import after stub is in place
# ---------------------------------------------------------------------------

from pipe_meter import PipelineConfig, PreflightResult  # noqa: E402
from providers import CloudProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_shell():
    return MagicMock(execute=MagicMock())


@pytest.fixture
def base_config(tmp_path):
    return PipelineConfig(
        source_ip="10.0.0.4",
        dest_ip="10.0.0.5",
        ssh_user="azureuser",
        test_type="latency",
        iterations=8,
        is_baseline=False,
        storage_account="mystorage",
        container="pipe-meter-results",
        resource_group="my-rg",
        session_id="pmeter_test",
        audit_dir=str(tmp_path),
        compare_baseline=False,
    )


@pytest.fixture
def mock_provider():
    p = MagicMock(spec=CloudProvider)
    p.check_nsg_ports.return_value = {5001: True, 19765: True}
    p.read_blob.return_value = None
    p.write_blob.return_value = "https://mystorage.blob.core.windows.net/pipe-meter-results/blob"
    return p


@pytest.fixture
def make_args():
    def _make(**overrides):
        defaults = dict(
            source_ip="10.0.0.4",
            dest_ip="10.0.0.5",
            ssh_user="azureuser",
            test_type="latency",
            iterations=8,
            is_baseline=False,
            compare_baseline=False,
            storage_account="mystorage",
            container="pipe-meter-results",
            resource_group="my-rg",
            session_id=None,
            audit_dir=None,
            source_public_ip=None,
            source_vm_key_path=None,
            dest_vm_key_path=None,
            subscription_id=None,
            location=None,
            vnet_name=None,
            subnet_name=None,
            source_nsg_name=None,
            dest_nsg_name=None,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)
    return _make
