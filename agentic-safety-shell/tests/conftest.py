"""Shared fixtures for Safe-Exec Shell tests.

Fixtures are auto-injected by pytest. Helper functions are in helpers.py.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory and tests directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from safe_exec_shell import SafeExecShell, TopologyAnonymizer
from helpers import hitl_approve, hitl_deny


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_audit_dir(tmp_path):
    return str(tmp_path / "audit")


@pytest.fixture
def make_shell(tmp_audit_dir):
    """Factory fixture to create SafeExecShell instances with configurable options."""
    def _make(
        hitl_callback=None,
        timeout=120,
        anonymization=False,
        session_id="test_session",
    ):
        return SafeExecShell(
            session_id=session_id,
            audit_dir=tmp_audit_dir,
            hitl_callback=hitl_callback,
            timeout_seconds=timeout,
            anonymization_enabled=anonymization,
        )
    return _make


@pytest.fixture
def shell_approve(make_shell):
    """Shell with HITL callback that always approves."""
    return make_shell(hitl_callback=hitl_approve)


@pytest.fixture
def shell_deny(make_shell):
    """Shell with HITL callback that always denies."""
    return make_shell(hitl_callback=hitl_deny)


@pytest.fixture
def shell_default(make_shell):
    """Shell with default HITL (denies everything — fail-closed)."""
    return make_shell()


@pytest.fixture
def shell_anon(make_shell):
    """Shell with anonymization enabled and HITL auto-approve."""
    return make_shell(hitl_callback=hitl_approve, anonymization=True)


@pytest.fixture
def anonymizer():
    return TopologyAnonymizer()
