"""Pytest fixtures for Cloud Orchestrator tests."""
import os
import sys
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import cloud_orchestrator as co
from cloud_orchestrator import CloudOrchestrator
from helpers import MockShell, SAFE_OK


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Replace time.sleep with a no-op for all tests."""
    m = MagicMock()
    monkeypatch.setattr(co.time, "sleep", m)
    return m


@pytest.fixture
def tmp_dirs(tmp_path):
    """Temp directories for task registry and captures."""
    td = tmp_path / "audit"
    td.mkdir()
    cd = tmp_path / "captures"
    cd.mkdir()
    return str(td), str(cd)


@pytest.fixture
def shell():
    """MockShell pre-configured for clean init (empty orphan scan)."""
    s = MockShell()
    s.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
    return s


@pytest.fixture
def orch(shell, tmp_dirs):
    """Ready-to-use orchestrator with mock shell and temp dirs."""
    td, cd = tmp_dirs
    return CloudOrchestrator(
        shell=shell, session_id="test_sess",
        task_dir=td, local_capture_dir=cd,
    )
