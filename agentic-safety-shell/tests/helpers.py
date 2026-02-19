"""Shared helper functions and classes for Safe-Exec Shell tests.

Import these in test files: from helpers import make_request, HitlTracker, ...
Fixtures are in conftest.py and are auto-injected by pytest.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

from safe_exec_shell import HitlDecision


# ---------------------------------------------------------------------------
# HITL callback helpers
# ---------------------------------------------------------------------------

def hitl_approve(command, reasoning, risk_explanation, tier):
    return HitlDecision(action="approve")


def hitl_deny(command, reasoning, risk_explanation, tier):
    return HitlDecision(action="deny")


def hitl_error(command, reasoning, risk_explanation, tier):
    raise RuntimeError("HITL mechanism failure")


class HitlTracker:
    """HITL callback that tracks invocations and returns configurable responses."""

    def __init__(self, action="approve", modified_command=None):
        self.calls = []
        self.action = action
        self.modified_command = modified_command

    def __call__(self, command, reasoning, risk_explanation, tier):
        self.calls.append({
            "command": command,
            "reasoning": reasoning,
            "risk_explanation": risk_explanation,
            "tier": tier,
        })
        return HitlDecision(action=self.action, modified_command=self.modified_command)


# ---------------------------------------------------------------------------
# Subprocess mock helper
# ---------------------------------------------------------------------------

def mock_subprocess_result(stdout="", stderr="", returncode=0):
    """Create a mock subprocess.CompletedProcess."""
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ---------------------------------------------------------------------------
# Request builder helper
# ---------------------------------------------------------------------------

def make_request(command, reasoning="Test reasoning"):
    return {"command": command, "reasoning": reasoning}


# ---------------------------------------------------------------------------
# Audit log reader helper
# ---------------------------------------------------------------------------

def read_audit_records(audit_dir, session_id="test_session"):
    """Read all audit records from a session's JSONL file."""
    filepath = Path(audit_dir) / f"shell_audit_{session_id}.jsonl"
    if not filepath.exists():
        return []
    records = []
    for line in filepath.read_text().strip().split("\n"):
        if line:
            records.append(json.loads(line))
    return records
