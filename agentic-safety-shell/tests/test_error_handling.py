"""Section 12 — Error Handling.

Tests ER.01–ER.14. P0 (critical errors) and P1 (behavioral).
"""

import subprocess as sp

import pytest
from unittest.mock import patch

from helpers import hitl_approve, hitl_deny, make_request, mock_subprocess_result


# ---------------------------------------------------------------------------
# P0 — MUST PASS
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestCriticalErrors:

    def test_er01_empty_command(self, shell_default):
        """ER.01: Empty command '' -> error, empty_command."""
        resp = shell_default.execute(make_request(""))
        assert resp["status"] == "error"
        assert resp["error"] == "empty_command"

    def test_er02_whitespace_only(self, shell_default):
        """ER.02: Whitespace-only command -> error, empty_command."""
        resp = shell_default.execute(make_request("   "))
        assert resp["status"] == "error"
        assert resp["error"] == "empty_command"

    def test_er03_redaction_exception(self, shell_default):
        """ER.03: Redaction regex throws -> error, output empty."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("output")):
            with patch("safe_exec_shell.redact_output",
                        side_effect=Exception("regex error")):
                resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "error"
        assert resp["error"] == "redaction_failure"
        assert resp["output"] == ""


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestErrorBehavior:

    def test_er10_timeout(self, make_shell):
        """ER.10: Command times out -> error, timeout, duration non-null."""
        shell = make_shell(timeout=1)

        def timeout_effect(*args, **kwargs):
            raise sp.TimeoutExpired(cmd="sleep", timeout=1)

        with patch("safe_exec_shell.subprocess.run", side_effect=timeout_effect):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "error"
        assert resp["error"] == "timeout"
        assert resp["duration_seconds"] is not None

    def test_er11_nonzero_exit_not_error(self, shell_default):
        """ER.11: Non-zero exit code -> completed (not error)."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("", "fail", 2)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 2

    def test_er12_command_not_found(self, shell_approve):
        """ER.12: OS command not found -> completed, exit_code 127."""
        with patch("safe_exec_shell.subprocess.run",
                    side_effect=FileNotFoundError()):
            resp = shell_approve.execute(make_request("nonexistent_tool"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 127
        assert "command not found" in resp["stderr"]

    def test_er13_hitl_timeout(self, make_shell):
        """ER.13: HITL timeout -> denied, user_abandoned."""
        def timeout_cb(cmd, reason, risk, tier):
            raise TimeoutError("HITL timeout")
        shell = make_shell(hitl_callback=timeout_cb)
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "denied"
        assert resp["action"] == "user_abandoned"

    def test_er14_forbidden_error(self, shell_default):
        """ER.14: FORBIDDEN command -> error, forbidden_command, FORBIDDEN."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["status"] == "error"
        assert resp["error"] == "forbidden_command"
        assert resp["classification"] == "FORBIDDEN"
