"""Section 7 — Execution (Stage 3).

Tests E.01–E.13. P0 (subprocess safety) and P1 (behavioral correctness).
"""

import subprocess as sp

import pytest
from unittest.mock import patch, call

from helpers import hitl_approve, make_request, mock_subprocess_result

from safe_exec_shell import SafeExecShell


# ---------------------------------------------------------------------------
# P0 — MUST PASS
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestExecutionSafety:

    def test_e01_no_shell_true(self, shell_default):
        """E.01: Commands are executed via argument list, never shell=True."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")) as mock_run:
            shell_default.execute(make_request("ping 8.8.8.8"))

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False or kwargs.get("shell", None) is False, (
            "E.01: subprocess.run must be called with shell=False"
        )
        # First positional arg should be a list
        args_passed = mock_run.call_args[0][0]
        assert isinstance(args_passed, list), "E.01: Command must be passed as a list"

    def test_e02_timeout_kills_subprocess(self, make_shell):
        """E.02: Command exceeding timeout is killed; returns timeout error."""
        shell = make_shell(timeout=1)

        def timeout_effect(*args, **kwargs):
            raise sp.TimeoutExpired(cmd="sleep", timeout=1)

        with patch("safe_exec_shell.subprocess.run", side_effect=timeout_effect):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "error"
        assert resp["error"] == "timeout"

    def test_e03_stdout_stderr_captured_separately(self, shell_default):
        """E.03: stdout and stderr are captured in separate fields."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(
                        stdout="stdout content", stderr="stderr content", returncode=0
                    )):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["output"] == "stdout content"
        assert resp["stderr"] == "stderr content"


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestExecutionBehavior:

    def test_e10_safe_exit_zero(self, shell_default):
        """E.10: SAFE command exits 0 -> completed, exit_code 0."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok", returncode=0)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 0

    def test_e11_nonzero_exit_is_completed(self, shell_default):
        """E.11: Non-zero exit code -> status is completed (not error)."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("", "Error occurred", 1)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 1
        assert "Error" in resp["stderr"]

    def test_e12_command_not_found(self, shell_approve):
        """E.12: Non-existent command (approved) -> exit_code 127."""
        with patch("safe_exec_shell.subprocess.run",
                    side_effect=FileNotFoundError("No such file")):
            resp = shell_approve.execute(make_request("nonexistent_tool --foo"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 127
        assert "command not found" in resp["stderr"]

    def test_e13_no_output(self, shell_default):
        """E.13: Command producing no output -> empty output, exit_code 0."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("", "", 0)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert resp["output"] == ""
        assert resp["exit_code"] == 0
