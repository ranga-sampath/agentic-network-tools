"""Section 5 — HITL Gate.

Tests H.01–H.15. P0 (fail-closed invariants) and P1 (behavioral correctness).
"""

import pytest
from unittest.mock import patch

from helpers import (
    HitlTracker,
    hitl_approve,
    hitl_deny,
    hitl_error,
    make_request,
    mock_subprocess_result,
)

from safe_exec_shell import HitlDecision, SafeExecShell


# ---------------------------------------------------------------------------
# P0 — MUST PASS: Fail-closed invariants
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestHitlFailClosed:

    def test_h01_risky_denied(self, shell_deny):
        """H.01: RISKY command + user denies -> denied, no execution."""
        with patch("safe_exec_shell.subprocess.run") as mock_run:
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "denied"
        assert resp["action"] == "user_denied"
        mock_run.assert_not_called()

    def test_h02_hitl_timeout(self, make_shell):
        """H.02: RISKY command + HITL timeout -> denied, user_abandoned."""
        def timeout_callback(cmd, reason, risk, tier):
            raise TimeoutError("Timeout")

        shell = make_shell(hitl_callback=timeout_callback)
        with patch("safe_exec_shell.subprocess.run") as mock_run:
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "denied"
        assert resp["action"] == "user_abandoned"
        mock_run.assert_not_called()

    def test_h03_terminal_close(self, make_shell):
        """H.03: Simulated terminal close (exception) -> denied."""
        def close_callback(cmd, reason, risk, tier):
            raise EOFError("Terminal closed")

        shell = make_shell(hitl_callback=close_callback)
        with patch("safe_exec_shell.subprocess.run") as mock_run:
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "denied"
        assert resp["action"] == "user_abandoned"
        mock_run.assert_not_called()

    def test_h04_hitl_exception(self, make_shell):
        """H.04: HITL mechanism throws exception -> denied."""
        shell = make_shell(hitl_callback=hitl_error)
        with patch("safe_exec_shell.subprocess.run") as mock_run:
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "denied"
        mock_run.assert_not_called()

    def test_h05_safe_bypasses_hitl(self, make_shell):
        """H.05: SAFE command -> HITL gate not invoked."""
        tracker = HitlTracker(action="approve")
        shell = make_shell(hitl_callback=tracker)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("PING ok")):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert len(tracker.calls) == 0, "HITL must not be invoked for SAFE commands"

    def test_h06_forbidden_bypasses_hitl(self, make_shell):
        """H.06: FORBIDDEN command -> HITL gate not invoked."""
        tracker = HitlTracker(action="approve")
        shell = make_shell(hitl_callback=tracker)
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell.execute(make_request("rm -rf /"))
        assert resp["status"] == "error"
        assert resp["classification"] == "FORBIDDEN"
        assert len(tracker.calls) == 0


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS: Behavioral correctness
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestHitlBehavior:

    def test_h10_risky_approved(self, shell_approve):
        """H.10: RISKY command + user approves -> completed."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("output")):
            resp = shell_approve.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "completed"
        assert resp["action"] == "user_approved"

    def test_h11_modify_to_safe(self, make_shell):
        """H.11: User modifies RISKY command to SAFE -> executed without further HITL."""
        tracker = HitlTracker(action="modify", modified_command="ping 8.8.8.8")
        shell = make_shell(hitl_callback=tracker)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("PING ok")):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "completed"
        assert resp["action"] == "user_modified"
        # HITL should have been called exactly once (for the original RISKY command)
        assert len(tracker.calls) == 1

    def test_h12_modify_to_still_risky(self, make_shell):
        """H.12: User modifies RISKY command to still-RISKY -> HITL again."""
        call_count = 0

        def escalating_callback(cmd, reason, risk, tier):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return HitlDecision(action="modify", modified_command="apt-get update")
            return HitlDecision(action="approve")

        shell = make_shell(hitl_callback=escalating_callback)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert call_count >= 2, "HITL must be triggered again for still-RISKY modified command"

    def test_h13_prompt_contains_required_elements(self, make_shell):
        """H.13: HITL prompt includes command, reasoning, risk explanation, and tier."""
        tracker = HitlTracker(action="deny")
        shell = make_shell(hitl_callback=tracker)
        with patch("safe_exec_shell.subprocess.run"):
            shell.execute(make_request("systemctl status nginx", "Checking service"))
        assert len(tracker.calls) == 1
        call = tracker.calls[0]
        assert call["command"] == "systemctl status nginx"
        assert call["reasoning"] == "Checking service"
        assert call["risk_explanation"]  # non-empty
        assert call["tier"] is not None

    def test_h14_approved_has_exit_code(self, shell_approve):
        """H.14: Approved RISKY command has non-null exit_code."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok", returncode=0)):
            resp = shell_approve.execute(make_request("systemctl status nginx"))
        assert resp["exit_code"] is not None

    def test_h15_denied_has_null_fields(self, shell_deny):
        """H.15: Denied RISKY command has null exit_code, empty output, null duration."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["exit_code"] is None
        assert resp["output"] == ""
        assert resp["duration_seconds"] is None
