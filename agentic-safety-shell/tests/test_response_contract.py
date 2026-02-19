"""Section 6 — Response Contract.

Tests R.01–R.20. All P1 (SHOULD PASS).
"""

import pytest
from unittest.mock import patch

from helpers import (
    HitlTracker,
    hitl_approve,
    hitl_deny,
    make_request,
    mock_subprocess_result,
)

from safe_exec_shell import SafeExecShell


REQUIRED_FIELDS_COMPLETED = {
    "status", "classification", "action", "output", "stderr",
    "exit_code", "output_metadata", "audit_id",
}

REQUIRED_FIELDS_ALL = REQUIRED_FIELDS_COMPLETED | {"error"}


# ---------------------------------------------------------------------------
# R.01–R.04: Field presence
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestFieldPresence:

    def test_r01_safe_completed(self, shell_default):
        """R.01: SAFE command completes — all fields present."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        for field in REQUIRED_FIELDS_COMPLETED:
            assert field in resp, f"R.01: Missing field '{field}'"

    def test_r02_risky_denied(self, shell_deny):
        """R.02: RISKY command denied — all fields present."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        for field in REQUIRED_FIELDS_COMPLETED:
            assert field in resp, f"R.02: Missing field '{field}'"

    def test_r03_forbidden(self, shell_default):
        """R.03: FORBIDDEN command — all fields including error present."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        for field in REQUIRED_FIELDS_ALL:
            assert field in resp, f"R.03: Missing field '{field}'"
        assert resp["error"] is not None

    def test_r04_empty_command(self, shell_default):
        """R.04: Empty command — minimal error response."""
        resp = shell_default.execute(make_request(""))
        assert "status" in resp
        assert "error" in resp
        assert "audit_id" in resp


# ---------------------------------------------------------------------------
# R.10–R.20: Field value constraints
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestFieldValues:

    def test_r10_status_enum(self, shell_default, shell_deny):
        """R.10: status is always one of completed/denied/error."""
        valid_statuses = {"completed", "denied", "error"}

        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] in valid_statuses

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["status"] in valid_statuses

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["status"] in valid_statuses

    def test_r11_classification_enum(self, shell_default, shell_deny):
        """R.11: classification is always FORBIDDEN/SAFE/RISKY."""
        valid = {"FORBIDDEN", "SAFE", "RISKY"}

        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["classification"] in valid

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["classification"] in valid

    def test_r12_action_enum(self, shell_default, shell_deny, shell_approve):
        """R.12: action is always one of the valid values."""
        valid = {"auto_approved", "user_approved", "user_denied", "user_modified", "user_abandoned"}

        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["action"] in valid

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["action"] in valid

    def test_r13_error_enum(self, shell_default):
        """R.13: error is one of the valid values or null."""
        valid = {"forbidden_command", "timeout", "redaction_failure", "empty_command", None}

        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["error"] in valid

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["error"] in valid

        resp = shell_default.execute(make_request(""))
        assert resp["error"] in valid

    def test_r14_completed_has_int_exit_code(self, shell_default):
        """R.14: When completed, exit_code is an integer."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok", returncode=0)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert isinstance(resp["exit_code"], int)

    def test_r15_denied_has_null_exit_code(self, shell_deny):
        """R.15: When denied or error, exit_code is null."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["exit_code"] is None

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("rm -rf /"))
        assert resp["exit_code"] is None

    def test_r16_safe_is_auto_approved(self, shell_default):
        """R.16: SAFE classification -> action is auto_approved."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["classification"] == "SAFE"
        assert resp["action"] == "auto_approved"

    def test_r17_forbidden_is_error(self, shell_default):
        """R.17: FORBIDDEN classification -> status is error, error is forbidden_command."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["classification"] == "FORBIDDEN"
        assert resp["status"] == "error"
        assert resp["error"] == "forbidden_command"

    def test_r18_duration_null_when_not_executed(self, shell_deny):
        """R.18: duration_seconds is null when command was not executed."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert resp["duration_seconds"] is None

    def test_r18b_duration_float_when_executed(self, shell_default):
        """R.18: duration_seconds is a non-negative float when executed."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert isinstance(resp["duration_seconds"], float)
        assert resp["duration_seconds"] >= 0

    def test_r19_duration_present_on_timeout(self, make_shell):
        """R.19: duration_seconds is present even on timeout."""
        import subprocess as sp
        shell = make_shell(hitl_callback=None, timeout=1)

        def timeout_side_effect(*args, **kwargs):
            raise sp.TimeoutExpired(cmd="sleep", timeout=1)

        with patch("safe_exec_shell.subprocess.run", side_effect=timeout_side_effect):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        assert resp["error"] == "timeout"
        assert resp["duration_seconds"] is not None

    def test_r20_audit_id_non_empty(self, shell_default, shell_deny):
        """R.20: audit_id is a non-empty string for every response."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert isinstance(resp["audit_id"], str) and resp["audit_id"]

        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_deny.execute(make_request("systemctl status nginx"))
        assert isinstance(resp["audit_id"], str) and resp["audit_id"]

        resp = shell_default.execute(make_request(""))
        assert isinstance(resp["audit_id"], str) and resp["audit_id"]
