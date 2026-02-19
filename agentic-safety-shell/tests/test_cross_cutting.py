"""Section 18 — Interaction Combinations (Cross-Cutting).

Tests X.01–X.13. P0 (compound safety) and P1 (compound behavior).
"""

import json

import pytest
from unittest.mock import patch
import subprocess as sp

from helpers import (
    HitlTracker,
    hitl_approve,
    make_request,
    mock_subprocess_result,
    read_audit_records,
)

from safe_exec_shell import HitlDecision


# ---------------------------------------------------------------------------
# P0 — MUST PASS: Compound safety scenarios
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestCrossCuttingSafety:

    def test_x01_forbidden_plus_anonymization(self, shell_anon):
        """X.01: FORBIDDEN + anonymization enabled -> error returned, no output to anonymize."""
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_anon.execute(make_request("rm -rf /"))
        assert resp["status"] == "error"
        assert resp["classification"] == "FORBIDDEN"
        assert resp["output"] == ""

    def test_x02_safe_with_secret_and_ip_anonymized(self, shell_anon):
        """X.02: SAFE + output has bearer token + internal IP + anonymization on."""
        output = "Authorization: Bearer eyJ0eXAi host=10.0.0.5 data=ok"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        # Secret redacted
        assert "eyJ0eXAi" not in resp["output"]
        assert "Bearer [REDACTED]" in resp["output"]
        # IP anonymized
        assert "10.0.0.5" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_x03_approved_then_timeout(self, make_shell):
        """X.03: RISKY + approved + timeout -> error, timeout."""
        shell = make_shell(hitl_callback=hitl_approve, timeout=1)

        def timeout_effect(*args, **kwargs):
            raise sp.TimeoutExpired(cmd="long", timeout=1)

        with patch("safe_exec_shell.subprocess.run", side_effect=timeout_effect):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "error"
        assert resp["error"] == "timeout"

    def test_x04_modify_to_forbidden(self, make_shell):
        """X.04: RISKY + user modifies to FORBIDDEN -> FORBIDDEN error."""
        tracker = HitlTracker(action="modify", modified_command="rm -rf /")
        shell = make_shell(hitl_callback=tracker)
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["status"] == "error"
        assert resp["classification"] == "FORBIDDEN"
        assert resp["error"] == "forbidden_command"

    def test_x05_az_login_safe_but_redacted(self, shell_default):
        """X.05: az login SAFE but output has bearer tokens -> redacted."""
        output = "Token: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_default.execute(make_request("az login"))
        assert resp["classification"] == "SAFE"
        assert "eyJ0eXAi" not in resp["output"]


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS: Compound behavior
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestCrossCuttingBehavior:

    def test_x10_large_json_with_secret_and_anon(self, shell_anon):
        """X.10: Large JSON array (500 items) + secret in item 250 + anonymization.

        After truncation (first 3 + last 1), secret in item 250 is gone.
        Remaining IPs are anonymized.
        """
        items = []
        for i in range(500):
            item = {"id": i, "host": f"10.0.{i % 256}.{i % 256}"}
            if i == 250:
                item["secret"] = "password=TopSecret"
            items.append(item)
        raw = json.dumps(items)

        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(raw)):
            resp = shell_anon.execute(make_request("az vm list"))
        assert "TopSecret" not in resp["output"]
        # IPs in shown items should be anonymized
        assert "10.0.0." not in resp["output"] or "[INTERNAL_IP_" in resp["output"]

    def test_x11_modify_to_safe_with_truncation(self, make_shell):
        """X.11: RISKY + modify to SAFE + output requires truncation."""
        tracker = HitlTracker(action="modify", modified_command="ping 8.8.8.8")
        shell = make_shell(hitl_callback=tracker)
        long_output = "\n".join([f"line {i}" for i in range(2000)])
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(long_output)):
            resp = shell.execute(make_request("systemctl status nginx"))
        assert resp["action"] == "user_modified"
        assert resp["output_metadata"].get("truncation_applied") is True

    def test_x12_nonzero_exit_stderr_has_password(self, shell_default):
        """X.12: Non-zero exit + stderr has password -> stderr redacted."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("", "password=oops", 1)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "completed"
        assert "oops" not in resp["stderr"]
        assert "[REDACTED]" in resp["stderr"]

    def test_x13_forbidden_plus_audit_failure(self, make_shell):
        """X.13: FORBIDDEN + audit write failure -> error returned, no crash."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run"):
            with patch("safe_exec_shell._write_audit_record", side_effect=IOError("disk full")):
                resp = shell.execute(make_request("rm -rf /"))
        assert resp["status"] == "error"
        assert resp["classification"] == "FORBIDDEN"
