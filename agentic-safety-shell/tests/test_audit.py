"""Section 11 — Audit Trail.

Tests AU.01–AU.41. P1 (schema/storage) and P2 (failure handling).
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
from unittest.mock import patch

from helpers import (
    hitl_approve,
    hitl_deny,
    make_request,
    mock_subprocess_result,
    read_audit_records,
)


# ---------------------------------------------------------------------------
# P1 — Record schema completeness
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAuditSchema:

    EXPECTED_FIELDS = {
        "timestamp", "session_id", "sequence", "command", "reasoning",
        "status", "classification", "tier_triggered", "error", "action",
        "user_decision", "modified_command", "environment", "exit_code",
        "output_summary", "output_truncated", "redactions_applied",
        "redaction_categories", "duration_seconds", "anonymization_applied",
    }

    def test_au01_all_fields_present(self, make_shell, tmp_audit_dir):
        """AU.01: Completed SAFE command has all 20 fields."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1
        for field in self.EXPECTED_FIELDS:
            assert field in records[0], f"AU.01: Missing field '{field}'"

    def test_au02_timestamp_iso8601(self, make_shell, tmp_audit_dir):
        """AU.02: timestamp is valid ISO 8601."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        ts = records[0]["timestamp"]
        datetime.fromisoformat(ts)  # raises if invalid

    def test_au03_session_id_consistent(self, make_shell, tmp_audit_dir):
        """AU.03: session_id is consistent across all records."""
        shell = make_shell(session_id="sess_abc")
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
            shell.execute(make_request("dig google.com"))
        records = read_audit_records(tmp_audit_dir, session_id="sess_abc")
        assert all(r["session_id"] == "sess_abc" for r in records)

    def test_au04_sequence_monotonic(self, make_shell, tmp_audit_dir):
        """AU.04: sequence is monotonically increasing."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            for _ in range(5):
                shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        seqs = [r["sequence"] for r in records]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 5  # all unique

    def test_au05_classification_matches_response(self, make_shell, tmp_audit_dir):
        """AU.05: classification in audit matches response."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["classification"] == resp["classification"]

    def test_au06_status_matches_response(self, make_shell, tmp_audit_dir):
        """AU.06: status in audit matches response."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["status"] == resp["status"]

    def test_au07_tier_triggered_values(self, make_shell, tmp_audit_dir):
        """AU.07: tier_triggered is 0 for FORBIDDEN, 1/2/3 for RISKY, null for SAFE."""
        shell = make_shell()

        # FORBIDDEN -> tier 0
        with patch("safe_exec_shell.subprocess.run"):
            shell.execute(make_request("rm -rf /"))

        # SAFE -> tier null
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))

        records = read_audit_records(tmp_audit_dir)
        forbidden_rec = next(r for r in records if r["classification"] == "FORBIDDEN")
        safe_rec = next(r for r in records if r["classification"] == "SAFE")
        assert forbidden_rec["tier_triggered"] == 0
        assert safe_rec["tier_triggered"] is None

    def test_au08_environment_field(self, make_shell, tmp_audit_dir):
        """AU.08: environment is 'local' for local, 'azure' for az commands."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
            shell.execute(make_request("az vm list"))
        records = read_audit_records(tmp_audit_dir)
        ping_rec = next(r for r in records if r["command"] == "ping 8.8.8.8")
        az_rec = next(r for r in records if r["command"] == "az vm list")
        assert ping_rec["environment"] == "local"
        assert az_rec["environment"] == "azure"

    def test_au09_output_summary_200_chars(self, make_shell, tmp_audit_dir):
        """AU.09: output_summary is first 200 chars of processed output."""
        shell = make_shell()
        long_output = "x" * 500
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(long_output)):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records[0]["output_summary"]) <= 200

    def test_au10_modified_command_only_on_modify(self, make_shell, tmp_audit_dir):
        """AU.10: modified_command is non-null only when user chose Modify."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["modified_command"] is None

    def test_au11_user_decision_null_for_safe(self, make_shell, tmp_audit_dir):
        """AU.11: user_decision is null for SAFE commands."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["user_decision"] is None

    def test_au12_anonymization_field_present(self, make_shell, tmp_audit_dir):
        """AU.12: anonymization_applied field is present in every record."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert "anonymization_applied" in records[0]


# ---------------------------------------------------------------------------
# P1 — Storage
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAuditStorage:

    def test_au20_jsonl_format(self, make_shell, tmp_audit_dir):
        """AU.20: Audit file is JSONL (each line is valid JSON)."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
            shell.execute(make_request("dig google.com"))
        filepath = Path(tmp_audit_dir) / "shell_audit_test_session.jsonl"
        for line in filepath.read_text().strip().split("\n"):
            json.loads(line)  # raises if invalid JSON

    def test_au21_file_naming(self, make_shell, tmp_audit_dir):
        """AU.21: File is named shell_audit_{session_id}.jsonl."""
        shell = make_shell(session_id="sess_xyz")
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        expected = Path(tmp_audit_dir) / "shell_audit_sess_xyz.jsonl"
        assert expected.exists()

    def test_au22_append_only(self, make_shell, tmp_audit_dir):
        """AU.22: 5 commands -> exactly 5 lines (no overwrites)."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            for _ in range(5):
                shell.execute(make_request("ping 8.8.8.8"))
        filepath = Path(tmp_audit_dir) / "shell_audit_test_session.jsonl"
        lines = filepath.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_au23_one_file_per_session(self, tmp_audit_dir):
        """AU.23: Two sessions -> two files."""
        from safe_exec_shell import SafeExecShell
        s1 = SafeExecShell("sess_a", audit_dir=tmp_audit_dir)
        s2 = SafeExecShell("sess_b", audit_dir=tmp_audit_dir)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            s1.execute(make_request("ping 8.8.8.8"))
            s2.execute(make_request("ping 8.8.8.8"))
        assert (Path(tmp_audit_dir) / "shell_audit_sess_a.jsonl").exists()
        assert (Path(tmp_audit_dir) / "shell_audit_sess_b.jsonl").exists()


# ---------------------------------------------------------------------------
# P1 — Logging behavior by command type
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAuditLoggingBehavior:

    def test_au30_empty_command_no_audit(self, make_shell, tmp_audit_dir):
        """AU.30: Empty command -> no audit record."""
        shell = make_shell()
        shell.execute(make_request(""))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 0

    def test_au31_forbidden_is_logged(self, make_shell, tmp_audit_dir):
        """AU.31: FORBIDDEN command IS logged."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run"):
            shell.execute(make_request("rm -rf /"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1
        assert records[0]["classification"] == "FORBIDDEN"

    def test_au32_safe_is_logged(self, make_shell, tmp_audit_dir):
        """AU.32: SAFE command is logged."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1

    def test_au33_risky_denied_is_logged(self, make_shell, tmp_audit_dir):
        """AU.33: RISKY command (denied) is logged."""
        shell = make_shell(hitl_callback=hitl_deny)
        with patch("safe_exec_shell.subprocess.run"):
            shell.execute(make_request("systemctl status nginx"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1
        assert records[0]["status"] == "denied"

    def test_au34_risky_approved_is_logged(self, make_shell, tmp_audit_dir):
        """AU.34: RISKY command (approved) is logged."""
        shell = make_shell(hitl_callback=hitl_approve)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("systemctl status nginx"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1
        assert records[0]["status"] == "completed"


# ---------------------------------------------------------------------------
# P2 — Audit failure handling
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestAuditFailure:

    def test_au40_audit_failure_non_blocking(self, make_shell):
        """AU.40: Audit write failure does not block command execution."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            with patch("safe_exec_shell._write_audit_record", side_effect=IOError("disk full")):
                resp = shell.execute(make_request("ping 8.8.8.8"))
        # Command should still return results
        assert resp["status"] == "completed"

    def test_au41_audit_failure_logged_to_stderr(self, make_shell, capsys):
        """AU.41: Audit write failure is logged to stderr."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            with patch("safe_exec_shell._write_audit_record", side_effect=IOError("disk full")):
                shell.execute(make_request("ping 8.8.8.8"))
        captured = capsys.readouterr()
        assert "WARNING" in captured.err or "Audit" in captured.err
