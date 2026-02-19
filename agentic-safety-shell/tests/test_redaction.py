"""Section 9 — Output Processing: Privacy Redaction.

Tests S.01–S.33. P0 (secrets never leak) and P2 (metadata accuracy).
"""

import json

import pytest
from unittest.mock import patch

from helpers import make_request, mock_subprocess_result, read_audit_records

from safe_exec_shell import redact_output


# ---------------------------------------------------------------------------
# P0 — MUST PASS: Redaction pattern coverage
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestRedactionPatterns:

    def test_s01_api_key(self):
        """S.01: API key pattern redacted."""
        text = "api-key: sk-abc123def456"
        result, _ = redact_output(text)
        assert "sk-abc123def456" not in result
        assert "[REDACTED]" in result

    def test_s02_password(self):
        """S.02: password= pattern redacted."""
        text = "password=MyS3cret!"
        result, _ = redact_output(text)
        assert "MyS3cret!" not in result
        assert "[REDACTED]" in result

    def test_s03_passwd(self):
        """S.03: passwd= variant redacted."""
        text = "passwd=hunter2"
        result, _ = redact_output(text)
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_s04_pwd(self):
        """S.04: pwd= variant redacted."""
        text = "pwd=secret123"
        result, _ = redact_output(text)
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_s05_bearer_token(self):
        """S.05: Bearer token redacted."""
        text = "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxMjM0"
        result, _ = redact_output(text)
        assert "eyJ0eXAi" not in result
        assert "Bearer [REDACTED]" in result

    def test_s06_connection_string(self):
        """S.06: Connection string redacted."""
        text = "Server=tcp:mydb.database.windows.net;Database=mydb;Password=abc123"
        result, _ = redact_output(text)
        assert "Password=abc123" not in result
        assert "[REDACTED_CONNECTION_STRING]" in result

    def test_s07_private_key(self):
        """S.07: PEM private key redacted."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----"
        result, _ = redact_output(text)
        assert "MIIEpAI" not in result
        assert "[REDACTED_PRIVATE_KEY]" in result

    def test_s08_azure_subscription_id(self):
        """S.08: Azure subscription ID redacted."""
        text = '"subscriptionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"'
        result, _ = redact_output(text)
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result
        assert "[REDACTED]" in result

    def test_s09_storage_key(self):
        """S.09: Azure storage key redacted."""
        text = "AccountKey=SGVsbG8gV29ybGQgVGhpcyBJcyBBIFRlc3Q=="
        result, _ = redact_output(text)
        assert "SGVsbG8g" not in result
        assert "[REDACTED]" in result

    def test_s10_sas_token(self):
        """S.10: SAS token redacted."""
        text = "?sv=2021-06-08&ss=b&srt=co&sp=rwdlacup&se=2023-01-01&st=2022-01-01&spr=https&sig=abc123"
        result, _ = redact_output(text)
        assert "sig=abc123" not in result
        assert "[REDACTED_SAS_TOKEN]" in result


# ---------------------------------------------------------------------------
# P0 — Redaction ordering and safety invariants
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestRedactionInvariants:

    def test_s20_redaction_after_truncation(self, shell_default):
        """S.20: Secret at line 500 of 2000-line output — removed by truncation, not leaked."""
        lines = [f"Log line {i}" for i in range(2000)]
        lines[500] = "password=TopSecret123"
        raw = "\n".join(lines)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(raw)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        # Secret at line 500 should not be in truncated output (first 20 + last 10)
        assert "TopSecret123" not in resp["output"]

    def test_s21_redaction_failure_fail_closed(self, shell_default):
        """S.21: Redaction regex exception -> error, raw output NOT returned."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("some output")):
            with patch("safe_exec_shell.redact_output", side_effect=Exception("regex broke")):
                resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert resp["status"] == "error"
        assert resp["error"] == "redaction_failure"
        assert resp["output"] == ""

    def test_s22_audit_has_redacted_output(self, make_shell, tmp_audit_dir):
        """S.22: Audit log contains redacted output, not raw."""
        shell = make_shell()
        raw_output = "password=SuperSecret123 and some data"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(raw_output)):
            resp = shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert len(records) == 1
        assert "SuperSecret123" not in records[0]["output_summary"]

    def test_s23_az_login_safe_but_redacted(self, shell_default):
        """S.23: az login classified SAFE, but output is redacted."""
        az_output = 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJ0ZW5hbnQiOiIxMjM0NTY3OCJ9'
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(az_output)):
            resp = shell_default.execute(make_request("az login"))
        assert resp["classification"] == "SAFE"
        assert "eyJ0eXAi" not in resp["output"]
        assert "Bearer [REDACTED]" in resp["output"]


# ---------------------------------------------------------------------------
# P2 — GOOD TO PASS: Redaction metadata
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestRedactionMetadata:

    def test_s30_redactions_applied_flag(self):
        """S.30: redactions_applied is true when redactions occurred."""
        _, meta = redact_output("password=secret")
        assert meta["redactions_applied"] is True

        _, meta = redact_output("clean text with no secrets")
        assert meta["redactions_applied"] is False

    def test_s31_redaction_count(self):
        """S.31: redaction_count matches number of redactions."""
        text = "password=a password=b password=c"
        _, meta = redact_output(text)
        assert meta["redaction_count"] == 3

    def test_s32_redaction_categories(self):
        """S.32: redaction_categories lists correct categories."""
        text = "password=secret and Bearer eyJ0eXAi"
        _, meta = redact_output(text)
        assert "password" in meta["redaction_categories"]
        assert "bearer_token" in meta["redaction_categories"]

    def test_s33_no_secrets_empty_categories(self):
        """S.33: No secrets -> empty categories."""
        _, meta = redact_output("clean text")
        assert meta["redaction_categories"] == []
