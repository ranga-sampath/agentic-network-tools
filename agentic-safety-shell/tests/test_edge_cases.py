"""Section 13 — Input Validation & Edge Cases.

Tests EC.01–EC.13. P1 and P2.
"""

import pytest
from unittest.mock import patch

from helpers import make_request, mock_subprocess_result

from safe_exec_shell import CLASSIFICATION_RISKY, classify


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestInputValidation:

    def test_ec01_embedded_newlines(self):
        """EC.01: Command with embedded newlines -> RISKY (Tier 3)."""
        classification, tier, _ = classify("ping 8.8.8.8\nrm -rf /")
        assert classification == CLASSIFICATION_RISKY
        assert tier == 3

    def test_ec02_missing_reasoning(self, shell_default):
        """EC.02: Missing reasoning field -> error."""
        resp = shell_default.execute({"command": "ping 8.8.8.8"})
        assert resp["status"] == "error"

    def test_ec03_missing_command(self, shell_default):
        """EC.03: Missing command field -> error."""
        resp = shell_default.execute({"reasoning": "test"})
        assert resp["status"] == "error"

    def test_ec04_null_command(self, shell_default):
        """EC.04: command is None -> error, empty_command."""
        resp = shell_default.execute({"command": None, "reasoning": "test"})
        assert resp["status"] == "error"
        assert resp["error"] == "empty_command"


# ---------------------------------------------------------------------------
# P2 — GOOD TO PASS
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestEdgeCaseRobustness:

    def test_ec10_extremely_long_args(self, shell_default):
        """EC.10: 10,000-char arguments -> no crash."""
        long_arg = "a" * 10000
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request(f"ping {long_arg}"))
        # Should not crash — either completed or error
        assert resp["status"] in ("completed", "error")

    def test_ec11_unicode_characters(self):
        """EC.11: Unicode in command -> classified normally, no crash."""
        classification, _, _ = classify("ping café.example.com")
        # Should not crash — classification result is valid
        assert classification in ("SAFE", "RISKY", "FORBIDDEN")

    def test_ec12_empty_reasoning(self, shell_default):
        """EC.12: Empty reasoning string -> allowed, command executes normally."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute({"command": "ping 8.8.8.8", "reasoning": ""})
        assert resp["status"] == "completed"

    def test_ec13_very_long_reasoning(self, shell_default):
        """EC.13: 10,000-char reasoning -> accepted without error."""
        long_reasoning = "x" * 10000
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8", long_reasoning))
        assert resp["status"] == "completed"
