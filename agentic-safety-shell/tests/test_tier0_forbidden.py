"""Section 1 — Tier 0: Forbidden Commands.

Tests T0.01–T0.23. All P0 (MUST PASS).
"""

import pytest
from unittest.mock import patch
from helpers import HitlTracker, make_request, mock_subprocess_result, read_audit_records

from safe_exec_shell import (
    CLASSIFICATION_FORBIDDEN,
    CLASSIFICATION_RISKY,
    classify,
)


# ---------------------------------------------------------------------------
# T0.01–T0.14: Commands that MUST be classified FORBIDDEN
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param("rm -rf /", id="T0.01"),
    pytest.param("rm -rf /*", id="T0.02"),
    pytest.param("mkfs.ext4 /dev/sda1", id="T0.03"),
    pytest.param("mkfs /dev/sda", id="T0.04"),
    pytest.param("dd if=/dev/zero of=/dev/sda", id="T0.05"),
    pytest.param("dd if=/dev/urandom of=/dev/sda1", id="T0.06"),
    pytest.param(":(){ :|:& };:", id="T0.07"),
    pytest.param("shutdown now", id="T0.08"),
    pytest.param("shutdown -h now", id="T0.09"),
    pytest.param("reboot", id="T0.10"),
    pytest.param("halt", id="T0.11"),
    pytest.param("poweroff", id="T0.12"),
    pytest.param("init 0", id="T0.13"),
    pytest.param("init 6", id="T0.14"),
])
def test_forbidden_classification(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_FORBIDDEN, (
        f"Expected FORBIDDEN for '{command}', got {classification}"
    )
    assert tier == 0


# ---------------------------------------------------------------------------
# T0.15–T0.17: FORBIDDEN response field invariants
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestForbiddenResponseFields:
    """T0.15–T0.17: FORBIDDEN response has null exit_code, empty output, null duration."""

    def test_t0_15_exit_code_is_null(self, shell_default):
        with patch("safe_exec_shell.subprocess.run") as mock_run:
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["exit_code"] is None, "T0.15: FORBIDDEN exit_code must be null"
        mock_run.assert_not_called()

    def test_t0_16_output_is_empty(self, shell_default):
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["output"] == "", "T0.16: FORBIDDEN output must be empty"

    def test_t0_17_duration_is_null(self, shell_default):
        with patch("safe_exec_shell.subprocess.run"):
            resp = shell_default.execute(make_request("rm -rf /"))
        assert resp["duration_seconds"] is None, "T0.17: FORBIDDEN duration must be null"


# ---------------------------------------------------------------------------
# T0.18: HITL prompt is NEVER invoked for FORBIDDEN
# ---------------------------------------------------------------------------

@pytest.mark.p0
def test_t0_18_hitl_never_invoked_for_forbidden(make_shell):
    tracker = HitlTracker(action="approve")
    shell = make_shell(hitl_callback=tracker)
    with patch("safe_exec_shell.subprocess.run"):
        shell.execute(make_request("rm -rf /"))
    assert len(tracker.calls) == 0, "T0.18: HITL must not be invoked for FORBIDDEN commands"


# ---------------------------------------------------------------------------
# T0.19: FORBIDDEN command produces an audit log entry
# ---------------------------------------------------------------------------

@pytest.mark.p0
def test_t0_19_forbidden_produces_audit_record(make_shell, tmp_audit_dir):
    shell = make_shell()
    with patch("safe_exec_shell.subprocess.run"):
        shell.execute(make_request("rm -rf /"))
    records = read_audit_records(tmp_audit_dir)
    assert len(records) == 1, "T0.19: FORBIDDEN commands must be logged to audit trail"
    assert records[0]["classification"] == CLASSIFICATION_FORBIDDEN


# ---------------------------------------------------------------------------
# T0.20–T0.23: Commands that must NOT be FORBIDDEN (negative tests)
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command,expected_not", [
    pytest.param("rm /tmp/results.txt", CLASSIFICATION_FORBIDDEN, id="T0.20"),
    pytest.param("rm -rf /tmp/test", CLASSIFICATION_FORBIDDEN, id="T0.21"),
    pytest.param("dd if=input.pcap of=output.pcap", CLASSIFICATION_FORBIDDEN, id="T0.22"),
    pytest.param("init 3", CLASSIFICATION_FORBIDDEN, id="T0.23"),
])
def test_not_forbidden(command, expected_not):
    classification, _, _ = classify(command)
    assert classification != expected_not, (
        f"'{command}' should NOT be {expected_not}, got {classification}"
    )
    # T0.20 and T0.21 should be RISKY (Tier 3 — rm/destructive pattern)
    # T0.22 should be RISKY (Tier 1 — dd not in allowlist or Tier 3)
    # T0.23 — init 3 should be RISKY (not forbidden, not in allowlist)
    assert classification == CLASSIFICATION_RISKY
