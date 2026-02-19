"""Section 16 — Subprocess Safety.

Tests SS.01–SS.13. P0 (static analysis) and P3 (real execution).
"""

import subprocess as sp

import pytest
from unittest.mock import patch

from helpers import hitl_approve, make_request, mock_subprocess_result


# ---------------------------------------------------------------------------
# P0 — MUST PASS: Static analysis
# ---------------------------------------------------------------------------

@pytest.mark.p0
class TestSubprocessStatic:

    def test_ss01_no_shell_true_in_source(self):
        """SS.01: No code path uses shell=True."""
        from pathlib import Path
        source = Path(__file__).parent.parent / "safe_exec_shell.py"
        code = source.read_text()
        # The only shell= should be shell=False in subprocess.run
        import re
        shell_calls = re.findall(r"shell\s*=\s*(True|False)", code)
        for val in shell_calls:
            assert val == "False", f"SS.01: Found shell={val} in source code"

    def test_ss02_command_passed_as_list(self, shell_default):
        """SS.02: Commands are passed as argument lists, not strings."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")) as mock_run:
            shell_default.execute(make_request("ping 8.8.8.8"))
        args = mock_run.call_args[0][0]
        assert isinstance(args, list), "SS.02: Command must be passed as a list"
        assert args == ["ping", "8.8.8.8"]


# ---------------------------------------------------------------------------
# P3 — MAY FAIL: Real subprocess execution
# ---------------------------------------------------------------------------

@pytest.mark.p3
class TestRealSubprocess:

    def test_ss10_real_ping(self, shell_default):
        """SS.10: Real ping -c 1 127.0.0.1 -> completed, exit 0."""
        resp = shell_default.execute(make_request("ping -c 1 127.0.0.1"))
        assert resp["status"] == "completed"
        assert resp["exit_code"] == 0

    def test_ss11_real_dig(self, shell_default):
        """SS.11: Real dig google.com -> completed, output has DNS data."""
        resp = shell_default.execute(make_request("dig google.com"))
        assert resp["status"] == "completed"
        # dig output typically contains "ANSWER SECTION" or status
        assert resp["output"]  # non-empty

    @pytest.mark.xfail(reason="P3: Timing-sensitive — depends on OS subprocess timeout behavior")
    def test_ss12_real_timeout(self, make_shell):
        """SS.12: Command with 1-second timeout that sleeps 5s -> timeout."""
        shell = make_shell(hitl_callback=hitl_approve, timeout=1)
        # sleep is not in the allowlist -> RISKY -> needs HITL approve
        resp = shell.execute(make_request("sleep 5"))
        assert resp["status"] == "error"
        assert resp["error"] == "timeout"

    def test_ss13_real_netstat(self, shell_default):
        """SS.13: Real netstat -an -> completed, output has connections."""
        resp = shell_default.execute(make_request("netstat -an"))
        assert resp["status"] == "completed"
        assert resp["output"]  # non-empty
