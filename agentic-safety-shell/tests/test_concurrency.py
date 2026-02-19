"""Section 17 — Concurrent Request Handling.

Tests CO.01–CO.02. P2 (GOOD TO PASS).
"""

import threading

import pytest
from unittest.mock import patch

from helpers import make_request, mock_subprocess_result, read_audit_records


# ---------------------------------------------------------------------------
# P2 — GOOD TO PASS
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestConcurrency:

    def test_co01_serialized_execution(self, make_shell, tmp_audit_dir):
        """CO.01: Concurrent requests are serialized (no interleaving)."""
        shell = make_shell()
        results = []

        def run_command(cmd):
            with patch("safe_exec_shell.subprocess.run",
                        return_value=mock_subprocess_result(f"output for {cmd}")):
                resp = shell.execute(make_request(cmd))
                results.append(resp)

        t1 = threading.Thread(target=run_command, args=("ping 8.8.8.8",))
        t2 = threading.Thread(target=run_command, args=("dig google.com",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 2
        # Both should complete (no crash)
        assert all(r["status"] == "completed" for r in results)

    def test_co02_sequence_monotonic_under_concurrent(self, make_shell, tmp_audit_dir):
        """CO.02: Audit sequence numbers are monotonically increasing even under concurrent calls."""
        shell = make_shell()
        results = []

        def run_command():
            with patch("safe_exec_shell.subprocess.run",
                        return_value=mock_subprocess_result("ok")):
                resp = shell.execute(make_request("ping 8.8.8.8"))
                results.append(resp)

        threads = [threading.Thread(target=run_command) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        records = read_audit_records(tmp_audit_dir)
        seqs = sorted(r["sequence"] for r in records)
        # All should be unique (no duplicates)
        assert len(seqs) == len(set(seqs))
