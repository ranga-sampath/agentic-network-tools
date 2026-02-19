"""Section 15 — Dual Environment.

Tests DE.01–DE.04. All P1 (SHOULD PASS).
"""

import pytest
from unittest.mock import patch

from helpers import make_request, mock_subprocess_result, read_audit_records


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestDualEnvironment:

    def test_de01_same_pipeline(self, shell_default):
        """DE.01: Local and Azure commands go through same pipeline."""
        # Both should execute via the same shell.execute() method
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp1 = shell_default.execute(make_request("ping 8.8.8.8"))
            resp2 = shell_default.execute(make_request("az vm list"))
        # Both have same response structure
        assert set(resp1.keys()) == set(resp2.keys())

    def test_de02_local_environment(self, make_shell, tmp_audit_dir):
        """DE.02: ping -> environment is 'local'."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["environment"] == "local"

    def test_de03_azure_environment(self, make_shell, tmp_audit_dir):
        """DE.03: az vm list -> environment is 'azure'."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("az vm list"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["environment"] == "azure"

    def test_de04_pcap_is_local(self, make_shell, tmp_audit_dir):
        """DE.04: pcap_forensics.py -> environment is 'local'."""
        shell = make_shell()
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("pcap_forensics.py --input file.pcap"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["environment"] == "local"
