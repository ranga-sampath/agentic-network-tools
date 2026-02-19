"""Section 10 — Topology Anonymization (Opt-In).

Tests A.01–A.44. P1 (enabled/disabled behavior) and P2 (metadata).
"""

import pytest
from unittest.mock import patch

from helpers import hitl_approve, make_request, mock_subprocess_result, read_audit_records

from safe_exec_shell import TopologyAnonymizer


# ---------------------------------------------------------------------------
# P1 — Default behavior (anonymization OFF)
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAnonymizationOff:

    def test_a01_ip_passes_through(self, shell_default):
        """A.01: Anonymization disabled — internal IP passes through."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("src=10.0.0.5 dst=8.8.8.8")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert "10.0.0.5" in resp["output"]

    def test_a02_resource_id_passes_through(self, shell_default):
        """A.02: Anonymization disabled — Azure resource ID passes through."""
        output = "/subscriptions/abc/resourceGroups/prod-rg"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        assert "/subscriptions/abc/resourceGroups/prod-rg" in resp["output"]

    def test_a03_no_anonymization_metadata(self, shell_default):
        """A.03: Anonymization disabled — no anonymization metadata."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            resp = shell_default.execute(make_request("ping 8.8.8.8"))
        meta = resp["output_metadata"]
        assert meta.get("anonymization_applied", False) is False


# ---------------------------------------------------------------------------
# P1 — Enabled behavior
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAnonymizationEnabled:

    def test_a10_rfc1918_10(self, shell_anon):
        """A.10: 10.x.x.x replaced with [INTERNAL_IP_N]."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("src=10.0.0.5 ok")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "10.0.0.5" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_a11_rfc1918_172_16(self, shell_anon):
        """A.11: 172.16.0.1 replaced."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("host=172.16.0.1")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "172.16.0.1" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_a12_rfc1918_172_31(self, shell_anon):
        """A.12: 172.31.255.254 replaced (upper bound)."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("host=172.31.255.254")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "172.31.255.254" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_a13_rfc1918_192_168(self, shell_anon):
        """A.13: 192.168.1.100 replaced."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("gw=192.168.1.100")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "192.168.1.100" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_a14_subnet_cidr(self, shell_anon):
        """A.14: 10.0.1.0/24 replaced with [INTERNAL_SUBNET_N]."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("subnet=10.0.1.0/24")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "10.0.1.0/24" not in resp["output"]
        assert "[INTERNAL_SUBNET_" in resp["output"]

    def test_a15_azure_resource_id(self, shell_anon):
        """A.15: Azure resource ID replaced with [AZURE_RESOURCE_N]."""
        output = "resource: /subscriptions/abc123/resourceGroups/prod-rg"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert "/subscriptions/abc123" not in resp["output"]
        assert "[AZURE_RESOURCE_" in resp["output"]


# ---------------------------------------------------------------------------
# P1 — Consistent mapping within a session
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestConsistentMapping:

    def test_a20_same_ip_same_placeholder(self, shell_anon):
        """A.20: Same IP in two commands -> same placeholder."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("host=10.0.0.5")):
            resp1 = shell_anon.execute(make_request("ping 8.8.8.8"))
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("host=10.0.0.5")):
            resp2 = shell_anon.execute(make_request("dig google.com"))
        # Extract the placeholder from both responses
        assert resp1["output"] == resp2["output"]

    def test_a21_different_ips_different_placeholders(self):
        """A.21: Different IPs -> different placeholders."""
        anon = TopologyAnonymizer()
        r1 = anon.anonymize("host=10.0.0.5")
        r2 = anon.anonymize("host=10.0.0.6")
        # Should have different placeholder numbers
        assert "[INTERNAL_IP_1]" in r1
        assert "[INTERNAL_IP_2]" in r2

    def test_a22_same_ip_same_output(self):
        """A.22: Same IP twice in same output -> identical placeholders."""
        anon = TopologyAnonymizer()
        result = anon.anonymize("src=10.0.0.5 dst=10.0.0.5")
        # Both should be the same placeholder
        assert result.count("[INTERNAL_IP_1]") == 2


# ---------------------------------------------------------------------------
# P1 — Negative: must NOT anonymize
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestAnonymizationNegative:

    def test_a30_public_ip_not_anonymized(self):
        """A.30: Public IP 8.8.8.8 passes through."""
        anon = TopologyAnonymizer()
        result = anon.anonymize("dns=8.8.8.8")
        assert "8.8.8.8" in result
        assert "[INTERNAL_IP_" not in result

    def test_a31_172_32_not_anonymized(self):
        """A.31: 172.32.0.1 (not RFC 1918) passes through."""
        anon = TopologyAnonymizer()
        result = anon.anonymize("host=172.32.0.1")
        assert "172.32.0.1" in result

    def test_a32_172_15_not_anonymized(self):
        """A.32: 172.15.255.255 (below 172.16) passes through."""
        anon = TopologyAnonymizer()
        result = anon.anonymize("host=172.15.255.255")
        assert "172.15.255.255" in result


# ---------------------------------------------------------------------------
# P2 — Ordering and metadata
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestAnonymizationMetadata:

    def test_a40_anonymization_after_redaction(self, shell_anon):
        """A.40: Anonymization runs after redaction."""
        # Output with both a secret and an internal IP
        output = "password=secret host=10.0.0.5"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        # Secret should be redacted
        assert "secret" not in resp["output"]
        # IP should be anonymized
        assert "10.0.0.5" not in resp["output"]
        assert "[INTERNAL_IP_" in resp["output"]

    def test_a41_metadata_anonymization_applied(self, shell_anon):
        """A.41: output_metadata contains anonymization_applied: true."""
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("host=10.0.0.5")):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert resp["output_metadata"]["anonymization_applied"] is True

    def test_a42_metadata_mappings_count(self, shell_anon):
        """A.42: anonymization_mappings_count matches distinct anonymized values."""
        output = "src=10.0.0.5 dst=10.0.0.6 gw=192.168.1.1"
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result(output)):
            resp = shell_anon.execute(make_request("ping 8.8.8.8"))
        assert resp["output_metadata"]["anonymization_mappings_count"] == 3

    def test_a43_audit_anonymization_enabled(self, make_shell, tmp_audit_dir):
        """A.43: Audit record has anonymization_applied: true when enabled."""
        shell = make_shell(hitl_callback=hitl_approve, anonymization=True)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["anonymization_applied"] is True

    def test_a44_audit_anonymization_disabled(self, make_shell, tmp_audit_dir):
        """A.44: Audit record has anonymization_applied: false when disabled."""
        shell = make_shell(anonymization=False)
        with patch("safe_exec_shell.subprocess.run",
                    return_value=mock_subprocess_result("ok")):
            shell.execute(make_request("ping 8.8.8.8"))
        records = read_audit_records(tmp_audit_dir)
        assert records[0]["anonymization_applied"] is False
