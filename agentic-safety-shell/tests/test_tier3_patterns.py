"""Section 4 — Tier 3: Dangerous Pattern Detection.

Tests T3.01–T3.35. All P0 (MUST PASS).
"""

import pytest

from safe_exec_shell import CLASSIFICATION_RISKY, classify


# ---------------------------------------------------------------------------
# T3.01–T3.04: Privilege escalation
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param("sudo ping 8.8.8.8", id="T3.01"),
    pytest.param("sudo az vm list", id="T3.02"),
    pytest.param('su -c "netstat -an"', id="T3.03"),
    pytest.param("doas traceroute 10.0.0.1", id="T3.04"),
])
def test_privilege_escalation(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )
    # Note: sudo/su/doas are not in the allowlist, so Tier 1 catches them
    # before Tier 3. The classification (RISKY) is correct regardless.
    assert tier in (1, 3)


# ---------------------------------------------------------------------------
# T3.10–T3.15: Shell evasion
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param('bash -c "ping 8.8.8.8"', id="T3.10"),
    pytest.param('sh -c "dig google.com"', id="T3.11"),
    pytest.param('eval "ping 8.8.8.8"', id="T3.12"),
    pytest.param("exec ping 8.8.8.8", id="T3.13"),
    pytest.param("ping `hostname`", id="T3.14"),
    pytest.param("ping $(hostname)", id="T3.15"),
])
def test_shell_evasion(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )
    # Note: bash/sh/eval/exec are not in the allowlist, so Tier 1 catches
    # them before Tier 3. Backtick/$()/piped commands where the base command
    # IS in the allowlist will be caught by Tier 3.
    assert tier in (1, 3)


# ---------------------------------------------------------------------------
# T3.20–T3.28: Destructive operators
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param("netstat > /etc/resolv.conf", id="T3.20"),
    pytest.param("dig google.com >> /etc/hosts", id="T3.21"),
    pytest.param("rm -rf /tmp/results", id="T3.22"),
    pytest.param("chmod 777 /etc/hosts", id="T3.23"),
    pytest.param("chown root:root /tmp/file", id="T3.24"),
    pytest.param("kill -9 1234", id="T3.25"),
    pytest.param("killall nginx", id="T3.26"),
    pytest.param('pkill -f "python"', id="T3.27"),
    pytest.param("mv /etc/hosts /etc/hosts.bak", id="T3.28"),
])
def test_destructive_operators(command):
    classification, _, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T3.30–T3.35: Command chaining
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param("ping 8.8.8.8 && rm -rf /tmp", id="T3.30"),
    pytest.param("ping 8.8.8.8 || reboot", id="T3.31"),
    pytest.param("dig google.com ; shutdown now", id="T3.32"),
    pytest.param("netstat -an | tee /etc/hosts", id="T3.33"),
    pytest.param("netstat -an | grep 443", id="T3.34"),
    pytest.param("ping 8.8.8.8 && dig google.com", id="T3.35"),
])
def test_command_chaining(command):
    classification, _, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T3.32a: Chain with forbidden command — boundary test
# ---------------------------------------------------------------------------

@pytest.mark.p0
def test_t3_32a_chain_with_forbidden():
    """Verify behavior when a forbidden command appears in a chain.

    The spec is ambiguous: Tier 0 checks on the raw command first, but
    chains are detected in Tier 3. Since classify() checks Tier 0 first
    by parsing args (shlex.split would split on ;), and Tier 3 catches
    the chaining operator, the result should be at minimum RISKY.
    """
    classification, _, _ = classify("dig google.com ; shutdown now")
    # Must be at least RISKY — not SAFE
    assert classification in (CLASSIFICATION_RISKY, "FORBIDDEN"), (
        "Chain containing forbidden command must not be SAFE"
    )
