"""Section 2 — Tier 1: Command Allowlist.

Tests T1.01–T1.85. P0 (default deny) and P1 (allowlist correctness).
"""

import pytest

from safe_exec_shell import CLASSIFICATION_RISKY, CLASSIFICATION_SAFE, classify


# ---------------------------------------------------------------------------
# T1.01–T1.06: P0 — Default deny (commands NOT in allowlist -> RISKY)
# ---------------------------------------------------------------------------

@pytest.mark.p0
@pytest.mark.parametrize("command", [
    pytest.param("systemctl status nginx", id="T1.01"),
    pytest.param("apt-get install curl", id="T1.02"),
    pytest.param("python3 -c \"print('hello')\"", id="T1.03"),
    pytest.param("cat /etc/passwd", id="T1.04"),
    pytest.param("wget http://example.com/file", id="T1.05"),
    pytest.param("totally_made_up_command --foo", id="T1.06"),
])
def test_default_deny(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}' (not in allowlist), got {classification}"
    )
    assert tier == 1


# ---------------------------------------------------------------------------
# T1.10–T1.18: P1 — Network Discovery commands (SAFE)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("ping 8.8.8.8", id="T1.10"),
    pytest.param("ping -c 4 10.0.0.1", id="T1.11"),
    pytest.param("traceroute 8.8.8.8", id="T1.12"),
    pytest.param("dig google.com", id="T1.13"),
    pytest.param("dig @8.8.8.8 google.com MX", id="T1.14"),
    pytest.param("nslookup google.com", id="T1.15"),
    pytest.param("host google.com", id="T1.16"),
    pytest.param("whois google.com", id="T1.17"),
    pytest.param("mtr --report 8.8.8.8", id="T1.18"),
])
def test_network_discovery_safe(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_SAFE, (
        f"Expected SAFE for '{command}', got {classification}"
    )
    assert tier is None


# ---------------------------------------------------------------------------
# T1.20–T1.25: P1 — System State commands (SAFE)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("netstat -an", id="T1.20"),
    pytest.param("ss -tulnp", id="T1.21"),
    pytest.param("lsof -i", id="T1.22"),
    pytest.param("scutil --dns", id="T1.23"),
    pytest.param("scutil --proxy", id="T1.24"),
    pytest.param("scutil --nwi", id="T1.25"),
])
def test_system_state_safe(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_SAFE, (
        f"Expected SAFE for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T1.30–T1.40: P1 — Flag-sensitive commands (SAFE cases)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("ifconfig", id="T1.30"),
    pytest.param("ifconfig en0", id="T1.31"),
    pytest.param("ip addr show", id="T1.32"),
    pytest.param("ip route show", id="T1.33"),
    pytest.param("ip link show", id="T1.34"),
    pytest.param("ip neigh show", id="T1.35"),
    pytest.param("arp -a", id="T1.36"),
    pytest.param("arp -n", id="T1.37"),
    pytest.param("route get 8.8.8.8", id="T1.38"),
    pytest.param("networksetup -listallnetworkservices", id="T1.39"),
    pytest.param("networksetup -getinfo Wi-Fi", id="T1.40"),
])
def test_flag_sensitive_safe(command):
    classification, tier, _ = classify(command)
    assert classification == CLASSIFICATION_SAFE, (
        f"Expected SAFE for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T1.50–T1.65: P1 — Flag-sensitive commands (RISKY cases)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("ifconfig en0 up", id="T1.50"),
    pytest.param("ifconfig en0 down", id="T1.51"),
    pytest.param("ifconfig en0 mtu 9000", id="T1.52"),
    pytest.param("ifconfig en0 192.168.1.100", id="T1.53"),
    pytest.param("ip addr add 10.0.0.5/24 dev eth0", id="T1.54"),
    pytest.param("ip route del default", id="T1.55"),
    pytest.param("ip link set eth0 down", id="T1.56"),
    pytest.param("ip neigh flush all", id="T1.57"),
    pytest.param("arp -d 10.0.0.1", id="T1.58"),
    pytest.param("arp -s 10.0.0.1 aa:bb:cc:dd:ee:ff", id="T1.59"),
    pytest.param("route add default gw 10.0.0.1", id="T1.60"),
    pytest.param("route delete default", id="T1.61"),
    pytest.param("route flush", id="T1.62"),
    pytest.param("networksetup -setairportpower en0 on", id="T1.63"),
    pytest.param("networksetup -addpreferredwirelessnetwork en0 TestNet", id="T1.64"),
    pytest.param("networksetup -removenetworkservice TestVPN", id="T1.65"),
])
def test_flag_sensitive_risky(command):
    classification, _, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T1.70–T1.85: P1 — Data Analysis commands
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command,expected", [
    pytest.param("tshark -r capture.pcap", CLASSIFICATION_SAFE, id="T1.70"),
    pytest.param('tshark -r capture.pcap -Y "tcp.port == 443"', CLASSIFICATION_SAFE, id="T1.71"),
    pytest.param("tshark -i eth0", CLASSIFICATION_RISKY, id="T1.72"),
    pytest.param("tshark", CLASSIFICATION_RISKY, id="T1.73"),
    pytest.param("tcpdump -r capture.pcap", CLASSIFICATION_SAFE, id="T1.74"),
    pytest.param("tcpdump -i en0", CLASSIFICATION_RISKY, id="T1.75"),
    pytest.param("pcap_forensics.py --input capture.pcap --output report.json", CLASSIFICATION_SAFE, id="T1.76"),
    pytest.param("curl http://example.com", CLASSIFICATION_SAFE, id="T1.77"),
    pytest.param("curl -X GET http://example.com/api", CLASSIFICATION_SAFE, id="T1.78"),
    pytest.param("curl -X POST http://example.com/api", CLASSIFICATION_RISKY, id="T1.79"),
    pytest.param("curl -X PUT http://example.com/api", CLASSIFICATION_RISKY, id="T1.80"),
    pytest.param("curl -X DELETE http://example.com/api", CLASSIFICATION_RISKY, id="T1.81"),
    pytest.param("curl -X PATCH http://example.com/api", CLASSIFICATION_RISKY, id="T1.82"),
    pytest.param("curl -d '{\"key\":\"val\"}' http://example.com/api", CLASSIFICATION_RISKY, id="T1.83"),
    pytest.param("curl --data '{\"key\":\"val\"}' http://example.com/api", CLASSIFICATION_RISKY, id="T1.84"),
    pytest.param("curl --upload-file report.json http://example.com/upload", CLASSIFICATION_RISKY, id="T1.85"),
])
def test_data_analysis(command, expected):
    classification, _, _ = classify(command)
    assert classification == expected, (
        f"Expected {expected} for '{command}', got {classification}"
    )
