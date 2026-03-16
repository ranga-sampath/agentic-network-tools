"""
IPv6 tests — Module 2 (ip6tables parser support).

Fixtures used:
  ubuntu2404-clean-ip6.txt          empty ip6tables-save output (Azure VM, no IPv6 rules)
  ubuntu2404-docker-ip6.txt         Docker VM with icmp6 rule; ::1/128 in nat OUTPUT
  ubuntu2404-docker-ip6-counters.txt  same VM, ip6tables-save --counters
"""
from parser_helpers import load
from iptables_parser import parse_iptables_save


# ---------------------------------------------------------------------------
# AC-F09: Empty ip6tables-save output
# ---------------------------------------------------------------------------

def test_f09_ip6_empty_input():
    """Empty ip6tables-save (no IPv6 rules) → family ipv6, tables {}, no warnings."""
    d = load("ubuntu2404-clean-ip6.txt", family="ipv6")
    assert d["family"] == "ipv6"
    assert d["input_format"] == "ip6tables-save"
    assert d["tables"] == {}
    assert d["parse_warnings"] == []


# ---------------------------------------------------------------------------
# AC-F10: Docker IPv6 fixture — structure and family fields
# ---------------------------------------------------------------------------

def test_f10_ip6_docker_family_and_format():
    """ip6tables-save with Docker rules → family ipv6, input_format ip6tables-save."""
    d = load("ubuntu2404-docker-ip6.txt", family="ipv6")
    assert d["family"] == "ipv6"
    assert d["input_format"] == "ip6tables-save"


def test_f10_ip6_docker_tables_present():
    """Docker IPv6 fixture has filter and nat tables."""
    d = load("ubuntu2404-docker-ip6.txt", family="ipv6")
    assert set(d["tables"].keys()) == {"filter", "nat"}


def test_f10_ip6_docker_chains():
    """Docker IPv6 filter table has 3 built-in + 6 user-defined chains."""
    d = load("ubuntu2404-docker-ip6.txt", family="ipv6")
    chains = d["tables"]["filter"]["chains"]
    builtin = {n for n, c in chains.items() if c["type"] == "builtin"}
    user_defined = {n for n, c in chains.items() if c["type"] == "user-defined"}
    assert builtin == {"INPUT", "FORWARD", "OUTPUT"}
    assert user_defined == {"DOCKER", "DOCKER-BRIDGE", "DOCKER-CT", "DOCKER-FORWARD", "DOCKER-INTERNAL", "DOCKER-USER"}


def test_f10_ip6_docker_counters_format():
    """ip6tables-save --counters → input_format ip6tables-save-counters."""
    d = load("ubuntu2404-docker-ip6-counters.txt", family="ipv6")
    assert d["input_format"] == "ip6tables-save-counters"
    icmp_rule = d["tables"]["filter"]["chains"]["INPUT"]["rules"][0]
    assert icmp_rule["packet_count"] == 0
    assert icmp_rule["byte_count"] == 0


# ---------------------------------------------------------------------------
# AC-FA10: icmp6 match extension
# ---------------------------------------------------------------------------

def test_fa10_icmp6_module_parsed():
    """-m icmp6 --icmpv6-type 128 → match_extensions.icmp6.icmpv6_type: '128'."""
    d = load("ubuntu2404-docker-ip6.txt", family="ipv6")
    input_rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    assert len(input_rules) == 1
    rule = input_rules[0]
    assert rule["protocol"] == "ipv6-icmp"
    assert "icmp6" in rule["match_extensions"]
    assert rule["match_extensions"]["icmp6"]["icmpv6_type"] == "128"
    assert rule["match_extensions"]["icmp6"]["negated"] is False
    assert rule["target"] == "ACCEPT"
    assert rule["target_stops_chain_traversal"] is True


# ---------------------------------------------------------------------------
# AC-FA11: IPv6 address preserved verbatim
# ---------------------------------------------------------------------------

def test_fa11_ipv6_address_verbatim():
    """::1/128 is preserved exactly as destination; negation flag is set correctly."""
    d = load("ubuntu2404-docker-ip6.txt", family="ipv6")
    nat_output_rules = d["tables"]["nat"]["chains"]["OUTPUT"]["rules"]
    assert len(nat_output_rules) == 1
    rule = nat_output_rules[0]
    assert rule["destination"] == "::1/128"
    assert rule["destination_negated"] is True


# ---------------------------------------------------------------------------
# AC-EC10: REJECT default is icmp6-port-unreachable for family=ipv6
# ---------------------------------------------------------------------------

def test_ec10_reject_default_ipv6():
    """REJECT without --reject-with → reject_with: icmp6-port-unreachable for family=ipv6."""
    d = parse_iptables_save(
        "*filter\n:INPUT DROP [0:0]\n-A INPUT -j REJECT\nCOMMIT\n",
        family="ipv6",
    )
    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    assert rules[0]["target_params"]["reject_with"] == "icmp6-port-unreachable"


def test_ec09_reject_default_ipv4_unchanged():
    """REJECT default for family=ipv4 is still icmp-port-unreachable."""
    d = parse_iptables_save(
        "*filter\n:INPUT DROP [0:0]\n-A INPUT -j REJECT\nCOMMIT\n",
        family="ipv4",
    )
    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    assert rules[0]["target_params"]["reject_with"] == "icmp-port-unreachable"


# ---------------------------------------------------------------------------
# AC-NF06: family defaults to ipv4 — all existing callers unaffected
# ---------------------------------------------------------------------------

def test_nf06_default_family_is_ipv4():
    """parse_iptables_save with no family argument → family: ipv4."""
    d = parse_iptables_save("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    assert d["family"] == "ipv4"
    assert d["input_format"] == "iptables-save"
