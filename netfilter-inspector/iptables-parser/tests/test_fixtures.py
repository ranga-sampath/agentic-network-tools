"""
AC-F01 through AC-F08: fixture-level criteria.

One test per fixture file. Each test asserts the specific field values documented
in the acceptance criteria for that fixture.
"""
from parser_helpers import load


def test_f01_azure_baseline():
    """AC-F01: ubuntu2404-clean.txt — security table only, no rule counters."""
    d = load("ubuntu2404-clean.txt")

    # Exactly one table: security; standard tables absent
    assert list(d["tables"].keys()) == ["security"]
    for absent in ("filter", "nat", "mangle", "raw"):
        assert absent not in d["tables"]

    t = d["tables"]["security"]
    assert set(t["chains"].keys()) == {"INPUT", "FORWARD", "OUTPUT"}

    # All three chains: ACCEPT policy, integer policy counters
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
        c = t["chains"][chain_name]
        assert c["default_policy"] == "ACCEPT"
        assert c["type"] == "builtin"
        assert isinstance(c["policy_packet_count"], int)
        assert isinstance(c["policy_byte_count"], int)

    # INPUT and FORWARD have no appended rules
    assert t["chains"]["INPUT"]["rules"] == []
    assert t["chains"]["FORWARD"]["rules"] == []

    # OUTPUT has exactly 3 rules
    rules = t["chains"]["OUTPUT"]["rules"]
    assert len(rules) == 3

    # All rules target 168.63.129.16/32 with no negation; no counters
    for r in rules:
        assert r["destination"] == "168.63.129.16/32"
        assert r["destination_negated"] is False
        assert r["packet_count"] is None
        assert r["byte_count"] is None
        assert r["raw_rule"] != ""

    r1, r2, r3 = rules
    assert r1["target"] == "ACCEPT"
    assert r1["protocol"] == "tcp"
    assert r1["dst_port"] == "53"
    assert r1["position"] == 1

    assert r2["target"] == "ACCEPT"
    assert r2["match_extensions"]["owner"]["uid_owner"] == "0"
    assert r2["position"] == 2

    assert r3["target"] == "DROP"
    assert r3["match_extensions"]["conntrack"]["ctstates"] == ["INVALID", "NEW"]
    assert r3["position"] == 3

    assert d["input_format"] == "iptables-save"
    import re
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", d["parsed_at"]), (
        f"parsed_at not ISO-8601: {d['parsed_at']!r}"
    )
    assert d["parse_warnings"] == []


def test_f02_azure_baseline_counters():
    """AC-F02: ubuntu2404-clean-counters.txt — same structure as F01, all rules have counters."""
    d = load("ubuntu2404-clean-counters.txt")

    assert list(d["tables"].keys()) == ["security"]
    t = d["tables"]["security"]
    assert set(t["chains"].keys()) == {"INPUT", "FORWARD", "OUTPUT"}

    # Chain policy counters present regardless of --counters flag (AC-F02 & AC-F01 both)
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
        c = t["chains"][chain_name]
        assert isinstance(c["policy_packet_count"], int)
        assert isinstance(c["policy_byte_count"], int)

    rules = t["chains"]["OUTPUT"]["rules"]
    assert len(rules) == 3

    for r in rules:
        assert isinstance(r["packet_count"], int) and r["packet_count"] >= 0
        assert isinstance(r["byte_count"], int) and r["byte_count"] >= 0

    # Match/target fields identical to F01
    assert rules[0]["target"] == "ACCEPT"
    assert rules[0]["dst_port"] == "53"
    assert rules[1]["match_extensions"]["owner"]["uid_owner"] == "0"
    assert rules[2]["target"] == "DROP"
    assert rules[2]["match_extensions"]["conntrack"]["ctstates"] == ["INVALID", "NEW"]

    assert d["input_format"] == "iptables-save-counters"
    assert d["parse_warnings"] == []


def test_f03_docker():
    """AC-F03: ubuntu2404-docker.txt — three tables, Docker v26 chain structure."""
    d = load("ubuntu2404-docker.txt")

    assert set(d["tables"].keys()) == {"raw", "filter", "nat"}

    f = d["tables"]["filter"]["chains"]
    assert set(f.keys()) == {
        "INPUT", "FORWARD", "OUTPUT",
        "DOCKER", "DOCKER-BRIDGE", "DOCKER-CT", "DOCKER-FORWARD",
        "DOCKER-INTERNAL", "DOCKER-USER",
    }

    assert f["DOCKER-USER"]["rules"] == []
    assert f["DOCKER-INTERNAL"]["rules"] == []
    assert f["FORWARD"]["default_policy"] == "DROP"
    assert f["INPUT"]["rules"] == []
    assert f["OUTPUT"]["rules"] == []

    # raw PREROUTING DROP with negated in_interface
    raw_pre = d["tables"]["raw"]["chains"]["PREROUTING"]["rules"]
    drop_rule = next(r for r in raw_pre if r["target"] == "DROP")
    assert drop_rule["in_interface"] == "docker0"
    assert drop_rule["in_interface_negated"] is True
    assert drop_rule["destination"] == "172.17.0.2/32"
    assert drop_rule["destination_negated"] is False
    assert drop_rule["target_stops_chain_traversal"] is True

    # filter DOCKER DROP: negated in_interface, non-negated out_interface
    docker_rules = f["DOCKER"]["rules"]
    docker_drop = next(r for r in docker_rules if r["target"] == "DROP")
    assert docker_drop["in_interface"] == "docker0"
    assert docker_drop["in_interface_negated"] is True
    assert docker_drop["out_interface"] == "docker0"
    assert docker_drop["out_interface_negated"] is False
    assert docker_drop["target_stops_chain_traversal"] is True

    # DOCKER-CT conntrack ACCEPT
    ct_rule = next(r for r in f["DOCKER-CT"]["rules"] if r["target"] == "ACCEPT")
    assert ct_rule["match_extensions"]["conntrack"]["ctstates"] == ["RELATED", "ESTABLISHED"]
    assert ct_rule["target_stops_chain_traversal"] is True

    # nat DOCKER DNAT
    nat_docker = d["tables"]["nat"]["chains"]["DOCKER"]["rules"]
    dnat = next(r for r in nat_docker if r["target"] == "DNAT")
    assert dnat["target_params"]["to_destination"] == "172.17.0.2:80"
    assert dnat["in_interface_negated"] is True
    assert dnat["dst_port"] == "8080"

    # nat POSTROUTING MASQUERADE — no to_ports → target_params is None
    nat_post = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"]
    masq = next(r for r in nat_post if r["target"] == "MASQUERADE")
    assert masq["source"] == "172.17.0.0/16"
    assert masq["out_interface"] == "docker0"
    assert masq["out_interface_negated"] is True
    assert masq["target_params"] is None

    # FORWARD rules jumping to user-defined chains are "conditional"
    fwd_jumps = [
        r for r in f["FORWARD"]["rules"]
        if r["target"] not in {"ACCEPT", "DROP", "REJECT", "RETURN"}
    ]
    assert len(fwd_jumps) > 0
    for r in fwd_jumps:
        assert r["target_stops_chain_traversal"] == "conditional"

    assert d["parse_warnings"] == []


def test_f04_docker_fail2ban():
    """AC-F04: ubuntu2404-docker-fail2ban.txt — fail2ban iptables backend, f2b-sshd chain."""
    d = load("ubuntu2404-docker-fail2ban.txt")

    f = d["tables"]["filter"]["chains"]
    assert "f2b-sshd" in f

    # INPUT jump to f2b-sshd via multiport
    input_rules = f["INPUT"]["rules"]
    jump = next(r for r in input_rules if r["target"] == "f2b-sshd")
    assert jump["target_stops_chain_traversal"] == "conditional"
    assert jump["dst_port"] is None  # multiport used, not --dport
    assert jump["match_extensions"]["multiport"]["destination_ports"] == ["22"]

    # f2b-sshd REJECT rule
    f2b_rules = f["f2b-sshd"]["rules"]
    reject = next(r for r in f2b_rules if r["target"] == "REJECT")
    assert reject["target_stops_chain_traversal"] is True
    assert reject["target_params"]["reject_with"] == "icmp-port-unreachable"

    # f2b-sshd RETURN rule — always True even in user-defined chain
    ret = next(r for r in f2b_rules if r["target"] == "RETURN")
    assert ret["target_stops_chain_traversal"] is True

    assert d["parse_warnings"] == []


def test_f05_docker_fail2ban_wireguard():
    """AC-F05: ubuntu2404-docker-fail2ban-wireguard.txt — dual MASQUERADE, WireGuard FORWARD rules."""
    d = load("ubuntu2404-docker-fail2ban-wireguard.txt")

    # Exactly 2 MASQUERADE rules in nat POSTROUTING
    post_rules = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"]
    masq_rules = [r for r in post_rules if r["target"] == "MASQUERADE"]
    assert len(masq_rules) == 2

    m1, m2 = masq_rules
    assert m1["source"] == "172.17.0.0/16"
    assert m1["out_interface"] == "docker0"
    assert m1["out_interface_negated"] is True

    assert m2["out_interface"] == "eth0"
    assert m2["out_interface_negated"] is False
    assert m2["source"] is None

    # WireGuard FORWARD rules
    fwd_rules = d["tables"]["filter"]["chains"]["FORWARD"]["rules"]

    wg_in = next(r for r in fwd_rules if r.get("in_interface") == "wg0")
    assert wg_in["in_interface_negated"] is False
    assert wg_in["target"] == "ACCEPT"

    wg_out = next(r for r in fwd_rules if r.get("out_interface") == "wg0")
    assert wg_out["out_interface_negated"] is False
    assert wg_out["target"] == "ACCEPT"

    assert d["parse_warnings"] == []


def test_f06_cis_hardened():
    """AC-F06: ubuntu2404-cis-hardened.txt — CIS benchmark, state module, icmp numeric type."""
    d = load("ubuntu2404-cis-hardened.txt")

    assert list(d["tables"].keys()) == ["filter"]
    f = d["tables"]["filter"]["chains"]

    assert f["INPUT"]["default_policy"] == "DROP"
    assert f["INPUT"]["type"] == "builtin"
    assert f["FORWARD"]["default_policy"] == "DROP"
    assert f["OUTPUT"]["default_policy"] == "ACCEPT"
    assert f["OUTPUT"]["type"] == "builtin"

    rules = f["INPUT"]["rules"]

    # state module — not conntrack
    state_rule = next(r for r in rules if "state" in r["match_extensions"])
    assert state_rule["match_extensions"]["state"]["states"] == ["RELATED", "ESTABLISHED"]
    assert "conntrack" not in state_rule["match_extensions"]
    assert state_rule["target"] == "ACCEPT"
    assert state_rule["target_stops_chain_traversal"] is True

    # icmp: icmp_type is numeric string, not normalised to "echo-request"
    icmp_rule = next(r for r in rules if r["protocol"] == "icmp")
    assert icmp_rule["match_extensions"]["icmp"]["icmp_type"] == "8"
    assert icmp_rule["target"] == "ACCEPT"

    # SSH rule: two modules on one rule object
    ssh_rule = next(r for r in rules if r["dst_port"] == "22")
    assert ssh_rule["dst_port"] == "22"
    assert ssh_rule["match_extensions"]["state"]["states"] == ["NEW"]

    assert d["parse_warnings"] == []


def test_f07_log_mark_snat():
    """AC-F07: ubuntu2404-log-mark-snat.txt — LOG with/without log_level, MARK set_xmark, SNAT."""
    d = load("ubuntu2404-log-mark-snat.txt")

    assert set(d["tables"].keys()) == {"mangle", "filter", "nat"}

    # MARK rules in mangle PREROUTING
    mangle_rules = d["tables"]["mangle"]["chains"]["PREROUTING"]["rules"]
    assert len(mangle_rules) == 2
    for rule, xmark_val in zip(mangle_rules, ["0x1", "0x2"]):
        assert rule["target"] == "MARK"
        assert rule["target_params"]["set_xmark_value"] == xmark_val
        assert rule["target_params"]["set_xmark_mask"] == "0xffffffff"
        assert rule["target_stops_chain_traversal"] is False

    filter_rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    log_rules = [r for r in filter_rules if r["target"] == "LOG"]
    assert len(log_rules) == 2  # duplicate rule is preserved

    # LOG with --log-level 6
    log_with_level = next(
        r for r in log_rules if "log_level" in (r["target_params"] or {})
    )
    assert log_with_level["target_params"]["log_prefix"] == "HTTP-ACCESS: "  # trailing space preserved
    assert log_with_level["target_params"]["log_level"] == "6"
    assert log_with_level["target_stops_chain_traversal"] is False

    # LOG without --log-level — key must be absent, not null
    log_no_level = next(
        r for r in log_rules if "log_level" not in (r["target_params"] or {})
    )
    assert log_no_level["target_params"]["log_prefix"] == "HTTP-ACCESS: "
    assert "log_level" not in log_no_level["target_params"]
    assert log_no_level["target_stops_chain_traversal"] is False

    # SNAT rule
    snat_rule = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"][0]
    assert snat_rule["target"] == "SNAT"
    assert snat_rule["target_params"]["to_source"] == "10.0.0.1"
    assert snat_rule["source"] == "192.168.100.0/24"
    assert snat_rule["source_negated"] is False
    assert snat_rule["out_interface"] == "eth0"
    assert snat_rule["out_interface_negated"] is False
    assert snat_rule["target_stops_chain_traversal"] is True

    assert d["parse_warnings"] == []


def test_f08_docker_counters():
    """AC-F08: ubuntu2404-docker-counters.txt — same as F03 with all rules having counters."""
    d = load("ubuntu2404-docker-counters.txt")

    assert d["input_format"] == "iptables-save-counters"

    for tdata in d["tables"].values():
        for cdata in tdata["chains"].values():
            for r in cdata["rules"]:
                assert isinstance(r["packet_count"], int) and r["packet_count"] >= 0
                assert isinstance(r["byte_count"], int) and r["byte_count"] >= 0

    # Filter chain structure identical to F03
    f = d["tables"]["filter"]["chains"]
    assert set(f.keys()) == {
        "INPUT", "FORWARD", "OUTPUT",
        "DOCKER", "DOCKER-BRIDGE", "DOCKER-CT", "DOCKER-FORWARD",
        "DOCKER-INTERNAL", "DOCKER-USER",
    }
    assert f["DOCKER-USER"]["rules"] == []
    assert f["FORWARD"]["default_policy"] == "DROP"

    # Spot-check key match/target fields identical to F03
    ct_rule = next(r for r in f["DOCKER-CT"]["rules"] if r["target"] == "ACCEPT")
    assert ct_rule["match_extensions"]["conntrack"]["ctstates"] == ["RELATED", "ESTABLISHED"]

    nat_docker = d["tables"]["nat"]["chains"]["DOCKER"]["rules"]
    dnat = next(r for r in nat_docker if r["target"] == "DNAT")
    assert dnat["target_params"]["to_destination"] == "172.17.0.2:80"
    assert dnat["dst_port"] == "8080"

    nat_post = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"]
    masq = next(r for r in nat_post if r["target"] == "MASQUERADE")
    assert masq["source"] == "172.17.0.0/16"
    assert masq["target_params"] is None

    assert d["parse_warnings"] == []
