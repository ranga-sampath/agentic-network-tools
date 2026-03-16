"""
AC-EC01 through AC-EC09: edge case criteria.

Most tests use synthetic inputs (short inline rule strings) so the
specific condition being tested is unambiguous.
"""
from parser_helpers import load, parse


def test_ec01_return_in_user_defined_chain():
    """AC-EC01: RETURN in a user-defined chain → target_stops_chain_traversal: True."""
    d = load("ubuntu2404-docker-fail2ban.txt")
    f2b_rules = d["tables"]["filter"]["chains"]["f2b-sshd"]["rules"]

    ret = next(r for r in f2b_rules if r["target"] == "RETURN")
    assert ret["target_stops_chain_traversal"] is True

    # Caller can distinguish context via chain type
    chain_type = d["tables"]["filter"]["chains"]["f2b-sshd"]["type"]
    assert chain_type == "user-defined"


def test_ec02_multiple_modules_one_rule():
    """AC-EC02: Multiple -m extensions on one rule → single rule object with all fields."""
    d = load("ubuntu2404-cis-hardened.txt")
    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]

    # -p tcp -m tcp --dport 22 -m state --state NEW uses two modules
    ssh = next(r for r in rules if r["dst_port"] == "22")
    assert ssh["dst_port"] == "22"
    assert ssh["match_extensions"]["state"]["states"] == ["NEW"]
    # Both fields present on the same rule object — rule was not split
    assert ssh["protocol"] == "tcp"


def test_ec03_set_xmark_with_mask():
    """AC-EC03: --set-xmark value/mask → two separate string fields in target_params."""
    d = load("ubuntu2404-log-mark-snat.txt")
    mangle_rules = d["tables"]["mangle"]["chains"]["PREROUTING"]["rules"]

    r1, r2 = mangle_rules
    assert r1["target_params"]["set_xmark_value"] == "0x1"
    assert r1["target_params"]["set_xmark_mask"] == "0xffffffff"
    assert r2["target_params"]["set_xmark_value"] == "0x2"
    assert r2["target_params"]["set_xmark_mask"] == "0xffffffff"

    # Hex strings verbatim — not converted to integers
    assert isinstance(r1["target_params"]["set_xmark_value"], str)
    assert isinstance(r1["target_params"]["set_xmark_mask"], str)


def test_ec04_optional_target_params_absent_when_not_specified():
    """AC-EC04: Optional target parameters are absent (not null) when not in source rule."""
    d = load("ubuntu2404-log-mark-snat.txt")
    filter_rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]
    log_rules = [r for r in filter_rules if r["target"] == "LOG"]

    # LOG without --log-level → key absent entirely
    log_no_level = next(
        r for r in log_rules if "log_level" not in (r["target_params"] or {})
    )
    assert "log_level" not in log_no_level["target_params"]
    # log_prefix is still present (it was specified)
    assert "log_prefix" in log_no_level["target_params"]

    # MASQUERADE without --to-ports → target_params is None
    d2 = load("ubuntu2404-docker.txt")
    masq = d2["tables"]["nat"]["chains"]["POSTROUTING"]["rules"][0]
    assert masq["target"] == "MASQUERADE"
    assert masq["target_params"] is None


def test_ec05_icmp_type_as_numeric_string():
    """AC-EC05: --icmp-type 8 → icmp_type: '8' — not normalised to 'echo-request'."""
    d = load("ubuntu2404-cis-hardened.txt")
    icmp_rule = next(
        r for r in d["tables"]["filter"]["chains"]["INPUT"]["rules"]
        if r["protocol"] == "icmp"
    )
    assert icmp_rule["match_extensions"]["icmp"]["icmp_type"] == "8"
    assert icmp_rule["match_extensions"]["icmp"]["icmp_type"] != "echo-request"


def test_ec06_duplicate_rules_preserved():
    """AC-EC06: Two identical rule lines → two separate rule objects; no deduplication."""
    d = load("ubuntu2404-log-mark-snat.txt")
    filter_rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]

    log_rules = [r for r in filter_rules if r["target"] == "LOG"]
    assert len(log_rules) == 2

    # The two LOG rules must have exactly one rule between them (the ACCEPT that follows each)
    positions = sorted(r["position"] for r in log_rules)
    assert positions[1] == positions[0] + 2, (
        f"Expected exactly one rule between duplicate LOG rules, got positions: {positions}"
    )
    mid_rule = next(r for r in filter_rules if r["position"] == positions[0] + 1)
    assert mid_rule["target"] == "ACCEPT"


def test_ec07_chain_position_is_one_based():
    """AC-EC07: First rule in a chain has position 1; increments by 1."""
    d = load("ubuntu2404-docker-fail2ban.txt")

    for tname, tdata in d["tables"].items():
        for cname, cdata in tdata["chains"].items():
            rules = cdata["rules"]
            if not rules:
                continue
            assert rules[0]["position"] == 1, (
                f"{tname}/{cname}: first rule position is {rules[0]['position']}, expected 1"
            )
            for j in range(1, len(rules)):
                assert rules[j]["position"] == rules[j - 1]["position"] + 1, (
                    f"{tname}/{cname}: position gap between rules {j - 1} and {j}"
                )


def test_ec08_all_empty_input():
    """AC-EC08: Input with only comments and whitespace → empty tables, empty diagnostics."""
    text = "# Generated by iptables-save\n# comment\n  \n\n"
    d = parse(text)

    assert d["tables"] == {}
    assert d["parse_warnings"] == []
    assert d["input_format"] == "iptables-save"

    diag = d["diagnostics"]
    assert diag["drop_policy_chains"] == []
    assert diag["accept_policy_chains"] == []
    assert diag["conntrack_position_warnings"] == []
    assert diag["active_drop_rules"] == []
    assert diag["nat_summary"]["masquerade_rules"] == []
    assert diag["nat_summary"]["dnat_rules"] == []
    assert diag["nat_summary"]["snat_rules"] == []
    assert diag["user_defined_chains"] == {}
    assert diag["unresolved_chain_references"] == []


def test_ec09_reject_without_reject_with_defaults_to_icmp_port_unreachable():
    """AC-EC09: -j REJECT without --reject-with → target_params.reject_with: 'icmp-port-unreachable'."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j REJECT
COMMIT
"""
    d = parse(text)
    reject_rule = d["tables"]["filter"]["chains"]["INPUT"]["rules"][0]
    assert reject_rule["target"] == "REJECT"
    assert reject_rule["target_params"]["reject_with"] == "icmp-port-unreachable"
    # Field must be explicit — not absent
    assert "reject_with" in reject_rule["target_params"]
