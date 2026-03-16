"""
AC-DI01 through AC-DI05: diagnostics criteria.

Verifies the diagnostics pass that runs after rule parsing: drop policy chains,
NAT summary, user-defined chain references, conntrack position warnings, and
the guarantee that all diagnostics sub-keys are always present.
"""
from parser_helpers import load, parse


def test_di01_drop_policy_chains():
    """AC-DI01: drop_policy_chains contains filter/INPUT and filter/FORWARD for CIS fixture."""
    d = load("ubuntu2404-cis-hardened.txt")
    drop_chains = d["diagnostics"]["drop_policy_chains"]

    assert "filter/INPUT" in drop_chains
    assert "filter/FORWARD" in drop_chains
    assert "filter/OUTPUT" not in drop_chains  # OUTPUT policy is ACCEPT
    assert len(drop_chains) == 2, f"Expected exactly 2 drop-policy chains, got: {drop_chains}"

    # Docker fixture: only FORWARD has DROP policy
    d2 = load("ubuntu2404-docker.txt")
    drop_chains2 = d2["diagnostics"]["drop_policy_chains"]
    assert "filter/FORWARD" in drop_chains2
    assert "filter/INPUT" not in drop_chains2
    assert "filter/OUTPUT" not in drop_chains2


def test_di02_nat_summary_from_nat_table():
    """AC-DI02: nat_summary populated with full rule records for each NAT target type."""
    d = load("ubuntu2404-docker.txt")
    nat = d["diagnostics"]["nat_summary"]

    # One MASQUERADE rule — must be a full rule record
    assert len(nat["masquerade_rules"]) == 1
    masq = nat["masquerade_rules"][0]
    assert masq["target"] == "MASQUERADE"
    assert masq["source"] == "172.17.0.0/16"
    assert masq["table"] == "nat"
    assert masq["chain"] == "POSTROUTING"
    assert masq["position"] >= 1
    assert "raw_rule" in masq and masq["raw_rule"] != ""

    # One DNAT rule — must be a full rule record
    assert len(nat["dnat_rules"]) == 1
    dnat = nat["dnat_rules"][0]
    assert dnat["target"] == "DNAT"
    assert dnat["target_params"]["to_destination"] == "172.17.0.2:80"
    assert dnat["table"] == "nat"
    assert dnat["chain"] == "DOCKER"
    assert "raw_rule" in dnat and dnat["raw_rule"] != ""

    # No SNAT in this fixture
    assert nat["snat_rules"] == []

    # SNAT fixture
    d2 = load("ubuntu2404-log-mark-snat.txt")
    nat2 = d2["diagnostics"]["nat_summary"]
    assert len(nat2["snat_rules"]) == 1
    assert nat2["snat_rules"][0]["target_params"]["to_source"] == "10.0.0.1"

    # Dual MASQUERADE in wireguard fixture
    d3 = load("ubuntu2404-docker-fail2ban-wireguard.txt")
    assert len(d3["diagnostics"]["nat_summary"]["masquerade_rules"]) == 2


def test_di03_user_defined_chains_referenced_from():
    """AC-DI03: user_defined_chains entry includes referenced_from with table/chain/position."""
    d = load("ubuntu2404-docker-fail2ban.txt")
    udc = d["diagnostics"]["user_defined_chains"]

    assert "f2b-sshd" in udc
    refs = udc["f2b-sshd"]["referenced_from"]
    assert len(refs) == 1, f"Expected exactly 1 reference to f2b-sshd, got {len(refs)}"

    ref = refs[0]
    assert ref["table"] == "filter"
    assert ref["chain"] == "INPUT"
    assert isinstance(ref["position"], int) and ref["position"] >= 1


def test_di04_conntrack_position_warnings():
    """AC-DI04: Drop/Reject at lower position than ESTABLISHED conntrack rule → warning."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
    d = parse(text)
    warnings = d["diagnostics"]["conntrack_position_warnings"]
    assert len(warnings) == 1

    w = warnings[0]
    assert w["table"] == "filter"
    assert w["chain"] == "INPUT"
    assert w["conntrack_rule_position"] == 2
    assert len(w["preceding_drop_rules"]) == 1
    assert w["preceding_drop_rules"][0]["position"] == 1

    # Normal ordering (DROP after ESTABLISHED) → no warning
    text_ok = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 80 -j DROP
COMMIT
"""
    d_ok = parse(text_ok)
    assert d_ok["diagnostics"]["conntrack_position_warnings"] == []


def test_di05_diagnostics_always_fully_present():
    """AC-DI05: All diagnostics sub-keys always present, even when all are empty."""
    required_keys = (
        "drop_policy_chains",
        "accept_policy_chains",
        "conntrack_position_warnings",
        "active_drop_rules",
        "nat_summary",
        "user_defined_chains",
        "unresolved_chain_references",
    )
    required_nat_keys = ("masquerade_rules", "dnat_rules", "snat_rules")

    # Test against empty input
    d_empty = parse("# comment only\n")
    diag = d_empty["diagnostics"]
    for key in required_keys:
        assert key in diag, f"diagnostics missing key: {key}"
    for key in required_nat_keys:
        assert key in diag["nat_summary"], f"nat_summary missing key: {key}"

    # Test against CIS fixture (no NAT, no user-defined chains)
    d_cis = load("ubuntu2404-cis-hardened.txt")
    diag2 = d_cis["diagnostics"]
    for key in required_keys:
        assert key in diag2, f"diagnostics missing key: {key} in cis fixture"
    for key in required_nat_keys:
        assert key in diag2["nat_summary"]
    # Sub-arrays are empty, not absent
    assert diag2["nat_summary"]["masquerade_rules"] == []
    assert diag2["user_defined_chains"] == {}
    assert diag2["unresolved_chain_references"] == []


def test_di04_conntrack_warning_in_forward_chain():
    """AC-DI04: Warning also fires for filter/FORWARD, not only INPUT."""
    text = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i eth1 -j DROP
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
COMMIT
"""
    d = parse(text)
    warnings = d["diagnostics"]["conntrack_position_warnings"]
    assert len(warnings) == 1
    w = warnings[0]
    assert w["chain"] == "FORWARD"
    assert w["conntrack_rule_position"] == 2
    assert w["preceding_drop_rules"][0]["position"] == 1


def test_di04_conntrack_warning_triggered_by_reject():
    """AC-DI04: REJECT before ESTABLISHED rule also triggers the warning, not only DROP."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j REJECT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
COMMIT
"""
    d = parse(text)
    warnings = d["diagnostics"]["conntrack_position_warnings"]
    assert len(warnings) == 1
    assert warnings[0]["preceding_drop_rules"][0]["position"] == 1


def test_di04_conntrack_warning_not_triggered_for_output_chain():
    """AC-DI04: Warning must NOT fire for filter/OUTPUT — only INPUT and FORWARD are monitored."""
    text = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport 80 -j DROP
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
COMMIT
"""
    d = parse(text)
    assert d["diagnostics"]["conntrack_position_warnings"] == []
