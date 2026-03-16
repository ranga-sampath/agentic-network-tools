"""
AC-FA01 through AC-FA09: field accuracy criteria.

These tests verify cross-cutting schema guarantees that apply to all rules,
not just specific fixtures.
"""
import hashlib
import json

from parser_helpers import load, parse, SAMPLES_DIR


def test_fa01_protocol_verbatim():
    """AC-FA01: Protocol string preserved verbatim — no normalisation to numeric form."""
    d = load("ubuntu2404-cis-hardened.txt")
    rules = d["tables"]["filter"]["chains"]["INPUT"]["rules"]

    tcp_rule = next(r for r in rules if r["dst_port"] == "22")
    assert tcp_rule["protocol"] == "tcp"  # not "6"

    icmp_rule = next(r for r in rules if r["protocol"] == "icmp")
    assert icmp_rule["protocol"] == "icmp"  # not "1"

    # Rule with no -p flag → null
    lo_rule = rules[0]  # -A INPUT -i lo -j ACCEPT
    assert lo_rule["protocol"] is None


def test_fa02_cidr_verbatim():
    """AC-FA02: CIDR notation preserved verbatim — no expansion or normalisation."""
    d = load("ubuntu2404-log-mark-snat.txt")
    snat = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"][0]
    assert snat["source"] == "192.168.100.0/24"  # not 192.168.100.0/255.255.255.0

    d2 = load("ubuntu2404-clean.txt")
    for r in d2["tables"]["security"]["chains"]["OUTPUT"]["rules"]:
        assert r["destination"] == "168.63.129.16/32"  # /32 preserved

    d3 = load("ubuntu2404-docker.txt")
    raw_pre = d3["tables"]["raw"]["chains"]["PREROUTING"]["rules"]
    drop = next(r for r in raw_pre if r["target"] == "DROP")
    assert drop["destination"] == "172.17.0.2/32"


def test_fa03_ports_as_strings():
    """AC-FA03: Port values are strings, not integers."""
    d = load("ubuntu2404-cis-hardened.txt")
    ssh = next(
        r for r in d["tables"]["filter"]["chains"]["INPUT"]["rules"]
        if r["dst_port"] is not None
    )
    assert ssh["dst_port"] == "22"
    assert isinstance(ssh["dst_port"], str)

    d2 = load("ubuntu2404-docker-fail2ban.txt")
    jump = next(
        r for r in d2["tables"]["filter"]["chains"]["INPUT"]["rules"]
        if r["target"] == "f2b-sshd"
    )
    ports = jump["match_extensions"]["multiport"]["destination_ports"]
    assert ports == ["22"]
    assert isinstance(ports[0], str)  # not integer


def test_fa04_state_list_preserves_order():
    """AC-FA04: State/ctstate lists preserve source order — not alphabetically sorted."""
    # RELATED,ESTABLISHED → ["RELATED", "ESTABLISHED"]
    d = load("ubuntu2404-cis-hardened.txt")
    state_rule = next(
        r for r in d["tables"]["filter"]["chains"]["INPUT"]["rules"]
        if "state" in r["match_extensions"]
        and "RELATED" in r["match_extensions"]["state"]["states"]
    )
    assert state_rule["match_extensions"]["state"]["states"] == ["RELATED", "ESTABLISHED"]

    # INVALID,NEW from ubuntu2404-clean.txt
    d2 = load("ubuntu2404-clean.txt")
    ct_rule = d2["tables"]["security"]["chains"]["OUTPUT"]["rules"][2]
    assert ct_rule["match_extensions"]["conntrack"]["ctstates"] == ["INVALID", "NEW"]

    # RELATED,ESTABLISHED from docker DOCKER-CT
    d3 = load("ubuntu2404-docker.txt")
    ct_rule2 = next(
        r for r in d3["tables"]["filter"]["chains"]["DOCKER-CT"]["rules"]
        if r["target"] == "ACCEPT"
    )
    assert ct_rule2["match_extensions"]["conntrack"]["ctstates"] == ["RELATED", "ESTABLISHED"]


def test_fa05_negation_explicit_booleans():
    """AC-FA05: All _negated fields are explicit booleans on every rule — never absent."""
    d = load("ubuntu2404-docker.txt")

    # A rule with explicit negation
    raw_pre = d["tables"]["raw"]["chains"]["PREROUTING"]["rules"]
    drop = next(r for r in raw_pre if r["target"] == "DROP")
    assert drop["in_interface_negated"] is True

    # A rule where out_interface is set but not negated
    nat_post = d["tables"]["nat"]["chains"]["POSTROUTING"]["rules"]
    masq = next(r for r in nat_post if r["target"] == "MASQUERADE")
    assert masq["out_interface_negated"] is True   # ! -o docker0
    assert masq["source_negated"] is False         # not negated

    # Every rule across all chains must have all _negated fields as booleans
    negated_fields = (
        "source_negated", "destination_negated",
        "in_interface_negated", "out_interface_negated",
        "protocol_negated", "dst_port_negated", "src_port_negated",
    )
    for tdata in d["tables"].values():
        for cdata in tdata["chains"].values():
            for r in cdata["rules"]:
                for field in negated_fields:
                    assert field in r, f"Missing '{field}' on rule: {r['raw_rule']!r}"
                    assert isinstance(r[field], bool), (
                        f"'{field}' is not bool on rule: {r['raw_rule']!r}"
                    )


def test_fa06_target_stops_chain_traversal_values():
    """AC-FA06: target_stops_chain_traversal three-value contract."""
    d_fail2ban = load("ubuntu2404-docker-fail2ban.txt")
    d_log_mark = load("ubuntu2404-log-mark-snat.txt")
    d_docker = load("ubuntu2404-docker.txt")

    f = d_fail2ban["tables"]["filter"]["chains"]
    f_cis = load("ubuntu2404-cis-hardened.txt")["tables"]["filter"]["chains"]

    # ACCEPT → True (use CIS fixture; fail2ban INPUT has no lo rule)
    lo_rule = f_cis["INPUT"]["rules"][0]  # -A INPUT -i lo -j ACCEPT
    assert lo_rule["target"] == "ACCEPT"
    assert lo_rule["target_stops_chain_traversal"] is True

    # REJECT → True
    reject = next(r for r in f["f2b-sshd"]["rules"] if r["target"] == "REJECT")
    assert reject["target_stops_chain_traversal"] is True

    # RETURN → True (even in user-defined chain)
    ret = next(r for r in f["f2b-sshd"]["rules"] if r["target"] == "RETURN")
    assert ret["target_stops_chain_traversal"] is True

    # MASQUERADE → True
    masq = d_docker["tables"]["nat"]["chains"]["POSTROUTING"]["rules"][0]
    assert masq["target_stops_chain_traversal"] is True

    # DNAT → True
    dnat = next(
        r for r in d_docker["tables"]["nat"]["chains"]["DOCKER"]["rules"]
        if r["target"] == "DNAT"
    )
    assert dnat["target_stops_chain_traversal"] is True

    # SNAT → True
    snat = d_log_mark["tables"]["nat"]["chains"]["POSTROUTING"]["rules"][0]
    assert snat["target_stops_chain_traversal"] is True

    # LOG → False
    for r in d_log_mark["tables"]["filter"]["chains"]["INPUT"]["rules"]:
        if r["target"] == "LOG":
            assert r["target_stops_chain_traversal"] is False

    # MARK → False
    for r in d_log_mark["tables"]["mangle"]["chains"]["PREROUTING"]["rules"]:
        assert r["target_stops_chain_traversal"] is False

    # Jump to user-defined chain → "conditional"
    fwd = d_docker["tables"]["filter"]["chains"]["FORWARD"]["rules"]
    jumps = [r for r in fwd if r["target"] not in {"ACCEPT", "DROP", "REJECT", "RETURN"}]
    assert len(jumps) > 0
    for r in jumps:
        assert r["target_stops_chain_traversal"] == "conditional"


def test_fa07_empty_chains_always_have_rules_list():
    """AC-FA07: Empty chains always have rules: [] — key is never absent."""
    d = load("ubuntu2404-docker.txt")
    f = d["tables"]["filter"]["chains"]

    for empty in ("DOCKER-USER", "DOCKER-INTERNAL", "INPUT", "OUTPUT"):
        assert "rules" in f[empty], f"Chain {empty} missing 'rules' key"
        assert f[empty]["rules"] == []

    # User-defined empty chain also has type and null policy
    assert f["DOCKER-USER"]["type"] == "user-defined"
    assert f["DOCKER-USER"]["default_policy"] is None


def test_fa08_raw_rule_always_present():
    """AC-FA08: raw_rule is present on every rule, including counter-prefixed files."""
    for filename in (
        "ubuntu2404-clean.txt",
        "ubuntu2404-docker-counters.txt",
        "ubuntu2404-docker-fail2ban-wireguard.txt",
        "ubuntu2404-log-mark-snat.txt",
    ):
        d = load(filename)
        for tdata in d["tables"].values():
            for cdata in tdata["chains"].values():
                for r in cdata["rules"]:
                    assert "raw_rule" in r, f"Missing raw_rule in {filename}"
                    assert r["raw_rule"] != ""

    # Counter-format file: raw_rule includes the [pkts:bytes] prefix
    d = load("ubuntu2404-docker-counters.txt")
    for tdata in d["tables"].values():
        for cdata in tdata["chains"].values():
            for r in cdata["rules"]:
                assert r["raw_rule"].strip().startswith("["), (
                    f"Expected counter prefix in raw_rule: {r['raw_rule']!r}"
                )


def test_fa09_parsed_at_excluded_from_determinism():
    """AC-FA09: parsed_at varies between runs; all other fields are byte-identical."""
    text = (SAMPLES_DIR / "ubuntu2404-docker.txt").read_text(encoding="utf-8")

    runs = [parse(text) for _ in range(10)]

    for r in runs:
        assert isinstance(r["parsed_at"], str)
        assert "T" in r["parsed_at"]  # ISO-8601 format

    def hash_without_parsed_at(d: dict) -> str:
        d2 = dict(d)
        d2.pop("parsed_at")
        return hashlib.md5(json.dumps(d2, sort_keys=True).encode()).hexdigest()

    hashes = {hash_without_parsed_at(r) for r in runs}
    assert len(hashes) == 1, "Output is not deterministic (excluding parsed_at)"


def test_fa05_old_style_negation_syntax():
    """AC-FA05: Old-style negation '-s ! addr' → source_negated: True (same as modern '! -s addr')."""
    text = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s ! 192.168.1.0/24 -j DROP
COMMIT
"""
    d = parse(text)
    rule = d["tables"]["filter"]["chains"]["INPUT"]["rules"][0]
    assert rule["source"] == "192.168.1.0/24"
    assert rule["source_negated"] is True
    assert rule["target"] == "DROP"
