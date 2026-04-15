"""
test_adversarial.py — Adversarial tests for security-rule-inspector

These tests exercise failure modes that produce incorrect verdicts without
obvious errors. All are tagged DANGER in the test plan.

Covers:
  T-ADV-01 through T-ADV-14
"""

import pytest

import nsg_engine
import nsg_preprocessor
from nsg_engine import (
    TrafficTuple,
    _match_rule,
    evaluate_verdict,
)
from conftest import fixture_path


# ---------------------------------------------------------------------------
# Helpers (duplicated from test_nsg_engine for module isolation)
# ---------------------------------------------------------------------------

def _load(fixture_name: str) -> dict:
    return nsg_preprocessor.preprocess(fixture_path(fixture_name))


def _make_rule(
    name: str = "test-rule",
    priority: int = 100,
    direction: str = "Inbound",
    access: str = "Allow",
    protocol: str = "*",
    source_address: str = "*",
    destination_address: str = "*",
    destination_ports: list = None,
    is_default: bool = False,
    shadowed_by: str = None,
) -> dict:
    return {
        "name": name,
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "source_address": source_address,
        "source_ports": ["*"],
        "destination_address": destination_address,
        "destination_ports": destination_ports if destination_ports is not None else ["*"],
        "is_default": is_default,
        "shadowed_by": shadowed_by,
    }


def _make_rule_sets(
    subnet_inbound: list = None,
    subnet_outbound: list = None,
    nic_inbound: list = None,
    nic_outbound: list = None,
    parse_warnings: list = None,
) -> dict:
    gates = []
    if subnet_inbound is not None or subnet_outbound is not None:
        gates.append({
            "gate": "subnet-nsg",
            "nsg_name": "test-subnet-nsg",
            "nsg_id": "",
            "association_type": "subnet",
            "association_id": "",
            "inbound_rules": subnet_inbound or [],
            "outbound_rules": subnet_outbound or [],
        })
    if nic_inbound is not None or nic_outbound is not None:
        gates.append({
            "gate": "nic-nsg",
            "nsg_name": "test-nic-nsg",
            "nsg_id": "",
            "association_type": "networkInterface",
            "association_id": "",
            "inbound_rules": nic_inbound or [],
            "outbound_rules": nic_outbound or [],
        })
    return {
        "gate_count": len(gates),
        "gates": gates,
        "parse_warnings": parse_warnings or [],
    }


# ---------------------------------------------------------------------------
# T-ADV-01 — Outbound gate reversal produces silent wrong verdict
# ---------------------------------------------------------------------------

def test_adv_01_outbound_gate_reversal_nic_denies_first():
    """T-ADV-01: Outbound — NIC denies at Gate 1; subnet allow never reached (fx-05) [DANGER, GATE-ORDER]"""
    rule_sets = _load("fx-05-outbound-nic-first.json")
    traffic = TrafficTuple(
        src_ip="10.0.1.10",
        dst_ip="10.0.3.5",
        dst_port=22,
        protocol="Tcp",
        direction="Outbound",
    )
    result = evaluate_verdict(rule_sets, traffic)

    assert result["final_verdict"] == "DENY"
    assert result["gate1"]["gate"] == "nic"
    assert result["gate2"]["evaluated"] is False
    # Guard: if this returns ALLOW, the gate order is reversed (subnet evaluated first)
    assert result["final_verdict"] != "ALLOW"


# ---------------------------------------------------------------------------
# T-ADV-02 — Shadowed allow rule cited as decisive rule
# ---------------------------------------------------------------------------

def test_adv_02_shadowed_allow_never_cited_as_decisive():
    """T-ADV-02: deny-all-custom (p=100) must be decisive; allow-https-inbound (p=200) never is [DANGER, SHADOW]"""
    rule_sets = _load("fx-04-shadowed-allow-rule.json")
    traffic = TrafficTuple(
        src_ip="1.2.3.4",
        dst_ip="10.0.1.5",
        dst_port=443,
        protocol="Tcp",
        direction="Inbound",
    )
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate1"]["decisive_rule"]["name"] == "deny-all-custom"

    # allow-https-inbound must appear only in shadowed_rules, never as decisive
    decisive_name = (result["gate1"]["decisive_rule"] or {}).get("name")
    assert decisive_name != "allow-https-inbound"


# ---------------------------------------------------------------------------
# T-ADV-03 — "All" protocol passes through as match for Tcp traffic
# ---------------------------------------------------------------------------

def test_adv_03_protocol_all_matches_tcp():
    """T-ADV-03: Protocol 'All' matches Tcp/22 [DANGER, MATCH]"""
    rule = _make_rule(protocol="All", destination_ports=["22"])
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 22, "Tcp", "Inbound")
    assert _match_rule(rule, traffic) is True


# ---------------------------------------------------------------------------
# T-ADV-04 — "0-65535" treated as port wildcard
# ---------------------------------------------------------------------------

def test_adv_04_port_0_65535_treated_same_as_wildcard():
    """T-ADV-04: '0-65535' and '*' both match port 443 [DANGER, MATCH]"""
    rule_range = _make_rule(destination_ports=["0-65535"])
    rule_star = _make_rule(destination_ports=["*"])
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 443, "Tcp", "Inbound")

    assert _match_rule(rule_range, traffic) is True
    assert _match_rule(rule_star, traffic) is True


# ---------------------------------------------------------------------------
# T-ADV-05 — INDETERMINATE propagation: Gate 2 NOT evaluated despite Gate 1 INDETERMINATE
# ---------------------------------------------------------------------------

def test_adv_05_gate2_not_evaluated_when_gate1_indeterminate():
    """T-ADV-05: Gate 1 INDETERMINATE → Gate 2 NOT evaluated; verdict is INDETERMINATE not DENY [DANGER, INDETERMINATE]"""
    # Gate 1 (subnet inbound): single rule with unresolvable service tag
    # Gate 2 (NIC inbound): clear DENY rule that would trigger if Gate 2 were evaluated
    rule_sets = _make_rule_sets(
        subnet_inbound=[
            _make_rule(
                name="rule-with-storage-src",
                priority=100,
                access="Allow",
                source_address="Storage",  # unresolvable → INDETERMINATE
                destination_ports=["*"],
            )
        ],
        nic_inbound=[
            _make_rule(
                name="deny-all-nic",
                priority=100,
                access="Deny",
                source_address="*",
                destination_ports=["*"],
            )
        ],
    )
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate2"]["evaluated"] is False
    assert result["gate2"]["skip_reason"] == "PRIOR_GATE_INDETERMINATE"
    # MUST be INDETERMINATE — not DENY
    assert result["final_verdict"] == "INDETERMINATE"


# ---------------------------------------------------------------------------
# T-ADV-06 — INDETERMINATE at Gate 2 not lost when Gate 1 ALLOWs
# ---------------------------------------------------------------------------

def test_adv_06_indeterminate_at_gate2_propagates_to_final():
    """T-ADV-06: Gate 1 ALLOW, Gate 2 INDETERMINATE → final_verdict INDETERMINATE [INDETERMINATE]"""
    rule_sets = _make_rule_sets(
        subnet_inbound=[
            _make_rule(
                name="allow-all-subnet",
                priority=100,
                access="Allow",
                protocol="*",
                source_address="*",
                destination_address="*",
                destination_ports=["*"],
            )
        ],
        nic_inbound=[
            _make_rule(
                name="rule-with-storage-dst",
                priority=100,
                access="Deny",
                source_address="*",
                destination_address="Storage",  # unresolvable destination
                destination_ports=["*"],
            )
        ],
    )
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate1"]["verdict"] == "ALLOW"
    assert result["gate2"]["verdict"] == "INDETERMINATE"
    assert result["final_verdict"] == "INDETERMINATE"


# ---------------------------------------------------------------------------
# T-ADV-07 — Subnet deny blocks; NIC allow is irrelevant (fx-02)
# ---------------------------------------------------------------------------

def test_adv_07_subnet_deny_at_p100_blocks_nic_allow_at_p1000():
    """T-ADV-07: Subnet deny (p=100) blocks port 5432; NIC allow (p=1000) never reached (fx-02) [GATE-ORDER, DANGER]"""
    rule_sets = _load("fx-02-subnet-deny-overrides-nic-allow.json")
    traffic = TrafficTuple(
        src_ip="10.0.1.5",
        dst_ip="10.0.2.10",
        dst_port=5432,
        protocol="Tcp",
        direction="Inbound",
    )
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate1"]["gate"] == "subnet"
    assert result["gate1"]["verdict"] == "DENY"
    assert result["gate1"]["decisive_rule"]["name"] == "ghost-demo-subnet-block-5432"
    assert result["gate2"]["evaluated"] is False

    # The NIC's allow-postgres must NEVER appear as decisive
    if result["gate2"].get("decisive_rule"):
        assert result["gate2"]["decisive_rule"]["name"] != "allow-postgres"


# ---------------------------------------------------------------------------
# T-ADV-08 — Port range off-by-one at boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port,expected", [
    (8079, False),   # just below lower bound
    (8091, False),   # just above upper bound
    (8080, True),    # lower bound
    (8090, True),    # upper bound
])
def test_adv_08_port_range_off_by_one(port, expected):
    """T-ADV-08: Port range 8080-8090 boundary values [DANGER, MATCH]"""
    rule = _make_rule(
        protocol="Tcp",
        source_address="*",
        destination_ports=["8080-8090"],
    )
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", port, "Tcp", "Inbound")
    result = _match_rule(rule, traffic)
    assert bool(result) == expected


# ---------------------------------------------------------------------------
# T-ADV-09 — Service tag in destination address INDETERMINATE (fx-07)
# ---------------------------------------------------------------------------

def test_adv_09_service_tag_in_destination_returns_none(tmp_path):
    """T-ADV-09: Storage destination tag → _match_rule returns None; unresolvable in verdict (fx-07) [INDETERMINATE, DANGER]"""
    rule = _make_rule(
        name="allow-storage-outbound",
        priority=110,
        direction="Outbound",
        access="Allow",
        protocol="Tcp",
        source_address="*",
        destination_address="Storage",  # unresolvable
        destination_ports=["443"],
    )
    # Directly check _match_rule returns None for Storage destination
    traffic = TrafficTuple("10.0.0.1", "52.96.0.0", 443, "Tcp", "Outbound")
    assert _match_rule(rule, traffic) is None

    # Verify the rule appears in unresolvable_rules in a verdict
    rule_sets = _make_rule_sets(
        nic_outbound=[rule],
    )
    result = evaluate_verdict(rule_sets, traffic)
    unresolvable_names = [ur["name"] for ur in result.get("unresolvable_rules") or []]
    assert "allow-storage-outbound" in unresolvable_names


# ---------------------------------------------------------------------------
# T-ADV-10 — Gate absent — treat as empty, not error
# ---------------------------------------------------------------------------

def test_adv_10_absent_gate_treated_as_empty_allow(tmp_path):
    """T-ADV-10: No NIC NSG → Gate 2 evaluated as empty (ALLOW, decisive_rule=None), no crash (fx-06) [GATE-ORDER]"""
    rule_sets = _load("fx-06-no-nic-nsg.json")
    traffic = TrafficTuple(
        src_ip="10.0.1.10",
        dst_ip="10.0.1.5",
        dst_port=80,
        protocol="Tcp",
        direction="Inbound",
    )
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate2"]["evaluated"] is True
    assert result["gate2"]["verdict"] == "ALLOW"
    assert result["gate2"]["decisive_rule"] is None


# ---------------------------------------------------------------------------
# T-ADV-11 — Gate ordering from preprocessor output order is ignored
# ---------------------------------------------------------------------------

def test_adv_11_gate_ordering_from_preprocessor_ignored_for_inbound():
    """T-ADV-11: NIC entry listed BEFORE subnet in raw data — subnet still Gate 1 for inbound [GATE-ORDER, DANGER]"""
    # Build a rule_sets where NIC gate appears first in the gates list
    rule_sets = {
        "gate_count": 2,
        "gates": [
            {
                "gate": "nic-nsg",
                "nsg_name": "test-nic-nsg",
                "nsg_id": "",
                "association_type": "networkInterface",  # NIC listed first
                "association_id": "",
                "inbound_rules": [
                    _make_rule(name="nic-allow-all", priority=100, access="Allow"),
                ],
                "outbound_rules": [],
            },
            {
                "gate": "subnet-nsg",
                "nsg_name": "test-subnet-nsg",
                "nsg_id": "",
                "association_type": "subnet",  # subnet listed second
                "association_id": "",
                "inbound_rules": [
                    _make_rule(name="subnet-deny-all", priority=100, access="Deny"),
                ],
                "outbound_rules": [],
            },
        ],
        "parse_warnings": [],
    }
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 80, "Tcp", "Inbound")
    result = evaluate_verdict(rule_sets, traffic)

    # Inbound: subnet must be Gate 1 regardless of list order
    assert result["gate1"]["gate"] == "subnet"
    # Subnet denies → final verdict is DENY (not ALLOW from NIC)
    assert result["final_verdict"] == "DENY"


# ---------------------------------------------------------------------------
# T-ADV-12 — _check_collision uses correct glob without double prefix
# ---------------------------------------------------------------------------

def test_adv_12_check_collision_correct_glob_no_double_prefix(tmp_path):
    """T-ADV-12: Collision glob matches correct session ID, not double-prefix variant [CLI]"""
    from security_rule_inspector import _check_collision

    session_id = "nsg_20260413_100000"

    # Correct file: should trigger collision
    (tmp_path / f"{session_id}_raw.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        _check_collision(session_id, tmp_path)
    assert exc_info.value.code == 2

    # Reset: remove correct file, add double-prefix file
    (tmp_path / f"{session_id}_raw.json").unlink()
    (tmp_path / f"nsg_{session_id}_raw.json").write_text("{}", encoding="utf-8")
    # Double-prefix file is NOT a collision for this session_id
    _check_collision(session_id, tmp_path)  # must not raise


# ---------------------------------------------------------------------------
# T-ADV-13 — Priority tiebreak: two rules at same priority, deterministic result
# ---------------------------------------------------------------------------

def test_adv_13_priority_tiebreak_deterministic_no_crash():
    """T-ADV-13: Two rules at same priority — deterministic selection, no crash [MATCH]"""
    rule_a = _make_rule(name="rule-allow", priority=100, access="Allow", destination_ports=["443"])
    rule_b = _make_rule(name="rule-deny",  priority=100, access="Deny",  destination_ports=["443"])

    rule_sets = _make_rule_sets(subnet_inbound=[rule_a, rule_b])
    traffic = TrafficTuple("10.0.0.1", "10.0.0.2", 443, "Tcp", "Inbound")

    result1 = evaluate_verdict(rule_sets, traffic)
    result2 = evaluate_verdict(rule_sets, traffic)

    # No crash; decisive rule chosen
    assert result1["final_verdict"] in ("ALLOW", "DENY")
    # Deterministic across repeated calls
    assert result1["final_verdict"] == result2["final_verdict"]
    decisive1 = (result1["gate1"]["decisive_rule"] or {}).get("name")
    decisive2 = (result2["gate1"]["decisive_rule"] or {}).get("name")
    assert decisive1 == decisive2


# ---------------------------------------------------------------------------
# T-ADV-14 — AzureLoadBalancer source rule INDETERMINATE (fx-10)
# ---------------------------------------------------------------------------

def test_adv_14_azure_load_balancer_tag_unresolvable(tmp_path):
    """T-ADV-14: AzureLoadBalancer source tag → _match_rule None → gate INDETERMINATE (fx-10) [MATCH, INDETERMINATE]"""
    # Direct _match_rule check for AzureLoadBalancer source
    rule = _make_rule(
        name="allow-https-from-lb",
        priority=100,
        access="Allow",
        protocol="Tcp",
        source_address="AzureLoadBalancer",  # unexpanded service tag
        destination_ports=["443"],
    )
    traffic = TrafficTuple("10.0.5.10", "10.0.2.15", 443, "Tcp", "Inbound")

    # _match_rule must return None (UNRESOLVABLE)
    assert _match_rule(rule, traffic) is None

    # Engine must halt at this rule and return INDETERMINATE for the gate
    rule_sets = _make_rule_sets(subnet_inbound=[rule])
    result = evaluate_verdict(rule_sets, traffic)

    assert result["gate1"]["verdict"] == "INDETERMINATE"
    assert result["final_verdict"] == "INDETERMINATE"
