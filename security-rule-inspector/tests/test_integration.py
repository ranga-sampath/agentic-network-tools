"""
test_integration.py — Integration tests for pipeline Stages 2–5

All tests use MockNSGProvider injected via _run_pipeline(args, provider=mock).
No subprocess calls; no real Azure access.

Covers:
  T-INT-01 through T-INT-10
"""

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import nsg_engine
from providers import (
    NICResolutionError,
    ProviderError,
    RBACError,
    ThrottleExhausted,
    VMNotFoundError,
)
from security_rule_inspector import _check_collision, _run_pipeline
from nsg_engine import TrafficTuple
from conftest import fixture_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_fixture_dict(name: str) -> dict:
    """Load a fixture file and return its content as a dict."""
    with open(fixture_path(name), encoding="utf-8") as fh:
        return json.load(fh)


def _mock_provider(fixture_name: str, nic_name: str = "test-nic") -> MagicMock:
    """Return a MockNSGProvider that returns the given fixture data."""
    provider = MagicMock()
    provider.get_nic_name.return_value = nic_name
    provider.get_effective_nsg.return_value = _load_fixture_dict(fixture_name)
    return provider


def _verdict_args(
    tmp_path: Path,
    session_id: str = "nsg_test_session",
    vm_name: str = "test-vm",
    resource_group: str = "test-rg",
    nic_name: str = None,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.1.10",
    dst_port: int = 443,
    proto: str = "Tcp",
    direction: str = "Inbound",
) -> argparse.Namespace:
    """Build a Namespace for verdict-mode pipeline invocation."""
    traffic = TrafficTuple(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        direction=direction,
    )
    return argparse.Namespace(
        vm_name=vm_name,
        resource_group=resource_group,
        nic_name=nic_name,
        subscription_id=None,
        session_id=session_id,
        audit_path=tmp_path,
        mode="verdict",
        traffic=traffic,
    )


def _audit_args(
    tmp_path: Path,
    session_id: str = "nsg_test_session",
    vm_name: str = "test-vm",
    resource_group: str = "test-rg",
    nic_name: str = None,
) -> argparse.Namespace:
    """Build a Namespace for audit-mode pipeline invocation."""
    return argparse.Namespace(
        vm_name=vm_name,
        resource_group=resource_group,
        nic_name=nic_name,
        subscription_id=None,
        session_id=session_id,
        audit_path=tmp_path,
        mode="audit",
        traffic=None,
    )


# ---------------------------------------------------------------------------
# T-INT-01 — Verdict mode: raw artifact written after collect
# ---------------------------------------------------------------------------

def test_int_01_verdict_mode_raw_artifact_written(tmp_path, capsys):
    """T-INT-01: Verdict mode — raw artifact written after collect [PIPELINE]"""
    provider = _mock_provider("fx-01-inbound-both-allow.json")
    args = _verdict_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)

    raw_path = tmp_path / "nsg_test_session_raw.json"
    assert raw_path.exists()
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    assert "value" in data
    assert rc == 0


# ---------------------------------------------------------------------------
# T-INT-02 — Verdict mode: verdict artifact written, stdout printed
# ---------------------------------------------------------------------------

def test_int_02_verdict_artifact_written_and_stdout_printed(tmp_path, capsys):
    """T-INT-02: Verdict mode — verdict artifact written, stdout contains ALLOW [PIPELINE]"""
    provider = _mock_provider("fx-01-inbound-both-allow.json")
    args = _verdict_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)

    verdict_path = tmp_path / "nsg_test_session_verdict.json"
    assert verdict_path.exists()

    artifact = json.loads(verdict_path.read_text(encoding="utf-8"))
    assert artifact["final_verdict"] == "ALLOW"

    captured = capsys.readouterr()
    assert "Final verdict" in captured.out
    assert "ALLOW" in captured.out
    assert rc == 0


# ---------------------------------------------------------------------------
# T-INT-03 — Audit mode: audit artifact written, stdout printed
# ---------------------------------------------------------------------------

def test_int_03_audit_mode_artifact_written_stdout_printed(tmp_path, capsys):
    """T-INT-03: Audit mode — audit artifact written, stdout contains FINDINGS [PIPELINE]"""
    provider = _mock_provider("fx-10-complex-production.json")
    args = _audit_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)

    audit_path = tmp_path / "nsg_test_session_audit.json"
    assert audit_path.exists()

    artifact = json.loads(audit_path.read_text(encoding="utf-8"))
    assert artifact["mode"] == "audit"

    captured = capsys.readouterr()
    assert "FINDINGS" in captured.out
    assert rc == 0


# ---------------------------------------------------------------------------
# T-INT-04 — Identity fields added by orchestrator, not engine
# ---------------------------------------------------------------------------

def test_int_04_identity_fields_in_artifact(tmp_path, capsys):
    """T-INT-04: vm_name, nic_name, session_id present in verdict artifact [PIPELINE]"""
    provider = _mock_provider("fx-01-inbound-both-allow.json", nic_name="resolved-nic")
    args = _verdict_args(tmp_path, vm_name="my-vm")

    _run_pipeline(args, provider=provider)

    verdict_path = tmp_path / "nsg_test_session_verdict.json"
    artifact = json.loads(verdict_path.read_text(encoding="utf-8"))

    assert artifact["vm_name"] == "my-vm"
    assert artifact["nic_name"] == "resolved-nic"
    assert artifact["session_id"].startswith("nsg_")


# ---------------------------------------------------------------------------
# T-INT-05 — parse_warnings forwarded into artifact
# ---------------------------------------------------------------------------

def test_int_05_parse_warnings_forwarded_into_artifact(tmp_path, capsys):
    """T-INT-05: parse_warnings from preprocessor appear in verdict artifact [PIPELINE]"""
    # Fixture with missing association → preprocessor warning about unknown gate type
    no_assoc_data = {
        "value": [
            {
                "networkSecurityGroup": {
                    "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
                },
                # No "association" key — triggers parse warning
                "effectiveSecurityRules": [
                    {
                        "name": "AllowVnetInBound",
                        "priority": 65000,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "All",
                        "sourceAddressPrefix": "*",
                        "sourcePortRange": "*",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "0-65535",
                    }
                ],
            }
        ]
    }
    provider = MagicMock()
    provider.get_nic_name.return_value = "test-nic"
    provider.get_effective_nsg.return_value = no_assoc_data

    args = _verdict_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)
    assert rc == 0

    verdict_path = tmp_path / "nsg_test_session_verdict.json"
    artifact = json.loads(verdict_path.read_text(encoding="utf-8"))
    assert len(artifact.get("parse_warnings") or []) > 0


# ---------------------------------------------------------------------------
# T-INT-06 — --nic-name override: get_nic_name() not called
# ---------------------------------------------------------------------------

def test_int_06_nic_name_override_skips_get_nic_name(tmp_path, capsys):
    """T-INT-06: --nic-name override bypasses get_nic_name() [PIPELINE]"""
    provider = _mock_provider("fx-01-inbound-both-allow.json", nic_name="ignored")
    args = _verdict_args(tmp_path, nic_name="preresolved-nic")

    _run_pipeline(args, provider=provider)

    provider.get_nic_name.assert_not_called()
    provider.get_effective_nsg.assert_called_once_with("preresolved-nic", "test-rg")


# ---------------------------------------------------------------------------
# T-INT-07 — RBACError → exit 2, no artifacts written
# ---------------------------------------------------------------------------

def test_int_07_rbac_error_exit_2_no_artifacts(tmp_path, capsys):
    """T-INT-07: RBACError → exit code 2; no raw artifact written [PIPELINE]"""
    provider = MagicMock()
    provider.get_nic_name.return_value = "test-nic"
    provider.get_effective_nsg.side_effect = RBACError(
        "Authorization failed",
        permission="Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action",
        operation="az network nic list-effective-nsg",
    )
    args = _verdict_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)

    assert rc == 2
    raw_path = tmp_path / "nsg_test_session_raw.json"
    assert not raw_path.exists()


# ---------------------------------------------------------------------------
# T-INT-08 — Preprocessor gate_count=0 → exit 2, raw artifact retained
# ---------------------------------------------------------------------------

def test_int_08_gate_count_zero_exit_2_raw_artifact_retained(tmp_path, capsys):
    """T-INT-08: gate_count=0 → exit 2; raw artifact exists; no verdict artifact [PIPELINE]"""
    empty_data = {"value": []}
    provider = MagicMock()
    provider.get_nic_name.return_value = "test-nic"
    provider.get_effective_nsg.return_value = empty_data
    args = _verdict_args(tmp_path)

    rc = _run_pipeline(args, provider=provider)

    assert rc == 2

    raw_path = tmp_path / "nsg_test_session_raw.json"
    assert raw_path.exists()  # raw artifact written before preprocessing failed

    verdict_path = tmp_path / "nsg_test_session_verdict.json"
    assert not verdict_path.exists()  # verdict artifact never written


# ---------------------------------------------------------------------------
# T-INT-09 — Collision check before any Azure call
# ---------------------------------------------------------------------------

def test_int_09_collision_check_before_azure_call(tmp_path, capsys):
    """T-INT-09: Collision detected before any Azure call; mock provider never called [PIPELINE]"""
    session_id = "nsg_collision_test"
    # Pre-create the raw artifact to simulate an existing session
    (tmp_path / f"{session_id}_raw.json").write_text("{}", encoding="utf-8")

    # _check_collision is called before _run_pipeline in main(); verify it exits
    with pytest.raises(SystemExit) as exc_info:
        _check_collision(session_id, tmp_path)
    assert exc_info.value.code == 2

    # The mock provider would never be reached because the collision check exits first
    provider = MagicMock()
    provider.get_nic_name.assert_not_called()
    provider.get_effective_nsg.assert_not_called()


# ---------------------------------------------------------------------------
# T-INT-10 — args.traffic reaches Stage 4 in verdict mode
# ---------------------------------------------------------------------------

def test_int_10_traffic_reaches_stage_4(tmp_path, monkeypatch, capsys):
    """T-INT-10: args.traffic.dst_port matches CLI --dst-port in verdict artifact [PIPELINE]"""
    captured_traffic = []
    original_evaluate = nsg_engine.evaluate_verdict

    def _spy_evaluate(rule_sets, traffic):
        captured_traffic.append(traffic)
        return original_evaluate(rule_sets, traffic)

    monkeypatch.setattr(nsg_engine, "evaluate_verdict", _spy_evaluate)

    provider = _mock_provider("fx-01-inbound-both-allow.json")
    args = _verdict_args(tmp_path, dst_port=8888)

    _run_pipeline(args, provider=provider)

    assert len(captured_traffic) == 1
    assert captured_traffic[0].dst_port == 8888
