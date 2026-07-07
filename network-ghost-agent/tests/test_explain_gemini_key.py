"""test_explain_gemini_key.py — explain requires GEMINI_API_KEY (BUG-05).

The firewall explanation engine (iptables_explain/nftables_explain) calls
Gemini directly, independent of --llm-provider. On Anthropic-only
deployments the mandated explain flow previously raised EnvironmentError
inside the handler and was buried as explanation_warning. The handler must
now surface a loud, structured, actionable error — and behave exactly as
before when the key is present.

Mock boundary: subprocess.run mocked for baseline/compare modes (same
pattern as test_firewall_inspector_handler.py); explain-only mode needs no
subprocess. GEMINI_API_KEY is manipulated via monkeypatch.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghost_agent import _run_firewall_inspector_handler


@pytest.fixture()
def ghost_cfg(tmp_path):
    return {
        "AUDIT_DIR":        str(tmp_path),
        "FW_TARGET_VM_IP":  "192.168.2.7",
        "FW_SSH_KEY_PATH":  "/tmp/test_key",
        "FW_SSH_USER":      "ubuntu",
    }


def _write_snapshot(audit_dir, session_id="fw_base"):
    path = Path(audit_dir) / f"{session_id}_snapshot.json"
    path.write_text(json.dumps({"framework": "iptables-legacy",
                                "rulesets": {"ipv4": {"tables": {}}}}))
    return path


def _write_drift(audit_dir, name="fw_cmp_drift.json"):
    path = Path(audit_dir) / name
    path.write_text(json.dumps({"drift_by_family": {
        "ipv4": {"drift_detected": True, "has_critical_changes": True,
                 "summary": {}, "changes": {}},
    }}))
    return path


# ---------------------------------------------------------------------------
# Key absent → loud structured error on all three explain paths
# ---------------------------------------------------------------------------

def test_explain_only_mode_errors_without_key(ghost_cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    _write_snapshot(tmp_path)

    result = _run_firewall_inspector_handler(
        ghost_cfg, {"explain": True, "session_id": "fw_base", "reasoning": "r"})

    assert result["status"] == "error"
    assert "GEMINI_API_KEY" in result["error"]
    assert "explanation_warning" not in result


def test_baseline_explain_returns_snapshot_with_explanation_error(
        ghost_cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def fake_run(cmd, **kwargs):
        _write_snapshot(tmp_path, "fw_new")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run_firewall_inspector_handler(
        ghost_cfg, {"is_baseline": True, "explain": True, "reasoning": "r"})

    # The probe still succeeds — only the explanation is unavailable, loudly.
    assert result["status"] == "success"
    assert result["mode"] == "baseline"
    assert "GEMINI_API_KEY" in result["explanation_error"]
    assert "explanation" not in result
    assert "explanation_warning" not in result


def test_compare_explain_returns_drift_with_explanation_error(
        ghost_cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def fake_run(cmd, **kwargs):
        _write_drift(tmp_path)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run_firewall_inspector_handler(
        ghost_cfg, {"compare_session_id": "fw_base", "explain": True,
                    "provider": "ssh", "reasoning": "r"})

    assert result["status"] == "success"
    assert result["mode"] == "compare"
    assert result["drift_detected"] is True
    assert "GEMINI_API_KEY" in result["explanation_error"]
    assert "explanation" not in result


# ---------------------------------------------------------------------------
# Key present → prior behavior unchanged
# ---------------------------------------------------------------------------

def test_explain_only_mode_proceeds_with_key(ghost_cfg, tmp_path, monkeypatch):
    """With the key set, the handler reaches the explain engine as before
    (the stubbed engine import fails → explanation_warning path, proving the
    precheck did not short-circuit)."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    _write_snapshot(tmp_path)

    result = _run_firewall_inspector_handler(
        ghost_cfg, {"explain": True, "session_id": "fw_base", "reasoning": "r"})

    assert result["status"] == "success"
    assert result["mode"] == "explain"
    assert "explanation_error" not in result


def test_no_explain_requested_never_prechecks(ghost_cfg, tmp_path, monkeypatch):
    """Without explain=True the key must not matter at all."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def fake_run(cmd, **kwargs):
        _write_snapshot(tmp_path, "fw_plain")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run_firewall_inspector_handler(
        ghost_cfg, {"is_baseline": True, "reasoning": "r"})

    assert result["status"] == "success"
    assert "explanation_error" not in result
