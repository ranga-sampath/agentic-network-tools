"""
test_handler.py — Ghost Agent handler tests for _run_security_rule_inspector_handler()

Covers:
  T-GH-01 through T-GH-06
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ghost_agent.py depends on dotenv, google.genai, and other heavy packages that may
# not be installed in the test environment. Stub them out before importing the module.
_STUB_MODULES = [
    "dotenv", "google", "google.genai", "google.genai.types",
    "safe_exec_shell", "cloud_orchestrator",
]
for _mod in _STUB_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# Provide the specific names ghost_agent accesses at module level
sys.modules["dotenv"].load_dotenv = MagicMock()
sys.modules["safe_exec_shell"].SafeExecShell = MagicMock()
sys.modules["safe_exec_shell"].HitlDecision = MagicMock()
sys.modules["cloud_orchestrator"].CloudOrchestrator = MagicMock()
sys.modules["google.genai"].types = MagicMock()

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "network-ghost-agent"))
from ghost_agent import _run_security_rule_inspector_handler  # noqa: E402

AUDIT_DIR = "/tmp/nsg-test-audit"


def _verdict_config(
    vm_name: str = "test-vm",
    resource_group: str = "test-rg",
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.1.10",
    dst_port: int = 443,
    proto: str = "Tcp",
    direction: str = "Inbound",
    session_id: str = "nsg_test_session",
    audit_dir: str = AUDIT_DIR,
    nic_name: str = None,
) -> dict:
    cfg = {
        "vm_name": vm_name,
        "resource_group": resource_group,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "direction": direction,
        "session_id": session_id,
        "audit_dir": audit_dir,
    }
    if nic_name:
        cfg["nic_name"] = nic_name
    return cfg


def _audit_config(
    vm_name: str = "test-vm",
    resource_group: str = "test-rg",
    session_id: str = "nsg_test_session",
    audit_dir: str = AUDIT_DIR,
) -> dict:
    return {
        "vm_name": vm_name,
        "resource_group": resource_group,
        "session_id": session_id,
        "audit_dir": audit_dir,
    }


# ---------------------------------------------------------------------------
# T-GH-01 — Handler constructs subprocess args correctly
# ---------------------------------------------------------------------------

def test_gh_01_subprocess_args_correct(tmp_path):
    """T-GH-01: Handler constructs subprocess args with all required flags [HANDLER]"""
    config = _verdict_config(audit_dir=str(tmp_path))

    captured_args = []
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # Pre-create the artifact that the handler would read
        (tmp_path / "nsg_test_session_verdict.json").write_text(
            json.dumps({"final_verdict": "ALLOW", "mode": "verdict"}), encoding="utf-8"
        )
        _run_security_rule_inspector_handler(config)
        captured_args = mock_run.call_args[0][0]

    assert "--vm-name" in captured_args
    assert "--resource-group" in captured_args
    assert "--src-ip" in captured_args
    assert "--dst-ip" in captured_args
    assert "--dst-port" in captured_args
    assert "--proto" in captured_args
    assert "--direction" in captured_args
    assert "--session-id" in captured_args
    assert "--audit-dir" in captured_args
    # No --nic-name when NIC override not set
    assert "--nic-name" not in captured_args


# ---------------------------------------------------------------------------
# T-GH-02 — Handler reads verdict artifact, not stdout
# ---------------------------------------------------------------------------

def test_gh_02_handler_reads_artifact_not_stdout(tmp_path):
    """T-GH-02: Handler parses the verdict artifact file, not subprocess stdout [HANDLER]"""
    config = _verdict_config(audit_dir=str(tmp_path))
    expected_verdict = {
        "final_verdict": "ALLOW",
        "mode": "verdict",
        "session_id": "nsg_test_session",
    }
    artifact_path = tmp_path / "nsg_test_session_verdict.json"
    artifact_path.write_text(json.dumps(expected_verdict), encoding="utf-8")

    with patch("subprocess.run") as mock_run:
        # stdout contains garbage — handler must NOT parse this
        mock_run.return_value = MagicMock(returncode=0, stdout="not-json-garbage", stderr="")
        result = _run_security_rule_inspector_handler(config)

    assert result["final_verdict"] == "ALLOW"


# ---------------------------------------------------------------------------
# T-GH-03 — Handler returns INDETERMINATE without proceeding
# ---------------------------------------------------------------------------

def test_gh_03_handler_returns_indeterminate_with_unresolvable_rules(tmp_path):
    """T-GH-03: INDETERMINATE verdict propagated; no 'clean NSG' signal emitted [HANDLER]"""
    config = _verdict_config(audit_dir=str(tmp_path))
    artifact = {
        "final_verdict": "INDETERMINATE",
        "mode": "verdict",
        "session_id": "nsg_test_session",
        "unresolvable_rules": [{"name": "AllowVnetInBound", "priority": 65000}],
    }
    (tmp_path / "nsg_test_session_verdict.json").write_text(
        json.dumps(artifact), encoding="utf-8"
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _run_security_rule_inspector_handler(config)

    assert result["final_verdict"] == "INDETERMINATE"
    assert len(result["unresolvable_rules"]) > 0
    # Handler must NOT signal "NSG is clean" when verdict is INDETERMINATE
    assert result.get("nsg_clean") is not True


# ---------------------------------------------------------------------------
# T-GH-04 — Handler checks file existence before parse on exit 2
# ---------------------------------------------------------------------------

def test_gh_04_handler_graceful_on_exit_2_no_artifact(tmp_path):
    """T-GH-04: subprocess exit 2, no artifact → structured error; no FileNotFoundError uncaught [HANDLER]"""
    config = _verdict_config(audit_dir=str(tmp_path))
    # Artifact does NOT exist at expected path

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="pipeline failed")
        result = _run_security_rule_inspector_handler(config)

    # Handler must return a structured error dict, not raise FileNotFoundError
    assert isinstance(result, dict)
    assert "error" in result or result.get("final_verdict") is None


# ---------------------------------------------------------------------------
# T-GH-05 — Handler uses correct artifact path for audit mode
# ---------------------------------------------------------------------------

def test_gh_05_handler_audit_mode_uses_audit_artifact_path(tmp_path):
    """T-GH-05: Audit mode uses {session_id}_audit.json, not _verdict.json [HANDLER]"""
    config = _audit_config(audit_dir=str(tmp_path))
    audit_artifact = tmp_path / "nsg_test_session_audit.json"
    audit_artifact.write_text(
        json.dumps({"mode": "audit", "session_id": "nsg_test_session"}),
        encoding="utf-8",
    )
    # Wrong path — must NOT be read
    (tmp_path / "nsg_test_session_verdict.json").write_text(
        json.dumps({"mode": "verdict", "final_verdict": "ALLOW"}),
        encoding="utf-8",
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _run_security_rule_inspector_handler(config)

    assert result["mode"] == "audit"
    assert result.get("final_verdict") is None  # audit artifacts don't have final_verdict


# ---------------------------------------------------------------------------
# T-GH-06 — Handler generates nsg_ session ID; prefix not doubled
# ---------------------------------------------------------------------------

def test_gh_06_session_id_prefix_not_doubled(tmp_path):
    """T-GH-06: Session ID passed as --session-id starts with 'nsg_' exactly once [HANDLER]"""
    # Config with session_id already starting with nsg_
    config = _verdict_config(session_id="nsg_20260413_120000", audit_dir=str(tmp_path))
    (tmp_path / "nsg_20260413_120000_verdict.json").write_text(
        json.dumps({"final_verdict": "ALLOW", "mode": "verdict"}), encoding="utf-8"
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _run_security_rule_inspector_handler(config)
        args = mock_run.call_args[0][0]

    # Extract the value after --session-id
    idx = args.index("--session-id")
    session_id_arg = args[idx + 1]

    assert session_id_arg.startswith("nsg_")
    assert not session_id_arg.startswith("nsg_nsg_")
