"""
test_effective_network_inspector_handler.py — Unit tests for
_run_effective_network_inspector_handler() in ghost_agent.py.

Test IDs match docs/test_plan.md (TC-GA-*):
  TC-GA-001  Handler writes correct config lines to temp file
  TC-GA-002  Handler uses ENI_VM_NAME over DEST_VM_NAME when both present
  TC-GA-003  Handler omits SUBSCRIPTION_ID when not in ghost_cfg
  TC-GA-004  Temp file deleted after subprocess regardless of exit code
  TC-GA-005  Baseline mode discovers eni_*_snapshot.json by mtime
  TC-GA-006  Compare mode discovers eni_*_vs_eni_*_diff.json by mtime
  TC-GA-007  No artifact found returns structured error
  TC-GA-008  Subprocess timeout returns structured error
  TC-GA-009  ghost_cfg=None at dispatch returns structured error
  TC-GA-010  Neither is_baseline nor compare_session_id returns structured error
  TC-GA-011  Tool declaration uses compare_session_id (not compare_baseline)

Mock boundary
-------------
subprocess.run is mocked. Artifact files are written directly to tmp_path
to simulate what effective_network_inspector.py would produce; this isolates
the handler's config-construction and result-parsing logic from the
actual Azure CLI pipeline already covered by effective-network-inspector tests.

eni_path.exists() is also patched to True so the handler doesn't abort
on the non-production path check.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# conftest.py has stubbed google.genai / safe_exec_shell / cloud_orchestrator
# and imported ghost_agent.  Importing it here is safe.
import ghost_agent
from ghost_agent import _run_effective_network_inspector_handler, _dispatch_tool, _build_ghost_tools


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc(returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode)


def _ghost_cfg(tmp_path, **overrides) -> dict:
    cfg = {
        "RESOURCE_GROUP": "my-rg",
        "DEST_VM_NAME":   "vm-dest",
        "AUDIT_DIR":      str(tmp_path),
    }
    cfg.update(overrides)
    return cfg


def _write_snapshot(audit_dir: str, session_id: str = "eni_20260401_120000") -> Path:
    p = Path(audit_dir) / f"{session_id}_snapshot.json"
    p.write_text(json.dumps({"nics": []}), encoding="utf-8")
    return p


def _write_diff(audit_dir: str,
                baseline: str = "eni_20260401_120000",
                compare: str = "eni_20260401_130000") -> Path:
    name = f"{baseline}_vs_{compare}_diff.json"
    payload = {
        "drift_detected":      True,
        "changes_count":       2,
        "changes_by_category": {"bgp_route_change": 2},
        "nic_diffs":           [],
        "skipped_nics":        [],
    }
    p = Path(audit_dir) / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _subprocess_writes_snapshot(audit_dir: str, session_id: str = "eni_20260401_120000"):
    """Return a side_effect that writes a snapshot file and returns proc(0)."""
    def _inner(*args, **kwargs):
        _write_snapshot(audit_dir, session_id)
        return _make_proc(0)
    return _inner


def _subprocess_writes_diff(audit_dir: str,
                            baseline: str = "eni_20260401_120000",
                            compare: str = "eni_20260401_130000"):
    """Return a side_effect that writes a diff file and returns proc(0)."""
    def _inner(*args, **kwargs):
        _write_diff(audit_dir, baseline, compare)
        return _make_proc(0)
    return _inner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def ghost_cfg_base(tmp_path):
    return _ghost_cfg(tmp_path)


@pytest.fixture()
def baseline_args():
    return {"is_baseline": True, "reasoning": "taking baseline before change window"}


@pytest.fixture()
def compare_args():
    return {
        "compare_session_id": "eni_20260401_120000",
        "reasoning":          "comparing after change window",
    }


# ---------------------------------------------------------------------------
# TC-GA-001: Handler writes correct config lines to temp file
# ---------------------------------------------------------------------------

def test_ga_001_config_file_contains_required_keys(tmp_path):
    """TC-GA-001: Temp config contains RESOURCE_GROUP, SCOPE=vm, VM_NAME, AUDIT_DIR."""
    cfg = _ghost_cfg(tmp_path, RESOURCE_GROUP="prod-rg", DEST_VM_NAME="prod-vm",
                     SUBSCRIPTION_ID="sub-abc-123")
    captured_path: list[str] = []

    def _capture_and_succeed(*args, **kwargs):
        # Find the --config argument and read the file before it's deleted
        cmd = args[0]
        idx = cmd.index("--config")
        captured_path.append(cmd[idx + 1])
        # Read NOW, before cleanup
        content = Path(captured_path[0]).read_text()
        captured_path.append(content)
        _write_snapshot(str(tmp_path))
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_capture_and_succeed), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(cfg, {"is_baseline": True})

    config_text = captured_path[1]
    assert "RESOURCE_GROUP=prod-rg"     in config_text
    assert "SCOPE=vm"                   in config_text
    assert "VM_NAME=prod-vm"            in config_text
    assert f"AUDIT_DIR={tmp_path}"      in config_text
    assert "SUBSCRIPTION_ID=sub-abc-123" in config_text


# ---------------------------------------------------------------------------
# TC-GA-002: ENI_VM_NAME takes precedence over DEST_VM_NAME
# ---------------------------------------------------------------------------

def test_ga_002_eni_vm_name_preferred_over_dest_vm_name(tmp_path):
    """TC-GA-002: When ENI_VM_NAME and DEST_VM_NAME both present, VM_NAME=ENI_VM_NAME."""
    cfg = _ghost_cfg(tmp_path, ENI_VM_NAME="vm-a", DEST_VM_NAME="vm-b")
    captured: list[str] = []

    def _side_effect(*args, **kwargs):
        cmd = args[0]
        idx = cmd.index("--config")
        captured.append(Path(cmd[idx + 1]).read_text())
        _write_snapshot(str(tmp_path))
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_side_effect), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(cfg, {"is_baseline": True})

    assert "VM_NAME=vm-a" in captured[0]
    assert "VM_NAME=vm-b" not in captured[0]


# ---------------------------------------------------------------------------
# TC-GA-003: SUBSCRIPTION_ID omitted when not in ghost_cfg
# ---------------------------------------------------------------------------

def test_ga_003_subscription_id_omitted_when_absent(tmp_path):
    """TC-GA-003: Config file must not contain SUBSCRIPTION_ID= when key not in ghost_cfg."""
    cfg = _ghost_cfg(tmp_path)  # no SUBSCRIPTION_ID
    captured: list[str] = []

    def _side_effect(*args, **kwargs):
        cmd = args[0]
        idx = cmd.index("--config")
        captured.append(Path(cmd[idx + 1]).read_text())
        _write_snapshot(str(tmp_path))
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_side_effect), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(cfg, {"is_baseline": True})

    assert "SUBSCRIPTION_ID" not in captured[0]


# ---------------------------------------------------------------------------
# TC-GA-004: Temp file deleted after subprocess regardless of exit code
# ---------------------------------------------------------------------------

def test_ga_004_temp_file_deleted_on_success(tmp_path, baseline_args):
    """TC-GA-004a: Temp file cleaned up when subprocess succeeds."""
    tmp_paths: list[str] = []

    def _capture_path_then_succeed(*args, **kwargs):
        cmd = args[0]
        idx = cmd.index("--config")
        tmp_paths.append(cmd[idx + 1])
        _write_snapshot(str(tmp_path))
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_capture_path_then_succeed), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert tmp_paths, "Expected --config path to be captured"
    assert not os.path.exists(tmp_paths[0]), "Temp config file must be deleted after success"


def test_ga_004_temp_file_deleted_on_timeout(tmp_path, baseline_args):
    """TC-GA-004b: Temp file cleaned up when subprocess raises TimeoutExpired."""
    tmp_paths: list[str] = []

    def _capture_path_then_timeout(*args, **kwargs):
        cmd = args[0]
        idx = cmd.index("--config")
        tmp_paths.append(cmd[idx + 1])
        raise subprocess.TimeoutExpired(cmd="eni", timeout=300)

    with patch("subprocess.run", side_effect=_capture_path_then_timeout), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert result["status"] == "error"
    assert tmp_paths, "Expected --config path to be captured"
    assert not os.path.exists(tmp_paths[0]), "Temp config file must be deleted after timeout"


# ---------------------------------------------------------------------------
# TC-GA-005: Baseline mode discovers eni_*_snapshot.json by mtime
# ---------------------------------------------------------------------------

def test_ga_005_baseline_discovers_snapshot_by_mtime(tmp_path, baseline_args):
    """TC-GA-005: Baseline mode returns session_id from the newest matching snapshot."""
    session_id = "eni_20260401_120000"

    with patch("subprocess.run",
               side_effect=_subprocess_writes_snapshot(str(tmp_path), session_id)), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert result["status"]     == "success"
    assert result["mode"]       == "baseline"
    assert result["session_id"] == session_id
    assert "artifact" in result


# ---------------------------------------------------------------------------
# TC-GA-006: Compare mode discovers eni_*_vs_eni_*_diff.json by mtime
# ---------------------------------------------------------------------------

def test_ga_006_compare_discovers_diff_by_mtime(tmp_path, compare_args):
    """TC-GA-006: Compare mode returns drift_detected and changes_count from diff artifact."""
    baseline = "eni_20260401_120000"
    compare  = "eni_20260401_130000"

    with patch("subprocess.run",
               side_effect=_subprocess_writes_diff(str(tmp_path), baseline, compare)), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), compare_args)

    assert result["status"]        == "success"
    assert result["mode"]          == "compare"
    assert result["drift_detected"] is True
    assert result["changes_count"] == 2
    assert "artifact" in result


def test_ga_006_compare_result_contains_changes_by_category(tmp_path, compare_args):
    """TC-GA-006b: changes_by_category forwarded from diff artifact."""
    with patch("subprocess.run",
               side_effect=_subprocess_writes_diff(str(tmp_path))), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), compare_args)

    assert "bgp_route_change" in result["changes_by_category"]


# ---------------------------------------------------------------------------
# TC-GA-007: No artifact found returns structured error
# ---------------------------------------------------------------------------

def test_ga_007_no_snapshot_artifact_returns_error(tmp_path, baseline_args):
    """TC-GA-007a: Baseline mode with no snapshot written returns error dict."""
    with patch("subprocess.run", return_value=_make_proc(0)), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert result["status"] == "error"
    assert "snapshot" in result["error"].lower() or "artifact" in result["error"].lower()


def test_ga_007_no_diff_artifact_returns_error(tmp_path, compare_args):
    """TC-GA-007b: Compare mode with no diff written returns error dict."""
    with patch("subprocess.run", return_value=_make_proc(0)), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), compare_args)

    assert result["status"] == "error"
    assert "diff" in result["error"].lower() or "artifact" in result["error"].lower()


# ---------------------------------------------------------------------------
# TC-GA-008: Subprocess timeout returns structured error
# ---------------------------------------------------------------------------

def test_ga_008_timeout_returns_structured_error(tmp_path, baseline_args):
    """TC-GA-008: TimeoutExpired returns {status: error, error: '...timed out after 300 seconds'}."""
    with patch("subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="eni", timeout=300)), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert result["status"] == "error"
    assert "timed out" in result["error"]
    assert "300" in result["error"]


# ---------------------------------------------------------------------------
# TC-GA-009: ghost_cfg=None at dispatch returns structured error
# ---------------------------------------------------------------------------

def test_ga_009_dispatch_with_no_ghost_cfg_returns_error():
    """TC-GA-009: _dispatch_tool with ghost_cfg=None returns error, no subprocess."""
    shell_mock = MagicMock()
    orch_mock  = MagicMock()

    with patch("subprocess.run") as mock_proc:
        result = _dispatch_tool(
            "detect_effective_network_drift",
            {"reasoning": "test"},
            shell_mock,
            orch_mock,
            ghost_cfg=None,
        )

    assert result["status"] == "error"
    assert "detect_effective_network_drift" in result["error"]
    mock_proc.assert_not_called()


# ---------------------------------------------------------------------------
# TC-GA-010: Neither is_baseline nor compare_session_id → structured error
# ---------------------------------------------------------------------------

def test_ga_010_missing_mode_returns_error_without_subprocess(tmp_path):
    """TC-GA-010: Omitting both flags returns error; subprocess must not be called."""
    with patch("subprocess.run") as mock_proc, \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(
            _ghost_cfg(tmp_path),
            {"reasoning": "no mode specified"},
        )

    assert result["status"] == "error"
    assert "is_baseline" in result["error"] or "compare_session_id" in result["error"]
    mock_proc.assert_not_called()


# ---------------------------------------------------------------------------
# TC-GA-011: Tool declaration uses compare_session_id (not compare_baseline)
# ---------------------------------------------------------------------------

def test_ga_011_tool_declaration_uses_compare_session_id():
    """TC-GA-011: FunctionDeclaration for detect_effective_network_drift has
    compare_session_id parameter — not compare_baseline.
    """
    tool = _build_ghost_tools()  # returns a single types.Tool, not a list
    decl = next(
        (fd for fd in tool.function_declarations
             if fd.name == "detect_effective_network_drift"),
        None,
    )
    assert decl is not None, "detect_effective_network_drift declaration not found"

    param_names = set(decl.parameters.properties.keys())
    assert "compare_session_id" in param_names, \
        "compare_session_id must be a declared parameter"
    assert "compare_baseline" not in param_names, \
        "compare_baseline must NOT appear — naming was corrected to compare_session_id"


# ---------------------------------------------------------------------------
# Additional: baseline result includes nic_count from snapshot data
# ---------------------------------------------------------------------------

def test_baseline_result_includes_nic_count(tmp_path, baseline_args):
    """Baseline result dict includes nic_count parsed from the snapshot artifact."""
    session_id = "eni_20260401_120000"

    def _write_snap_with_nics(*args, **kwargs):
        payload = {"nics": [{"nic_name": "nic-a"}, {"nic_name": "nic-b"}]}
        p = Path(str(tmp_path)) / f"{session_id}_snapshot.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_write_snap_with_nics), \
         patch.object(Path, "exists", return_value=True):
        result = _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), baseline_args)

    assert result["status"]    == "success"
    assert result["nic_count"] == 2


# ---------------------------------------------------------------------------
# Additional: compare_session_id passed as --compare-baseline argument
# ---------------------------------------------------------------------------

def test_compare_session_id_passed_to_subprocess(tmp_path, compare_args):
    """compare_session_id must be forwarded as --compare-baseline <value> in the cmd."""
    captured_cmd: list = []

    def _capture(*args, **kwargs):
        captured_cmd.extend(args[0])
        _write_diff(str(tmp_path))
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_capture), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(_ghost_cfg(tmp_path), compare_args)

    assert "--compare-baseline" in captured_cmd
    idx = captured_cmd.index("--compare-baseline")
    assert captured_cmd[idx + 1] == compare_args["compare_session_id"]


# ---------------------------------------------------------------------------
# Additional: session_id forwarded when present in tool_args
# ---------------------------------------------------------------------------

def test_custom_session_id_forwarded_to_subprocess(tmp_path):
    """--session-id arg is appended to cmd when session_id is in tool_args."""
    captured_cmd: list = []

    def _capture(*args, **kwargs):
        captured_cmd.extend(args[0])
        _write_snapshot(str(tmp_path), "my-custom-session")
        return _make_proc(0)

    with patch("subprocess.run", side_effect=_capture), \
         patch.object(Path, "exists", return_value=True):
        _run_effective_network_inspector_handler(
            _ghost_cfg(tmp_path),
            {"is_baseline": True, "session_id": "my-custom-session"},
        )

    assert "--session-id" in captured_cmd
    idx = captured_cmd.index("--session-id")
    assert captured_cmd[idx + 1] == "my-custom-session"
