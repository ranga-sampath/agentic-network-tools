"""test_integration.py — Integration tests (I1–I7)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import ghost_agent
from ghost_agent import (
    _new_session,
    _run_loop,
    _build_ghost_tools,
    _reconstruct_history,
    save_session,
)
from tests.conftest import (
    make_fc_response,
    STUB_CONTENT,
    STUB_PART,
    STUB_FC,
    STUB_FR,
)


SID = "ghost_20240101_120000"


def _setup(tmp_path):
    state = _new_session("gemini-2.0-flash", str(tmp_path / "audit"))
    session_file = str(tmp_path / "session.json")
    ghost_tools = _build_ghost_tools()
    return state, session_file, ghost_tools


# ---------------------------------------------------------------------------
# I1: Happy path (Gemini→run_shell_cmd→SAFE auto-approve→loop continues→complete)
# ---------------------------------------------------------------------------

def test_I1_happy_path_shell_cmd_then_complete(tmp_path):
    """Full happy path: run_shell_cmd dispatched, then complete_investigation exits."""
    state, session_file, ghost_tools = _setup(tmp_path)

    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed",
        "classification": "SAFE",
        "action": "auto_approved",
        "output": "64 bytes from 8.8.8.8",
        "stderr": "",
        "exit_code": 0,
        "error": None,
        "duration_seconds": 0.1,
        "output_metadata": {"truncation_applied": False},
        "audit_id": f"{SID}_001",
    }
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_completed"}

    resp1 = make_fc_response("run_shell_cmd", {
        "command": "ping 8.8.8.8",
        "reasoning": "Test connectivity",
    })
    resp2 = make_fc_response("complete_investigation", {
        "confidence": "high",
        "root_cause_summary": "Root cause identified.",
        "recommended_actions": ["Fix firewall rule"],
    })
    client = MagicMock()
    client.models.generate_content.side_effect = [resp1, resp2]
    history = []

    with patch.object(ghost_agent, "_generate_rca") as mock_rca:
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # shell.execute called once for run_shell_cmd
    shell.execute.assert_called_once()
    # generate_content called twice (once per loop turn)
    assert client.models.generate_content.call_count == 2
    # RCA generated
    mock_rca.assert_called_once()
    # turn_count incremented
    assert state["turn_count"] >= 1

    # Session file must be valid JSON
    with open(session_file) as f:
        data = json.load(f)
    assert "session_id" in data


# ---------------------------------------------------------------------------
# I2: Denial path — 3 denials → UNVERIFIABLE → state changes verified
# ---------------------------------------------------------------------------

def test_I2_denial_path_three_denials_makes_unverifiable(tmp_path):
    """Three denials for H1 must remove it from active_hypothesis_ids."""
    state, session_file, ghost_tools = _setup(tmp_path)
    state["active_hypothesis_ids"] = ["H1"]
    state["hypothesis_log"] = [
        {"id": "H1", "description": "Connectivity blocked by NSG", "state": "ACTIVE", "denial_events": []}
    ]

    shell = MagicMock()
    denied_result = {
        "status": "denied",
        "action": "user_denied",
        "exit_code": None,
        "audit_id": f"{SID}_001",
    }
    shell.execute.return_value = denied_result

    orch = MagicMock()

    # 3 rounds of run_shell_cmd (all denied), then complete_investigation
    resp_shell = make_fc_response("run_shell_cmd", {
        "command": "sudo tcpdump",
        "reasoning": "capture",
        "hypothesis_id": "H1",
    })
    resp_complete = make_fc_response("complete_investigation", {
        "confidence": "low",
        "root_cause_summary": "All hypotheses unverifiable",
        "unverifiable_hypotheses": ["H1"],
    })

    client = MagicMock()
    client.models.generate_content.side_effect = [
        resp_shell, resp_shell, resp_shell, resp_complete
    ]
    history = []

    ghost_agent.terminal_hitl_callback.captured_reason = ""

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # After 3 denials, H1 must be removed from active_hypothesis_ids
    assert "H1" not in state["active_hypothesis_ids"]
    # denial_tracker must show 3 denials for H1
    assert state["denial_tracker"].get("H1", 0) == 3


# ---------------------------------------------------------------------------
# I3: Resume path — session + JSONL → is_resume=True → reconstructed history used
# ---------------------------------------------------------------------------

def test_I3_resume_path_reconstructs_history(tmp_path):
    """On resume, _reconstruct_history must produce history from shell audit JSONL."""
    sid = SID
    audit_dir = str(tmp_path)

    shell_record = {
        "timestamp": "2024-01-01T12:00:00+00:00",
        "session_id": sid,
        "sequence": 1,
        "command": "ping 8.8.8.8",
        "reasoning": "Check connectivity",
        "status": "completed",
        "classification": "SAFE",
        "action": "auto_approved",
        "exit_code": 0,
        "output_summary": "64 bytes from 8.8.8.8",
        "environment": "local",
        "audit_id": f"{sid}_001",
        "duration_seconds": 0.5,
    }
    shell_path = tmp_path / f"shell_audit_{sid}.jsonl"
    with open(shell_path, "w") as f:
        f.write(json.dumps(shell_record) + "\n")

    # Create and save a session state
    state = _new_session("gemini-2.0-flash", audit_dir)
    state["session_id"] = sid
    state["is_resume"] = True

    history = _reconstruct_history(audit_dir, sid, denial_reasons=state.get("denial_reasons", {}))

    assert len(history) >= 2
    assert history[-1].role == "user"

    # The state is_resume flag must be True
    assert state["is_resume"] is True


# ---------------------------------------------------------------------------
# I4: Full RCA path (complete_investigation → both JSONL read → md written)
# ---------------------------------------------------------------------------

def test_I4_full_rca_path(tmp_path):
    """complete_investigation must trigger RCA generation that reads JSONL and writes .md."""
    sid = SID
    audit_dir = str(tmp_path)

    # Write shell audit JSONL
    shell_record = {
        "timestamp": "2024-01-01T12:00:00+00:00",
        "session_id": sid,
        "sequence": 1,
        "command": "ping 8.8.8.8",
        "reasoning": "Test",
        "status": "completed",
        "classification": "SAFE",
        "action": "auto_approved",
        "exit_code": 0,
        "output_summary": "64 bytes",
        "environment": "local",
        "audit_id": f"{sid}_001",
        "duration_seconds": 0.5,
    }
    with open(tmp_path / f"shell_audit_{sid}.jsonl", "w") as f:
        f.write(json.dumps(shell_record) + "\n")

    # Write task registry JSONL
    task_record = {
        "task_id": f"{sid}_vm1_20240101T120000",
        "session_id": sid,
        "state": "DONE",
        "target": "vm1",
        "report_path": None,
        "cleanup_status": "done",
    }
    with open(tmp_path / f"orchestrator_tasks_{sid}.jsonl", "w") as f:
        f.write(json.dumps(task_record) + "\n")

    state = _new_session("gemini-2.0-flash", audit_dir)
    state["session_id"] = sid
    state["audit_dir"] = audit_dir
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        ghost_agent._generate_rca(
            state,
            {"confidence": "high", "root_cause_summary": "Full path test."},
            shell,
            session_file,
        )

    report_path = tmp_path / f"ghost_report_{sid}.md"
    audit_path  = tmp_path / f"ghost_audit_{sid}.md"
    assert report_path.exists()
    assert audit_path.exists()
    assert "Investigation Report" in report_path.read_text()
    assert "Root Cause" in report_path.read_text()
    assert "Integrity Statement" in audit_path.read_text()
    assert state["rca_report_path"] is not None
    assert state["audit_trail_path"] is not None


# ---------------------------------------------------------------------------
# I5: real Azure — SKIP
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="SKIP: requires real Azure credentials and resources")
def test_I5_real_azure_capture():
    """Integration test with real Azure packet capture — requires live credentials."""
    pass


# ---------------------------------------------------------------------------
# I6: real Gemini API — SKIP
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="SKIP: requires real Gemini API key and quota")
def test_I6_real_gemini_api():
    """Integration test with real Gemini API — requires GEMINI_API_KEY."""
    pass


# ---------------------------------------------------------------------------
# I7: concurrent sessions — SKIP
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="SKIP: concurrent sessions require multi-process test infrastructure")
def test_I7_concurrent_sessions():
    """Integration test for concurrent session handling — out of scope for unit tests."""
    pass
