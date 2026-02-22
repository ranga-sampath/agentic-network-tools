"""test_startup.py — Startup/Handshake tests (H1–H15)."""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

import ghost_agent
from ghost_agent import (
    _classify_orphans,
    _present_orphan_report,
    _run_startup_cleanup,
    _new_session,
    save_session,
)
from tests.conftest import (
    STUB_SAFE_EXEC_SHELL,
    STUB_CLOUD_ORCHESTRATOR,
)


# ---------------------------------------------------------------------------
# H1: SafeExecShell instantiated before CloudOrchestrator
# ---------------------------------------------------------------------------

def test_H1_shell_instantiated_before_orchestrator():
    """SafeExecShell must be instantiated before CloudOrchestrator in main().

    We verify this by reading the source — the shell assignment must appear
    before the orchestrator assignment in the source code.
    """
    import inspect
    src = inspect.getsource(ghost_agent.main)
    idx_shell = src.find("SafeExecShell(")
    idx_orch = src.find("CloudOrchestrator(")
    assert idx_shell != -1, "SafeExecShell not found in main()"
    assert idx_orch != -1, "CloudOrchestrator not found in main()"
    assert idx_shell < idx_orch, (
        "SafeExecShell must be instantiated before CloudOrchestrator in main()"
    )


# ---------------------------------------------------------------------------
# H2: CloudOrchestrator gets same shell instance
# ---------------------------------------------------------------------------

def test_H2_orchestrator_receives_shell_instance():
    """CloudOrchestrator must receive the shell instance created in main().

    Verified via source inspection: the `shell` variable passed to
    CloudOrchestrator is the same local variable assigned from SafeExecShell.
    """
    import inspect
    src = inspect.getsource(ghost_agent.main)
    # After `shell = SafeExecShell(...)`, orchestrator must receive `shell=shell`
    assert "shell=shell" in src or "shell = shell" in src or "shell," in src, (
        "CloudOrchestrator must receive the shell variable from main()"
    )
    # More specifically: look for the orchestrator instantiation line
    assert "CloudOrchestrator(" in src
    orch_idx = src.find("CloudOrchestrator(")
    snippet = src[orch_idx: orch_idx + 200]
    assert "shell" in snippet, "CloudOrchestrator does not receive shell in its constructor call"


# ---------------------------------------------------------------------------
# H3: orphan report fetched via orchestrate({"intent": "list_tasks"})
# ---------------------------------------------------------------------------

def test_H3_orphan_report_via_list_tasks():
    """_classify_orphans must be called with the result of orchestrate(list_tasks).

    Verified by source inspection that main() calls orchestrate with list_tasks intent.
    """
    import inspect
    src = inspect.getsource(ghost_agent.main)
    assert '"list_tasks"' in src or "'list_tasks'" in src, (
        "main() must call orchestrate with intent='list_tasks'"
    )


# ---------------------------------------------------------------------------
# H4: abandoned_tasks bucket — non-terminal state from prior session
# ---------------------------------------------------------------------------

def test_H4_abandoned_tasks_bucket(tmp_path):
    """abandoned_tasks must contain tasks with type=='abandoned_task'."""
    orphan_report = {
        "status": "task_completed",
        "tasks": [],
        "orphans": [
            {"type": "abandoned_task", "task": {"task_id": "task_abc", "state": "WAITING"}},
            {"type": "abandoned_task", "task": {"task_id": "task_def", "state": "DETECTING"}},
        ],
    }
    buckets = _classify_orphans(orphan_report, str(tmp_path))
    assert len(buckets["abandoned_tasks"]) == 2
    task_ids = [t["task_id"] for t in buckets["abandoned_tasks"]]
    assert "task_abc" in task_ids
    assert "task_def" in task_ids


# ---------------------------------------------------------------------------
# H5: needs_cleanup bucket — cleanup_status=="pending"
# ---------------------------------------------------------------------------

def test_H5_needs_cleanup_bucket(tmp_path):
    """needs_cleanup must contain tasks with type=='needs_cleanup'."""
    orphan_report = {
        "status": "task_completed",
        "tasks": [],
        "orphans": [
            {"type": "needs_cleanup", "task": {"task_id": "task_xyz", "cleanup_status": "pending"}},
        ],
    }
    buckets = _classify_orphans(orphan_report, str(tmp_path))
    assert len(buckets["needs_cleanup"]) == 1
    assert buckets["needs_cleanup"][0]["task_id"] == "task_xyz"


# ---------------------------------------------------------------------------
# H6: partially_cleaned via CLI-side scan (not from _detect_orphans)
# ---------------------------------------------------------------------------

def test_H6_partially_cleaned_from_cli_scan(tmp_path):
    """partially_cleaned must be populated by CLI-side _find_partially_cleaned_tasks scan."""
    sid = "ghost_20240101_120000"
    jsonl_path = tmp_path / f"orchestrator_tasks_{sid}.jsonl"
    partial_record = {
        "task_id": f"{sid}_vm1_20240101T120000",
        "session_id": sid,
        "state": "DONE",
        "cleanup_status": "partial",
        "target": "vm1",
    }
    with open(jsonl_path, "w") as f:
        f.write(json.dumps(partial_record) + "\n")

    # Empty orphan report from orchestrator (does NOT include partial cleanup)
    orphan_report = {"status": "task_completed", "tasks": [], "orphans": []}
    buckets = _classify_orphans(orphan_report, str(tmp_path))

    # The partially_cleaned bucket must be filled by CLI scan
    assert len(buckets["partially_cleaned"]) == 1
    assert buckets["partially_cleaned"][0]["task_id"] == partial_record["task_id"]


# ---------------------------------------------------------------------------
# H7: untracked_azure and stale_local_files populated from orphan report
# ---------------------------------------------------------------------------

def test_H7_untracked_and_stale_buckets(tmp_path):
    """untracked_azure and stale_local_files must be populated from the orphan report."""
    orphan_report = {
        "status": "task_completed",
        "tasks": [],
        "orphans": [
            {"type": "untracked_azure_resource", "name": "cap123", "resource": {"resourceGroup": "rg1"}},
            {"type": "stale_local_file", "path": "/tmp/old.pcap"},
        ],
    }
    buckets = _classify_orphans(orphan_report, str(tmp_path))
    assert len(buckets["untracked_azure"]) == 1
    assert len(buckets["stale_local_files"]) == 1
    assert buckets["untracked_azure"][0]["name"] == "cap123"
    assert buckets["stale_local_files"][0]["path"] == "/tmp/old.pcap"


# ---------------------------------------------------------------------------
# H8: zero orphans → no prompt; prints OK
# ---------------------------------------------------------------------------

def test_H8_zero_orphans_prints_ok(capsys):
    """_present_orphan_report must print OK and return False when no orphans exist."""
    buckets = {
        "abandoned_tasks": [],
        "needs_cleanup": [],
        "partially_cleaned": [],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    result = _present_orphan_report(buckets)
    assert result is False
    captured = capsys.readouterr()
    assert "OK" in captured.out


# ---------------------------------------------------------------------------
# H9: cleanup_task called for each abandoned + needs_cleanup orphan
# ---------------------------------------------------------------------------

def test_H9_cleanup_task_called_for_abandoned_and_needs_cleanup(tmp_path):
    """_run_startup_cleanup must call orchestrate(cleanup_task) for each abandoned/needs_cleanup task."""
    buckets = {
        "abandoned_tasks": [{"task_id": "task_aband_1"}, {"task_id": "task_aband_2"}],
        "needs_cleanup": [{"task_id": "task_clean_1"}],
        "partially_cleaned": [],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_completed", "cleanup_status": "done"}
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    with patch("builtins.input", return_value="c"):
        _run_startup_cleanup(buckets, shell, orch, state, session_file)

    cleanup_calls = [
        c for c in orch.orchestrate.call_args_list
        if c[0][0].get("intent") == "cleanup_task"
    ]
    task_ids_called = [c[0][0]["task_id"] for c in cleanup_calls]
    assert "task_aband_1" in task_ids_called
    assert "task_aband_2" in task_ids_called
    assert "task_clean_1" in task_ids_called


# ---------------------------------------------------------------------------
# H10: cleanup_task re-attempted for each partially_cleaned orphan
# ---------------------------------------------------------------------------

def test_H10_cleanup_task_reattempted_for_partially_cleaned(tmp_path):
    """_run_startup_cleanup must call orchestrate(cleanup_task) for partially_cleaned tasks."""
    buckets = {
        "abandoned_tasks": [],
        "needs_cleanup": [],
        "partially_cleaned": [{"task_id": "task_partial_1"}],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_completed", "cleanup_status": "done"}
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    with patch("builtins.input", return_value="c"):
        _run_startup_cleanup(buckets, shell, orch, state, session_file)

    cleanup_calls = [
        c for c in orch.orchestrate.call_args_list
        if c[0][0].get("intent") == "cleanup_task"
    ]
    task_ids_called = [c[0][0]["task_id"] for c in cleanup_calls]
    assert "task_partial_1" in task_ids_called


# ---------------------------------------------------------------------------
# H11: still partial after re-attempt → added to manual_cleanup_pending
# ---------------------------------------------------------------------------

def test_H11_still_partial_batch_force_marks(tmp_path):
    """Batch [C] path: if cleanup returns partial, mark_task_cleaned is called (force-mark)."""
    buckets = {
        "abandoned_tasks": [],
        "needs_cleanup": [],
        "partially_cleaned": [{"task_id": "task_stubborn"}],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    shell = MagicMock()
    shell._hitl_callback = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_partially_cleaned", "cleanup_status": "partial"}
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    with patch("builtins.input", return_value="c"):
        _run_startup_cleanup(buckets, shell, orch, state, session_file)

    # Batch path force-marks partial tasks via mark_task_cleaned (no manual_cleanup_pending)
    orch.mark_task_cleaned.assert_called_once_with("task_stubborn")


def test_H11b_still_partial_review_adds_to_manual_cleanup_pending(tmp_path):
    """Review [R] path: if cleanup remains partial after re-attempt, add to manual_cleanup_pending."""
    buckets = {
        "abandoned_tasks": [],
        "needs_cleanup": [],
        "partially_cleaned": [{"task_id": "task_stubborn"}],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_partially_cleaned", "cleanup_status": "partial"}
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    with patch("builtins.input", return_value="y"):
        from ghost_agent import _run_interactive_cleanup
        _run_interactive_cleanup(buckets, shell, orch, state, session_file, location="eastus")

    assert "task_stubborn" in state.get("manual_cleanup_pending", [])


# ---------------------------------------------------------------------------
# H12: skip ([S]) — no cleanup called
# ---------------------------------------------------------------------------

def test_H12_skip_skips_all_cleanup(tmp_path):
    """Choosing [S]kip must not call orchestrate at all."""
    buckets = {
        "abandoned_tasks": [{"task_id": "task_aband_1"}],
        "needs_cleanup": [{"task_id": "task_clean_1"}],
        "partially_cleaned": [],
        "untracked_azure": [],
        "stale_local_files": [],
    }
    shell = MagicMock()
    orch = MagicMock()
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    with patch("builtins.input", return_value="s"):
        _run_startup_cleanup(buckets, shell, orch, state, session_file)

    orch.orchestrate.assert_not_called()


# ---------------------------------------------------------------------------
# H13: --resume verifies checksum (covered in S4/S5 via _load_session)
# ---------------------------------------------------------------------------

def test_H13_resume_verifies_checksum(tmp_path, sample_state):
    """_load_session is the resume entry point and verifies checksum integrity."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)
    sid = sample_state["session_id"]

    # Unmodified file must load successfully (valid checksum)
    result = ghost_agent._load_session(str(path), sid)
    assert result is not None
    assert result["is_resume"] is True


# ---------------------------------------------------------------------------
# H14: --resume reconstructs history from shell_audit JSONL
# ---------------------------------------------------------------------------

def test_H14_resume_reconstructs_history_from_jsonl(tmp_path):
    """_reconstruct_history must build model+user turn pairs from shell audit JSONL."""
    sid = "ghost_20240101_120000"
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
        "output_summary": "64 bytes...",
        "audit_id": f"{sid}_001",
    }
    shell_path = tmp_path / f"shell_audit_{sid}.jsonl"
    with open(shell_path, "w") as f:
        f.write(json.dumps(shell_record) + "\n")

    history = ghost_agent._reconstruct_history(audit_dir, sid)

    # Must have at least one model turn + one user turn
    assert len(history) >= 2
    roles = [h.role for h in history]
    # History must contain model turns with function_call
    model_turns = [h for h in history if h.role == "model"]
    assert len(model_turns) >= 1
    user_turns = [h for h in history if h.role == "user"]
    assert len(user_turns) >= 1
    # Last turn must be user role
    assert history[-1].role == "user"


# ---------------------------------------------------------------------------
# H15: session_id matches ghost_{YYYYMMDD}_{HHMMSS}
# ---------------------------------------------------------------------------

def test_H15_session_id_matches_pattern():
    """_new_session must return a session_id matching ghost_{YYYYMMDD}_{HHMMSS}."""
    state = _new_session("gemini-2.0-flash", "./audit")
    sid = state["session_id"]
    pattern = re.compile(r"^ghost_\d{8}_\d{6}$")
    assert pattern.match(sid), f"session_id '{sid}' does not match ghost_{{YYYYMMDD}}_{{HHMMSS}}"


# ---------------------------------------------------------------------------
# H16: orphan detection catches FAILED/CANCELLED/TIMED_OUT with cleanup_status=pending
# (Fix 2: previously only checked cleanup_status is None and missed CANCELLED entirely)
# ---------------------------------------------------------------------------

def test_H16_orphan_detection_cancelled_with_cleanup_pending():
    """_detect_orphans must classify CANCELLED tasks with cleanup_status='pending' as needs_cleanup."""
    import sys, types as _types

    # Build a minimal CloudOrchestrator class that exposes only _detect_orphans behaviour.
    # We test the ghost_agent._classify_orphans path since cloud_orchestrator is not imported
    # in tests (it requires Azure SDK).  Instead verify the source directly.
    import inspect
    import importlib
    import os

    orch_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "agentic-cloud-orchestrator", "cloud_orchestrator.py",
    )
    src = open(orch_path).read()

    # Verify the fix is present in source: CANCELLED in the needs_cleanup condition
    assert "CANCELLED" in src, "_detect_orphans must check CANCELLED state"
    # Verify cleanup_status='pending' check is present
    assert '"pending"' in src or "'pending'" in src, \
        "_detect_orphans must check cleanup_status='pending'"
    # Confirm the old insufficient condition (is None only) is not the sole check
    condition_line = [l for l in src.splitlines() if "FAILED" in l and "TIMED_OUT" in l and "cleanup_status" in l]
    assert condition_line, "Expected combined FAILED/TIMED_OUT/CANCELLED cleanup_status condition"
    assert "CANCELLED" in condition_line[0], "CANCELLED must be in the orphan detection condition"


# ---------------------------------------------------------------------------
# H17: trivial text-only response auto-continues without prompting user
# ---------------------------------------------------------------------------

def test_H17_trivial_text_only_auto_continues(tmp_path):
    """Short text-only responses during active investigation must auto-continue (no user input)."""
    from ghost_agent import _run_loop, _new_session, _build_ghost_tools, save_session
    from tests.conftest import make_fc_response, make_text_response
    from unittest.mock import MagicMock, patch

    state = _new_session("gemini-2.0-flash", str(tmp_path / "audit"))
    state["active_task_ids"] = ["ghost_tf-source-vm_stub"]
    state["active_hypothesis_ids"] = ["H1"]
    session_file = str(tmp_path / "session.json")
    ghost_tools = _build_ghost_tools()
    shell = MagicMock()
    orch = MagicMock()

    # First response: trivial text-only (simulates "[recovering]" brain echo)
    trivial = make_text_response("[recovering]")
    # Second response: complete_investigation so loop exits
    done = make_fc_response("complete_investigation", {
        "confidence": "low",
        "root_cause_summary": "Could not complete.",
    })

    client = MagicMock()
    client.models.generate_content.side_effect = [trivial, done]

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            with patch("builtins.input") as mock_input:
                _run_loop(state, [], shell, orch, ghost_tools, client, session_file)
                # "Continue investigation?" must NOT have been called
                # (auto-continue fires instead of user prompt)
                continue_calls = [
                    c for c in mock_input.call_args_list
                    if "Continue investigation" in str(c)
                ]
                assert not continue_calls, (
                    "Short text-only response during active investigation "
                    "must not prompt the user for Continue/Done"
                )


# ---------------------------------------------------------------------------
# H18: capture_traffic auto-chains: _burst_poll called inside _create_single_capture
# ---------------------------------------------------------------------------

def test_H18_capture_traffic_auto_chains_burst_poll():
    """capture_traffic must call _burst_poll at the end of _create_single_capture (source check)."""
    import os
    orch_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "agentic-cloud-orchestrator", "cloud_orchestrator.py",
    )
    src = open(orch_path).read()
    # The provisioning block must end with _burst_poll, not _build_response, so that
    # capture_traffic blocks until capture completes.
    assert "return self._burst_poll(task)" in src, (
        "_create_single_capture must return self._burst_poll(task) at the end of the "
        "WAITING state transition (auto-chain fix)"
    )
