"""test_cancel_task_not_denial.py — cancel_task success is not a denial (BUG-04).

The orchestrator returns status=task_cancelled as cancel_task's normal
success (and idempotent) response. A Brain-initiated cancellation must not
increment denial counters or drive hypotheses toward UNVERIFIABLE; only
HITL-driven signals (run_shell_cmd user_denied, capture_traffic cancelled by
a denied step) advance the denial state machine.
"""

import ghost_agent
from ghost_agent import _apply_denial_detection, _new_session


def _state():
    state = _new_session("gemini-2.0-flash", "./audit")
    state["active_hypothesis_ids"] = ["H1"]
    state["hypothesis_log"] = [
        {"id": "H1", "description": "H1 desc", "state": "ACTIVE", "denial_events": []},
    ]
    return state


def _cancel_result():
    return {"status": "task_cancelled", "task_id": "ghost_vm_20260707T120000",
            "error_detail": "Task cancelled by user"}


def test_successful_cancel_task_does_not_increment_denials():
    state = _state()
    tool_args = {"task_id": "ghost_vm_20260707T120000", "reason": "wrong target",
                 "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("cancel_task", tool_args, _cancel_result(), state)

    assert state["denial_tracker"].get("H1", 0) == 0
    assert "_meta" not in _cancel_result()
    h1 = state["hypothesis_log"][0]
    assert h1["denial_events"] == []


def test_three_cancels_do_not_mark_hypothesis_unverifiable():
    state = _state()
    tool_args = {"task_id": "t1", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    for _ in range(3):
        _apply_denial_detection("cancel_task", tool_args, _cancel_result(), state)

    assert "H1" in state["active_hypothesis_ids"]
    assert state["denial_tracker"].get("H1", 0) == 0


def test_capture_traffic_cancelled_still_counts_as_denial():
    """The HITL-deny sentinel for capture_traffic must keep working."""
    state = _state()
    tool_args = {"target": "vm-a", "resource_group": "rg", "storage_account": "sa",
                 "hypothesis_id": "H1"}
    result = {"status": "task_cancelled", "task_id": "t1",
              "error_detail": "User denied capture creation"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("capture_traffic", tool_args, result, state)

    assert state["denial_tracker"].get("H1", 0) == 1
    assert "pivot_instruction" in result.get("_meta", {})


def test_successful_cancel_resets_consecutive_counter():
    """A successful cancel is a successful tool result — consecutive-denial
    tracking for the scoped hypothesis resets, same as any other success."""
    state = _state()
    state["consecutive_denial_counter"] = {"H1": 2}
    tool_args = {"task_id": "t1", "hypothesis_id": "H1"}

    _apply_denial_detection("cancel_task", tool_args, _cancel_result(), state)

    assert state["consecutive_denial_counter"]["H1"] == 0
