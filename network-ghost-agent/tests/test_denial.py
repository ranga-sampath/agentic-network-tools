"""test_denial.py — Denial State Machine tests (M1–M11)."""

from unittest.mock import MagicMock, patch

import pytest

import ghost_agent
from ghost_agent import (
    _apply_denial_detection,
    _new_session,
)


def _base_state(audit_dir="./audit"):
    state = _new_session("gemini-2.0-flash", audit_dir)
    state["active_hypothesis_ids"] = ["H1", "H2"]
    state["hypothesis_log"] = [
        {"id": "H1", "description": "H1 desc", "state": "ACTIVE", "denial_events": []},
        {"id": "H2", "description": "H2 desc", "state": "ACTIVE", "denial_events": []},
    ]
    return state


def _denied_shell_result(audit_id="ghost_20240101_120000_001"):
    return {
        "status": "denied",
        "action": "user_denied",
        "audit_id": audit_id,
        "exit_code": None,
    }


# ---------------------------------------------------------------------------
# M1: denial_tracker[h_id] increments on user_denied
# ---------------------------------------------------------------------------

def test_M1_denial_tracker_increments_on_user_denied():
    """denial_tracker[h_id] must increment by 1 on each user_denied result."""
    state = _base_state()
    result = _denied_shell_result()
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("run_shell_cmd", tool_args, result, state)
    assert state["denial_tracker"].get("H1", 0) == 1

    result2 = _denied_shell_result()
    _apply_denial_detection("run_shell_cmd", tool_args, result2, state)
    assert state["denial_tracker"].get("H1", 0) == 2


# ---------------------------------------------------------------------------
# M2: count==1 → pivot_instruction injected
# ---------------------------------------------------------------------------

def test_M2_count_1_pivot_instruction():
    """First denial must inject _meta.pivot_instruction."""
    state = _base_state()
    result = _denied_shell_result()
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("run_shell_cmd", tool_args, result, state)

    assert state["denial_tracker"]["H1"] == 1
    assert "pivot_instruction" in result.get("_meta", {})
    assert result["_meta"]["pivot_instruction"]


# ---------------------------------------------------------------------------
# M3: count==2 → approaching_threshold=True injected
# ---------------------------------------------------------------------------

def test_M3_count_2_approaching_threshold():
    """Second denial must inject _meta.approaching_threshold=True."""
    state = _base_state()
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    # First denial
    _apply_denial_detection("run_shell_cmd", tool_args, _denied_shell_result("a001"), state)
    # Second denial
    result2 = _denied_shell_result("a002")
    _apply_denial_detection("run_shell_cmd", tool_args, result2, state)

    assert state["denial_tracker"]["H1"] == 2
    meta = result2.get("_meta", {})
    assert meta.get("approaching_threshold") is True
    assert "warning" in meta


# ---------------------------------------------------------------------------
# M4: count>=3 → denial_threshold_reached=True injected
# ---------------------------------------------------------------------------

def test_M4_count_3_threshold_reached():
    """Third denial must inject _meta.denial_threshold_reached=True."""
    state = _base_state()
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    for i in range(2):
        _apply_denial_detection("run_shell_cmd", tool_args, _denied_shell_result(f"a00{i}"), state)

    result3 = _denied_shell_result("a003")
    _apply_denial_detection("run_shell_cmd", tool_args, result3, state)

    assert state["denial_tracker"]["H1"] == 3
    meta = result3.get("_meta", {})
    assert meta.get("denial_threshold_reached") is True


# ---------------------------------------------------------------------------
# M5: h_id removed from active_hypothesis_ids at threshold
# ---------------------------------------------------------------------------

def test_M5_h_id_removed_at_threshold():
    """H1 must be removed from active_hypothesis_ids after 3 denials."""
    state = _base_state()
    assert "H1" in state["active_hypothesis_ids"]
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    for i in range(3):
        _apply_denial_detection("run_shell_cmd", tool_args, _denied_shell_result(f"a00{i}"), state)

    assert "H1" not in state["active_hypothesis_ids"]
    # H2 must remain
    assert "H2" in state["active_hypothesis_ids"]


# ---------------------------------------------------------------------------
# M6: successful tool result resets consecutive_denial_counter for scoped hypotheses
# ---------------------------------------------------------------------------

def test_M6_success_resets_consecutive_denial_counter():
    """A successful (non-denied) result must reset consecutive_denial_counter for scoped h_ids."""
    state = _base_state()
    state["consecutive_denial_counter"] = {"H1": 2, "H2": 1}
    tool_args = {
        "command": "ping 8.8.8.8",
        "reasoning": "test",
        "hypothesis_id": "H1",
    }
    success_result = {
        "status": "completed",
        "action": "auto_approved",
        "exit_code": 0,
        "audit_id": "ghost_20240101_120000_002",
    }
    _apply_denial_detection("run_shell_cmd", tool_args, success_result, state)

    # H1 counter must be reset to 0
    assert state["consecutive_denial_counter"].get("H1", 0) == 0
    # H2 must be unchanged (scoped to H1 only)
    assert state["consecutive_denial_counter"].get("H2", 1) == 1


# ---------------------------------------------------------------------------
# M7: denial applies to attributed hypothesis only (not all active)
# ---------------------------------------------------------------------------

def test_M7_denial_scoped_to_attributed_hypothesis():
    """Denial for H1 must NOT increment denial_tracker for H2."""
    state = _base_state()
    tool_args = {"command": "sudo tcpdump", "reasoning": "capture", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("run_shell_cmd", tool_args, _denied_shell_result(), state)

    assert state["denial_tracker"].get("H1", 0) == 1
    assert state["denial_tracker"].get("H2", 0) == 0


# ---------------------------------------------------------------------------
# M8: once UNVERIFIABLE, h_id not in active (terminal)
# ---------------------------------------------------------------------------

def test_M8_unverifiable_removed_from_active():
    """After 3 denials, H1 must be absent from active_hypothesis_ids (terminal)."""
    state = _base_state()
    tool_args = {"command": "ping", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    for i in range(3):
        _apply_denial_detection("run_shell_cmd", tool_args, _denied_shell_result(f"x{i}"), state)

    assert "H1" not in state["active_hypothesis_ids"]


# ---------------------------------------------------------------------------
# M9: denial_reason captured from terminal_hitl_callback.captured_reason when non-empty
# ---------------------------------------------------------------------------

def test_M9_denial_reason_captured_from_hitl_callback():
    """denial_reason must be captured from terminal_hitl_callback.captured_reason when non-empty."""
    state = _base_state()
    result = _denied_shell_result("a001")
    tool_args = {"command": "sudo tcpdump", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = "Too risky for production"
    _apply_denial_detection("run_shell_cmd", tool_args, result, state)

    assert result["_meta"].get("denial_reason") == "Too risky for production"
    # Must also be persisted to state["denial_reasons"]
    assert state["denial_reasons"].get("a001") == "Too risky for production"

    # Reset for other tests
    ghost_agent.terminal_hitl_callback.captured_reason = ""


# ---------------------------------------------------------------------------
# M10: denial_event {turn,command,denial_reason,audit_id} appended to hypothesis log
# ---------------------------------------------------------------------------

def test_M10_denial_event_appended_to_hypothesis_log():
    """A denial event must be appended to the matching hypothesis log entry."""
    state = _base_state()
    result = _denied_shell_result("a001")
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}
    state["turn_count"] = 3

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("run_shell_cmd", tool_args, result, state)

    h1_entry = next(e for e in state["hypothesis_log"] if e["id"] == "H1")
    assert len(h1_entry["denial_events"]) == 1
    evt = h1_entry["denial_events"][0]
    assert evt["turn"] == 3
    assert evt["command"] == "ping 8.8.8.8"
    assert "audit_id" in evt


# ---------------------------------------------------------------------------
# M11: empty denial reason → denial_reason absent from _meta
# ---------------------------------------------------------------------------

def test_M11_empty_denial_reason_absent_from_meta():
    """If terminal_hitl_callback.captured_reason is empty, _meta must not have denial_reason."""
    state = _base_state()
    result = _denied_shell_result("a001")
    tool_args = {"command": "ping", "reasoning": "test", "hypothesis_id": "H1"}

    ghost_agent.terminal_hitl_callback.captured_reason = ""
    _apply_denial_detection("run_shell_cmd", tool_args, result, state)

    meta = result.get("_meta", {})
    assert "denial_reason" not in meta
