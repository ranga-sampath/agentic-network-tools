"""test_empty_response_recovery.py — unit tests for _recover_empty_response (IMP-02).

Covers the consolidated recovery path shared by the empty-candidates and
candidate.content=None branches of _run_loop: counter increment, synthetic
model bridge + targeted user nudge, nudge selection by session state, and
the 3-strike halt.
"""

import pytest

from ghost_agent import _new_session, _recover_empty_response


def _state(**overrides):
    state = _new_session("gemini-2.0-flash", "./audit")
    state.update(overrides)
    return state


def test_counter_increments_and_history_gets_bridge_and_nudge(tmp_path):
    state = _state(active_hypothesis_ids=["H1"])
    history = []
    session_file = str(tmp_path / "s.json")

    new_count = _recover_empty_response(
        state, history, session_file, 0,
        warn_prefix="LLM empty response", detail="safety/quota",
        halt_message="Persistent empty responses after 3 attempts. Halting.",
    )

    assert new_count == 1
    # Synthetic model bridge, then user nudge — valid alternating history
    assert len(history) == 2
    assert history[0].role == "model"
    assert history[0].parts[0].text == "[recovering]"
    assert history[1].role == "user"


def test_nudge_targets_pending_capture_task(tmp_path):
    state = _state(active_task_ids=["ghost_vm_20260707T120000"])
    history = []

    _recover_empty_response(
        state, history, str(tmp_path / "s.json"), 0,
        warn_prefix="LLM empty response", detail="safety/quota",
        halt_message="halt",
    )

    nudge = history[1].parts[0].text
    assert "check_task" in nudge
    assert "ghost_vm_20260707T120000" in nudge


def test_nudge_continues_investigation_when_hypotheses_active(tmp_path):
    state = _state(active_hypothesis_ids=["H1"])
    history = []

    _recover_empty_response(
        state, history, str(tmp_path / "s.json"), 0,
        warn_prefix="LLM candidate content is None", detail="finish_reason=SAFETY",
        halt_message="halt",
    )

    assert "Continue the investigation" in history[1].parts[0].text


def test_nudge_requests_completion_when_nothing_active(tmp_path):
    state = _state()
    history = []

    _recover_empty_response(
        state, history, str(tmp_path / "s.json"), 0,
        warn_prefix="LLM empty response", detail="safety/quota",
        halt_message="halt",
    )

    assert "complete_investigation" in history[1].parts[0].text


def test_third_strike_halts_with_abort_reason(tmp_path):
    state = _state(active_hypothesis_ids=["H1"])
    history = []
    session_file = str(tmp_path / "s.json")

    with pytest.raises(SystemExit) as exc_info:
        _recover_empty_response(
            state, history, session_file, 2,
            warn_prefix="LLM empty response", detail="safety/quota",
            halt_message="Persistent empty responses after 3 attempts. Halting.",
        )

    assert exc_info.value.code == 1
    assert state["abort_reason"] == "empty_response"
    # No bridge/nudge appended on the halt path
    assert history == []
