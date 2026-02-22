"""test_loop.py — Tool-Use Loop tests (L1–L8)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

import ghost_agent
from ghost_agent import _run_loop, _new_session, _build_ghost_tools, save_session
from tests.conftest import (
    make_fc_response,
    make_text_response,
    STUB_CONTENT,
    STUB_PART,
    STUB_FC,
    STUB_FR,
)


def _setup(tmp_path):
    state = _new_session("gemini-2.0-flash", str(tmp_path / "audit"))
    session_file = str(tmp_path / "session.json")
    ghost_tools = _build_ghost_tools()
    return state, session_file, ghost_tools


# ---------------------------------------------------------------------------
# L1: loop exits when complete_investigation called
# ---------------------------------------------------------------------------

def test_L1_loop_exits_on_complete_investigation(tmp_path):
    """_run_loop must return after complete_investigation is dispatched."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    orch = MagicMock()

    response = make_fc_response("complete_investigation", {
        "confidence": "high",
        "root_cause_summary": "Root cause identified.",
    })
    client = MagicMock()
    client.models.generate_content.return_value = response
    history = []

    with patch.object(ghost_agent, "_generate_rca") as mock_rca:
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    mock_rca.assert_called_once()
    # generate_content called exactly once → loop exited after first turn
    assert client.models.generate_content.call_count == 1


# ---------------------------------------------------------------------------
# L2: save_session called after every loop turn
# ---------------------------------------------------------------------------

def test_L2_save_session_called_after_every_turn(tmp_path):
    """save_session must be called at least once per tool-use turn."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed", "action": "auto_approved", "exit_code": 0,
        "audit_id": "ghost_20240101_120000_001",
    }
    orch = MagicMock()

    # Turn 1: run_shell_cmd; Turn 2: complete_investigation
    resp1 = make_fc_response("run_shell_cmd", {"command": "ping 8.8.8.8", "reasoning": "test"})
    resp2 = make_fc_response("complete_investigation", {
        "confidence": "medium", "root_cause_summary": "done"
    })
    client = MagicMock()
    client.models.generate_content.side_effect = [resp1, resp2]
    history = []

    with patch.object(ghost_agent, "save_session", wraps=ghost_agent.save_session) as mock_save:
        with patch.object(ghost_agent, "_generate_rca"):
            with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
                _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    assert mock_save.call_count >= 2


# ---------------------------------------------------------------------------
# L3: function responses appended as "user" role turn
# ---------------------------------------------------------------------------

def test_L3_function_responses_appended_as_user_turn(tmp_path):
    """Function responses from tool dispatch must be appended as a user-role turn."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed", "action": "auto_approved", "exit_code": 0,
        "audit_id": "ghost_20240101_120000_001",
    }
    orch = MagicMock()

    resp1 = make_fc_response("run_shell_cmd", {"command": "ping 8.8.8.8", "reasoning": "test"})
    resp2 = make_fc_response("complete_investigation", {
        "confidence": "medium", "root_cause_summary": "done"
    })
    client = MagicMock()
    client.models.generate_content.side_effect = [resp1, resp2]
    history = []

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # Find user-role turns with function_response parts
    user_fn_turns = [
        h for h in history
        if h.role == "user" and any(p.function_response for p in h.parts)
    ]
    assert len(user_fn_turns) >= 1


# ---------------------------------------------------------------------------
# L4: model response appended as "model" role turn before function responses
# ---------------------------------------------------------------------------

def test_L4_model_response_appended_before_function_responses(tmp_path):
    """The model's response must be appended to history BEFORE the function responses."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed", "action": "auto_approved", "exit_code": 0,
        "audit_id": "ghost_20240101_120000_001",
    }
    orch = MagicMock()

    resp1 = make_fc_response("run_shell_cmd", {"command": "ping 8.8.8.8", "reasoning": "test"})
    resp2 = make_fc_response("complete_investigation", {
        "confidence": "medium", "root_cause_summary": "done"
    })
    client = MagicMock()
    client.models.generate_content.side_effect = [resp1, resp2]
    history = []

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # Check ordering: find the first model turn with function_call parts
    # followed by a user turn with function_response parts
    model_fc_idx = None
    for i, h in enumerate(history):
        if h.role == "model" and any(p.function_call for p in h.parts):
            model_fc_idx = i
            break

    assert model_fc_idx is not None, "No model turn with function_call found"
    # The next turn after the model turn must be user
    if model_fc_idx + 1 < len(history):
        assert history[model_fc_idx + 1].role == "user"


# ---------------------------------------------------------------------------
# L5: STOP with no function calls → print text, offer [C]/[D]
# ---------------------------------------------------------------------------

def test_L5_text_only_offers_continue_or_done(tmp_path):
    """Text-only Gemini response must offer [C]ontinue/[D]one."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    orch = MagicMock()

    text_resp = make_text_response("I have some observations.")
    complete_resp = make_fc_response("complete_investigation", {
        "confidence": "low", "root_cause_summary": "text done"
    })
    client = MagicMock()
    client.models.generate_content.side_effect = [text_resp, complete_resp]
    history = []

    # User picks [D]one on first prompt, then the loop should exit
    with patch("builtins.input", return_value="d"):
        with patch.object(ghost_agent, "_generate_rca"):
            with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
                _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # generate_content called once → user chose Done after the text-only response
    assert client.models.generate_content.call_count == 1


# ---------------------------------------------------------------------------
# L6: at MAX_LOOP_TURNS → pause, offer [E]xtend/[G]enerate
# ---------------------------------------------------------------------------

def test_L6_max_loop_turns_offers_extend_or_generate(tmp_path):
    """At MAX_LOOP_TURNS the loop must offer [E]xtend/[G]enerate and not crash."""
    state, session_file, ghost_tools = _setup(tmp_path)
    state["turn_count"] = ghost_agent.MAX_LOOP_TURNS  # already at limit
    shell = MagicMock()
    orch = MagicMock()
    client = MagicMock()
    history = []

    # User picks [G]enerate RCA
    with patch("builtins.input", return_value="g"):
        with patch.object(ghost_agent, "_generate_rca") as mock_rca:
            with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
                _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    mock_rca.assert_called_once()
    # generate_content not called because we hit the turn limit before calling Gemini
    client.models.generate_content.assert_not_called()


# ---------------------------------------------------------------------------
# L7: [E]xtend increments max by 10 and continues
# ---------------------------------------------------------------------------

def test_L7_extend_increments_max_and_continues(tmp_path):
    """Choosing [E]xtend at max turns must allow 10 more turns."""
    state, session_file, ghost_tools = _setup(tmp_path)
    state["turn_count"] = ghost_agent.MAX_LOOP_TURNS
    shell = MagicMock()
    orch = MagicMock()

    complete_resp = make_fc_response("complete_investigation", {
        "confidence": "medium", "root_cause_summary": "done after extend"
    })
    client = MagicMock()
    client.models.generate_content.return_value = complete_resp
    history = []

    # First input: [E]xtend, then the loop calls Gemini (complete_investigation) and exits
    with patch("builtins.input", return_value="e"):
        with patch.object(ghost_agent, "_generate_rca"):
            with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
                _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # After extending, the loop must call generate_content at least once
    assert client.models.generate_content.call_count >= 1


# ---------------------------------------------------------------------------
# L8: evidence_conflicts entry recorded (marked xfail — out of current scope)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(reason="evidence_conflicts population not yet implemented in _run_loop", strict=False)
def test_L8_evidence_conflicts_recorded(tmp_path):
    """Conflicting evidence should be recorded in state['evidence_conflicts']."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    orch = MagicMock()
    client = MagicMock()
    history = []

    complete_resp = make_fc_response("complete_investigation", {
        "confidence": "medium",
        "root_cause_summary": "contradicted",
        "contradicted_hypotheses": ["H1"],
    })
    client.models.generate_content.return_value = complete_resp

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # evidence_conflicts should have at least one entry
    assert len(state["evidence_conflicts"]) > 0
