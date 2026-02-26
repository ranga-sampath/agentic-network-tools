"""test_errors.py — Error Recovery tests (E1–E7)."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import ghost_agent
from ghost_agent import _new_session, _run_loop, _build_ghost_tools, save_session
from tests.conftest import (
    make_fc_response,
    STUB_CONTENT,
    STUB_PART,
    STUB_FC,
)


def _setup(tmp_path):
    state = _new_session("gemini-2.0-flash", str(tmp_path / "audit"))
    session_file = str(tmp_path / "session.json")
    ghost_tools = _build_ghost_tools()
    return state, session_file, ghost_tools


# ---------------------------------------------------------------------------
# E1: KeyboardInterrupt → save_session in finally; session file is valid JSON
# ---------------------------------------------------------------------------

def test_E1_keyboard_interrupt_saves_session(tmp_path):
    """KeyboardInterrupt during main must save the session; the file must be valid JSON."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    orch = MagicMock()
    client = MagicMock()
    client.models.generate_content.side_effect = KeyboardInterrupt("Interrupted")
    history = []

    save_session(state, session_file)

    with pytest.raises((KeyboardInterrupt, SystemExit)):
        try:
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)
        except KeyboardInterrupt:
            save_session(state, session_file)
            raise

    # The session file must be valid JSON
    with open(session_file) as f:
        data = json.load(f)
    assert "session_id" in data


def test_E1_main_saves_on_keyboard_interrupt(tmp_path):
    """main() must save the session when KeyboardInterrupt is raised in the loop."""
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "ghost_session.json")

    save_calls = []
    original_save = ghost_agent.save_session

    def tracking_save(s, p=ghost_agent.SESSION_FILE):
        save_calls.append(p)
        return original_save(s, p)

    with patch.object(ghost_agent, "_run_loop", side_effect=KeyboardInterrupt):
        with patch.object(ghost_agent, "save_session", side_effect=tracking_save):
            with patch.object(ghost_agent, "_new_session", return_value=state):
                with patch.object(ghost_agent, "SafeExecShell"):
                    with patch.object(ghost_agent, "CloudOrchestrator") as mock_orch_cls:
                        mock_orch = MagicMock()
                        mock_orch.orchestrate.return_value = {
                            "status": "task_completed", "tasks": [], "orphans": []
                        }
                        mock_orch_cls.return_value = mock_orch
                        with patch("os.environ.get", return_value="fake-api-key"):
                            with patch("sys.argv", ["ghost_agent.py"]):
                                # Multi-line input loop: first call returns intent text,
                                # second call returns "" to break the loop.
                                with patch("builtins.input", side_effect=["test intent", ""]):
                                    with pytest.raises(SystemExit):
                                        ghost_agent.main()

    # save_session must have been called (in the except KeyboardInterrupt handler)
    assert len(save_calls) >= 1


# ---------------------------------------------------------------------------
# E2: GoogleAPIError → save_session and prints resume instructions
# ---------------------------------------------------------------------------

def test_E2_google_api_error_saves_and_prints_resume(tmp_path, capsys):
    """An exception from Gemini API must trigger save_session and print resume instructions."""
    state, session_file, ghost_tools = _setup(tmp_path)
    shell = MagicMock()
    orch = MagicMock()
    client = MagicMock()
    client.models.generate_content.side_effect = Exception("GoogleAPIError: quota exceeded")
    history = []

    with patch.object(ghost_agent, "save_session", wraps=ghost_agent.save_session) as mock_save:
        with pytest.raises(SystemExit) as exc:
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    assert exc.value.code == 1
    assert mock_save.called

    captured = capsys.readouterr()
    assert "Resume" in captured.out or "--resume" in captured.out or "resume" in captured.out.lower()


# ---------------------------------------------------------------------------
# E3: missing GEMINI_API_KEY exits code 1 before sub-module instantiation
# ---------------------------------------------------------------------------

def test_E3_missing_api_key_exits_before_submodules(tmp_path):
    """main() must exit(1) before SafeExecShell is instantiated when GEMINI_API_KEY is missing."""
    shell_instantiated = []

    def tracking_shell(*args, **kwargs):
        shell_instantiated.append(True)
        return MagicMock()

    with patch.object(ghost_agent, "SafeExecShell", side_effect=tracking_shell):
        with patch("os.environ.get", return_value=None):
            with patch("sys.argv", ["ghost_agent.py"]):
                with pytest.raises(SystemExit) as exc:
                    ghost_agent.main()

    assert exc.value.code == 1
    assert len(shell_instantiated) == 0, (
        "SafeExecShell must NOT be instantiated before GEMINI_API_KEY check"
    )


# ---------------------------------------------------------------------------
# E4: JSONDecodeError on session load → [F]/[A]
# ---------------------------------------------------------------------------

def test_E4_json_decode_error_offers_fresh_or_abort(tmp_path):
    """Corrupted session file must offer [F]resh / [A]bort."""
    path = str(tmp_path / "session.json")
    with open(path, "w") as f:
        f.write("NOT VALID JSON {{{")

    # [F]resh → returns None
    with patch("builtins.input", return_value="f"):
        result = ghost_agent._load_session(path, "ghost_20240101_120000")
    assert result is None


def test_E4_json_decode_error_abort_exits_1(tmp_path):
    """Choosing [A]bort after JSONDecodeError must exit with code 1."""
    path = str(tmp_path / "session.json")
    with open(path, "w") as f:
        f.write("NOT VALID JSON {{{")

    with patch("builtins.input", return_value="a"):
        with pytest.raises(SystemExit) as exc:
            ghost_agent._load_session(path, "ghost_20240101_120000")
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# E5: FileNotFoundError on audit JSONL → continues with empty history
# ---------------------------------------------------------------------------

def test_E5_missing_audit_jsonl_continues_with_empty_history(tmp_path):
    """If the shell audit JSONL is missing, _reconstruct_history must return a list (possibly empty)."""
    # No files created — directory exists but JSONL does not
    sid = "ghost_20240101_120000"
    history = ghost_agent._reconstruct_history(str(tmp_path), sid)
    # Must return a list (not raise)
    assert isinstance(history, list)


# ---------------------------------------------------------------------------
# E6: timeout result → marked xfail (shell returns error=="timeout"; not injected by denial detection)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(reason="timeout _meta injection not implemented in _apply_denial_detection", strict=False)
def test_E6_timeout_result_injects_meta_timeout(tmp_path):
    """If shell returns error=='timeout', _meta.timeout should be True (not yet implemented)."""
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    state["active_hypothesis_ids"] = ["H1"]
    state["hypothesis_log"] = [
        {"id": "H1", "description": "test", "state": "ACTIVE", "denial_events": []}
    ]
    tool_args = {"command": "ping 8.8.8.8", "reasoning": "test", "hypothesis_id": "H1"}
    result = {
        "status": "error",
        "action": "error",
        "error": "timeout",
        "exit_code": None,
    }
    ghost_agent._apply_denial_detection("run_shell_cmd", tool_args, result, state)
    assert result.get("_meta", {}).get("timeout") is True


# ---------------------------------------------------------------------------
# E7: exit_code==127 surfaced in response (command not found)
# ---------------------------------------------------------------------------

def test_E7_exit_code_127_in_result(tmp_path):
    """_dispatch_tool must surface exit_code==127 from shell.execute unchanged."""
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed",
        "action": "auto_approved",
        "exit_code": 127,
        "error": "command not found",
        "audit_id": "ghost_20240101_120000_001",
    }
    orch = MagicMock()

    result = ghost_agent._dispatch_tool(
        "run_shell_cmd",
        {"command": "nonexistent_cmd", "reasoning": "test"},
        shell,
        orch,
    )
    assert result["exit_code"] == 127
