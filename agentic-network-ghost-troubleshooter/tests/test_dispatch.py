"""test_dispatch.py — Tool Dispatch tests (D1–D12)."""

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import ghost_agent
from ghost_agent import _dispatch_tool, _build_ghost_tools, _run_loop, _new_session
from tests.conftest import (
    STUB_SAFE_EXEC_SHELL,
    STUB_CLOUD_ORCHESTRATOR,
    make_fc_response,
    make_text_response,
    STUB_CONTENT,
    STUB_PART,
    STUB_FC,
    STUB_FR,
)

GHOST_AGENT_PATH = Path(__file__).parent.parent / "ghost_agent.py"


# ---------------------------------------------------------------------------
# D1: run_shell_cmd → shell.execute({"command":...,"reasoning":...})
# ---------------------------------------------------------------------------

def test_D1_run_shell_cmd_calls_shell_execute():
    """_dispatch_tool('run_shell_cmd') must call shell.execute with command and reasoning."""
    shell = MagicMock()
    shell.execute.return_value = {"status": "completed", "exit_code": 0}
    orch = MagicMock()

    tool_args = {"command": "ping 8.8.8.8", "reasoning": "Check connectivity"}
    _dispatch_tool("run_shell_cmd", tool_args, shell, orch)

    shell.execute.assert_called_once_with({
        "command": "ping 8.8.8.8",
        "reasoning": "Check connectivity",
    })
    orch.orchestrate.assert_not_called()


# ---------------------------------------------------------------------------
# D2: capture_traffic → orchestrator.orchestrate({"intent":"capture_traffic",...})
# ---------------------------------------------------------------------------

def test_D2_capture_traffic_calls_orchestrate():
    """_dispatch_tool('capture_traffic') must call orchestrator.orchestrate with correct payload."""
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_pending", "task_id": "t1"}

    tool_args = {
        "target": "vm-test",
        "resource_group": "rg1",
        "storage_account": "sa1",
        "investigation_context": "Testing",
        "duration_seconds": 60,
    }
    _dispatch_tool("capture_traffic", tool_args, shell, orch)

    shell.execute.assert_not_called()
    call_args = orch.orchestrate.call_args[0][0]
    assert call_args["intent"] == "capture_traffic"
    assert call_args["target"] == "vm-test"
    assert call_args["investigation_context"] == "Testing"
    assert call_args["parameters"]["resource_group"] == "rg1"
    assert call_args["parameters"]["storage_account"] == "sa1"
    assert call_args["parameters"]["duration_seconds"] == 60


# ---------------------------------------------------------------------------
# D3: check_task → orchestrator.orchestrate({"intent":"check_task","task_id":...})
# ---------------------------------------------------------------------------

def test_D3_check_task_calls_orchestrate():
    """_dispatch_tool('check_task') must call orchestrate with intent=check_task."""
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_pending", "task_id": "t1"}

    _dispatch_tool("check_task", {"task_id": "t1"}, shell, orch)

    shell.execute.assert_not_called()
    call_args = orch.orchestrate.call_args[0][0]
    assert call_args["intent"] == "check_task"
    assert call_args["task_id"] == "t1"


# ---------------------------------------------------------------------------
# D4: cancel_task → orchestrator.orchestrate({"intent":"cancel_task","task_id":...})
# ---------------------------------------------------------------------------

def test_D4_cancel_task_calls_orchestrate():
    """_dispatch_tool('cancel_task') must call orchestrate with intent=cancel_task."""
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_cancelled", "task_id": "t2"}

    _dispatch_tool("cancel_task", {"task_id": "t2"}, shell, orch)

    shell.execute.assert_not_called()
    call_args = orch.orchestrate.call_args[0][0]
    assert call_args["intent"] == "cancel_task"
    assert call_args["task_id"] == "t2"


# ---------------------------------------------------------------------------
# D5: cleanup_task → orchestrator.orchestrate({"intent":"cleanup_task","task_id":...})
# ---------------------------------------------------------------------------

def test_D5_cleanup_task_calls_orchestrate():
    """_dispatch_tool('cleanup_task') must call orchestrate with intent=cleanup_task."""
    shell = MagicMock()
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_completed", "task_id": "t3"}

    _dispatch_tool("cleanup_task", {"task_id": "t3"}, shell, orch)

    shell.execute.assert_not_called()
    call_args = orch.orchestrate.call_args[0][0]
    assert call_args["intent"] == "cleanup_task"
    assert call_args["task_id"] == "t3"


# ---------------------------------------------------------------------------
# D6: complete_investigation does NOT call shell or orchestrator (loop exits)
# ---------------------------------------------------------------------------

def test_D6_complete_investigation_no_shell_or_orch(tmp_path):
    """complete_investigation in _run_loop must not call shell.execute or orch.orchestrate."""
    shell = MagicMock()
    orch = MagicMock()
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    session_file = str(tmp_path / "session.json")

    response = make_fc_response("complete_investigation", {
        "confidence": "high",
        "root_cause_summary": "Root cause found",
    })
    client = MagicMock()
    client.models.generate_content.return_value = response

    ghost_tools = _build_ghost_tools()
    history = []

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    shell.execute.assert_not_called()
    # Orchestrate should NOT be called for the complete_investigation dispatch
    orchestrate_intents = [
        c[0][0].get("intent")
        for c in orch.orchestrate.call_args_list
    ]
    assert "complete_investigation" not in orchestrate_intents


# ---------------------------------------------------------------------------
# D7: unknown tool → {"status":"error","error":"unknown_tool"}
# ---------------------------------------------------------------------------

def test_D7_unknown_tool_returns_error():
    """_dispatch_tool with unknown tool_name must return error dict."""
    shell = MagicMock()
    orch = MagicMock()

    result = _dispatch_tool("totally_unknown_tool", {}, shell, orch)

    assert result["status"] == "error"
    assert result["error"] == "unknown_tool"
    assert result["tool"] == "totally_unknown_tool"
    shell.execute.assert_not_called()
    orch.orchestrate.assert_not_called()


# ---------------------------------------------------------------------------
# D8: subprocess never imported in ghost_agent.py (AST check)
# ---------------------------------------------------------------------------

def test_D8_no_subprocess_import():
    """ghost_agent.py must not import subprocess anywhere."""
    src = GHOST_AGENT_PATH.read_text()
    tree = ast.parse(src)

    imported_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)

    assert "subprocess" not in imported_modules, (
        "ghost_agent.py must not import subprocess"
    )


# ---------------------------------------------------------------------------
# D9: pcap_forensics never imported in ghost_agent.py (AST check)
# ---------------------------------------------------------------------------

def test_D9_no_pcap_forensics_import():
    """ghost_agent.py must not import pcap_forensics anywhere."""
    src = GHOST_AGENT_PATH.read_text()
    tree = ast.parse(src)

    imported_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)

    for mod in imported_modules:
        assert "pcap_forensics" not in mod, (
            f"ghost_agent.py must not import pcap_forensics (found: {mod})"
        )


# ---------------------------------------------------------------------------
# D10: multiple function_call parts dispatched before response appended
# ---------------------------------------------------------------------------

def test_D10_multiple_function_calls_dispatched(tmp_path):
    """_run_loop must dispatch all function_call parts before appending the user turn."""
    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed", "action": "auto_approved", "exit_code": 0,
        "audit_id": "ghost_20240101_120000_001",
    }
    orch = MagicMock()
    orch.orchestrate.return_value = {"status": "task_completed"}

    state = _new_session("gemini-2.0-flash", str(tmp_path))
    state["active_hypothesis_ids"] = ["H1"]
    session_file = str(tmp_path / "session.json")

    # First response: two function calls
    fc1 = STUB_FC(name="run_shell_cmd", args={"command": "ping 8.8.8.8", "reasoning": "test"})
    fc2 = STUB_FC(name="run_shell_cmd", args={"command": "dig google.com", "reasoning": "test2"})
    p1 = STUB_PART(function_call=fc1)
    p2 = STUB_PART(function_call=fc2)
    content1 = STUB_CONTENT(role="model", parts=[p1, p2])
    cand1 = MagicMock()
    cand1.content = content1
    cand1.finish_reason = "STOP"
    resp1 = MagicMock()
    resp1.candidates = [cand1]

    # Second response: complete_investigation
    resp2 = make_fc_response("complete_investigation", {
        "confidence": "medium",
        "root_cause_summary": "Done",
    })

    client = MagicMock()
    client.models.generate_content.side_effect = [resp1, resp2]

    ghost_tools = _build_ghost_tools()
    history = []

    with patch.object(ghost_agent, "_generate_rca"):
        with patch.object(ghost_agent, "_offer_cleanup_before_rca"):
            _run_loop(state, history, shell, orch, ghost_tools, client, session_file)

    # shell.execute should have been called twice (for each function_call)
    assert shell.execute.call_count == 2


# ---------------------------------------------------------------------------
# D11: capture_traffic schema does not have storage_auth_mode
# ---------------------------------------------------------------------------

def test_D11_capture_traffic_no_storage_auth_mode():
    """capture_traffic FunctionDeclaration must not have storage_auth_mode parameter."""
    tools = _build_ghost_tools()
    capture_decl = next(
        (fd for fd in tools.function_declarations if fd.name == "capture_traffic"),
        None,
    )
    assert capture_decl is not None
    if capture_decl.parameters and capture_decl.parameters.properties:
        assert "storage_auth_mode" not in capture_decl.parameters.properties, (
            "capture_traffic schema must not contain storage_auth_mode"
        )


# ---------------------------------------------------------------------------
# D12: --storage-auth-mode CLI argument exists
# ---------------------------------------------------------------------------

def test_D12_storage_auth_mode_cli_arg_exists():
    """ghost_agent main() must define a --storage-auth-mode argument."""
    import inspect
    src = inspect.getsource(ghost_agent.main)
    assert "storage-auth-mode" in src or "storage_auth_mode" in src, (
        "main() must define --storage-auth-mode CLI argument"
    )
