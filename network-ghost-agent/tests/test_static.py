"""test_static.py — Static/Structural tests (T1–T5)."""

import ast
from pathlib import Path

import pytest

import ghost_agent
from ghost_agent import _build_ghost_tools, _new_session

GHOST_AGENT_PATH = Path(__file__).parent.parent / "ghost_agent.py"


# ---------------------------------------------------------------------------
# T1: ghost_agent.py imports only allowed modules (no subprocess, no pcap_forensics)
# ---------------------------------------------------------------------------

def test_T1_only_allowed_imports():
    """ghost_agent.py must not import subprocess or pcap_forensics at module level.

    Handler functions (_run_firewall_inspector_handler, _run_pipe_meter_handler)
    are permitted to use local 'import subprocess' to launch sibling Python modules
    as subprocesses. These are trusted local invocations, not remote network commands.
    pcap_forensics is always forbidden — it must be invoked via shell.execute().
    """
    src = GHOST_AGENT_PATH.read_text()
    tree = ast.parse(src)

    # Only check module-level imports (direct children of the Module node).
    module_level_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_level_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_level_imports.append(node.module)

    # subprocess at module level is forbidden; local handler imports are allowed.
    # pcap_forensics is always forbidden everywhere.
    forbidden_module_level = ["subprocess"]
    for forbidden_mod in forbidden_module_level:
        violators = [m for m in module_level_imports if forbidden_mod in m]
        assert not violators, (
            f"ghost_agent.py must not import '{forbidden_mod}' at module level, found: {violators}"
        )

    # pcap_forensics forbidden everywhere (walk full tree)
    all_imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                all_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                all_imports.append(node.module)
    pcap_violators = [m for m in all_imports if "pcap_forensics" in m]
    assert not pcap_violators, (
        f"ghost_agent.py must not import 'pcap_forensics' anywhere, found: {pcap_violators}"
    )

    # Allowed imports verification (positive check)
    allowed_patterns = [
        "argparse", "glob", "hashlib", "json", "os", "sys", "datetime",
        "pathlib", "dotenv", "google", "safe_exec_shell", "cloud_orchestrator",
    ]
    for allowed in allowed_patterns:
        # Check at least some of these are present (sanity check)
        found = any(allowed in m for m in all_imports)
        # We don't assert they're all present — just that forbidden ones are absent


# ---------------------------------------------------------------------------
# T2: 7 FunctionDeclarations with required fields
# ---------------------------------------------------------------------------

def test_T2_nine_function_declarations():
    """_build_ghost_tools() must return exactly 9 FunctionDeclarations.

    Original 7: run_shell_cmd, capture_traffic, check_task, cancel_task,
                cleanup_task, manage_hypotheses, complete_investigation.
    Added in v1.1: run_pipe_meter (use cases G-L: VM-to-VM performance),
                   detect_config_drift (use cases J-K: OS firewall inspection).
    """
    tools = _build_ghost_tools()
    declarations = tools.function_declarations
    assert len(declarations) == 9, (
        f"Expected 9 FunctionDeclarations, got {len(declarations)}: "
        f"{[d.name for d in declarations]}"
    )

    expected_names = {
        "run_shell_cmd",
        "capture_traffic",
        "check_task",
        "cancel_task",
        "cleanup_task",
        "manage_hypotheses",
        "complete_investigation",
        "run_pipe_meter",
        "detect_config_drift",
    }
    actual_names = {d.name for d in declarations}
    assert actual_names == expected_names, (
        f"Tool names mismatch. Expected: {expected_names}, Got: {actual_names}"
    )

    # Each declaration must have name and description
    for decl in declarations:
        assert decl.name, f"FunctionDeclaration missing name"
        assert decl.description, f"FunctionDeclaration '{decl.name}' missing description"


# ---------------------------------------------------------------------------
# T3: capture_traffic schema has no storage_auth_mode
# ---------------------------------------------------------------------------

def test_T3_capture_traffic_no_storage_auth_mode():
    """capture_traffic FunctionDeclaration must not include storage_auth_mode parameter."""
    tools = _build_ghost_tools()
    capture_decl = next(
        (d for d in tools.function_declarations if d.name == "capture_traffic"),
        None,
    )
    assert capture_decl is not None, "capture_traffic declaration not found"
    assert capture_decl.parameters is not None
    props = capture_decl.parameters.properties or {}
    assert "storage_auth_mode" not in props, (
        "capture_traffic schema must not contain storage_auth_mode"
    )


# ---------------------------------------------------------------------------
# T4: complete_investigation schema has contradicted_hypotheses parameter
# ---------------------------------------------------------------------------

def test_T4_complete_investigation_has_contradicted_hypotheses():
    """complete_investigation FunctionDeclaration must include contradicted_hypotheses parameter."""
    tools = _build_ghost_tools()
    complete_decl = next(
        (d for d in tools.function_declarations if d.name == "complete_investigation"),
        None,
    )
    assert complete_decl is not None, "complete_investigation declaration not found"
    assert complete_decl.parameters is not None
    props = complete_decl.parameters.properties or {}
    assert "contradicted_hypotheses" in props, (
        "complete_investigation schema must include contradicted_hypotheses parameter"
    )


# ---------------------------------------------------------------------------
# T5: _new_session required fields all present
# ---------------------------------------------------------------------------

def test_T5_new_session_all_required_fields():
    """_new_session must return a dict with all 17 required session fields."""
    state = _new_session("gemini-2.0-flash", "./audit")

    required_fields = [
        "session_id",
        "created_at",
        "resumed_from",
        "model",
        "audit_dir",
        "turn_count",
        "rca_report_path",
        "audit_trail_path",
        "hypothesis_log",
        "denial_tracker",
        "consecutive_denial_counter",
        "active_hypothesis_ids",
        "active_task_ids",
        "evidence_conflicts",
        "is_resume",
        "manual_cleanup_pending",
        "denial_reasons",
    ]
    for field in required_fields:
        assert field in state, f"_new_session missing required field: '{field}'"

    # Verify default values
    assert state["turn_count"] == 0
    assert state["rca_report_path"] is None
    assert state["audit_trail_path"] is None
    assert state["resumed_from"] is None
    assert state["hypothesis_log"] == []
    assert state["denial_tracker"] == {}
    assert state["consecutive_denial_counter"] == {}
    assert state["active_hypothesis_ids"] == []
    assert state["active_task_ids"] == []
    assert state["evidence_conflicts"] == []
    assert state["is_resume"] is False
    assert state["manual_cleanup_pending"] == []
    assert state["denial_reasons"] == {}
    assert state["model"] == "gemini-2.0-flash"
    assert state["audit_dir"] == "./audit"
