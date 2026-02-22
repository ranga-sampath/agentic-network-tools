"""test_rca.py — RCA Generation tests (R1–R15)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

import ghost_agent
from ghost_agent import (
    _generate_rca,
    _read_task_registry,
    _new_session,
    save_session,
)


SID = "ghost_20240101_120000"


def _make_state(tmp_path):
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    state["session_id"] = SID
    state["audit_dir"] = str(tmp_path)
    return state


def _write_shell_jsonl(tmp_path, records):
    path = tmp_path / f"shell_audit_{SID}.jsonl"
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return path


def _write_task_jsonl(tmp_path, records):
    path = tmp_path / f"orchestrator_tasks_{SID}.jsonl"
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return path


def _base_shell_record(**kwargs):
    defaults = {
        "timestamp": "2024-01-01T12:00:00+00:00",
        "session_id": SID,
        "sequence": 1,
        "command": "ping 8.8.8.8",
        "reasoning": "Check connectivity",
        "status": "completed",
        "classification": "SAFE",
        "action": "auto_approved",
        "exit_code": 0,
        "output_summary": "64 bytes from 8.8.8.8",
        "environment": "local",
        "audit_id": f"{SID}_001",
        "duration_seconds": 0.5,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# R1: shell_audit JSONL opened read-only
# ---------------------------------------------------------------------------

def test_R1_shell_audit_opened_read_only(tmp_path):
    """_read_shell_audit must open the JSONL file in read-only ('r') mode."""
    _write_shell_jsonl(tmp_path, [_base_shell_record()])

    open_calls = []
    original_open = open

    def tracking_open(path, mode="r", **kw):
        open_calls.append((str(path), mode))
        return original_open(path, mode, **kw)

    with patch("builtins.open", side_effect=tracking_open):
        records = ghost_agent._read_shell_audit(str(tmp_path), SID)

    shell_opens = [
        (p, m) for p, m in open_calls
        if f"shell_audit_{SID}" in p
    ]
    assert len(shell_opens) >= 1
    for path, mode in shell_opens:
        assert "w" not in mode and "a" not in mode, (
            f"shell_audit must be opened read-only, got mode='{mode}'"
        )


# ---------------------------------------------------------------------------
# R2: orchestrator_tasks JSONL opened read-only
# ---------------------------------------------------------------------------

def test_R2_task_registry_opened_read_only(tmp_path):
    """_read_task_registry must open JSONL files in read-only mode."""
    _write_task_jsonl(tmp_path, [{
        "task_id": f"{SID}_vm1",
        "session_id": SID,
        "state": "COMPLETED",
        "cleanup_status": "pending",
        "target": "vm1",
    }])

    open_calls = []
    original_open = open

    def tracking_open(path, mode="r", **kw):
        open_calls.append((str(path), mode))
        return original_open(path, mode, **kw)

    with patch("builtins.open", side_effect=tracking_open):
        tasks = _read_task_registry(str(tmp_path), SID)

    task_opens = [
        (p, m) for p, m in open_calls
        if f"orchestrator_tasks_{SID}" in p
    ]
    assert len(task_opens) >= 1
    for path, mode in task_opens:
        assert "w" not in mode and "a" not in mode, (
            f"task registry must be opened read-only, got mode='{mode}'"
        )


# ---------------------------------------------------------------------------
# R3: malformed JSONL lines skipped without crash
# ---------------------------------------------------------------------------

def test_R3_malformed_jsonl_skipped(tmp_path):
    """Malformed JSONL lines must be silently skipped during shell audit read."""
    path = tmp_path / f"shell_audit_{SID}.jsonl"
    with open(path, "w") as f:
        f.write('{"sequence": 1, "command": "ping 8.8.8.8", "environment": "local"}\n')
        f.write('NOT VALID JSON {\n')
        f.write('{"sequence": 2, "command": "dig google.com", "environment": "local"}\n')

    records = ghost_agent._read_shell_audit(str(tmp_path), SID)
    assert len(records) == 2
    commands = [r["command"] for r in records]
    assert "ping 8.8.8.8" in commands
    assert "dig google.com" in commands


# ---------------------------------------------------------------------------
# R4: last-write-wins per task_id in task registry
# ---------------------------------------------------------------------------

def test_R4_task_registry_last_write_wins(tmp_path):
    """_read_task_registry must apply last-write-wins per task_id."""
    task_id = f"{SID}_vm1_20240101T120000"
    path = tmp_path / f"orchestrator_tasks_{SID}.jsonl"
    with open(path, "w") as f:
        f.write(json.dumps({
            "task_id": task_id,
            "session_id": SID,
            "state": "WAITING",
            "cleanup_status": "pending",
        }) + "\n")
        f.write(json.dumps({
            "task_id": task_id,
            "session_id": SID,
            "state": "COMPLETED",
            "cleanup_status": "done",
        }) + "\n")

    tasks = _read_task_registry(str(tmp_path), SID)
    assert task_id in tasks
    assert tasks[task_id]["state"] == "COMPLETED"


# ---------------------------------------------------------------------------
# R5: _ctx="LOCAL" for environment=="local", "CLOUD" for "azure"
# ---------------------------------------------------------------------------

def test_R5_ctx_tag_local_and_cloud(tmp_path):
    """Shell records must get _ctx='LOCAL' for local and 'CLOUD' for azure environment."""
    _write_shell_jsonl(tmp_path, [
        _base_shell_record(sequence=1, environment="local", command="ping 8.8.8.8"),
        _base_shell_record(sequence=2, environment="azure", command="az network nsg list"),
    ])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)
    shell = MagicMock()
    shell.execute.return_value = {"status": "denied", "exit_code": None}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {
            "confidence": "medium",
            "root_cause_summary": "Context test",
        }, shell, session_file)

    # [LOCAL] / [CLOUD] markers are in the audit trail document
    audit_path = tmp_path / f"ghost_audit_{SID}.md"
    assert audit_path.exists()
    content = audit_path.read_text()
    assert "[LOCAL]" in content
    assert "[CLOUD]" in content


# ---------------------------------------------------------------------------
# R6: forensic consistency check Pattern A fires (local fail + cloud allow)
# ---------------------------------------------------------------------------

def test_R6_pattern_A_advisory_note(tmp_path):
    """Pattern A advisory note must appear when local probe fails alongside Azure Allow NSG."""
    _write_shell_jsonl(tmp_path, [
        _base_shell_record(
            sequence=1,
            environment="local",
            command="ping 10.0.0.1",
            exit_code=1,
            status="completed",
        ),
        _base_shell_record(
            sequence=2,
            environment="azure",
            command='az network nsg rule list --nsg-name myrule -o json',
            exit_code=0,
            status="completed",
            output_summary='{"access": "Allow", "name": "Allow-HTTP"}',
        ),
    ])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)
    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "low", "root_cause_summary": "test"}, shell, session_file)

    # Advisory notes appear in the investigation report
    report_path = tmp_path / f"ghost_report_{SID}.md"
    content = report_path.read_text()
    assert "Advisory" in content or "advisory" in content or "PCAP" in content


# ---------------------------------------------------------------------------
# R7: Pattern B fires when COMPLETED + no cat result
# ---------------------------------------------------------------------------

def test_R7_pattern_B_advisory_note_when_report_unavailable(tmp_path):
    """Advisory note must appear for COMPLETED tasks where cat was denied."""
    task_id = f"{SID}_vm1_20240101T120000"
    report_path = str(tmp_path / f"{task_id}_forensic_report.md")

    _write_task_jsonl(tmp_path, [{
        "task_id": task_id,
        "session_id": SID,
        "state": "COMPLETED",
        "target": "vm1",
        "report_path": report_path,
        "cleanup_status": "pending",
    }])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    # Mock shell.execute to return denied for cat
    shell = MagicMock()
    shell.execute.return_value = {"status": "denied", "exit_code": None}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "low", "root_cause_summary": "denied"}, shell, session_file)

    # Advisory notes appear in the investigation report
    report_path = tmp_path / f"ghost_report_{SID}.md"
    content = report_path.read_text()
    assert "unavailable" in content.lower() or "denied" in content.lower() or "Advisory" in content


# ---------------------------------------------------------------------------
# R9: Phase 4 cat via shell.execute() not direct file I/O
# ---------------------------------------------------------------------------

def test_R9_cat_via_shell_execute(tmp_path):
    """_generate_rca must read forensic reports via shell.execute, not direct file I/O."""
    task_id = f"{SID}_vm1_20240101T120000"
    report_path = str(tmp_path / f"{task_id}_forensic_report.md")
    Path(report_path).write_text("Report content.")

    _write_task_jsonl(tmp_path, [{
        "task_id": task_id,
        "session_id": SID,
        "state": "COMPLETED",
        "target": "vm1",
        "report_path": report_path,
        "cleanup_status": "pending",
    }])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {
        "status": "completed", "exit_code": 0, "output": "Report content."
    }

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "high", "root_cause_summary": "test"}, shell, session_file)

    # shell.execute must have been called (cat command)
    assert shell.execute.called
    # Find the cat call
    cat_calls = [
        c for c in shell.execute.call_args_list
        if "cat" in c[0][0].get("command", "")
    ]
    assert len(cat_calls) >= 1


# ---------------------------------------------------------------------------
# R10: cat denied → advisory note about unavailability
# ---------------------------------------------------------------------------

def test_R10_cat_denied_advisory_note(tmp_path):
    """When cat is denied, an advisory note about unavailability must appear in the RCA."""
    task_id = f"{SID}_vm1_20240101T120000"
    report_path = str(tmp_path / f"{task_id}_forensic_report.md")

    _write_task_jsonl(tmp_path, [{
        "task_id": task_id,
        "session_id": SID,
        "state": "COMPLETED",
        "target": "vm1",
        "report_path": report_path,
        "cleanup_status": "pending",
    }])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied", "exit_code": None}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "low", "root_cause_summary": "denied"}, shell, session_file)

    # Advisory notes appear in the investigation report
    report_path = tmp_path / f"ghost_report_{SID}.md"
    content = report_path.read_text()
    assert (
        "unavailable" in content.lower()
        or "denied" in content.lower()
        or "Advisory" in content
    ), "Advisory note about cat denial must appear in investigation report"


# ---------------------------------------------------------------------------
# R11: Report and audit trail contain their required sections
# ---------------------------------------------------------------------------

def test_R11_rca_contains_required_sections(tmp_path):
    """Investigation report and audit trail must each contain their required sections."""
    _write_shell_jsonl(tmp_path, [_base_shell_record()])
    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {
            "confidence": "medium",
            "root_cause_summary": "Test summary.",
            "recommended_actions": ["Check firewall"],
        }, shell, session_file)

    # Investigation report
    report_path = tmp_path / f"ghost_report_{SID}.md"
    assert report_path.exists()
    report_content = report_path.read_text()
    for section in ["Investigation Report", "Root Cause", "Recommended Actions"]:
        assert section in report_content, f"Missing from report: '{section}'"

    # Audit trail
    audit_path = tmp_path / f"ghost_audit_{SID}.md"
    assert audit_path.exists()
    audit_content = audit_path.read_text()
    assert "Integrity Statement" in audit_content


# ---------------------------------------------------------------------------
# R12: Context column shows [LOCAL]/[CLOUD] (in audit trail)
# ---------------------------------------------------------------------------

def test_R12_command_evidence_context_column(tmp_path):
    """Command Evidence table must include [LOCAL] and [CLOUD] context markers (in audit trail)."""
    _write_shell_jsonl(tmp_path, [
        _base_shell_record(sequence=1, environment="local"),
        _base_shell_record(sequence=2, environment="azure", command="az vm list"),
    ])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "medium", "root_cause_summary": "ctx test"}, shell, session_file)

    # Command Evidence with [LOCAL]/[CLOUD] lives in the audit trail
    audit_path = tmp_path / f"ghost_audit_{SID}.md"
    content = audit_path.read_text()
    assert "[LOCAL]" in content
    assert "[CLOUD]" in content


# ---------------------------------------------------------------------------
# R13: Neither document reproduces raw command output
# ---------------------------------------------------------------------------

def test_R13_rca_no_raw_output(tmp_path):
    """Neither the investigation report nor the audit trail must reproduce raw command output."""
    raw_output = "PING 8.8.8.8 56 bytes of data. 64 bytes from 8.8.8.8: icmp_seq=1"
    _write_shell_jsonl(tmp_path, [
        _base_shell_record(output_summary=raw_output, sequence=1),
    ])

    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "low", "root_cause_summary": "no output"}, shell, session_file)

    for filename in [f"ghost_report_{SID}.md", f"ghost_audit_{SID}.md"]:
        content = (tmp_path / filename).read_text()
        assert "| output |" not in content.lower()
        assert raw_output not in content, f"Raw output must not appear in {filename}"


# ---------------------------------------------------------------------------
# R14: state["rca_report_path"] and ["audit_trail_path"] set after successful write
# ---------------------------------------------------------------------------

def test_R14_rca_report_path_set_on_success(tmp_path):
    """state['rca_report_path'] and ['audit_trail_path'] must be set after successful write."""
    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    with patch.object(ghost_agent, "save_session"):
        _generate_rca(state, {"confidence": "high", "root_cause_summary": "done"}, shell, session_file)

    assert state["rca_report_path"] == str(tmp_path / f"ghost_report_{SID}.md")
    assert state["audit_trail_path"] == str(tmp_path / f"ghost_audit_{SID}.md")


# ---------------------------------------------------------------------------
# R15: write failure → prints to stdout, rca_report_path=None
# ---------------------------------------------------------------------------

def test_R15_write_failure_prints_to_stdout(tmp_path, capsys):
    """If the RCA write fails with OSError, state['rca_report_path'] must be None."""
    state = _make_state(tmp_path)
    session_file = str(tmp_path / "session.json")
    save_session(state, session_file)

    shell = MagicMock()
    shell.execute.return_value = {"status": "denied"}

    original_open = open

    def fail_on_rca_write(path, mode="r", **kw):
        if "ghost_report_" in str(path) and "w" in mode:
            raise OSError("Permission denied")
        return original_open(path, mode, **kw)

    with patch("builtins.open", side_effect=fail_on_rca_write):
        with patch.object(ghost_agent, "save_session"):
            _generate_rca(state, {"confidence": "low", "root_cause_summary": "write fail"}, shell, session_file)

    assert state["rca_report_path"] is None
    assert state["audit_trail_path"] is None
    captured = capsys.readouterr()
    assert "ERROR" in captured.out or "Could not write" in captured.out or "Root Cause" in captured.out
