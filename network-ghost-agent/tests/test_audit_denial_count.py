"""test_audit_denial_count.py — Denials column in the audit trail (BUG-01).

The Hypotheses Log table in ghost_audit_*.md previously rendered a
nonexistent 'denial_count' field and therefore always showed 0. It must
reflect the denial_events recorded against each hypothesis.
"""

from unittest.mock import MagicMock

from ghost_agent import _generate_rca, _new_session

SID = "ghost_20240101_120000"


def _make_state(tmp_path, hypothesis_log):
    state = _new_session("gemini-2.0-flash", str(tmp_path))
    state["session_id"] = SID
    state["audit_dir"] = str(tmp_path)
    state["hypothesis_log"] = hypothesis_log
    return state


def _denial_event(n):
    return {"turn": n, "command": f"cmd {n}", "denial_reason": "", "audit_id": f"{SID}_{n:03d}"}


def _run_rca(tmp_path, state):
    shell = MagicMock()
    _generate_rca(
        state,
        {"confidence": "low", "root_cause_summary": "test", "recommended_actions": []},
        shell,
        str(tmp_path / "session.json"),
    )
    return (tmp_path / f"ghost_audit_{SID}.md").read_text()


def test_denials_column_reflects_denial_events(tmp_path):
    state = _make_state(tmp_path, [
        {"id": "H1", "description": "NSG blocks port", "state": "UNVERIFIABLE",
         "denial_events": [_denial_event(1), _denial_event(2), _denial_event(3)]},
        {"id": "H2", "description": "Route blackhole", "state": "REFUTED",
         "denial_events": [_denial_event(4)]},
    ])

    audit = _run_rca(tmp_path, state)

    assert "| H1 | NSG blocks port | UNVERIFIABLE | 3 |" in audit
    assert "| H2 | Route blackhole | REFUTED | 1 |" in audit


def test_denials_column_zero_when_no_denials(tmp_path):
    state = _make_state(tmp_path, [
        {"id": "H1", "description": "Clean run", "state": "CONFIRMED",
         "denial_events": []},
    ])

    audit = _run_rca(tmp_path, state)

    assert "| H1 | Clean run | CONFIRMED | 0 |" in audit


def test_denials_column_tolerates_missing_denial_events_key(tmp_path):
    """Hypothesis entries from older sessions may lack denial_events entirely."""
    state = _make_state(tmp_path, [
        {"id": "H1", "description": "Legacy entry", "state": "ACTIVE"},
    ])

    audit = _run_rca(tmp_path, state)

    assert "| H1 | Legacy entry | ACTIVE | 0 |" in audit
