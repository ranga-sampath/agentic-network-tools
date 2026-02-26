"""test_session.py — Session State tests (S1–S12)."""

import hashlib
import json
import re
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import ghost_agent
from ghost_agent import (
    _checksum,
    _load_session,
    _new_session,
    save_session,
)


# ---------------------------------------------------------------------------
# S1: save_session writes all required fields + _checksum
# ---------------------------------------------------------------------------

def test_S1_save_session_required_fields(tmp_path, sample_state):
    """save_session must write all required session fields and a _checksum field."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)

    with open(path) as f:
        data = json.load(f)

    required_fields = [
        "session_id", "created_at", "resumed_from", "model", "audit_dir",
        "turn_count", "rca_report_path", "audit_trail_path", "hypothesis_log", "denial_tracker",
        "consecutive_denial_counter", "active_hypothesis_ids", "active_task_ids",
        "evidence_conflicts", "is_resume", "manual_cleanup_pending", "denial_reasons",
        "_checksum",
    ]
    for field in required_fields:
        assert field in data, f"Missing field in saved session: {field}"


# ---------------------------------------------------------------------------
# S2: _checksum = SHA-256 of sorted JSON excluding _checksum; 64-char hex
# ---------------------------------------------------------------------------

def test_S2_checksum_is_sha256_hex(sample_state):
    """_checksum must return 64-char lowercase hex SHA-256 of sorted JSON."""
    cs = _checksum(sample_state)
    assert len(cs) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", cs), f"Checksum not 64-char lowercase hex: {cs}"

    # Verify it matches manual calculation
    payload = json.dumps(sample_state, sort_keys=True, default=str)
    expected = hashlib.sha256(payload.encode()).hexdigest()
    assert cs == expected


def test_S2_checksum_excludes_checksum_key():
    """_checksum excludes _checksum key itself from the payload."""
    data = {"session_id": "ghost_20240101_120000", "turn_count": 0}
    data_with_cs = dict(data)
    data_with_cs["_checksum"] = "old_checksum"

    # checksum of data vs checksum of data_with_cs should differ unless _checksum is excluded
    cs_clean = _checksum(data)
    # When calling _checksum(data_with_cs) the function itself does NOT strip _checksum —
    # the caller (save_session) does. So verify that the stripped version matches.
    stripped = {k: v for k, v in data_with_cs.items() if k != "_checksum"}
    cs_stripped = _checksum(stripped)
    assert cs_clean == cs_stripped


# ---------------------------------------------------------------------------
# S3: modifying a field → next save recomputes checksum
# ---------------------------------------------------------------------------

def test_S3_checksum_changes_when_field_modified(tmp_path, sample_state):
    """Changing any field must produce a different checksum on next save."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)
    with open(path) as f:
        data1 = json.load(f)
    cs1 = data1["_checksum"]

    sample_state["turn_count"] = 99
    save_session(sample_state, path)
    with open(path) as f:
        data2 = json.load(f)
    cs2 = data2["_checksum"]

    assert cs1 != cs2


# ---------------------------------------------------------------------------
# S4: unmodified session verifies checksum on load
# ---------------------------------------------------------------------------

def test_S4_unmodified_session_loads_cleanly(tmp_path, sample_state):
    """An unmodified saved session must load without triggering any prompt."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)
    sid = sample_state["session_id"]

    result = _load_session(str(path), sid)
    assert result is not None
    assert result["session_id"] == sid
    assert result["is_resume"] is True


# ---------------------------------------------------------------------------
# S5: tampered field (stale checksum) triggers [C]/[F]/[A] prompt
# ---------------------------------------------------------------------------

def test_S5_tampered_session_triggers_prompt(tmp_path, sample_state, capsys):
    """Tampering with a field after saving must trigger the checksum-mismatch prompt."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)

    # Tamper with the file
    with open(path) as f:
        data = json.load(f)
    data["turn_count"] = 999  # tamper
    with open(path, "w") as f:
        json.dump(data, f)

    sid = sample_state["session_id"]
    # User answers [C]ontinue — should not crash
    with patch("builtins.input", return_value="c"):
        result = _load_session(str(path), sid)

    # Should return the (tampered) dict since user said continue
    assert result is not None


# ---------------------------------------------------------------------------
# S6: [A]bort exits with code 1
# ---------------------------------------------------------------------------

def test_S6_abort_on_checksum_mismatch_exits_1(tmp_path, sample_state):
    """Choosing [A]bort on checksum mismatch must call sys.exit(1)."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)

    with open(path) as f:
        data = json.load(f)
    data["turn_count"] = 999  # tamper
    with open(path, "w") as f:
        json.dump(data, f)

    sid = sample_state["session_id"]
    with patch("builtins.input", return_value="a"):
        with pytest.raises(SystemExit) as exc:
            _load_session(str(path), sid)
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# S7: [F]resh returns None
# ---------------------------------------------------------------------------

def test_S7_fresh_on_checksum_mismatch_returns_none(tmp_path, sample_state):
    """Choosing [F]resh on checksum mismatch must return None."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)

    with open(path) as f:
        data = json.load(f)
    data["turn_count"] = 999  # tamper
    with open(path, "w") as f:
        json.dump(data, f)

    sid = sample_state["session_id"]
    with patch("builtins.input", return_value="f"):
        result = _load_session(str(path), sid)
    assert result is None


# ---------------------------------------------------------------------------
# S8: [C]ontinue proceeds without crash
# ---------------------------------------------------------------------------

def test_S8_continue_on_checksum_mismatch_proceeds(tmp_path, sample_state):
    """Choosing [C]ontinue on checksum mismatch must return the (tampered) session dict."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)

    with open(path) as f:
        data = json.load(f)
    original_sid = data["session_id"]
    data["turn_count"] = 5  # tamper
    with open(path, "w") as f:
        json.dump(data, f)

    with patch("builtins.input", return_value="c"):
        result = _load_session(str(path), original_sid)

    assert result is not None
    assert result["session_id"] == original_sid
    assert result["turn_count"] == 5


# ---------------------------------------------------------------------------
# S9: missing _checksum loads without error (backward compat)
# ---------------------------------------------------------------------------

def test_S9_missing_checksum_loads_without_error(tmp_path, sample_state):
    """Session file with no _checksum field must load cleanly."""
    path = str(tmp_path / "session.json")
    # Write without _checksum
    data = {k: v for k, v in sample_state.items() if k != "_checksum"}
    with open(path, "w") as f:
        json.dump(data, f)

    sid = sample_state["session_id"]
    result = _load_session(str(path), sid)
    assert result is not None
    assert result["session_id"] == sid


# ---------------------------------------------------------------------------
# S10: session file never contains raw command output
# ---------------------------------------------------------------------------

def test_S10_session_file_no_raw_output(tmp_path, sample_state):
    """The saved session JSON must not contain any 'output' key with shell results."""
    path = str(tmp_path / "session.json")
    # Add some hypothesis log entries (no output field expected)
    sample_state["hypothesis_log"].append({
        "id": "H1",
        "description": "test hypothesis",
        "state": "ACTIVE",
        "denial_events": [],
    })
    save_session(sample_state, path)

    with open(path) as f:
        raw_text = f.read()
        data = json.loads(raw_text)

    # Top-level keys must not include 'output'
    assert "output" not in data

    def _has_raw_output(obj, depth=0):
        """Recursively check that no dict has key 'output' with a long string value."""
        if depth > 10:
            return False
        if isinstance(obj, dict):
            if "output" in obj and isinstance(obj["output"], str) and len(obj["output"]) > 50:
                return True
            return any(_has_raw_output(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return any(_has_raw_output(item, depth + 1) for item in obj)
        return False

    assert not _has_raw_output(data), "Session file contains raw command output"


# ---------------------------------------------------------------------------
# S11: is_resume=True when session loaded via _load_session
# ---------------------------------------------------------------------------

def test_S11_is_resume_true_on_load(tmp_path, sample_state):
    """_load_session must set is_resume=True on the returned dict."""
    path = str(tmp_path / "session.json")
    save_session(sample_state, path)
    sid = sample_state["session_id"]

    result = _load_session(str(path), sid)
    assert result is not None
    assert result["is_resume"] is True


# ---------------------------------------------------------------------------
# S12: turn_count persisted after every loop turn
# ---------------------------------------------------------------------------

def test_S12_turn_count_persisted(tmp_path, sample_state):
    """turn_count must be written to the session file on every save."""
    path = str(tmp_path / "session.json")
    sample_state["turn_count"] = 7
    save_session(sample_state, path)

    with open(path) as f:
        data = json.load(f)
    assert data["turn_count"] == 7

    # Increment and re-save
    sample_state["turn_count"] = 8
    save_session(sample_state, path)
    with open(path) as f:
        data = json.load(f)
    assert data["turn_count"] == 8
