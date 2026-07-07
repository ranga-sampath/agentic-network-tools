"""test_artifact_discovery.py — unit tests for _latest_artifact (IMP-01).

Covers the shared artifact-discovery helper used by all subprocess tool
handlers: mtime window filtering, newest-wins ordering, prefix exclusion
(eni_ snapshots must never be attributed to a firewall probe), and the
empty-result case.
"""

import os
import time

from ghost_agent import _latest_artifact


def _touch(path, mtime):
    path.write_text("{}")
    os.utime(path, (mtime, mtime))
    return path


def test_returns_none_when_no_match(tmp_path):
    assert _latest_artifact(str(tmp_path), "*_snapshot.json", time.time()) is None


def test_excludes_files_older_than_start_time(tmp_path):
    now = time.time()
    _touch(tmp_path / "fw_old_snapshot.json", now - 3600)
    assert _latest_artifact(str(tmp_path), "*_snapshot.json", now) is None


def test_one_second_tolerance_for_clock_skew(tmp_path):
    """A file written up to 1s before start_time is still attributed to this run."""
    now = time.time()
    _touch(tmp_path / "fw_a_snapshot.json", now - 0.5)
    found = _latest_artifact(str(tmp_path), "*_snapshot.json", now)
    assert found is not None
    assert found.name == "fw_a_snapshot.json"


def test_newest_artifact_wins(tmp_path):
    now = time.time()
    _touch(tmp_path / "fw_a_snapshot.json", now + 1)
    _touch(tmp_path / "fw_b_snapshot.json", now + 5)
    found = _latest_artifact(str(tmp_path), "*_snapshot.json", now)
    assert found.name == "fw_b_snapshot.json"


def test_exclude_prefixes_filters_foreign_artifacts(tmp_path):
    """An eni_ snapshot newer than the fw snapshot must not be picked up."""
    now = time.time()
    _touch(tmp_path / "fw_a_snapshot.json", now + 1)
    _touch(tmp_path / "eni_b_snapshot.json", now + 5)
    found = _latest_artifact(str(tmp_path), "*_snapshot.json", now,
                             exclude_prefixes=("eni_",))
    assert found.name == "fw_a_snapshot.json"


def test_exclude_prefixes_only_match_returns_none(tmp_path):
    now = time.time()
    _touch(tmp_path / "eni_b_snapshot.json", now + 5)
    assert _latest_artifact(str(tmp_path), "*_snapshot.json", now,
                            exclude_prefixes=("eni_",)) is None


def test_custom_session_id_snapshots_still_found(tmp_path):
    """Operator-chosen session IDs (e.g. 'pre_change') carry no fw_ prefix —
    the glob must remain broad enough to find them."""
    now = time.time()
    _touch(tmp_path / "pre_change_snapshot.json", now + 1)
    found = _latest_artifact(str(tmp_path), "*_snapshot.json", now,
                             exclude_prefixes=("eni_",))
    assert found.name == "pre_change_snapshot.json"
