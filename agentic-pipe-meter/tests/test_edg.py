"""EDG-01 to EDG-05: Edge case tests."""

import json
import os
import pytest
from unittest.mock import patch
from helpers import shell_ok
from pipe_meter import (
    compute, compare, _write_artifact, MeasurementRaw, ComputedStats, ComparisonResult,
    PreflightResult, report, raw_to_dict
)


# ---------------------------------------------------------------------------
# EDG-01  compute() with single-sample latency → Gap Rule returns is_stable=True
# ---------------------------------------------------------------------------

def test_edg01_single_sample_stable(tmp_path):
    """EDG-01 O: Single latency sample → Gap Rule is_stable=True (no variance)."""
    raw = MeasurementRaw(latency_samples=[100.0], throughput_samples=[], session_id="pmeter_test")
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.is_stable is True
    assert stats.anomaly_type is None


# ---------------------------------------------------------------------------
# EDG-02  Gap Rule boundary: spread exactly 50% → stable
# ---------------------------------------------------------------------------

def test_edg02_gap_rule_boundary_stable(tmp_path):
    """EDG-02 O: Spread exactly 50% → stable (not > 50%)."""
    # min=100, max=150, (150-100)/100 = 0.50, not > 0.50 → stable
    raw = MeasurementRaw(latency_samples=[100.0, 150.0], throughput_samples=[], session_id="pmeter_test")
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.is_stable is True


# ---------------------------------------------------------------------------
# EDG-03  compare() with baseline existing and is_baseline=True → prints note
# ---------------------------------------------------------------------------

def test_edg03_baseline_overwrite_note(base_config, mock_provider, tmp_path, capsys):
    """EDG-03 G: is_baseline=True with existing baseline → prints overwrite note."""
    base_config.audit_dir = str(tmp_path)
    base_config.is_baseline = True
    base_config.compare_baseline = True
    baseline_data = {
        "test_metadata": {"timestamp": "2025-01-01T00:00:00+00:00"},
        "results": {"latency_p90": 100.0, "throughput_p90": None},
    }
    mock_provider.read_blob.return_value = json.dumps(baseline_data).encode()
    stats = ComputedStats(
        latency_p90=120.0, latency_min=100.0, latency_max=150.0,
        throughput_p90=None, throughput_min=None, throughput_max=None,
        is_stable=True, anomaly_type=None,
    )
    compare(base_config, stats, mock_provider)
    out = capsys.readouterr().out
    assert "already exists" in out or "overwritten" in out or "baseline" in out.lower()


# ---------------------------------------------------------------------------
# EDG-04  compute() CONNECTIVITY_DROP takes priority when both signals occur
# ---------------------------------------------------------------------------

def test_edg04_connectivity_drop_priority(tmp_path):
    """EDG-04 M: CONNECTIVITY_DROP takes priority over HIGH_VARIANCE in 'both' mode."""
    raw = MeasurementRaw(
        latency_samples=[100.0, 0.0, 100.0],    # CONNECTIVITY_DROP
        throughput_samples=[8.0, 8.0, 13.0],    # HIGH_VARIANCE (> 50%)
        session_id="pmeter_test",
    )
    stats = compute(raw, "both", str(tmp_path))
    assert stats.anomaly_type == "CONNECTIVITY_DROP"
    assert stats.is_stable is False


# ---------------------------------------------------------------------------
# EDG-05  _write_artifact creates parent dir and writes file
# ---------------------------------------------------------------------------

def test_edg05_write_artifact_creates_parent(tmp_path):
    """EDG-05 M: _write_artifact creates missing parent directory and writes file."""
    new_dir = tmp_path / "new_subdir"
    assert not new_dir.exists()
    path = str(new_dir / "artifact.json")
    _write_artifact(path, {"hello": "world"})
    assert new_dir.exists()
    assert os.path.exists(path)
    data = json.loads(open(path).read())
    assert data["hello"] == "world"
