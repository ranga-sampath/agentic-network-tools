"""COM-01 to COM-16: compute() tests."""

import json
import math
import pytest
from pipe_meter import compute, MeasurementRaw, ComputedStats


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _raw(lat=None, thr=None, sid="pmeter_test"):
    return MeasurementRaw(
        latency_samples=lat or [],
        throughput_samples=thr or [],
        session_id=sid,
    )


# ---------------------------------------------------------------------------
# COM-01  Latency P90 correct (8 samples)
# ---------------------------------------------------------------------------

def test_com01_latency_p90(tmp_path):
    """COM-01 M: P90 computed correctly for 8 latency samples."""
    samples = [100.0, 110.0, 120.0, 130.0, 140.0, 150.0, 160.0, 170.0]
    raw = _raw(lat=samples)
    stats = compute(raw, "latency", str(tmp_path))
    sorted_s = sorted(samples)
    idx = math.floor(0.90 * len(sorted_s))
    assert stats.latency_p90 == sorted_s[idx]


# ---------------------------------------------------------------------------
# COM-02  Throughput P90 correct
# ---------------------------------------------------------------------------

def test_com02_throughput_p90(tmp_path):
    """COM-02 M: P90 computed correctly for throughput samples."""
    samples = [8.0, 8.5, 9.0, 9.5, 10.0]
    raw = _raw(thr=samples)
    stats = compute(raw, "throughput", str(tmp_path))
    sorted_s = sorted(samples)
    idx = math.floor(0.90 * len(sorted_s))
    assert stats.throughput_p90 == sorted_s[idx]


# ---------------------------------------------------------------------------
# COM-03  Min/Max latency correct
# ---------------------------------------------------------------------------

def test_com03_latency_min_max(tmp_path):
    """COM-03 M: min and max latency correct."""
    samples = [50.0, 100.0, 200.0, 150.0]
    raw = _raw(lat=samples)
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.latency_min == 50.0
    assert stats.latency_max == 200.0


# ---------------------------------------------------------------------------
# COM-04  Min/Max throughput correct
# ---------------------------------------------------------------------------

def test_com04_throughput_min_max(tmp_path):
    """COM-04 M: min and max throughput correct."""
    samples = [7.5, 9.0, 10.5]
    raw = _raw(thr=samples)
    stats = compute(raw, "throughput", str(tmp_path))
    assert stats.throughput_min == 7.5
    assert stats.throughput_max == 10.5


# ---------------------------------------------------------------------------
# COM-05  is_stable=True for uniform samples
# ---------------------------------------------------------------------------

def test_com05_stable_uniform(tmp_path):
    """COM-05 M: Uniform samples → is_stable=True, anomaly_type=None."""
    samples = [100.0] * 8
    raw = _raw(lat=samples)
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.is_stable is True
    assert stats.anomaly_type is None


# ---------------------------------------------------------------------------
# COM-06  CONNECTIVITY_DROP when sample is zero
# ---------------------------------------------------------------------------

def test_com06_connectivity_drop(tmp_path):
    """COM-06 M: Zero sample → CONNECTIVITY_DROP anomaly."""
    samples = [100.0, 0.0, 100.0, 100.0]
    raw = _raw(lat=samples)
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.is_stable is False
    assert stats.anomaly_type == "CONNECTIVITY_DROP"


# ---------------------------------------------------------------------------
# COM-07  HIGH_VARIANCE when spread > 50%
# ---------------------------------------------------------------------------

def test_com07_high_variance(tmp_path):
    """COM-07 M: Spread > 50% of min → HIGH_VARIANCE."""
    samples = [100.0, 100.0, 160.0]  # (160-100)/100 = 0.60 > 0.50
    raw = _raw(lat=samples)
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.is_stable is False
    assert stats.anomaly_type == "HIGH_VARIANCE"


# ---------------------------------------------------------------------------
# COM-08  CONNECTIVITY_DROP takes priority over HIGH_VARIANCE (both)
# ---------------------------------------------------------------------------

def test_com08_both_connectivity_drop_priority(tmp_path):
    """COM-08 M: CONNECTIVITY_DROP takes priority when both occur (both mode)."""
    raw = _raw(
        lat=[100.0, 0.0, 100.0],   # CONNECTIVITY_DROP
        thr=[8.0, 8.0, 13.0],      # HIGH_VARIANCE (spread > 50%)
    )
    stats = compute(raw, "both", str(tmp_path))
    assert stats.anomaly_type == "CONNECTIVITY_DROP"


# ---------------------------------------------------------------------------
# COM-09  Empty latency samples with test_type=latency → RuntimeError
# ---------------------------------------------------------------------------

def test_com09_empty_latency_raises(tmp_path):
    """COM-09 M: Empty latency samples raises RuntimeError."""
    raw = _raw(lat=[])
    with pytest.raises(RuntimeError, match="Latency samples expected"):
        compute(raw, "latency", str(tmp_path))


# ---------------------------------------------------------------------------
# COM-10  Empty throughput samples with test_type=throughput → RuntimeError
# ---------------------------------------------------------------------------

def test_com10_empty_throughput_raises(tmp_path):
    """COM-10 M: Empty throughput samples raises RuntimeError."""
    raw = _raw(thr=[])
    with pytest.raises(RuntimeError, match="Throughput samples expected"):
        compute(raw, "throughput", str(tmp_path))


# ---------------------------------------------------------------------------
# COM-11  test_type=throughput → latency stats are None
# ---------------------------------------------------------------------------

def test_com11_throughput_latency_none(tmp_path):
    """COM-11 M: throughput-only mode → latency stats are None."""
    raw = _raw(thr=[9.0, 9.5, 10.0])
    stats = compute(raw, "throughput", str(tmp_path))
    assert stats.latency_p90 is None
    assert stats.latency_min is None
    assert stats.latency_max is None


# ---------------------------------------------------------------------------
# COM-12  test_type=latency → throughput stats are None
# ---------------------------------------------------------------------------

def test_com12_latency_throughput_none(tmp_path):
    """COM-12 M: latency-only mode → throughput stats are None."""
    raw = _raw(lat=[120.0, 130.0, 140.0])
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.throughput_p90 is None
    assert stats.throughput_min is None
    assert stats.throughput_max is None


# ---------------------------------------------------------------------------
# COM-13  _computed.json artifact written
# ---------------------------------------------------------------------------

def test_com13_computed_artifact_written(tmp_path):
    """COM-13 M: _computed.json artifact written after compute."""
    raw = _raw(lat=[100.0] * 8)
    compute(raw, "latency", str(tmp_path))
    art_path = tmp_path / f"{raw.session_id}_computed.json"
    assert art_path.exists()


# ---------------------------------------------------------------------------
# COM-14  _computed.json has correct fields
# ---------------------------------------------------------------------------

def test_com14_computed_artifact_fields(tmp_path):
    """COM-14 M: _computed.json contains expected keys."""
    raw = _raw(lat=[100.0] * 8)
    compute(raw, "latency", str(tmp_path))
    art_path = tmp_path / f"{raw.session_id}_computed.json"
    data = json.loads(art_path.read_text())
    for key in ("latency_p90", "latency_min", "latency_max", "is_stable", "anomaly_type"):
        assert key in data


# ---------------------------------------------------------------------------
# COM-15  Single sample — P90 is that sample
# ---------------------------------------------------------------------------

def test_com15_single_sample_p90(tmp_path):
    """COM-15 O: Single sample → P90 equals that sample."""
    raw = _raw(lat=[999.0])
    stats = compute(raw, "latency", str(tmp_path))
    assert stats.latency_p90 == 999.0


# ---------------------------------------------------------------------------
# COM-16  None values in artifact rendered as JSON null
# ---------------------------------------------------------------------------

def test_com16_none_as_json_null(tmp_path):
    """COM-16 G: throughput fields are null in JSON for latency-only run."""
    raw = _raw(lat=[100.0] * 3)
    compute(raw, "latency", str(tmp_path))
    art_path = tmp_path / f"{raw.session_id}_computed.json"
    data = json.loads(art_path.read_text())
    assert data["throughput_p90"] is None
    assert data["throughput_min"] is None
    assert data["throughput_max"] is None
