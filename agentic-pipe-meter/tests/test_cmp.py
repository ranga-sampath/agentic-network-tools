"""CMP-01 to CMP-13: compare() tests."""

import json
import pytest
from pipe_meter import compare, ComputedStats, ComparisonResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stats(lat_p90=120.0, thr_p90=9.5, is_stable=True, anomaly=None):
    return ComputedStats(
        latency_p90=lat_p90,
        latency_min=100.0,
        latency_max=150.0,
        throughput_p90=thr_p90,
        throughput_min=8.0,
        throughput_max=11.0,
        is_stable=is_stable,
        anomaly_type=anomaly,
    )


def _baseline_bytes(lat_p90=100.0, thr_p90=10.0, ts="2025-01-01T00:00:00+00:00"):
    data = {
        "test_metadata": {"timestamp": ts},
        "results": {
            "latency_p90": lat_p90,
            "throughput_p90": thr_p90,
        }
    }
    return json.dumps(data).encode()


# ---------------------------------------------------------------------------
# CMP-01  No baseline — deltas are None
# ---------------------------------------------------------------------------

def test_cmp01_no_baseline(base_config, mock_provider, tmp_path):
    """CMP-01 M: compare_baseline=True, no blob found → deltas None."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = None
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.delta_pct_latency is None
    assert result.delta_pct_throughput is None
    assert result.baseline_timestamp is None


# ---------------------------------------------------------------------------
# CMP-02  Baseline found — delta computed correctly (regression)
# ---------------------------------------------------------------------------

def test_cmp02_baseline_found_regression(base_config, mock_provider, tmp_path):
    """CMP-02 M: Baseline found; current worse → positive delta_pct_latency."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = _baseline_bytes(lat_p90=100.0)
    stats = _stats(lat_p90=120.0)
    result = compare(base_config, stats, mock_provider)
    # (120 - 100) / 100 * 100 = 20.0%
    assert abs(result.delta_pct_latency - 20.0) < 0.01


# ---------------------------------------------------------------------------
# CMP-03  Baseline found — delta computed correctly (improvement)
# ---------------------------------------------------------------------------

def test_cmp03_baseline_found_improvement(base_config, mock_provider, tmp_path):
    """CMP-03 M: Baseline found; current better → negative delta_pct_latency."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = _baseline_bytes(lat_p90=150.0)
    stats = _stats(lat_p90=120.0)
    result = compare(base_config, stats, mock_provider)
    # (120 - 150) / 150 * 100 = -20.0%
    assert abs(result.delta_pct_latency - (-20.0)) < 0.01


# ---------------------------------------------------------------------------
# CMP-04  write_as_baseline=True when is_baseline set
# ---------------------------------------------------------------------------

def test_cmp04_write_as_baseline(base_config, mock_provider, tmp_path):
    """CMP-04 M: is_baseline=True → write_as_baseline=True."""
    base_config.audit_dir = str(tmp_path)
    base_config.is_baseline = True
    base_config.compare_baseline = False
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.write_as_baseline is True


# ---------------------------------------------------------------------------
# CMP-05  write_as_baseline=False when is_baseline not set
# ---------------------------------------------------------------------------

def test_cmp05_not_write_as_baseline(base_config, mock_provider, tmp_path):
    """CMP-05 M: is_baseline=False → write_as_baseline=False."""
    base_config.audit_dir = str(tmp_path)
    base_config.is_baseline = False
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.write_as_baseline is False


# ---------------------------------------------------------------------------
# CMP-06  Malformed baseline JSON → deltas None (graceful)
# ---------------------------------------------------------------------------

def test_cmp06_malformed_baseline(base_config, mock_provider, tmp_path):
    """CMP-06 M: Malformed baseline JSON → deltas None."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = b"{ invalid json }"
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.delta_pct_latency is None


# ---------------------------------------------------------------------------
# CMP-07  RuntimeError from read_blob → deltas None
# ---------------------------------------------------------------------------

def test_cmp07_read_blob_error(base_config, mock_provider, tmp_path):
    """CMP-07 M: read_blob raises RuntimeError → deltas None."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.side_effect = RuntimeError("Storage auth failed")
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.delta_pct_latency is None


# ---------------------------------------------------------------------------
# CMP-08  Throughput delta computed
# ---------------------------------------------------------------------------

def test_cmp08_throughput_delta(base_config, mock_provider, tmp_path):
    """CMP-08 M: Throughput delta computed correctly."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = _baseline_bytes(thr_p90=10.0)
    stats = _stats(thr_p90=9.0)
    result = compare(base_config, stats, mock_provider)
    # (9 - 10) / 10 * 100 = -10.0%
    assert abs(result.delta_pct_throughput - (-10.0)) < 0.01


# ---------------------------------------------------------------------------
# CMP-09  _comparison.json artifact written
# ---------------------------------------------------------------------------

def test_cmp09_artifact_written(base_config, mock_provider, tmp_path):
    """CMP-09 M: _comparison.json artifact written."""
    base_config.audit_dir = str(tmp_path)
    stats = _stats()
    compare(base_config, stats, mock_provider)
    art_path = tmp_path / f"{base_config.session_id}_comparison.json"
    assert art_path.exists()


# ---------------------------------------------------------------------------
# CMP-10  No input() called for auto-approved paths (no prompts)
# ---------------------------------------------------------------------------

def test_cmp10_no_input_called(base_config, mock_provider, tmp_path, monkeypatch):
    """CMP-10 O: compare() never calls input()."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    mock_provider.read_blob.return_value = _baseline_bytes()
    stats = _stats()
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(AssertionError("input() was called")))
    # Should not raise
    compare(base_config, stats, mock_provider)


# ---------------------------------------------------------------------------
# CMP-11  Baseline timestamp preserved in result
# ---------------------------------------------------------------------------

def test_cmp11_baseline_timestamp(base_config, mock_provider, tmp_path):
    """CMP-11 G: baseline_timestamp from blob preserved in ComparisonResult."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = True
    ts = "2025-06-01T12:00:00+00:00"
    mock_provider.read_blob.return_value = _baseline_bytes(ts=ts)
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert result.baseline_timestamp == ts


# ---------------------------------------------------------------------------
# CMP-12  compare_baseline=False → read_blob not called
# ---------------------------------------------------------------------------

def test_cmp12_no_compare_no_read(base_config, mock_provider, tmp_path):
    """CMP-12 M: compare_baseline=False → provider.read_blob never called."""
    base_config.audit_dir = str(tmp_path)
    base_config.compare_baseline = False
    stats = _stats()
    compare(base_config, stats, mock_provider)
    assert mock_provider.read_blob.call_count == 0


# ---------------------------------------------------------------------------
# CMP-13  is_baseline=True and compare_baseline=False → no read_blob
# ---------------------------------------------------------------------------

def test_cmp13_is_baseline_no_read(base_config, mock_provider, tmp_path):
    """CMP-13 M: is_baseline=True, compare_baseline=False → no read_blob."""
    base_config.audit_dir = str(tmp_path)
    base_config.is_baseline = True
    base_config.compare_baseline = False
    stats = _stats()
    result = compare(base_config, stats, mock_provider)
    assert mock_provider.read_blob.call_count == 0
    assert result.write_as_baseline is True
