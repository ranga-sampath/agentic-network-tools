"""REP-01 to REP-19: report() tests."""

import json
import pytest
from pipe_meter import (
    report, compare, ComputedStats, ComparisonResult, PreflightResult,
    PipelineResult, raw_to_dict, MeasurementRaw, _write_artifact
)
import os


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stats(lat_p90=120.0, thr_p90=None, is_stable=True, anomaly=None):
    return ComputedStats(
        latency_p90=lat_p90,
        latency_min=100.0,
        latency_max=150.0,
        throughput_p90=thr_p90,
        throughput_min=None if thr_p90 is None else 8.0,
        throughput_max=None if thr_p90 is None else 11.0,
        is_stable=is_stable,
        anomaly_type=anomaly,
    )


def _comparison(stats, baseline_lat=None, baseline_thr=None, baseline_ts=None,
                 delta_lat=None, delta_thr=None, write_as_baseline=False):
    return ComparisonResult(
        stats=stats,
        baseline_p90_latency=baseline_lat,
        baseline_p90_throughput=baseline_thr,
        baseline_timestamp=baseline_ts,
        delta_pct_latency=delta_lat,
        delta_pct_throughput=delta_thr,
        write_as_baseline=write_as_baseline,
    )


def _preflight_ok():
    return PreflightResult(ports_open=True, tools_ready=True, actions_taken=[])


def _write_raw(config, lat_samples=None, thr_samples=None):
    """Pre-write the _raw.json that report/_assemble_artifact reads."""
    raw = MeasurementRaw(
        latency_samples=lat_samples or [100.0] * 8,
        throughput_samples=thr_samples or [],
        session_id=config.session_id,
    )
    path = os.path.join(config.audit_dir, f"{config.session_id}_raw.json")
    _write_artifact(path, raw_to_dict(raw))


# ---------------------------------------------------------------------------
# REP-01  _result.json written with expected keys
# ---------------------------------------------------------------------------

def test_rep01_result_artifact_keys(base_config, mock_provider, tmp_path):
    """REP-01 M: _result.json written with all required top-level keys."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    art_path = tmp_path / f"{base_config.session_id}_result.json"
    data = json.loads(art_path.read_text())
    for key in ("test_metadata", "preflight", "results", "comparison"):
        assert key in data


# ---------------------------------------------------------------------------
# REP-02  iteration_data length matches sample count
# ---------------------------------------------------------------------------

def test_rep02_iteration_data_count(base_config, mock_provider, tmp_path):
    """REP-02 M: iteration_data length equals number of latency samples."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config, lat_samples=[120.0] * 8)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    art_path = tmp_path / f"{base_config.session_id}_result.json"
    data = json.loads(art_path.read_text())
    assert len(data["results"]["iteration_data"]) == 8


# ---------------------------------------------------------------------------
# REP-03  provider.write_blob called with correct blob name and data
# ---------------------------------------------------------------------------

def test_rep03_write_blob_called(base_config, mock_provider, tmp_path):
    """REP-03 M: write_blob called with artifact data."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    assert mock_provider.write_blob.called
    call_args = mock_provider.write_blob.call_args
    assert base_config.session_id in call_args[0][2]  # blob_name contains session_id


# ---------------------------------------------------------------------------
# REP-04  PipelineResult status=success
# ---------------------------------------------------------------------------

def test_rep04_result_status_success(base_config, mock_provider, tmp_path):
    """REP-04 M: report() returns PipelineResult with status='success'."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    result = report(comp, base_config, mock_provider, _preflight_ok())
    assert result.status == "success"


# ---------------------------------------------------------------------------
# REP-05  blob_url in PipelineResult
# ---------------------------------------------------------------------------

def test_rep05_blob_url_in_result(base_config, mock_provider, tmp_path):
    """REP-05 M: PipelineResult.blob_url is non-empty on success."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    result = report(comp, base_config, mock_provider, _preflight_ok())
    assert result.blob_url != ""


# ---------------------------------------------------------------------------
# REP-06  write_blob raises → result still success, local artifact ok
# ---------------------------------------------------------------------------

def test_rep06_blob_upload_failure_graceful(base_config, mock_provider, tmp_path):
    """REP-06 G: write_blob RuntimeError → status still success (local saved)."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    mock_provider.write_blob.side_effect = RuntimeError("Blob upload failed: access denied")
    stats = _stats()
    comp = _comparison(stats)
    result = report(comp, base_config, mock_provider, _preflight_ok())
    assert result.status == "success"
    assert result.blob_url == ""


# ---------------------------------------------------------------------------
# REP-07  write_as_baseline=True → write_blob called twice
# ---------------------------------------------------------------------------

def test_rep07_baseline_upload(base_config, mock_provider, tmp_path):
    """REP-07 M: write_as_baseline=True → write_blob called twice."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats, write_as_baseline=True)
    report(comp, base_config, mock_provider, _preflight_ok())
    assert mock_provider.write_blob.call_count == 2


# ---------------------------------------------------------------------------
# REP-08  Console output contains session_id
# ---------------------------------------------------------------------------

def test_rep08_console_session_id(base_config, mock_provider, tmp_path, capsys):
    """REP-08 M: Console output includes session_id."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert base_config.session_id in out


# ---------------------------------------------------------------------------
# REP-09  Console output contains source and dest IPs
# ---------------------------------------------------------------------------

def test_rep09_console_ips(base_config, mock_provider, tmp_path, capsys):
    """REP-09 M: Console output includes source and dest IPs."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert base_config.source_ip in out
    assert base_config.dest_ip in out


# ---------------------------------------------------------------------------
# REP-10  Console output contains latency P90
# ---------------------------------------------------------------------------

def test_rep10_console_latency_p90(base_config, mock_provider, tmp_path, capsys):
    """REP-10 M: Console output includes latency P90 value."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats(lat_p90=120.0)
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "120" in out


# ---------------------------------------------------------------------------
# REP-11  Console output: STABLE when is_stable=True
# ---------------------------------------------------------------------------

def test_rep11_console_stable(base_config, mock_provider, tmp_path, capsys):
    """REP-11 M: Console output shows STABLE when is_stable=True."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats(is_stable=True)
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "STABLE" in out


# ---------------------------------------------------------------------------
# REP-12  Console output: UNSTABLE when anomaly present
# ---------------------------------------------------------------------------

def test_rep12_console_unstable(base_config, mock_provider, tmp_path, capsys):
    """REP-12 M: Console output shows UNSTABLE when anomaly present."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats(is_stable=False, anomaly="HIGH_VARIANCE")
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "UNSTABLE" in out


# ---------------------------------------------------------------------------
# REP-13  Console output: delta percentage shown when baseline exists
# ---------------------------------------------------------------------------

def test_rep13_console_delta_shown(base_config, mock_provider, tmp_path, capsys):
    """REP-13 G: Delta % shown in console when baseline comparison available."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats(lat_p90=120.0)
    comp = _comparison(stats, baseline_lat=100.0, delta_lat=20.0)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "20" in out or "+20" in out


# ---------------------------------------------------------------------------
# REP-14  Console output: blob URL shown
# ---------------------------------------------------------------------------

def test_rep14_console_blob_url(base_config, mock_provider, tmp_path, capsys):
    """REP-14 G: Console output includes blob URL."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "https://" in out


# ---------------------------------------------------------------------------
# REP-15  Console: "(upload failed)" shown when blob upload fails
# ---------------------------------------------------------------------------

def test_rep15_console_upload_failed(base_config, mock_provider, tmp_path, capsys):
    """REP-15 G: '(upload failed)' shown in console when upload fails."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    mock_provider.write_blob.side_effect = RuntimeError("Blob upload failed: access denied")
    stats = _stats()
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "upload failed" in out.lower()


# ---------------------------------------------------------------------------
# REP-16  No throughput shown in latency-only mode
# ---------------------------------------------------------------------------

def test_rep16_no_throughput_in_latency_mode(base_config, mock_provider, tmp_path, capsys):
    """REP-16 G: Throughput line not shown for latency-only test."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "latency"
    _write_raw(base_config)
    stats = _stats(lat_p90=120.0, thr_p90=None)
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "Throughput" not in out


# ---------------------------------------------------------------------------
# REP-17  Throughput shown in 'both' mode
# ---------------------------------------------------------------------------

def test_rep17_throughput_shown_in_both(base_config, mock_provider, tmp_path, capsys):
    """REP-17 G: Throughput line shown for 'both' test type."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "both"
    _write_raw(base_config, thr_samples=[9.5] * 8)
    stats = _stats(lat_p90=120.0, thr_p90=9.5)
    comp = _comparison(stats)
    report(comp, base_config, mock_provider, _preflight_ok())
    out = capsys.readouterr().out
    assert "Throughput" in out


# ---------------------------------------------------------------------------
# REP-18  local_artifact_path in PipelineResult is absolute
# ---------------------------------------------------------------------------

def test_rep18_local_path_absolute(base_config, mock_provider, tmp_path):
    """REP-18 G: PipelineResult.local_artifact_path is absolute."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    result = report(comp, base_config, mock_provider, _preflight_ok())
    assert os.path.isabs(result.local_artifact_path)


# ---------------------------------------------------------------------------
# REP-19  session_id in PipelineResult
# ---------------------------------------------------------------------------

def test_rep19_session_id_in_pipeline_result(base_config, mock_provider, tmp_path):
    """REP-19 G: PipelineResult.session_id matches config.session_id."""
    base_config.audit_dir = str(tmp_path)
    _write_raw(base_config)
    stats = _stats()
    comp = _comparison(stats)
    result = report(comp, base_config, mock_provider, _preflight_ok())
    assert result.session_id == base_config.session_id
