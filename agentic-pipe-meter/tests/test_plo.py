"""PLO-01 to PLO-05: run_pipeline() orchestrator tests."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from helpers import shell_ok
from pipe_meter import run_pipeline, PipelineConfig, PreflightResult, PipelineResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LAT_OUT = "tcp_lat:\n    latency = 120 us\n"


def _make_config(tmp_path):
    return PipelineConfig(
        source_ip="10.0.0.4",
        dest_ip="10.0.0.5",
        ssh_user="azureuser",
        test_type="latency",
        iterations=2,
        is_baseline=False,
        storage_account="mystorage",
        container="results",
        resource_group="my-rg",
        session_id="pmeter_test",
        audit_dir=str(tmp_path),
        compare_baseline=False,
    )


# ---------------------------------------------------------------------------
# PLO-01  measure() raises → run_pipeline returns status='error'
# ---------------------------------------------------------------------------

@patch("pipe_meter.preflight")
@patch("pipe_meter.measure")
@patch("time.sleep")
def test_plo01_measure_error(mock_sleep, mock_measure, mock_preflight, mock_provider, tmp_path):
    """PLO-01 M: measure() raises RuntimeError → PipelineResult.status='error'."""
    config = _make_config(tmp_path)
    mock_preflight.return_value = PreflightResult(
        ports_open=True, tools_ready=True, actions_taken=[]
    )
    mock_measure.side_effect = RuntimeError("qperf client failed")
    shell = MagicMock()
    result = run_pipeline(config, shell, mock_provider)
    assert result.status == "error"
    assert "qperf client failed" in result.error_message


# ---------------------------------------------------------------------------
# PLO-02  preflight fails → status='aborted_preflight'
# ---------------------------------------------------------------------------

@patch("pipe_meter.preflight")
@patch("time.sleep")
def test_plo02_preflight_fails(mock_sleep, mock_preflight, mock_provider, tmp_path):
    """PLO-02 M: preflight returns ports_open=False → status='aborted_preflight'."""
    config = _make_config(tmp_path)
    mock_preflight.return_value = PreflightResult(
        ports_open=False, tools_ready=False,
        actions_taken=[], blocked_ports=[5001]
    )
    # Write the preflight artifact so run_pipeline can reference the path
    import pipe_meter
    def fake_preflight(cfg, sh, prov):
        path = os.path.join(cfg.audit_dir, f"{cfg.session_id}_preflight.json")
        pipe_meter._write_artifact(path, {"ports_open": False, "tools_ready": False, "actions_taken": [], "blocked_ports": [5001], "session_id": cfg.session_id, "timestamp_utc": "2025-01-01T00:00:00+00:00"})
        return PreflightResult(ports_open=False, tools_ready=False, actions_taken=[], blocked_ports=[5001])
    mock_preflight.side_effect = fake_preflight
    shell = MagicMock()
    result = run_pipeline(config, shell, mock_provider)
    assert result.status == "aborted_preflight"


# ---------------------------------------------------------------------------
# PLO-03  Successful pipeline → status='success'
# ---------------------------------------------------------------------------

@patch("pipe_meter.preflight")
@patch("pipe_meter.measure")
@patch("pipe_meter.compute")
@patch("pipe_meter.compare")
@patch("pipe_meter.report")
@patch("time.sleep")
def test_plo03_success(mock_sleep, mock_report, mock_compare, mock_compute, mock_measure, mock_preflight, mock_provider, tmp_path):
    """PLO-03 M: Full pipeline success → status='success'."""
    from pipe_meter import ComputedStats, ComparisonResult, MeasurementRaw

    config = _make_config(tmp_path)
    mock_preflight.return_value = PreflightResult(ports_open=True, tools_ready=True, actions_taken=[])
    mock_measure.return_value = MeasurementRaw([120.0] * 2, [], "pmeter_test")
    mock_compute.return_value = ComputedStats(120.0, 100.0, 150.0, None, None, None, True, None)
    mock_compare.return_value = ComparisonResult(
        stats=mock_compute.return_value,
        baseline_p90_latency=None, baseline_p90_throughput=None,
        baseline_timestamp=None, delta_pct_latency=None,
        delta_pct_throughput=None, write_as_baseline=False,
    )
    mock_report.return_value = PipelineResult(
        status="success",
        local_artifact_path=str(tmp_path / "result.json"),
        blob_url="https://...",
        session_id="pmeter_test",
        error_message=None,
    )
    shell = MagicMock()
    result = run_pipeline(config, shell, mock_provider)
    assert result.status == "success"


# ---------------------------------------------------------------------------
# PLO-04  _manifest.json written before preflight
# ---------------------------------------------------------------------------

@patch("pipe_meter.preflight")
@patch("time.sleep")
def test_plo04_manifest_written(mock_sleep, mock_preflight, mock_provider, tmp_path):
    """PLO-04 M: _manifest.json exists after run_pipeline (written first)."""
    config = _make_config(tmp_path)

    manifest_check = {}

    def fake_preflight(cfg, sh, prov):
        # By the time preflight runs, manifest should already exist
        path = os.path.join(cfg.audit_dir, f"{cfg.session_id}_manifest.json")
        manifest_check["exists"] = os.path.exists(path)
        return PreflightResult(ports_open=False, tools_ready=False, actions_taken=[], blocked_ports=[5001])

    mock_preflight.side_effect = fake_preflight
    # Write the preflight artifact for the aborted path
    import pipe_meter
    original_preflight = fake_preflight

    shell = MagicMock()
    # Make preflight write its artifact
    def fake_preflight2(cfg, sh, prov):
        path = os.path.join(cfg.audit_dir, f"{cfg.session_id}_preflight.json")
        pipe_meter._write_artifact(path, {"ports_open": False, "tools_ready": False, "actions_taken": [], "blocked_ports": [5001], "session_id": cfg.session_id, "timestamp_utc": "now"})
        manifest_path = os.path.join(cfg.audit_dir, f"{cfg.session_id}_manifest.json")
        manifest_check["exists"] = os.path.exists(manifest_path)
        return PreflightResult(ports_open=False, tools_ready=False, actions_taken=[], blocked_ports=[5001])

    mock_preflight.side_effect = fake_preflight2
    run_pipeline(config, shell, mock_provider)
    assert manifest_check.get("exists") is True


# ---------------------------------------------------------------------------
# PLO-05  preflight tools_ready=False → measure() never called
# ---------------------------------------------------------------------------

@patch("pipe_meter.preflight")
@patch("pipe_meter.measure")
@patch("time.sleep")
def test_plo05_preflight_tools_fail_no_measure(mock_sleep, mock_measure, mock_preflight, mock_provider, tmp_path):
    """PLO-05 M: preflight tools_ready=False → measure() not called."""
    config = _make_config(tmp_path)

    import pipe_meter
    def fake_preflight(cfg, sh, prov):
        path = os.path.join(cfg.audit_dir, f"{cfg.session_id}_preflight.json")
        pipe_meter._write_artifact(path, {"ports_open": True, "tools_ready": False, "actions_taken": [], "blocked_ports": [], "session_id": cfg.session_id, "timestamp_utc": "now"})
        return PreflightResult(ports_open=True, tools_ready=False, actions_taken=[], blocked_ports=[])

    mock_preflight.side_effect = fake_preflight
    shell = MagicMock()
    result = run_pipeline(config, shell, mock_provider)
    assert result.status == "aborted_preflight"
    assert mock_measure.call_count == 0
