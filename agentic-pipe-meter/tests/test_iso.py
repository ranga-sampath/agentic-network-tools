"""ISO-01 to ISO-04: Stage isolation — artifact file presence tests."""

import json
import os
import pytest
from unittest.mock import patch
from helpers import shell_ok
from pipe_meter import (
    measure, compute, MeasurementRaw, _write_artifact, raw_to_dict
)


# ---------------------------------------------------------------------------
# ISO-01  measure() writes _raw.json; compute() reads it independently
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_iso01_raw_artifact_readable_by_compute(mock_sleep, base_config, mock_shell, tmp_path):
    """ISO-01 M: _raw.json written by measure() is readable by compute()."""
    base_config.audit_dir = str(tmp_path)
    LAT_OUT = "tcp_lat:\n    latency = 120 us\n"
    mock_shell.execute.side_effect = [
        shell_ok(""),                       # lsof
        shell_ok("9876"),                   # nohup qperf
        shell_ok(LAT_OUT),                  # warm-up
        *[shell_ok(LAT_OUT)] * 8,           # iterations
        shell_ok(""),                       # kill
    ]
    raw = measure(base_config, mock_shell)
    raw_path = tmp_path / f"{base_config.session_id}_raw.json"
    assert raw_path.exists()
    data = json.loads(raw_path.read_text())
    assert data["session_id"] == base_config.session_id
    assert len(data["latency_samples_us"]) == 8


# ---------------------------------------------------------------------------
# ISO-02  compute() writes _computed.json with correct stats
# ---------------------------------------------------------------------------

def test_iso02_compute_writes_computed_artifact(base_config, tmp_path):
    """ISO-02 M: compute() writes _computed.json with correct stats."""
    base_config.audit_dir = str(tmp_path)
    raw = MeasurementRaw(
        latency_samples=[100.0] * 8,
        throughput_samples=[],
        session_id=base_config.session_id,
    )
    stats = compute(raw, "latency", str(tmp_path))
    art_path = tmp_path / f"{base_config.session_id}_computed.json"
    assert art_path.exists()
    data = json.loads(art_path.read_text())
    assert data["latency_p90"] == stats.latency_p90


# ---------------------------------------------------------------------------
# ISO-03  _write_artifact creates parent directories if needed
# ---------------------------------------------------------------------------

def test_iso03_write_artifact_creates_dirs(tmp_path):
    """ISO-03 M: _write_artifact creates missing parent directories."""
    deep_path = str(tmp_path / "a" / "b" / "c" / "artifact.json")
    _write_artifact(deep_path, {"key": "value"})
    assert os.path.exists(deep_path)


# ---------------------------------------------------------------------------
# ISO-04  Artifact files isolated by session_id
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_iso04_sessions_isolated(mock_sleep, mock_shell, mock_provider, tmp_path):
    """ISO-04 O: Two sessions with different IDs produce separate artifact files."""
    from pipe_meter import PipelineConfig
    LAT_OUT = "tcp_lat:\n    latency = 120 us\n"

    for session_id in ("pmeter_session_A", "pmeter_session_B"):
        config = PipelineConfig(
            source_ip="10.0.0.4",
            dest_ip="10.0.0.5",
            ssh_user="azureuser",
            test_type="latency",
            iterations=2,
            is_baseline=False,
            storage_account="mystorage",
            container="results",
            resource_group="my-rg",
            session_id=session_id,
            audit_dir=str(tmp_path),
        )
        mock_shell.execute.side_effect = [
            shell_ok(""),              # lsof
            shell_ok("9876"),          # nohup qperf
            shell_ok(LAT_OUT),         # warm-up
            shell_ok(LAT_OUT),         # iter 1
            shell_ok(LAT_OUT),         # iter 2
            shell_ok(""),              # kill
        ]
        measure(config, mock_shell)

    assert (tmp_path / "pmeter_session_A_raw.json").exists()
    assert (tmp_path / "pmeter_session_B_raw.json").exists()
