"""MEA-01 to MEA-22: measure() tests."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from helpers import shell_ok, shell_fail, shell_denied
from pipe_meter import measure, MeasurementRaw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LAT_OUT = "tcp_lat:\n    latency = 120 us\n"
THR_OUT = "[SUM] 0.0-10.0 sec  11.6 GBytes  9.94 Gbits/sec\n"


def _lat_side_effect(n=8):
    """Build side_effect list for a pure latency run."""
    return [
        shell_ok(""),              # lsof — no stale pids
        shell_ok("9876"),          # nohup qperf — PID
        shell_ok(LAT_OUT),         # warm-up
        *[shell_ok(LAT_OUT)] * n, # iterations
        shell_ok(""),              # kill qperf
    ]


def _thr_side_effect(n=2):
    """Build side_effect list for a pure throughput run (after lsof)."""
    return [
        shell_ok(""),              # lsof — no stale pids
        shell_ok("5678"),          # nohup iperf — PID
        shell_ok(THR_OUT),         # warm-up
        *[shell_ok(THR_OUT)] * n, # iterations
        shell_ok(""),              # kill iperf
    ]


def _both_side_effect(n=2):
    """Build side_effect list for a 'both' run."""
    return [
        shell_ok(""),              # lsof
        shell_ok("9876"),          # nohup qperf
        shell_ok(LAT_OUT),         # qperf warm-up
        *[shell_ok(LAT_OUT)] * n, # qperf iterations
        shell_ok(""),              # kill qperf
        shell_ok("5678"),          # nohup iperf
        shell_ok(THR_OUT),         # iperf warm-up
        *[shell_ok(THR_OUT)] * n, # iperf iterations
        shell_ok(""),              # kill iperf
    ]


# ---------------------------------------------------------------------------
# MEA-01  Happy path: latency, N=8 — correct sample count
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea01_latency_happy(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-01 M: latency run collects correct number of samples."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = _lat_side_effect(8)
    raw = measure(base_config, mock_shell)
    assert len(raw.latency_samples) == 8
    assert len(raw.throughput_samples) == 0


# ---------------------------------------------------------------------------
# MEA-02  Happy path: throughput, N=2
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea02_throughput_happy(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-02 M: throughput run collects correct samples."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    base_config.iterations = 2
    mock_shell.execute.side_effect = _thr_side_effect(2)
    raw = measure(base_config, mock_shell)
    assert len(raw.throughput_samples) == 2
    assert len(raw.latency_samples) == 0


# ---------------------------------------------------------------------------
# MEA-03  Happy path: both, N=2
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea03_both_happy(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-03 M: both run collects latency and throughput samples."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "both"
    base_config.iterations = 2
    mock_shell.execute.side_effect = _both_side_effect(2)
    raw = measure(base_config, mock_shell)
    assert len(raw.latency_samples) == 2
    assert len(raw.throughput_samples) == 2


# ---------------------------------------------------------------------------
# MEA-04  _raw.json artifact written
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea04_raw_artifact_written(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-04 M: _raw.json artifact written with correct fields."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = _lat_side_effect(8)
    measure(base_config, mock_shell)
    art_path = tmp_path / f"{base_config.session_id}_raw.json"
    assert art_path.exists()
    data = json.loads(art_path.read_text())
    assert "latency_samples_us" in data
    assert len(data["latency_samples_us"]) == 8


# ---------------------------------------------------------------------------
# MEA-05  Stale PIDs detected and killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea05_stale_pids_killed(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-05 M: Stale PIDs found → kill command executed."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok("1234\n5678"),    # lsof — stale pids
        shell_ok(""),              # kill stale pids
        shell_ok("9876"),          # nohup qperf
        shell_ok(LAT_OUT),         # warm-up
        *[shell_ok(LAT_OUT)] * 8,  # iterations
        shell_ok(""),              # kill qperf
    ]
    raw = measure(base_config, mock_shell)
    assert len(raw.latency_samples) == 8


# ---------------------------------------------------------------------------
# MEA-06  Kill stale pids denied → RuntimeError
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea06_stale_kill_denied(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-06 M: Kill stale pids denied → RuntimeError raised."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok("1234"),  # lsof — stale pid
        shell_denied(),    # kill denied
    ]
    with pytest.raises(RuntimeError, match="kill was declined"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-07  qperf server start denied → RuntimeError + server killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea07_qperf_start_denied(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-07 M: qperf server start denied → RuntimeError."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),    # lsof
        shell_denied(),  # nohup qperf denied
        shell_ok(""),    # kill in finally (pkill since no pid)
    ]
    with pytest.raises(RuntimeError, match="qperf server start failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-08  iperf server start denied → RuntimeError
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea08_iperf_start_denied(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-08 M: iperf server start denied → RuntimeError."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    mock_shell.execute.side_effect = [
        shell_ok(""),    # lsof
        shell_denied(),  # nohup iperf denied
        shell_ok(""),    # kill in finally (pkill since no pid)
    ]
    with pytest.raises(RuntimeError, match="iperf server start failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-09  test_type=throughput → no qperf server command
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea09_throughput_no_qperf_server(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-09 M: throughput-only run does not start qperf server."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    base_config.iterations = 2
    mock_shell.execute.side_effect = _thr_side_effect(2)
    measure(base_config, mock_shell)
    calls = [str(c) for c in mock_shell.execute.call_args_list]
    assert not any("nohup qperf" in c for c in calls)


# ---------------------------------------------------------------------------
# MEA-10  test_type=latency → no iperf server command
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea10_latency_no_iperf_server(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-10 M: latency-only run does not start iperf server."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = _lat_side_effect(8)
    measure(base_config, mock_shell)
    calls = [str(c) for c in mock_shell.execute.call_args_list]
    assert not any("nohup iperf" in c for c in calls)


# ---------------------------------------------------------------------------
# MEA-11  qperf warmup fail → RuntimeError + server killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea11_qperf_warmup_fails(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-11 M: qperf warm-up failure → RuntimeError, server still killed."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),                # lsof
        shell_ok("9876"),            # nohup qperf
        shell_fail("timeout", 1),    # warm-up fails
        shell_ok(""),                # kill qperf (finally)
    ]
    with pytest.raises(RuntimeError, match="Warm-up qperf failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-12  iperf warmup fail → RuntimeError + server killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea12_iperf_warmup_fails(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-12 M: iperf warm-up failure → RuntimeError, server still killed."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    mock_shell.execute.side_effect = [
        shell_ok(""),                # lsof
        shell_ok("5678"),            # nohup iperf
        shell_fail("timeout", 1),    # warm-up fails
        shell_ok(""),                # kill iperf (finally)
    ]
    with pytest.raises(RuntimeError, match="Warm-up iperf failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-13  qperf iteration fails → RuntimeError + server killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea13_qperf_iteration_fails(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-13 M: qperf client fails on iteration → RuntimeError, server killed."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),               # lsof
        shell_ok("9876"),           # nohup qperf
        shell_ok(LAT_OUT),          # warm-up ok
        shell_fail("error", 1),     # iteration 1 fails
        shell_ok(""),               # kill qperf (finally)
    ]
    with pytest.raises(RuntimeError, match="qperf client failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-14  iperf iteration fails → RuntimeError + server killed
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea14_iperf_iteration_fails(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-14 M: iperf client fails on iteration → RuntimeError, server killed."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    mock_shell.execute.side_effect = [
        shell_ok(""),               # lsof
        shell_ok("5678"),           # nohup iperf
        shell_ok(THR_OUT),          # warm-up
        shell_fail("error", 1),     # iteration 1 fails
        shell_ok(""),               # kill iperf (finally)
    ]
    with pytest.raises(RuntimeError, match="iperf client failed"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-15  Server kill (teardown) always runs on exception
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea15_server_kill_on_exception(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-15 M: Server teardown runs even when iteration raises."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),               # lsof
        shell_ok("9876"),           # nohup qperf
        shell_ok(LAT_OUT),          # warm-up
        shell_fail("error", 1),     # iteration 1 fails
        shell_ok(""),               # kill qperf (finally — must be called)
    ]
    with pytest.raises(RuntimeError):
        measure(base_config, mock_shell)
    # All 5 calls consumed means kill was called
    assert mock_shell.execute.call_count == 5


# ---------------------------------------------------------------------------
# MEA-16  non-integer PID from qperf → RuntimeError
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea16_qperf_non_integer_pid(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-16 M: Non-integer PID from qperf server → RuntimeError."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),          # lsof
        shell_ok("not_a_pid"), # nohup qperf — bad output
        shell_ok(""),          # pkill in finally (pid unknown)
    ]
    with pytest.raises(RuntimeError, match="non-integer PID"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-17  non-integer PID from iperf → RuntimeError
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea17_iperf_non_integer_pid(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-17 M: Non-integer PID from iperf server → RuntimeError."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    mock_shell.execute.side_effect = [
        shell_ok(""),          # lsof
        shell_ok("not_a_pid"), # nohup iperf — bad output
        shell_ok(""),          # pkill in finally
    ]
    with pytest.raises(RuntimeError, match="non-integer PID"):
        measure(base_config, mock_shell)


# ---------------------------------------------------------------------------
# MEA-18  Latency values parsed correctly
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea18_latency_values_parsed(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-18 M: Latency values extracted from qperf output correctly."""
    base_config.audit_dir = str(tmp_path)
    base_config.iterations = 2
    mock_shell.execute.side_effect = [
        shell_ok(""),
        shell_ok("9876"),
        shell_ok("tcp_lat:\n    latency = 100 us\n"),
        shell_ok("tcp_lat:\n    latency = 200 us\n"),
        shell_ok("tcp_lat:\n    latency = 150 us\n"),
        shell_ok(""),
    ]
    raw = measure(base_config, mock_shell)
    assert raw.latency_samples == [200.0, 150.0]


# ---------------------------------------------------------------------------
# MEA-19  Throughput values parsed correctly
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea19_throughput_values_parsed(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-19 M: Throughput values extracted from iperf output correctly."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "throughput"
    base_config.iterations = 2
    mock_shell.execute.side_effect = [
        shell_ok(""),
        shell_ok("5678"),
        shell_ok("[SUM] 0.0-10.0 sec  10.0 GBytes  8.59 Gbits/sec\n"),
        shell_ok("[SUM] 0.0-10.0 sec  10.5 GBytes  9.01 Gbits/sec\n"),
        shell_ok("[SUM] 0.0-10.0 sec  11.0 GBytes  9.44 Gbits/sec\n"),
        shell_ok(""),
    ]
    raw = measure(base_config, mock_shell)
    assert abs(raw.throughput_samples[0] - 9.01) < 0.01
    assert abs(raw.throughput_samples[1] - 9.44) < 0.01


# ---------------------------------------------------------------------------
# MEA-20  session_id in returned MeasurementRaw
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea20_session_id_in_raw(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-20 M: Returned MeasurementRaw.session_id matches config."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = _lat_side_effect(8)
    raw = measure(base_config, mock_shell)
    assert raw.session_id == base_config.session_id


# ---------------------------------------------------------------------------
# MEA-21  Both blocks sequential: latency first, throughput second
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea21_both_sequential(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-21 M: 'both' — latency completes before throughput starts."""
    base_config.audit_dir = str(tmp_path)
    base_config.test_type = "both"
    base_config.iterations = 2
    mock_shell.execute.side_effect = _both_side_effect(2)
    raw = measure(base_config, mock_shell)
    calls = [str(c) for c in mock_shell.execute.call_args_list]
    qperf_idx = next(i for i, c in enumerate(calls) if "nohup qperf" in c)
    iperf_idx = next(i for i, c in enumerate(calls) if "nohup iperf" in c)
    assert qperf_idx < iperf_idx


# ---------------------------------------------------------------------------
# MEA-22  RuntimeError in measure → _raw.json NOT written
# ---------------------------------------------------------------------------

@patch("time.sleep")
def test_mea22_raw_not_written_on_exception(mock_sleep, base_config, mock_shell, tmp_path):
    """MEA-22 M: RuntimeError raised before write → _raw.json does not exist."""
    base_config.audit_dir = str(tmp_path)
    mock_shell.execute.side_effect = [
        shell_ok(""),
        shell_ok("9876"),
        shell_fail("timeout", 1),  # warm-up fails
        shell_ok(""),              # kill in finally
    ]
    with pytest.raises(RuntimeError):
        measure(base_config, mock_shell)
    raw_path = tmp_path / f"{base_config.session_id}_raw.json"
    assert not raw_path.exists()
