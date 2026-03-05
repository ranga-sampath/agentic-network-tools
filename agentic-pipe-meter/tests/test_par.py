"""PAR-01 to PAR-10: parse_qperf_latency() and parse_iperf2_throughput() tests."""

import pytest
from pipe_meter import parse_qperf_latency, parse_iperf2_throughput, ParseError


# ---------------------------------------------------------------------------
# PAR-01  qperf: basic 'us' unit
# ---------------------------------------------------------------------------

def test_par01_qperf_us():
    """PAR-01 M: Basic µs output parsed correctly."""
    out = "tcp_lat:\n    latency = 120 us\n"
    assert parse_qperf_latency(out) == 120.0


# ---------------------------------------------------------------------------
# PAR-02  qperf: µs unicode symbol
# ---------------------------------------------------------------------------

def test_par02_qperf_unicode_us():
    """PAR-02 M: µs (unicode) unit parsed correctly."""
    out = "tcp_lat:\n    latency = 85.3 µs\n"
    assert abs(parse_qperf_latency(out) - 85.3) < 0.001


# ---------------------------------------------------------------------------
# PAR-03  qperf: ms unit → converted to µs
# ---------------------------------------------------------------------------

def test_par03_qperf_ms_conversion():
    """PAR-03 M: ms unit converted to µs (×1000)."""
    out = "tcp_lat:\n    latency = 1.5 ms\n"
    assert abs(parse_qperf_latency(out) - 1500.0) < 0.001


# ---------------------------------------------------------------------------
# PAR-04  qperf: decimal value
# ---------------------------------------------------------------------------

def test_par04_qperf_decimal():
    """PAR-04 M: Decimal latency value parsed correctly."""
    out = "tcp_lat:\n    latency = 99.7 us\n"
    assert abs(parse_qperf_latency(out) - 99.7) < 0.001


# ---------------------------------------------------------------------------
# PAR-05  qperf: unparseable output → ParseError
# ---------------------------------------------------------------------------

def test_par05_qperf_parse_error():
    """PAR-05 M: Unparseable output raises ParseError."""
    with pytest.raises(ParseError):
        parse_qperf_latency("some unexpected output")


# ---------------------------------------------------------------------------
# PAR-06  iperf2: Gbits/sec SUM line
# ---------------------------------------------------------------------------

def test_par06_iperf_gbits():
    """PAR-06 M: Gbits/sec SUM line parsed correctly."""
    out = "[SUM] 0.0-10.0 sec  11.6 GBytes  9.94 Gbits/sec\n"
    assert abs(parse_iperf2_throughput(out) - 9.94) < 0.001


# ---------------------------------------------------------------------------
# PAR-07  iperf2: Mbits/sec → converted to Gbps
# ---------------------------------------------------------------------------

def test_par07_iperf_mbits_conversion():
    """PAR-07 M: Mbits/sec converted to Gbps (÷1000)."""
    out = "[SUM] 0.0-10.0 sec  1.0 GBytes  850 Mbits/sec\n"
    assert abs(parse_iperf2_throughput(out) - 0.85) < 0.001


# ---------------------------------------------------------------------------
# PAR-08  iperf2: no SUM line → ParseError
# ---------------------------------------------------------------------------

def test_par08_iperf_no_sum_line():
    """PAR-08 M: No [SUM] line raises ParseError."""
    with pytest.raises(ParseError):
        parse_iperf2_throughput("[  3] local 10.0.0.4 port 5001\n")


# ---------------------------------------------------------------------------
# PAR-09  iperf2: empty string → ParseError
# ---------------------------------------------------------------------------

def test_par09_iperf_empty_string():
    """PAR-09 M: Empty output raises ParseError."""
    with pytest.raises(ParseError):
        parse_iperf2_throughput("")


# ---------------------------------------------------------------------------
# PAR-10  qperf: whitespace variations
# ---------------------------------------------------------------------------

def test_par10_qperf_whitespace():
    """PAR-10 G: Extra whitespace around '=' handled."""
    out = "tcp_lat:\n    latency=200 us\n"
    assert parse_qperf_latency(out) == 200.0
