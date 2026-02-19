"""Section 8 — Output Processing: Truncation.

Tests TR.01–TR.24. P0/P1/P2.
"""

import json

import pytest

from safe_exec_shell import truncate_output


# ---------------------------------------------------------------------------
# Fixture generators
# ---------------------------------------------------------------------------

def _make_json_array(n):
    # Use indent=2 so multi-line output exceeds the 200-line / 4000-token threshold
    return json.dumps([{"id": i, "name": f"item_{i}"} for i in range(n)], indent=2)


def _make_tabular(n_rows):
    header = "Name          Age   City          Country"
    rows = [f"Person_{i:<6} {20+i%50:<5} City_{i%10:<10} Country_{i%5}" for i in range(n_rows)]
    return "\n".join([header] + rows)


def _make_log_lines(n):
    return "\n".join([f"2025-01-15T14:32:{i:02d}.000Z INFO Processing item {i}" for i in range(n)])


# ---------------------------------------------------------------------------
# P1 — SHOULD PASS: Format-aware truncation
# ---------------------------------------------------------------------------

@pytest.mark.p1
class TestTruncationRules:

    def test_tr01_json_array_large(self):
        """TR.01: JSON array with 312 items -> first 3 + last 1 + message."""
        raw = _make_json_array(312)
        truncated, meta = truncate_output(raw)
        assert meta["truncation_applied"] is True
        assert meta["items_total"] == 312
        assert meta["items_shown"] == 4
        assert "[truncated: showing 4 of 312 items]" in truncated

    def test_tr02_json_array_small(self):
        """TR.02: JSON array with 3 items -> unmodified."""
        raw = _make_json_array(3)
        truncated, meta = truncate_output(raw)
        assert meta["truncation_applied"] is False
        data = json.loads(truncated)
        assert len(data) == 3

    def test_tr03_json_object_nested_arrays(self):
        """TR.03: JSON object with nested arrays -> nested arrays truncated."""
        obj = {
            "resources": [{"id": i, "name": f"resource_{i}"} for i in range(100)],
            "metadata": {"version": "1.0"},
        }
        # Use indent=2 to exceed thresholds
        raw = json.dumps(obj, indent=2)
        truncated, meta = truncate_output(raw)
        result = json.loads(truncated)
        # Nested array should be truncated to first 3 + message + last 1
        assert len(result["resources"]) == 5  # 3 + message + 1
        assert any("truncated" in str(item) for item in result["resources"])
        assert result["metadata"]["version"] == "1.0"

    def test_tr04_json_object_deep_nesting(self):
        """TR.04: JSON object deeper than 3 levels -> capped at depth 3."""
        obj = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
        # Need to exceed threshold with bulk data (indent=2 for multi-line)
        obj["bulk"] = [{"id": i, "name": f"item_{i}"} for i in range(200)]
        raw = json.dumps(obj, indent=2)
        truncated, meta = truncate_output(raw)
        result = json.loads(truncated)
        # Depth 3 should be "..." for the deeply nested part
        assert result["a"]["b"]["c"] == "..."

    def test_tr05_tabular_500_rows(self):
        """TR.05: Tabular text with 500 rows -> header + first N rows + message."""
        raw = _make_tabular(500)
        truncated, meta = truncate_output(raw)
        assert meta["truncation_applied"] is True
        assert meta["output_type"] == "tabular"
        assert "[truncated:" in truncated
        assert "of 500 rows]" in truncated

    def test_tr06_log_stream_2000_lines(self):
        """TR.06: Log/stream text with 2000 lines -> first 20 + last 10 + message."""
        raw = _make_log_lines(2000)
        truncated, meta = truncate_output(raw)
        assert meta["truncation_applied"] is True
        assert meta["output_type"] == "log_stream"
        assert "[truncated:" in truncated
        assert "lines omitted]" in truncated
        # Should show 30 lines of actual content
        assert meta["lines_shown"] == 30

    def test_tr07_binary_output(self):
        """TR.07: Binary output -> replaced entirely with message."""
        raw = "\x00\x01\x02\x03" * 100 + "\x80\x81\x82" * 50
        truncated, meta = truncate_output(raw)
        assert meta["output_type"] == "binary"
        assert "[binary output:" in truncated
        assert "not displayed]" in truncated

    def test_tr08_under_threshold(self):
        """TR.08: Output under threshold -> no truncation."""
        raw = "Line 1\nLine 2\nLine 3"
        truncated, meta = truncate_output(raw)
        assert meta["truncation_applied"] is False
        assert truncated == raw


# ---------------------------------------------------------------------------
# P0 — MUST PASS: stderr never truncated
# ---------------------------------------------------------------------------

@pytest.mark.p0
def test_tr09_stderr_never_truncated(shell_default):
    """TR.09: stderr is NEVER truncated, even if very long."""
    from unittest.mock import patch
    from helpers import mock_subprocess_result, make_request

    long_stderr = "\n".join([f"Error line {i}" for i in range(10000)])
    with patch("safe_exec_shell.subprocess.run",
                return_value=mock_subprocess_result("", long_stderr, 1)):
        resp = shell_default.execute(make_request("ping 8.8.8.8"))
    # stderr should contain all 10000 lines (not truncated)
    assert resp["stderr"].count("\n") >= 9999


# ---------------------------------------------------------------------------
# P2 — GOOD TO PASS: Metadata accuracy
# ---------------------------------------------------------------------------

@pytest.mark.p2
class TestTruncationMetadata:

    def test_tr20_truncation_applied_flag(self):
        """TR.20: truncation_applied is true when truncation occurred."""
        raw = _make_log_lines(2000)
        _, meta = truncate_output(raw)
        assert meta["truncation_applied"] is True

        _, meta = truncate_output("short")
        assert meta["truncation_applied"] is False

    def test_tr21_total_lines_accurate(self):
        """TR.21: total_lines matches actual line count."""
        raw = _make_log_lines(500)
        _, meta = truncate_output(raw)
        assert meta["total_lines"] == 500

    def test_tr22_lines_shown_accurate(self):
        """TR.22: lines_shown matches truncated output line count."""
        raw = _make_log_lines(2000)
        truncated, meta = truncate_output(raw)
        assert meta["lines_shown"] == 30  # 20 head + 10 tail

    def test_tr23_json_array_items_accurate(self):
        """TR.23: items_total and items_shown are accurate for JSON arrays."""
        # _make_json_array uses indent=2, so 100 items will exceed thresholds
        raw = _make_json_array(100)
        _, meta = truncate_output(raw)
        assert meta["items_total"] == 100
        assert meta["items_shown"] == 4

    def test_tr24_output_type_detection(self):
        """TR.24: output_type correctly identifies format."""
        assert truncate_output(_make_json_array(5))[1]["output_type"] == "json_array"
        assert truncate_output('{"key": "value"}')[1]["output_type"] == "json_object"
        assert truncate_output(_make_log_lines(10))[1]["output_type"] == "log_stream"
        assert truncate_output("")[1]["output_type"] == "empty"
