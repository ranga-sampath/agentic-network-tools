"""BLB-01 to BLB-04: _ip_to_blob_prefix() and blob naming tests."""

import pytest
from pipe_meter import _ip_to_blob_prefix


# ---------------------------------------------------------------------------
# BLB-01  IP dots replaced with underscores
# ---------------------------------------------------------------------------

def test_blb01_ip_to_blob_prefix():
    """BLB-01 M: IP address dots replaced with underscores."""
    assert _ip_to_blob_prefix("10.0.0.4") == "10_0_0_4"


# ---------------------------------------------------------------------------
# BLB-02  Dest IP also converted
# ---------------------------------------------------------------------------

def test_blb02_dest_ip():
    """BLB-02 M: Destination IP converted correctly."""
    assert _ip_to_blob_prefix("10.0.0.5") == "10_0_0_5"


# ---------------------------------------------------------------------------
# BLB-03  Baseline blob name pattern
# ---------------------------------------------------------------------------

def test_blb03_baseline_blob_name():
    """BLB-03 M: Baseline blob name constructed from prefix."""
    prefix = f"{_ip_to_blob_prefix('10.0.0.4')}_{_ip_to_blob_prefix('10.0.0.5')}"
    blob_name = f"{prefix}_baseline.json"
    assert blob_name == "10_0_0_4_10_0_0_5_baseline.json"


# ---------------------------------------------------------------------------
# BLB-04  Result blob name includes session_id
# ---------------------------------------------------------------------------

def test_blb04_result_blob_name():
    """BLB-04 M: Result blob name includes source/dest prefix and session_id."""
    prefix = f"{_ip_to_blob_prefix('10.0.0.4')}_{_ip_to_blob_prefix('10.0.0.5')}"
    session_id = "pmeter_test"
    blob_name = f"{prefix}_{session_id}.json"
    assert blob_name == "10_0_0_4_10_0_0_5_pmeter_test.json"
