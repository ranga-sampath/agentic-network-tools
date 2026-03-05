"""VAL-01 to VAL-12: validate() tests."""

import re
import pytest
from helpers import shell_ok, shell_fail, shell_denied
from pipe_meter import validate, PipelineConfig


# ---------------------------------------------------------------------------
# VAL-01  Happy path — all fields populated, session_id generated
# ---------------------------------------------------------------------------

def test_val01_happy_path(make_args):
    """VAL-01 M: Valid args produce correct PipelineConfig."""
    cfg = validate(make_args())
    assert cfg.source_ip == "10.0.0.4"
    assert cfg.dest_ip == "10.0.0.5"
    assert cfg.ssh_user == "azureuser"
    assert cfg.test_type == "latency"
    assert cfg.iterations == 8
    assert cfg.is_baseline is False
    assert cfg.storage_account == "mystorage"
    assert cfg.container == "pipe-meter-results"
    assert cfg.resource_group == "my-rg"
    # session_id auto-generated when not supplied
    assert re.match(r"pmeter_\d{8}T\d{6}", cfg.session_id)
    assert cfg.audit_dir == "./audit"


# ---------------------------------------------------------------------------
# VAL-02  test_type="throughput"
# ---------------------------------------------------------------------------

def test_val02_test_type_throughput(make_args):
    """VAL-02 M: test_type='throughput' accepted."""
    cfg = validate(make_args(test_type="throughput"))
    assert cfg.test_type == "throughput"


# ---------------------------------------------------------------------------
# VAL-03  test_type="both"
# ---------------------------------------------------------------------------

def test_val03_test_type_both(make_args):
    """VAL-03 M: test_type='both' accepted."""
    cfg = validate(make_args(test_type="both"))
    assert cfg.test_type == "both"


# ---------------------------------------------------------------------------
# VAL-04  Invalid test_type
# ---------------------------------------------------------------------------

def test_val04_invalid_test_type(make_args):
    """VAL-04 M: invalid test_type raises ValueError."""
    with pytest.raises(ValueError, match="--test-type"):
        validate(make_args(test_type="ping"))


# ---------------------------------------------------------------------------
# VAL-05  Invalid source IP
# ---------------------------------------------------------------------------

def test_val05_invalid_source_ip(make_args):
    """VAL-05 M: invalid source IP raises ValueError."""
    with pytest.raises(ValueError, match="--source-ip"):
        validate(make_args(source_ip="not_an_ip"))


# ---------------------------------------------------------------------------
# VAL-06  Invalid dest IP
# ---------------------------------------------------------------------------

def test_val06_invalid_dest_ip(make_args):
    """VAL-06 M: invalid dest IP raises ValueError."""
    with pytest.raises(ValueError, match="--dest-ip"):
        validate(make_args(dest_ip="300.0.0.1"))


# ---------------------------------------------------------------------------
# VAL-07  source_ip == dest_ip
# ---------------------------------------------------------------------------

def test_val07_same_src_dst(make_args):
    """VAL-07 M: source and dest same IP raises ValueError."""
    with pytest.raises(ValueError, match="must be different"):
        validate(make_args(source_ip="10.0.0.4", dest_ip="10.0.0.4"))


# ---------------------------------------------------------------------------
# VAL-08  iterations < 1
# ---------------------------------------------------------------------------

def test_val08_iterations_zero(make_args):
    """VAL-08 M: iterations=0 raises ValueError."""
    with pytest.raises(ValueError, match="--iterations"):
        validate(make_args(iterations=0))


# ---------------------------------------------------------------------------
# VAL-09  Missing ssh_user
# ---------------------------------------------------------------------------

def test_val09_missing_ssh_user(make_args):
    """VAL-09 M: empty ssh_user raises ValueError."""
    with pytest.raises(ValueError, match="--ssh-user"):
        validate(make_args(ssh_user=""))


# ---------------------------------------------------------------------------
# VAL-10  Missing storage_account
# ---------------------------------------------------------------------------

def test_val10_missing_storage_account(make_args):
    """VAL-10 M: empty storage_account raises ValueError."""
    with pytest.raises(ValueError, match="--storage-account"):
        validate(make_args(storage_account=""))


# ---------------------------------------------------------------------------
# VAL-11  Custom session_id preserved
# ---------------------------------------------------------------------------

def test_val11_custom_session_id(make_args):
    """VAL-11 M: explicit session_id passed through."""
    cfg = validate(make_args(session_id="my_custom_session"))
    assert cfg.session_id == "my_custom_session"


# ---------------------------------------------------------------------------
# VAL-12  compare_baseline flag
# ---------------------------------------------------------------------------

def test_val12_compare_baseline(make_args):
    """VAL-12 M: compare_baseline=True passes through."""
    cfg = validate(make_args(compare_baseline=True))
    assert cfg.compare_baseline is True
