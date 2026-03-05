"""NSG-01 to NSG-10: AzureProvider._find_safe_nsg_priority() tests."""

import json
import pytest
from unittest.mock import MagicMock
from providers import AzureProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider(shell):
    return AzureProvider(shell, "my-rg")


def _nsg_show_response(rules):
    return {
        "exit_code": 0,
        "output": json.dumps(rules),
        "status": "success",
        "audit_id": "a1"
    }


def _deny_rule(priority, port_range="5001"):
    return {
        "priority": priority,
        "access": "Deny",
        "direction": "Inbound",
        "protocol": "Tcp",
        "destinationPortRange": port_range,
        "destinationPortRanges": [],
    }


def _allow_rule(priority, port_range="5001"):
    return {
        "priority": priority,
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "destinationPortRange": port_range,
        "destinationPortRanges": [],
    }


# ---------------------------------------------------------------------------
# NSG-01  No deny rules → priority 200
# ---------------------------------------------------------------------------

def test_nsg01_no_deny_rules():
    """NSG-01 M: No deny rules → default priority 200."""
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response([])))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 200


# ---------------------------------------------------------------------------
# NSG-02  Deny at 300 → priority 290 (300-10)
# ---------------------------------------------------------------------------

def test_nsg02_deny_at_300():
    """NSG-02 M: Deny at priority 300 → new priority 290."""
    rules = [_deny_rule(300)]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 290


# ---------------------------------------------------------------------------
# NSG-03  Deny at 110 → priority 100
# ---------------------------------------------------------------------------

def test_nsg03_deny_at_110():
    """NSG-03 M: Deny at priority 110 → new priority 100."""
    rules = [_deny_rule(110)]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 100


# ---------------------------------------------------------------------------
# NSG-04  Deny at 100 → RuntimeError (can't go below 100)
# ---------------------------------------------------------------------------

def test_nsg04_deny_at_100_raises():
    """NSG-04 M: Deny at minimum priority 100 → RuntimeError."""
    rules = [_deny_rule(100)]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    with pytest.raises(RuntimeError, match="Cannot place ALLOW rule"):
        p._find_safe_nsg_priority("my-nsg", [5001])


# ---------------------------------------------------------------------------
# NSG-05  Collision avoidance: target taken → decrement by 1
# ---------------------------------------------------------------------------

def test_nsg05_collision_avoidance():
    """NSG-05 M: Collision at target → decrement to next free slot."""
    # No deny rules → target=200; 200 is occupied → should use 199
    rules = [_allow_rule(200)]  # existing rule at 200
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 199


# ---------------------------------------------------------------------------
# NSG-06  Multiple occupied slots → decrement until free
# ---------------------------------------------------------------------------

def test_nsg06_multiple_collisions():
    """NSG-06 M: Multiple consecutive collisions → finds first free slot."""
    # No deny; target=200; 200,199,198 occupied → should use 197
    rules = [
        _allow_rule(200),
        _allow_rule(199),
        _allow_rule(198),
    ]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 197


# ---------------------------------------------------------------------------
# NSG-07  NSG show command fails → RuntimeError
# ---------------------------------------------------------------------------

def test_nsg07_nsg_show_fails():
    """NSG-07 M: NSG show command failure → RuntimeError."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 1, "output": "Error", "status": "error", "audit_id": "a1"
    }))
    p = _provider(shell)
    with pytest.raises(RuntimeError, match="NSG rule scan failed"):
        p._find_safe_nsg_priority("my-nsg", [5001])


# ---------------------------------------------------------------------------
# NSG-08  Empty output treated as no rules
# ---------------------------------------------------------------------------

def test_nsg08_empty_output():
    """NSG-08 G: Empty shell output treated as empty rules list."""
    shell = MagicMock(execute=MagicMock(return_value={
        "exit_code": 0, "output": "", "status": "success", "audit_id": "a1"
    }))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 200


# ---------------------------------------------------------------------------
# NSG-09  Multiple deny rules → uses minimum priority deny
# ---------------------------------------------------------------------------

def test_nsg09_min_deny_priority():
    """NSG-09 M: Multiple deny rules; minimum priority deny used."""
    rules = [
        _deny_rule(300),
        _deny_rule(200),   # minimum deny priority
        _deny_rule(400),
    ]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 190  # 200 - 10


# ---------------------------------------------------------------------------
# NSG-10  Deny for different port → not counted
# ---------------------------------------------------------------------------

def test_nsg10_deny_different_port_ignored():
    """NSG-10 G: Deny rule for port 80 not counted when checking port 5001.

    No relevant deny for 5001 → target=200. Port-80 deny occupies 200, so
    collision avoidance yields 199 (not a lower bound violation).
    """
    rules = [_deny_rule(200, port_range="80")]
    shell = MagicMock(execute=MagicMock(return_value=_nsg_show_response(rules)))
    p = _provider(shell)
    # No deny covers 5001 → default start=200; 200 is taken → collision → 199
    priority = p._find_safe_nsg_priority("my-nsg", [5001])
    assert priority == 199
