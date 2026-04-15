"""
conftest.py — shared pytest configuration for security-rule-inspector tests.

Adds the parent directory to sys.path so source modules (nsg_engine,
nsg_preprocessor, providers, security_rule_inspector) can be imported
without installing the package.
"""

import sys
from pathlib import Path

# Parent directory contains all source modules
_PARENT = Path(__file__).parent.parent
sys.path.insert(0, str(_PARENT))

# Absolute path to the fixtures directory used by all fixture-based tests
FIXTURES_DIR = _PARENT / "fixtures"


def fixture_path(name: str) -> str:
    """Return the absolute path string for a fixture file by filename."""
    return str(FIXTURES_DIR / name)
