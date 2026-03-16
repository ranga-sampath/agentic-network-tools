"""
conftest.py — pytest entry point for the iptables-parser test suite.

Helpers (parse, load, SAMPLES_DIR, PARSER_PATH) are in parser_helpers.py
and imported explicitly in each test file:
    from parser_helpers import parse, load, SAMPLES_DIR, PARSER_PATH

This file exists so pytest recognises the tests/ directory as a conftest root
and sets up sys.path before any test module is collected.
"""
import sys
from pathlib import Path

# Make iptables_parser importable when running tests from this directory
sys.path.insert(0, str(Path(__file__).parent.parent))
