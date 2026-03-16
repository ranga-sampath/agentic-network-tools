"""
Shared helpers for the iptables-parser test suite.

Import directly in test files:
    from parser_helpers import parse, load, SAMPLES_DIR, PARSER_PATH
"""
import sys
from pathlib import Path

# Make all netfilter-inspector modules importable without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

from iptables_parser import parse_iptables_save  # noqa: E402 (after sys.path patch)

SAMPLES_DIR = Path(__file__).parent.parent / "iptables-samples"
PARSER_PATH = Path(__file__).parent.parent / "iptables_parser.py"


def parse(text: str, family: str = "ipv4") -> dict:
    """Parse an iptables-save text string and return the result dict."""
    return parse_iptables_save(text, family=family)


def load(filename: str, family: str = "ipv4") -> dict:
    """Parse a fixture file from iptables-samples/ and return the result dict."""
    return parse_iptables_save(
        (SAMPLES_DIR / filename).read_text(encoding="utf-8"), family=family
    )
