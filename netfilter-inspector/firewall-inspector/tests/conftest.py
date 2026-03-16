"""
Shared helpers for the firewall-inspector test suite.

Sets up sys.path for both firewall-inspector/ modules and the sibling
iptables-parser/ module, then exposes the parse() helper used by test_diff.py.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent          # netfilter-inspector/
_FIREWALL_INSPECTOR = Path(__file__).parent.parent   # firewall-inspector/

sys.path.insert(0, str(_FIREWALL_INSPECTOR))
sys.path.insert(0, str(_ROOT / "iptables-parser"))

from iptables_parser import parse_iptables_save  # noqa: E402


def parse(text: str, family: str = "ipv4") -> dict:
    """Parse an iptables-save text string and return the result dict."""
    return parse_iptables_save(text, family=family)
