"""
pytest configuration for nftables-parser tests.
Adds the tests/ and package root directories to sys.path so helpers and
the module under test are importable regardless of the cwd pytest is run from.
"""
import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).parent
_REPO_ROOT  = _TESTS_DIR.parent

for _p in (str(_TESTS_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
