"""
CLI tests for nftables_parser.py and nftables_diff.py

Covers: AC-DC*, AC-NF04, AC-NF05, AC-EH07
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT   = Path(__file__).parent.parent
SAMPLES_DIR = REPO_ROOT / "nftables-samples"
PARSER_CLI  = str(REPO_ROOT / "nftables_parser.py")
DIFF_CLI    = str(REPO_ROOT / "nftables_diff.py")
FX02        = str(SAMPLES_DIR / "fx-02-ip-clean.json")
FX01        = str(SAMPLES_DIR / "fx-01-empty.json")
FX03        = str(SAMPLES_DIR / "fx-03-inet-drop-policy.json")


def _run_parser(*args, stdin_text=None):
    return subprocess.run(
        [sys.executable, PARSER_CLI, *args],
        capture_output=True, text=True,
        input=stdin_text,
    )


def _run_diff(*args, stdin_text=None):
    return subprocess.run(
        [sys.executable, DIFF_CLI, *args],
        capture_output=True, text=True,
        input=stdin_text,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Parser CLI — AC-NF04, AC-NF05, AC-EH07
# ═══════════════════════════════════════════════════════════════════════════

def test_NF04_parser_file_path():
    """AC-NF04: file path argument → JSON on stdout, exit 0"""
    r = _run_parser(FX02)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["input_format"] == "nft-json"
    assert r.stderr == ""


def test_NF04_parser_stdin():
    """AC-NF04: stdin → same JSON output"""
    content = Path(FX02).read_text()
    r = _run_parser(stdin_text=content)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["input_format"] == "nft-json"


def test_NF05_parser_indent_2_default():
    """AC-NF05: default indent=2"""
    r = _run_parser(FX02)
    assert r.returncode == 0
    # Check 2-space indent by looking at the raw output
    assert "\n  " in r.stdout


def test_NF05_parser_indent_4():
    """AC-NF05: --indent 4"""
    r = _run_parser(FX02, "--indent", "4")
    assert r.returncode == 0
    assert "\n    " in r.stdout


def test_NF05_parser_indent_0():
    """AC-NF05: --indent 0 → compact"""
    r = _run_parser(FX02, "--indent", "0")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["input_format"] == "nft-json"


def test_EH07_parser_file_not_found():
    """AC-EH07: missing file → exit 1, error on stderr"""
    r = _run_parser("/nonexistent/path.json")
    assert r.returncode == 1
    assert r.stderr.strip() != ""
    assert "traceback" not in r.stderr.lower()


def test_parser_missing_arguments():
    """No arguments → argparse error, exit 2 or 1"""
    r = _run_parser()
    # argparse exits 2 for missing positional
    assert r.returncode in (1, 2)


# ═══════════════════════════════════════════════════════════════════════════
# Diff CLI — AC-DC01 through AC-DC06
# ═══════════════════════════════════════════════════════════════════════════

def _parsed_json(fixture_path: str, tmp_path) -> str:
    """Parse a fixture through nftables_parser.py and return a path to the parsed JSON."""
    r = _run_parser(fixture_path)
    assert r.returncode == 0, r.stderr
    p = tmp_path / (Path(fixture_path).stem + "_parsed.json")
    p.write_text(r.stdout)
    return str(p)


def test_DC01_successful_diff_from_file_paths(tmp_path):
    """AC-DC01"""
    parsed = _parsed_json(FX02, tmp_path)
    r = _run_diff(parsed, parsed)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["drift_detected"] is False
    assert r.stderr == ""


def test_DC02_drift_exit_code_still_0(tmp_path):
    """AC-DC02: drift does not produce exit code 1"""
    b = _parsed_json(FX01, tmp_path)
    c = _parsed_json(FX02, tmp_path)
    r = _run_diff(b, c)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["drift_detected"] is True


def test_DC03_current_from_stdin(tmp_path):
    """AC-DC03: cat current | diff baseline -"""
    parsed_path = _parsed_json(FX02, tmp_path)
    content = Path(parsed_path).read_text()
    r = _run_diff(parsed_path, "-", stdin_text=content)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["drift_detected"] is False


def test_DC04_file_not_found_exit_1():
    """AC-DC04"""
    r = _run_diff("/nonexistent/baseline.json", FX02)
    assert r.returncode == 1
    assert r.stderr.strip() != ""
    assert "traceback" not in r.stderr.lower()


def test_DC05_cross_format_exit_1(tmp_path):
    """AC-DC05: baseline has iptables-save format"""
    fake_baseline = tmp_path / "iptables_baseline.json"
    fake_baseline.write_text(json.dumps({
        "input_format": "iptables-save",
        "tables": {},
        "parse_warnings": [],
    }))
    parsed_current = _parsed_json(FX02, tmp_path)
    r = _run_diff(str(fake_baseline), parsed_current)
    assert r.returncode == 1
    assert r.stderr.strip() != ""


def test_DC06_missing_arguments_exit_2():
    """AC-DC06"""
    r = _run_diff()
    assert r.returncode == 2


def test_diff_indent_option(tmp_path):
    """--indent passes through"""
    parsed = _parsed_json(FX02, tmp_path)
    r = _run_diff(parsed, parsed, "--indent", "4")
    assert r.returncode == 0, r.stderr
    assert "\n    " in r.stdout


def test_DC07_summary_flag_produces_markdown(tmp_path):
    """AC-DC07: --summary → Markdown output, not JSON"""
    parsed = _parsed_json(FX02, tmp_path)
    r = _run_diff(parsed, parsed, "--summary")
    assert r.returncode == 0, r.stderr
    assert "nftables Ruleset Diff" in r.stdout
    assert "No drift detected." in r.stdout
    # output must not be valid JSON
    with pytest.raises((json.JSONDecodeError, ValueError)):
        json.loads(r.stdout)


def test_DC08_summary_drift_shows_changes(tmp_path):
    """AC-DC08: --summary on differing inputs → drift section headers present"""
    b = _parsed_json(FX01, tmp_path)
    c = _parsed_json(FX02, tmp_path)
    r = _run_diff(b, c, "--summary")
    assert r.returncode == 0, r.stderr
    assert "nftables Ruleset Diff" in r.stdout
    assert "Drift detected" in r.stdout


def test_DC09_summary_verbose_produces_markdown(tmp_path):
    """AC-DC09: --summary --verbose → Markdown output"""
    b = _parsed_json(FX01, tmp_path)
    c = _parsed_json(FX02, tmp_path)
    r = _run_diff(b, c, "--summary", "--verbose")
    assert r.returncode == 0, r.stderr
    assert "nftables Ruleset Diff" in r.stdout
    # must not be JSON
    with pytest.raises((json.JSONDecodeError, ValueError)):
        json.loads(r.stdout)


def test_DC10_verbose_without_summary_produces_json(tmp_path):
    """AC-DC10: --verbose without --summary → valid JSON (verbose silently ignored)"""
    parsed = _parsed_json(FX02, tmp_path)
    r = _run_diff(parsed, parsed, "--verbose")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["drift_detected"] is False
