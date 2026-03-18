"""
Shared fixtures and helpers for nftables-parser test suite.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# ── paths ────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).parent.parent
SAMPLES_DIR = REPO_ROOT / "nftables-samples"

sys.path.insert(0, str(REPO_ROOT))

from nftables_parser import parse_nft_ruleset  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def load_fixture(name: str) -> str:
    """Return raw text content of a fixture file."""
    return (SAMPLES_DIR / name).read_text(encoding="utf-8")


def parse_fixture(name: str) -> dict:
    """Parse a fixture file with parse_nft_ruleset() and return the result."""
    return parse_nft_ruleset(load_fixture(name))


def make_nft_json(objects: list) -> str:
    """
    Wrap a list of nftables objects into a valid nft --json top-level envelope.
    Prepends a standard metainfo object unless one is already present.
    """
    has_meta = any("metainfo" in obj for obj in objects)
    if not has_meta:
        meta = {"metainfo": {"version": "1.0.9", "json_schema_version": 1}}
        objects = [meta] + objects
    return json.dumps({"nftables": objects})


def parse_objects(objects: list) -> dict:
    """Build a minimal nft JSON envelope from objects and parse it."""
    return parse_nft_ruleset(make_nft_json(objects))


def rules_in(result: dict, table_key: str, chain_name: str) -> list:
    """Return the rule list for a given table/chain from a parse result."""
    return (
        result["tables"]
        .get(table_key, {})
        .get("chains", {})
        .get(chain_name, {})
        .get("rules", [])
    )


def rule_by_handle(result: dict, table_key: str, chain_name: str, handle: int) -> dict:
    """Return the single rule with the given handle; raises if not found."""
    for r in rules_in(result, table_key, chain_name):
        if r["handle"] == handle:
            return r
    raise KeyError(f"handle {handle} not found in {table_key}/{chain_name}")


def assert_summary_matches_lists(diff: dict) -> None:
    """AC-D23: verify every summary count equals its change list length."""
    changes = diff["changes"]
    summary = diff["summary"]
    for key in (
        "tables_added", "tables_removed",
        "chains_added", "chains_removed",
        "policy_changes",
        "rules_added", "rules_removed",
        "rules_repositioned", "rules_recreated",
    ):
        assert summary[key] == len(changes[key]), (
            f"summary[{key}]={summary[key]} != len(changes[{key}])={len(changes[key])}"
        )
