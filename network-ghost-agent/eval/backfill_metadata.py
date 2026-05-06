#!/usr/bin/env python3
"""One-time backfill: write metadata.json for all existing runs that lack it.

For each run directory containing run_summary.json but no metadata.json:
  - run_id         built from use_case, model, created_at in run_summary.json
  - system_prompt_hash  SHA-256 of current ghost_agent.py (system prompt has not
                        changed since testing; this is the accurate baseline hash)
  - ghost_agent_commit  nearest git commit at or before the run's created_at
  - backfilled     true  (marks that this was reconstructed, not captured live)

Usage:
    python eval/backfill_metadata.py [--force]

    --force   overwrite metadata.json even if it already exists
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path

EVAL_DIR  = Path(__file__).parent
AGENT_DIR = EVAL_DIR.parent
RUNS_DIR  = EVAL_DIR / "runs"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit_before(repo_dir: Path, iso_ts: str) -> str:
    """Return the HEAD commit hash at or just before iso_ts."""
    try:
        ts = datetime.fromisoformat(iso_ts)
        git_date = ts.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        r = subprocess.run(
            ["git", "log", f"--before={git_date}", "-1", "--format=%H"],
            cwd=str(repo_dir), capture_output=True, text=True, check=True,
        )
        commit = r.stdout.strip()
        return commit if commit else "unknown"
    except Exception:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true",
                        help="Overwrite metadata.json if it already exists")
    args = parser.parse_args()

    agent_py  = AGENT_DIR / "ghost_agent.py"
    sp_hash   = _sha256_file(agent_py)

    run_dirs = sorted(RUNS_DIR.rglob("run_summary.json"))
    print(f"Found {len(run_dirs)} run(s) to process\n")

    written = skipped = 0
    for summary_path in run_dirs:
        run_dir = summary_path.parent
        meta_path = run_dir / "metadata.json"

        if meta_path.exists() and not args.force:
            print(f"  [SKIP] {run_dir.relative_to(RUNS_DIR)} — metadata.json exists")
            skipped += 1
            continue

        summary = json.loads(summary_path.read_text())
        use_case_id = summary["use_case"]        # e.g. "use_case_f"
        model_id    = summary["model"]            # e.g. "claude-sonnet-4-6"
        created_at  = summary.get("created_at")  # ISO 8601

        if not created_at:
            print(f"  [WARN] {run_dir.relative_to(RUNS_DIR)} — no created_at in run_summary.json, skipping")
            skipped += 1
            continue

        ts = datetime.fromisoformat(created_at)
        ts_compact = ts.strftime("%Y%m%d_%H%M%S")
        run_id = f"{use_case_id}_{model_id}_{ts_compact}"

        commit = _git_commit_before(AGENT_DIR, created_at)

        metadata = {
            "run_id":                   run_id,
            "model_id":                 model_id,
            "use_case_id":              use_case_id,
            "timestamp_utc":            created_at,
            "system_prompt_hash":       sp_hash,
            "ghost_agent_commit":       commit,
            "silent_update_detectable": False,
            "backfilled":               True,
        }
        meta_path.write_text(json.dumps(metadata, indent=2))
        print(f"  [OK] {run_dir.relative_to(RUNS_DIR)}  run_id={run_id}  commit={commit[:10]}")
        written += 1

    print(f"\nDone — {written} written, {skipped} skipped")


if __name__ == "__main__":
    main()
