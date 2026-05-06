#!/usr/bin/env python3
"""Build and maintain the eval artifact store.

Copies canonical run artifacts into eval/artifact-store/ and keeps
run_index.json current. Multi-session run directories (where earlier
aborted attempts left orphan files) are handled correctly: only the
files matching the canonical session_id from run_summary.json are copied.

Usage:
    # Initial population from all existing runs
    python eval/populate_artifact_store.py

    # Add a single run (called automatically by eval_runner.py after each run)
    python eval/populate_artifact_store.py --run-dir eval/runs/phase2/anthropic/claude-sonnet-4-6/use_case_f

    # Force overwrite an existing store entry
    python eval/populate_artifact_store.py [--run-dir <path>] --force
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

EVAL_DIR    = Path(__file__).parent
AGENT_DIR   = EVAL_DIR.parent
DEMO_DIR    = AGENT_DIR / "demo"
RUNS_DIR    = EVAL_DIR / "runs"
STORE_DIR   = EVAL_DIR / "artifact-store"
INDEX_PATH  = STORE_DIR / "run_index.json"


def _load_index() -> dict:
    if INDEX_PATH.exists():
        return json.loads(INDEX_PATH.read_text())
    return {"schema_version": "1", "runs": []}


def _save_index(index: dict) -> None:
    INDEX_PATH.write_text(json.dumps(index, indent=2))


def _artifact_coverage(run_dir: Path, session_id: str) -> str:
    audit_dir = run_dir / "audit"
    has_shell  = (audit_dir / f"shell_audit_{session_id}.jsonl").exists()
    has_audit  = (audit_dir / f"ghost_audit_{session_id}.md").exists()
    return "full" if (has_shell and has_audit) else "report_only"


def populate_run(run_dir: Path, force: bool = False) -> bool:
    """Add one run to the artifact store. Returns True if the entry was written."""
    run_dir = run_dir.resolve()

    summary_path = run_dir / "run_summary.json"
    meta_path    = run_dir / "metadata.json"

    if not summary_path.exists():
        print(f"  [SKIP] {run_dir.name} — no run_summary.json")
        return False
    if not meta_path.exists():
        print(f"  [SKIP] {run_dir.name} — no metadata.json (run Phase 1 backfill first)")
        return False

    summary    = json.loads(summary_path.read_text())
    metadata   = json.loads(meta_path.read_text())
    session_id = summary.get("session_id")
    run_id     = metadata.get("run_id")
    use_case   = metadata.get("use_case_id")     # e.g. "use_case_f"
    model      = metadata.get("model_id")        # e.g. "claude-sonnet-4-6"

    if not all([session_id, run_id, use_case, model]):
        print(f"  [SKIP] {run_dir.name} — missing required fields in metadata/summary")
        return False

    store_path    = STORE_DIR / use_case / model / run_id
    already_existed = store_path.exists()

    # Idempotency check
    if already_existed and not force:
        print(f"  [SKIP] {use_case}/{model}/{run_id} — already in store")
        return False

    # Identify canonical files
    audit_dir = run_dir / "audit"
    files_to_copy: list[tuple[Path, Path]] = [
        (meta_path,                                           store_path / "metadata.json"),
        (summary_path,                                        store_path / "run_summary.json"),
        (DEMO_DIR / use_case / "PROMPT.txt",                 store_path / "PROMPT.txt"),
        (audit_dir / f"ghost_report_{session_id}.md",        store_path / f"ghost_report_{session_id}.md"),
        (audit_dir / f"ghost_audit_{session_id}.md",         store_path / f"ghost_audit_{session_id}.md"),
        (audit_dir / f"shell_audit_{session_id}.jsonl",      store_path / f"shell_audit_{session_id}.jsonl"),
    ]

    missing = [src for src, _ in files_to_copy if not src.exists()]
    if missing:
        print(f"  [WARN] {use_case}/{model}/{run_id} — missing source files:")
        for m in missing:
            print(f"           {m.name}")

    store_path.mkdir(parents=True, exist_ok=True)
    for src, dst in files_to_copy:
        if src.exists():
            shutil.copy2(src, dst)

    # Update run_index.json
    coverage = _artifact_coverage(run_dir, session_id)
    rel_path = f"{use_case}/{model}/{run_id}"

    index = _load_index()
    existing = next((r for r in index["runs"] if r["run_id"] == run_id), None)
    entry = {
        "run_id":             run_id,
        "use_case_id":        use_case,
        "model_id":           model,
        "system_prompt_hash": metadata.get("system_prompt_hash", ""),
        "backfilled":         metadata.get("backfilled", False),
        "artifact_coverage":  coverage,
        "path":               rel_path,
        "superseded_by":      existing.get("superseded_by") if existing else None,
    }

    if existing:
        index["runs"][index["runs"].index(existing)] = entry
    else:
        index["runs"].append(entry)

    _save_index(index)

    flag = " (forced overwrite)" if (already_existed and force) else ""
    print(f"  [OK] {rel_path}  coverage={coverage}{flag}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--run-dir", metavar="PATH",
        help="Path to a single run directory. Omit to process all runs.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite store entry even if it already exists.",
    )
    args = parser.parse_args()

    STORE_DIR.mkdir(parents=True, exist_ok=True)

    if args.run_dir:
        run_dir = Path(args.run_dir)
        if not run_dir.is_absolute():
            run_dir = Path.cwd() / run_dir
        populate_run(run_dir, force=args.force)
    else:
        run_dirs = sorted(RUNS_DIR.rglob("run_summary.json"))
        print(f"Found {len(run_dirs)} run(s)\n")
        written = skipped = 0
        for p in run_dirs:
            ok = populate_run(p.parent, force=args.force)
            if ok:
                written += 1
            else:
                skipped += 1
        index = _load_index()
        print(f"\nDone — {written} added/updated, {skipped} skipped")
        print(f"Index : {INDEX_PATH}  ({len(index['runs'])} total entries)")


if __name__ == "__main__":
    main()
