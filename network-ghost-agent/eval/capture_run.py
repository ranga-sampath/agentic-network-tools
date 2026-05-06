#!/usr/bin/env python3
"""Extract key metrics from a completed Phase 1 run and write run_summary.json.

Called automatically by run_phase1.sh after the agent exits. Can also be run
manually to re-extract from an existing run directory.

Usage:
    python eval/capture_run.py \\
        --run-dir eval/runs/phase1/gemini/use_case_a \\
        --use-case use_case_a --provider gemini --model gemini-2.0-flash

Reads:
    <run-dir>/ghost_session.json         — turn count, hypotheses, rca path
    <run-dir>/audit/shell_audit_*.jsonl  — command counts and sequence
    <run-dir>/audit/ghost_rca_*.md       — confidence and root cause text

Writes:
    <run-dir>/run_summary.json
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _extract_rca_fields(rca_path: Path) -> dict:
    """Parse confidence, root_cause_summary, and recommended_actions from RCA markdown."""
    text = rca_path.read_text()

    confidence = None
    m = re.search(r"_Confidence:\s*(\w+)_", text)
    if m:
        confidence = m.group(1).lower()

    root_cause = None
    m = re.search(r"## Root Cause\s*\n+(.+?)(?=\n##|\Z)", text, re.DOTALL)
    if m:
        root_cause = m.group(1).strip()

    recommended: list[str] = []
    m = re.search(r"## Recommended Actions\s*\n+(.+?)(?=\n##|\Z)", text, re.DOTALL)
    if m:
        for line in m.group(1).strip().splitlines():
            line = re.sub(r"^[\d\.\-\)\s]+", "", line).strip()
            if line:
                recommended.append(line)

    return {
        "confidence":          confidence,
        "root_cause_summary":  root_cause,
        "recommended_actions": recommended,
    }


def _read_shell_audit(audit_dir: Path) -> dict:
    """Count commands and build the command sequence from shell_audit_*.jsonl."""
    total = denied = auto_approved = user_approved = 0
    commands: list[str] = []

    for path in sorted(audit_dir.glob("shell_audit_*.jsonl")):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            action = rec.get("action", "")
            if action == "user_denied":
                denied += 1
            elif action == "auto_approved":
                auto_approved += 1
            elif action in ("user_approved", "user_modified"):
                user_approved += 1
            cmd = rec.get("command", "")
            if cmd:
                commands.append(cmd[:100])

    return {
        "commands_issued":       total,
        "commands_denied":       denied,
        "commands_auto_approved": auto_approved,
        "commands_user_approved": user_approved,
        "command_sequence":      commands,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir",  required=True, help="Path to the run directory")
    parser.add_argument("--use-case", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model",    required=True)
    args = parser.parse_args()

    run_dir   = Path(args.run_dir)
    audit_dir = run_dir / "audit"

    session_path = run_dir / "ghost_session.json"
    if not session_path.exists():
        raise SystemExit(f"[ERROR] ghost_session.json not found in {run_dir}")

    session = json.loads(session_path.read_text())
    session.pop("_checksum", None)

    rca_generated  = session.get("rca_report_path") is not None
    rca_fields: dict = {"confidence": None, "root_cause_summary": None, "recommended_actions": []}
    if rca_generated:
        rca_files = sorted(audit_dir.glob("ghost_report_*.md"))
        if rca_files:
            rca_fields = _extract_rca_fields(rca_files[-1])

    shell_metrics = _read_shell_audit(audit_dir)

    hypothesis_log = session.get("hypothesis_log", [])

    summary = {
        "use_case":        args.use_case,
        "provider":        args.provider,
        "model":           args.model,
        "session_id":      session.get("session_id"),
        "created_at":      session.get("created_at"),
        "turn_count":      session.get("turn_count", 0),
        "rca_generated":   rca_generated,
        "abort_reason":    session.get("abort_reason"),
        **rca_fields,
        **shell_metrics,
        "hypothesis_count": len(hypothesis_log),
        "hypotheses": [
            {
                "id":           h.get("id"),
                "description":  h.get("description"),
                "state":        h.get("state"),
                "denial_count": h.get("denial_count", 0),
            }
            for h in hypothesis_log
        ],
    }

    out = run_dir / "run_summary.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"run_summary.json written → {out}")


if __name__ == "__main__":
    main()
