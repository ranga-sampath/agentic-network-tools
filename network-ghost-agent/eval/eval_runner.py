#!/usr/bin/env python3
"""Automated eval runner for Ghost Agent.

Runs ghost_agent.py non-interactively across a matrix of use cases and models,
writing artifacts to eval/runs/<run-label>/<provider>/<model>/<use_case>/ and a
per-run log to eval/runs/<run-label>/runner_log.jsonl.

Run order per use case:
    setup.sh once → all models sequentially → teardown.sh once

Usage:
    # Baseline eval — all models, specific use cases
    python eval/eval_runner.py --use-cases f q --providers all --run-label baseline

    # Variant A test — use_case_q with tc/netfilter boundary instruction
    python eval/eval_runner.py --use-cases q --providers all --run-label variant-a \\
        --prompt-addon eval/variant-a-prompt.txt

    # Variant B test — multi-fault use cases with multi-symptom mandate
    python eval/eval_runner.py --use-cases j p q --providers all --run-label variant-b \\
        --prompt-addon eval/variant-b-prompt.txt

    # Re-run a single provider+model after a failure
    python eval/eval_runner.py --use-cases q \\
        --providers "gemini:gemini-2.5-flash" --run-label variant-a --force

Idempotency:
    If a run directory already contains ghost_session.json, that run is skipped
    unless --force is passed. Safe to re-run after partial failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Default provider:model matrix (used when --providers all) ─────────────
DEFAULT_PROVIDERS: list[tuple[str, str]] = [
    ("gemini",     "gemini-2.5-flash"),
    ("anthropic",  "claude-sonnet-4-6"),
    ("anthropic",  "claude-haiku-4-5-20251001"),
]

EVAL_DIR   = Path(__file__).parent
AGENT_DIR  = EVAL_DIR.parent
DEMO_DIR   = AGENT_DIR / "demo"
PYTHON     = str(AGENT_DIR / ".venv" / "bin" / "python")
CONFIG_ENV = str(DEMO_DIR / "config.env")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(log_path: Path, record: dict) -> None:
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head(repo_dir: Path) -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_dir), capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()
    except Exception:
        return "unknown"


def _write_metadata(
    run_dir: Path,
    use_case: str,
    model: str,
    start_ts: str,
    agent_dir: Path,
) -> None:
    ts = datetime.fromisoformat(start_ts)
    ts_compact = ts.strftime("%Y%m%d_%H%M%S")
    use_case_id = f"use_case_{use_case}"
    run_id = f"{use_case_id}_{model}_{ts_compact}"
    metadata = {
        "run_id":                   run_id,
        "model_id":                 model,
        "use_case_id":              use_case_id,
        "timestamp_utc":            start_ts,
        "system_prompt_hash":       _sha256_file(agent_dir / "ghost_agent.py"),
        "ghost_agent_commit":       _git_head(agent_dir),
        "silent_update_detectable": False,
    }
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))


def _parse_providers(raw: list[str]) -> list[tuple[str, str]]:
    """Expand 'all' or parse 'provider:model' strings."""
    if raw == ["all"]:
        return DEFAULT_PROVIDERS
    result = []
    for s in raw:
        if ":" not in s:
            print(f"[ERROR] --providers value {s!r} must be 'all' or 'provider:model'")
            sys.exit(1)
        provider, model = s.split(":", 1)
        result.append((provider, model))
    return result


def _run_script(script_path: Path, label: str) -> int:
    """Run setup.sh or teardown.sh. Returns exit code."""
    if not script_path.exists():
        print(f"  [SKIP] {label}: {script_path.name} not found")
        return 0
    print(f"  [{label}] running {script_path.name}...")
    result = subprocess.run(
        ["bash", str(script_path)],
        cwd=str(script_path.parent),
    )
    if result.returncode != 0:
        print(f"  [WARN] {label} exited with code {result.returncode}")
    return result.returncode


def _run_agent(
    use_case: str,
    provider: str,
    model: str,
    run_label: str,
    force: bool,
    log_path: Path,
    prompt_file: Path,
    prompt_addon: Path | None = None,
) -> bool:
    """Run the agent for one (use_case, provider, model). No setup/teardown."""
    output_dir  = EVAL_DIR / "runs" / run_label / provider / model / f"use_case_{use_case}"
    audit_dir   = output_dir / "audit"
    session_dst = output_dir / "ghost_session.json"
    stdout_log  = output_dir / "runner_stdout.log"

    # Idempotency check
    if session_dst.exists() and not force:
        print(f"\n  [SKIP] {provider}/{model}/use_case_{use_case} — artifacts exist (use --force to re-run)")
        _log(log_path, {
            "event":    "skipped",
            "use_case": use_case,
            "provider": provider,
            "model":    model,
            "reason":   "artifacts_exist",
            "ts":       _now_iso(),
        })
        return True

    audit_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n  ── {provider} / {model} ──")

    start_ts   = _now_iso()
    start_mono = time.monotonic()

    _log(log_path, {
        "event":    "run_start",
        "use_case": use_case,
        "provider": provider,
        "model":    model,
        "ts":       start_ts,
    })

    agent_rc   = -1
    session_id = None
    try:
        cmd = [
            PYTHON, "ghost_agent.py",
            "--config",       CONFIG_ENV,
            "--llm-provider", provider,
            "--model",        model,
            "--auto-approve",
            "--audit-dir",    str(audit_dir),
        ]
        if prompt_addon:
            cmd += ["--prompt-addon", str(prompt_addon)]
        print(f"  Running agent (output → {stdout_log.name})...")
        with open(prompt_file) as stdin_f, open(stdout_log, "w") as out_f:
            proc = subprocess.run(
                cmd,
                stdin=stdin_f,
                stdout=out_f,
                stderr=subprocess.STDOUT,
                cwd=str(AGENT_DIR),
                timeout=1800,
            )
        agent_rc = proc.returncode

        # Copy ghost_session.json from agent root immediately after run
        session_src = AGENT_DIR / "ghost_session.json"
        if session_src.exists():
            shutil.copy2(session_src, session_dst)
            raw = json.loads(session_dst.read_text())
            session_id = raw.get("session_id")
        else:
            print(f"  [WARN] ghost_session.json not found in agent root after run")

        # Extract metrics into run_summary.json
        subprocess.run(
            [PYTHON, str(EVAL_DIR / "capture_run.py"),
             "--run-dir",  str(output_dir),
             "--use-case", f"use_case_{use_case}",
             "--provider", provider,
             "--model",    model],
            cwd=str(AGENT_DIR),
            check=False,
        )

        _write_metadata(output_dir, use_case, model, start_ts, AGENT_DIR)

        subprocess.run(
            [PYTHON, str(EVAL_DIR / "populate_artifact_store.py"),
             "--run-dir", str(output_dir)],
            cwd=str(AGENT_DIR),
            check=False,
        )

    except subprocess.TimeoutExpired:
        print(f"  [ERROR] Agent timed out after 1800s")
        agent_rc = -2
    except Exception as exc:
        print(f"  [ERROR] Runner exception: {exc}")
        agent_rc = -3

    duration = round(time.monotonic() - start_mono, 1)
    success  = agent_rc == 0

    _log(log_path, {
        "event":      "run_end",
        "use_case":   use_case,
        "provider":   provider,
        "model":      model,
        "session_id": session_id,
        "agent_rc":   agent_rc,
        "duration_s": duration,
        "success":    success,
        "ts":         _now_iso(),
    })

    status = "OK" if success else f"FAILED (rc={agent_rc})"
    print(f"  [{status}] {duration}s  session={session_id or '?'}")
    return success


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--use-cases", nargs="+", required=True,
        metavar="CASE",
        help="Use case letter(s): a b f j m p q  (omit 'use_case_' prefix)",
    )
    parser.add_argument(
        "--providers", nargs="+", default=["all"],
        metavar="PROVIDER",
        help="'all' or one/more 'provider:model' strings, e.g. 'gemini:gemini-2.5-flash'",
    )
    parser.add_argument(
        "--run-label", required=True, metavar="LABEL",
        help="Directory label for this run batch, e.g. 'baseline', 'variant-a', 'variant-b'",
    )
    parser.add_argument("--force",        action="store_true", help="Re-run even if artifacts exist")
    parser.add_argument("--prompt-addon", default=None, metavar="FILE",
                        help="Append a text file to the system prompt (variant testing only)")
    parser.add_argument("--setup-delay",  type=int, default=30,
                        metavar="SECS",
                        help="Seconds to wait after setup.sh for fault to propagate (default: 30)")
    args = parser.parse_args()

    providers    = _parse_providers(args.providers)
    use_cases    = [uc.lower().replace("use_case_", "") for uc in args.use_cases]
    log_path     = EVAL_DIR / "runs" / args.run_label / "runner_log.jsonl"
    prompt_addon = Path(args.prompt_addon) if args.prompt_addon else None
    if prompt_addon and not prompt_addon.exists():
        print(f"[ERROR] --prompt-addon file not found: {prompt_addon}")
        sys.exit(1)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    total = len(use_cases) * len(providers)
    print(f"\nEval runner  [{args.run_label}]")
    print(f"  Use cases   : {', '.join(use_cases)}")
    print(f"  Providers   : {', '.join(f'{p}:{m}' for p, m in providers)}")
    print(f"  Total runs  : {total}  (force={args.force})")
    print(f"  Prompt addon: {prompt_addon or 'none (baseline)'}")
    print(f"  Log         : {log_path}")

    passed = failed = 0
    for use_case in use_cases:
        use_case_dir = DEMO_DIR / f"use_case_{use_case}"
        prompt_file  = use_case_dir / "PROMPT.txt"
        setup_sh     = use_case_dir / "setup.sh"
        teardown_sh  = use_case_dir / "teardown.sh"

        if not use_case_dir.exists():
            print(f"\n[ERROR] Use case directory not found: {use_case_dir}")
            failed += len(providers)
            continue
        if not prompt_file.exists():
            print(f"\n[ERROR] PROMPT.txt not found: {prompt_file}")
            failed += len(providers)
            continue

        print(f"\n{'═' * 60}")
        print(f"  use_case_{use_case}")
        print(f"{'═' * 60}")

        # Setup once for this use case
        setup_rc = _run_script(setup_sh, "SETUP")
        if setup_rc != 0:
            print(f"  [WARN] setup.sh failed — proceeding anyway")
        if args.setup_delay > 0:
            print(f"  Waiting {args.setup_delay}s for fault to propagate...")
            time.sleep(args.setup_delay)

        try:
            for provider, model in providers:
                ok = _run_agent(
                    use_case=use_case,
                    provider=provider,
                    model=model,
                    run_label=args.run_label,
                    force=args.force,
                    log_path=log_path,
                    prompt_file=prompt_file,
                    prompt_addon=prompt_addon,
                )
                if ok:
                    passed += 1
                else:
                    failed += 1
        finally:
            # Teardown always runs after all models for this use case
            print()
            _run_script(teardown_sh, "TEARDOWN")

    print(f"\n{'═' * 60}")
    print(f"  Done — {passed} passed, {failed} failed  (of {total} runs)")
    print(f"  Artifacts : eval/runs/{args.run_label}/")
    print(f"  Log       : {log_path}")
    print(f"{'═' * 60}\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
