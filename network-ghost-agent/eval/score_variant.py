#!/usr/bin/env python3
"""Score variant run directories against Phase 5 acceptance criteria.

Variant A acceptance criterion:
  All three models on use_case_q must issue a tc qdisc show command (via az vm
  run-command) when investigating the traffic shaping hypothesis — not the firewall
  inspector. Pass requires all three models; any single model failing = variant fails.

Variant B acceptance criterion:
  All three models on use_case_j, use_case_p, and use_case_q must:
    - Register an explicit hypothesis about the secondary fault/symptom
    - Issue at least one investigation command appropriate to that symptom class
  Pass requires all three models across all three use cases.

Usage:
    # Score a specific run directory
    python eval/score_variant.py --variant a --run-dir eval/runs/phase3/anthropic/claude-sonnet-4-6/use_case_q

    # Score all runs for a variant (from a phase directory)
    python eval/score_variant.py --variant a --phase-dir eval/runs/phase3

    # Score and show detailed evidence
    python eval/score_variant.py --variant b --phase-dir eval/runs/phase3 --verbose
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

EVAL_DIR = Path(__file__).parent

# ── Variant A ──────────────────────────────────────────────────────────────

VARIANT_A_USE_CASES = {"use_case_q"}

def _has_tc_command(shell_audit_path: Path) -> tuple[bool, str]:
    """Return (found, evidence_string) for tc qdisc show in shell audit."""
    if not shell_audit_path.exists():
        return False, "no shell_audit file"
    for line in shell_audit_path.read_text().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        cmd = rec.get("command", "")
        # Accept: tc qdisc show in a run-command script, or direct tc call
        if "tc qdisc" in cmd.lower():
            return True, f"found: {cmd[:120]}"
    return False, "no tc qdisc show command found in shell_audit"


def score_variant_a_run(run_dir: Path, verbose: bool = False) -> dict:
    """Score one run against Variant A criterion."""
    summary_path = run_dir / "run_summary.json"
    audit_dir    = run_dir / "audit"

    if not summary_path.exists():
        return {"pass": False, "reason": "no run_summary.json"}

    summary = json.loads(summary_path.read_text())
    use_case = summary.get("use_case", "")

    if use_case not in VARIANT_A_USE_CASES:
        return {"pass": None, "reason": f"{use_case} not in Variant A scope"}

    # Find the shell_audit for the canonical session
    session_id = summary.get("session_id", "")
    shell_audit = audit_dir / f"shell_audit_{session_id}.jsonl"
    found, evidence = _has_tc_command(shell_audit)

    # Also check for a traffic-shaping hypothesis being investigated (not just named)
    hypotheses = summary.get("hypotheses", [])
    tc_hyps = [h for h in hypotheses
               if any(kw in h.get("description", "").lower()
                      for kw in ["tc", "qdisc", "traffic shap", "netem", "tbf", "htb", "latency"])]

    result = {
        "pass":           found,
        "use_case":       use_case,
        "model":          summary.get("model", ""),
        "tc_command":     evidence,
        "tc_hypotheses":  [h["id"] for h in tc_hyps],
    }
    return result


# ── Variant B ──────────────────────────────────────────────────────────────

VARIANT_B_USE_CASES = {"use_case_j", "use_case_p", "use_case_q"}

# Secondary symptom keywords and appropriate tool signatures per use case
SECONDARY_SYMPTOM_CONFIG = {
    "use_case_q": {
        "symptom_keywords":  ["latency", "tc", "qdisc", "traffic shap", "netem", "performance"],
        "tool_signatures":   ["tc qdisc", "run_pipe_meter", "pipe_meter"],
        "description":       "latency spike — requires tc qdisc show or run_pipe_meter",
    },
    "use_case_j": {
        "symptom_keywords":  ["latency", "tc", "qdisc", "netem", "delay", "throughput", "performance"],
        "tool_signatures":   ["tc qdisc", "run_pipe_meter", "pipe_meter"],
        "description":       "tc netem latency on source VM — requires tc qdisc show",
    },
    "use_case_p": {
        "symptom_keywords":  ["os", "iptables", "nftables", "firewall", "os-layer", "os layer",
                               "port 5001", "hardening", "config drift", "detect_config"],
        "tool_signatures":   ["detect_config_drift", "iptables", "nftables", "config_drift"],
        "description":       "forgotten OS-level iptables rule — requires detect_config_drift",
    },
}


def _has_tool_call(shell_audit_path: Path, signatures: list[str]) -> tuple[bool, str]:
    """Return (found, evidence) if any command matches any signature."""
    if not shell_audit_path.exists():
        return False, "no shell_audit file"
    for line in shell_audit_path.read_text().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        cmd = rec.get("command", "").lower()
        for sig in signatures:
            if sig.lower() in cmd:
                return True, f"found '{sig}' in: {rec['command'][:120]}"
    return False, f"no command matching {signatures} found"


def score_variant_b_run(run_dir: Path, verbose: bool = False) -> dict:
    """Score one run against Variant B criterion."""
    summary_path = run_dir / "run_summary.json"
    audit_dir    = run_dir / "audit"

    if not summary_path.exists():
        return {"pass": False, "reason": "no run_summary.json"}

    summary  = json.loads(summary_path.read_text())
    use_case = summary.get("use_case", "")

    if use_case not in VARIANT_B_USE_CASES:
        return {"pass": None, "reason": f"{use_case} not in Variant B scope"}

    cfg          = SECONDARY_SYMPTOM_CONFIG[use_case]
    hypotheses   = summary.get("hypotheses", [])
    session_id   = summary.get("session_id", "")
    shell_audit  = audit_dir / f"shell_audit_{session_id}.jsonl"

    # Check 1: secondary symptom hypothesis registered
    secondary_hyps = [h for h in hypotheses
                      if any(kw in h.get("description", "").lower()
                             for kw in cfg["symptom_keywords"])]
    has_hypothesis = len(secondary_hyps) > 0

    # Check 2: appropriate investigation tool was called
    tool_found, tool_evidence = _has_tool_call(shell_audit, cfg["tool_signatures"])

    passed = has_hypothesis and tool_found

    return {
        "pass":              passed,
        "use_case":          use_case,
        "model":             summary.get("model", ""),
        "secondary_symptom": cfg["description"],
        "has_hypothesis":    has_hypothesis,
        "hypothesis_ids":    [h["id"] for h in secondary_hyps],
        "tool_called":       tool_found,
        "tool_evidence":     tool_evidence,
    }


# ── Runner ─────────────────────────────────────────────────────────────────

def _find_run_dirs(phase_dir: Path, target_use_cases: set[str]) -> list[Path]:
    """Find all run directories containing run_summary.json for target use cases."""
    results = []
    for p in sorted(phase_dir.rglob("run_summary.json")):
        run_dir  = p.parent
        summary  = json.loads(p.read_text())
        use_case = summary.get("use_case", "")
        if use_case in target_use_cases:
            results.append(run_dir)
    return results


def _print_result(result: dict, verbose: bool) -> None:
    status = "PASS" if result.get("pass") else ("N/A" if result.get("pass") is None else "FAIL")
    uc     = result.get("use_case", "?")
    model  = result.get("model", "?")
    print(f"  [{status:4}] {uc} / {model}")
    if verbose or not result.get("pass"):
        for k, v in result.items():
            if k not in ("pass", "use_case", "model"):
                print(f"           {k}: {v}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--variant",    required=True, choices=["a", "b"],
                        help="Which variant to score: a or b")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-dir",   metavar="PATH", help="Score a single run directory")
    group.add_argument("--runs-dir",  metavar="PATH", help="Score all matching runs under a label directory, e.g. eval/runs/variant-a")
    parser.add_argument("--verbose",  action="store_true", help="Show evidence details for all runs")
    args = parser.parse_args()

    score_fn       = score_variant_a_run if args.variant == "a" else score_variant_b_run
    target_cases   = VARIANT_A_USE_CASES if args.variant == "a" else VARIANT_B_USE_CASES
    variant_label  = f"Variant {'A' if args.variant == 'a' else 'B'}"
    acceptance_str = (
        "All 3 models on use_case_q must issue tc qdisc show"
        if args.variant == "a" else
        "All 3 models on use_case_j/p/q must register secondary hypothesis AND call appropriate tool"
    )

    print(f"\n{variant_label} acceptance criterion:")
    print(f"  {acceptance_str}\n")

    if args.run_dir:
        run_dirs = [Path(args.run_dir)]
    else:
        run_dirs = _find_run_dirs(Path(args.runs_dir), target_cases)

    if not run_dirs:
        print("No matching run directories found.")
        return

    results = [score_fn(rd, verbose=args.verbose) for rd in run_dirs]

    for result in results:
        _print_result(result, args.verbose)

    judged   = [r for r in results if r.get("pass") is not None]
    passed   = [r for r in judged  if r.get("pass")]
    failed   = [r for r in judged  if not r.get("pass")]

    print(f"\n{'─' * 60}")
    print(f"  {len(passed)}/{len(judged)} runs passed")

    if args.variant == "a":
        required = 3  # 3 models on use_case_q
        variant_passes = len(passed) == required and len(judged) == required
    else:
        required = 9  # 3 models × 3 use cases
        variant_passes = len(passed) == required and len(judged) == required

    verdict = "VARIANT ACCEPTED" if variant_passes else "VARIANT FAILED"
    print(f"  {verdict}  (requires {required}/{required})")
    if failed:
        print(f"\n  Failing runs:")
        for r in failed:
            print(f"    {r.get('use_case')} / {r.get('model')}")
    print(f"{'─' * 60}\n")


if __name__ == "__main__":
    main()
