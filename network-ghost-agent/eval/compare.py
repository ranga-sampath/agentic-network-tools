#!/usr/bin/env python3
"""Compare two Phase 1 run directories and score them against a use-case rubric.

Output is written to eval/runs/phase1/comparisons/ and printed to the terminal.

Usage:
    python eval/compare.py \\
        eval/runs/phase1/anthropic/claude-haiku-4-5-20251001/use_case_a \\
        eval/runs/phase1/anthropic/claude-sonnet-4-6/use_case_a
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Rubrics — one dict per use case.
# Each check: name, points, and a fn(summary) -> bool.
# Half-credit checks also have half_fn(summary) -> bool.
# Phase 2 will move these to eval/rubric/use_case_*.yaml.
# ---------------------------------------------------------------------------

def _text(summary: dict) -> str:
    """Concatenate root cause + recommended actions for keyword search."""
    parts = [
        summary.get("root_cause_summary") or "",
        " ".join(summary.get("recommended_actions") or []),
    ]
    return " ".join(parts).lower()


def _has_az_before_pcap(summary: dict) -> bool:
    seq = summary.get("command_sequence", [])
    pcap_idx = next((i for i, c in enumerate(seq) if "capture" in c.lower()), len(seq))
    return any("az " in c for c in seq[:pcap_idx])


_RUBRICS: dict[str, list[dict]] = {
    "use_case_e": [
        {
            "name":   "RCA generated (investigation completed)",
            "points": 20,
            "fn":     lambda s: s.get("rca_generated") is True,
        },
        {
            "name":   "Root cause identifies UDR / route table black hole",
            "points": 20,
            "fn":     lambda s: any(
                kw in _text(s) for kw in ["udr", "route", "blackhole", "black hole", "black-hole", "nva"]
            ),
        },
        {
            "name":   "Specific route or NVA named (ghost-demo-nva-redirect / 10.0.1.100)",
            "points": 20,
            "fn":     lambda s: any(
                kw in _text(s) for kw in ["ghost-demo-nva-redirect", "10.0.1.100", "ghost-demo-blackhole"]
            ),
        },
        {
            "name":    "Turn efficiency (≤15 full, ≤25 half)",
            "points":  20,
            "fn":      lambda s: (s.get("turn_count") or 999) <= 15,
            "half_fn": lambda s: (s.get("turn_count") or 999) <= 25,
        },
        {
            "name":   "Confidence: high or medium",
            "points": 10,
            "fn":     lambda s: s.get("confidence") in ("high", "medium"),
        },
        {
            "name":   "Effective route table queried (not just configured route table)",
            "points": 10,
            "fn":     lambda s: any(
                "effective-route" in c.lower() or "show-effective-route" in c.lower()
                for c in (s.get("command_sequence") or [])
            ),
        },
    ],
    "use_case_m": [
        {
            "name":   "RCA generated (investigation completed)",
            "points": 20,
            "fn":     lambda s: s.get("rca_generated") is True,
        },
        {
            "name":   "Root cause identifies OS-layer iptables / fail2ban",
            "points": 20,
            "fn":     lambda s: any(
                kw in _text(s) for kw in ["iptables", "fail2ban", "f2b", "f2b-sshd"]
            ),
        },
        {
            "name":   "Banned IP (203.0.113.47) named specifically",
            "points": 20,
            "fn":     lambda s: "203.0.113.47" in _text(s),
        },
        {
            "name":    "Turn efficiency (≤15 full, ≤25 half)",
            "points":  20,
            "fn":      lambda s: (s.get("turn_count") or 999) <= 15,
            "half_fn": lambda s: (s.get("turn_count") or 999) <= 25,
        },
        {
            "name":   "Confidence: high or medium",
            "points": 10,
            "fn":     lambda s: s.get("confidence") in ("high", "medium"),
        },
        {
            "name":   "NSG checked first (correct escalation: control-plane before OS-layer)",
            "points": 10,
            "fn":     lambda s: any(
                "az " in c and "nsg" in c.lower()
                for c in (s.get("command_sequence") or [])[:5]
            ),
        },
    ],
    "use_case_a": [
        {
            "name":   "RCA generated (investigation completed)",
            "points": 20,
            "fn":     lambda s: s.get("rca_generated") is True,
        },
        {
            "name":    "Root cause identifies NSG + port 8080",
            "points":  20,
            "fn":      lambda s: "nsg" in _text(s) and "8080" in _text(s),
        },
        {
            "name":    "Specific rule named (ghost-demo-block-8080)",
            "points":  20,
            "fn":      lambda s: "ghost-demo-block-8080" in _text(s),
        },
        {
            "name":    "Turn efficiency (≤12 = full, ≤20 = half, >20 = none)",
            "points":  20,
            "fn":      lambda s: (s.get("turn_count") or 999) <= 12,
            "half_fn": lambda s: (s.get("turn_count") or 999) <= 20,
        },
        {
            "name":   "Confidence: high",
            "points": 10,
            "fn":     lambda s: s.get("confidence") == "high",
        },
        {
            "name":   "Used Azure API commands (correct escalation path)",
            "points": 10,
            "fn":     _has_az_before_pcap,
        },
    ],
}

_QUALITATIVE_CHECKS = {
    "use_case_e": [
        "NSG checked first and correctly ruled out before pivoting to routing",
        "Effective route table queried at NIC level (not just configured route table)",
        "UDR black hole correctly distinguished from BGP withdrawal or system route change",
        "Recommendation names the specific route and route table, not generic 'review UDR' instruction",
    ],
    "use_case_m": [
        "NSG checked first before OS-layer tools (correct escalation order)",
        "detect_config_drift called with explain=True (not just baseline capture)",
        "f2b-sshd chain correctly identified as fail2ban, not generic iptables noise",
        "Recommendation names the specific chain and IP, not a generic 'review iptables' instruction",
    ],
    "use_case_a": [
        "First hypothesis was NSG block (not routing or service-down)",
        "No unnecessary PCAP started (NSG case should resolve at API level)",
        "Recommended action names the specific rule and NSG, not a generic 'review' instruction",
        "RCA cites specific audit_id as evidence",
    ],
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score(summary: dict) -> tuple[int, int, list[str]]:
    """Return (score, max_score, notes) for a run."""
    use_case = summary.get("use_case", "")
    checks   = _RUBRICS.get(use_case)
    if not checks:
        return 0, 0, [f"No rubric defined for {use_case!r}"]

    score = max_score = 0
    notes: list[str] = []

    for check in checks:
        pts = check["points"]
        max_score += pts
        if check["fn"](summary):
            score += pts
            notes.append(f"  PASS  ({pts:>2}pts) {check['name']}")
        elif "half_fn" in check and check["half_fn"](summary):
            half = pts // 2
            score += half
            notes.append(f"  HALF  ({half:>2}pts) {check['name']}")
        else:
            notes.append(f"  FAIL  ({0:>2}pts) {check['name']}")

    return score, max_score, notes


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _load(run_dir: Path) -> dict:
    path = run_dir / "run_summary.json"
    if not path.exists():
        sys.exit(
            f"[ERROR] run_summary.json not found in {run_dir}\n"
            f"        Run eval/capture_run.py first."
        )
    return json.loads(path.read_text())


def _cell(val, width: int) -> str:
    return str(val if val is not None else "—")[:width].ljust(width)


def _row(label: str, a, b, col: int = 34) -> str:
    return f"  {label:<28}  {_cell(a, col)}  {_cell(b, col)}"


def _yn(val) -> str:
    if val is True:  return "YES"
    if val is False: return "NO"
    return str(val) if val is not None else "—"


def _wrap(text: str, width: int = 70) -> list[str]:
    if not text:
        return ["—"]
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            if cur: lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur: lines.append(cur)
    return lines or ["—"]


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_report(a: dict, b: dict,
                  score_a: int, score_b: int, max_score: int,
                  notes_a: list[str], notes_b: list[str]) -> str:
    W   = 82
    col = 34

    label_a = f"{a['provider']} / {a['model']}"[:col]
    label_b = f"{b['provider']} / {b['model']}"[:col]

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s)

    ln(f"# Phase 1 Comparison — Use Case {a['use_case'].upper()}")
    ln(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    ln()

    # --- Score summary ---
    ln("## Score")
    gap   = abs(score_a - score_b)
    pct_a = f"{score_a}/{max_score}"
    pct_b = f"{score_b}/{max_score}"
    ln(_row("Model", label_a, label_b, col))
    ln(_row("Score", pct_a, pct_b, col))

    if max_score == 0:
        verdict = "No rubric defined for this use case."
    elif gap <= 10:
        verdict = f"Comparable performance (gap {gap}pts ≤ 10). Review qualitative section."
    elif score_a > score_b:
        verdict = f"{a['provider']} / {a['model']} wins by {gap}pts."
    else:
        verdict = f"{b['provider']} / {b['model']} wins by {gap}pts."

    ln()
    ln(f"**Verdict:** {verdict}")
    ln()

    # --- Score breakdown ---
    ln("## Score Breakdown")
    ln()
    ln(f"### {label_a}")
    for n in notes_a:
        ln(n)
    ln()
    ln(f"### {label_b}")
    for n in notes_b:
        ln(n)
    ln()

    # --- Comparison table ---
    ln("## Comparison Table")
    ln()
    ln("```")
    ln("═" * W)
    ln(f"  {'Metric':<28}  {label_a:<{col}}  {label_b}")
    ln("  " + "─" * (W - 2))

    ln("  [Outcome]")
    ln(_row("RCA generated",      _yn(a["rca_generated"]),  _yn(b["rca_generated"]),  col))
    ln(_row("Confidence",          a.get("confidence"),       b.get("confidence"),       col))
    ln(_row("Turn count",          a.get("turn_count"),       b.get("turn_count"),       col))
    ln()

    ln("  [Tool usage]")
    ln(_row("Commands issued",     a.get("commands_issued"),  b.get("commands_issued"),  col))
    ln(_row("Commands denied",     a.get("commands_denied"),  b.get("commands_denied"),  col))
    ln(_row("Auto-approved",       a.get("commands_auto_approved"), b.get("commands_auto_approved"), col))
    ln(_row("User-approved",       a.get("commands_user_approved"), b.get("commands_user_approved"), col))
    ln()

    ln("  [Hypothesis formation]")
    ln(_row("Hypothesis count",    a.get("hypothesis_count"), b.get("hypothesis_count"), col))
    hyps_a, hyps_b = a.get("hypotheses", []), b.get("hypotheses", [])
    for i in range(max(len(hyps_a), len(hyps_b))):
        ha = hyps_a[i] if i < len(hyps_a) else None
        hb = hyps_b[i] if i < len(hyps_b) else None
        va = f"{ha['description'][:24]} [{ha['state']}]" if ha else "—"
        vb = f"{hb['description'][:24]} [{hb['state']}]" if hb else "—"
        ln(_row(f"  H{i+1}", va, vb, col))
    ln()

    ln("  [Command sequence]")
    seq_a, seq_b = a.get("command_sequence", []), b.get("command_sequence", [])
    for i in range(max(len(seq_a), len(seq_b))):
        ca = seq_a[i] if i < len(seq_a) else "—"
        cb = seq_b[i] if i < len(seq_b) else "—"
        ln(_row(f"  step {i+1:>2}", ca[:30], cb[:30], col))
    ln("═" * W)
    ln("```")
    ln()

    # --- Root cause ---
    ln("## Root Cause Summaries")
    ln()
    ln(f"**{a['provider']} / {a['model']}**")
    ln()
    for line in _wrap(a.get("root_cause_summary") or ""):
        ln(f"> {line}")
    ln()
    ln(f"**{b['provider']} / {b['model']}**")
    ln()
    for line in _wrap(b.get("root_cause_summary") or ""):
        ln(f"> {line}")
    ln()

    # --- Recommended actions ---
    ln("## Recommended Actions")
    ln()
    acts_a = a.get("recommended_actions") or []
    acts_b = b.get("recommended_actions") or []
    ln(f"**{a['provider']} / {a['model']}**")
    for i, act in enumerate(acts_a, 1):
        ln(f"{i}. {act}")
    if not acts_a:
        ln("—")
    ln()
    ln(f"**{b['provider']} / {b['model']}**")
    for i, act in enumerate(acts_b, 1):
        ln(f"{i}. {act}")
    if not acts_b:
        ln("—")
    ln()

    # --- Qualitative checklist ---
    use_case = a.get("use_case", "")
    qual = _QUALITATIVE_CHECKS.get(use_case, [])
    if qual:
        ln("## Qualitative Checklist (fill in manually)")
        ln()
        ln(f"| Check | {label_a[:28]} | {label_b[:28]} |")
        ln("|-------|" + "-" * 30 + "|" + "-" * 30 + "|")
        for check in qual:
            ln(f"| {check[:60]} | | |")
        ln()

    # --- Session IDs ---
    ln("## Sessions")
    ln(f"- {a['session_id']}  ({a['provider']} / {a['model']})")
    ln(f"- {b['session_id']}  ({b['provider']} / {b['model']})")
    ln()

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage: compare.py <run_dir_a> <run_dir_b>")

    dir_a, dir_b = Path(sys.argv[1]), Path(sys.argv[2])
    a, b = _load(dir_a), _load(dir_b)

    score_a, max_a, notes_a = _score(a)
    score_b, max_b, notes_b = _score(b)
    max_score = max(max_a, max_b)

    report = _build_report(a, b, score_a, score_b, max_score, notes_a, notes_b)

    # Print to terminal
    print(report)

    # Write to file
    comparisons_dir = Path(__file__).parent / "runs" / "phase1" / "comparisons"
    comparisons_dir.mkdir(parents=True, exist_ok=True)

    safe = lambda s: s.replace("/", "_").replace(" ", "-")
    filename = (
        f"{safe(a['provider'])}_{safe(a['model'])}"
        f"_vs_{safe(b['provider'])}_{safe(b['model'])}"
        f"_{a['use_case']}.md"
    )
    out_path = comparisons_dir / filename
    out_path.write_text(report)
    print(f"\nReport written → {out_path}")


if __name__ == "__main__":
    main()
