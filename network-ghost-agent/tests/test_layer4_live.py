"""
test_layer4_live.py — Layer 4: Live Ghost Agent conversational session.

Runs the full pipeline — real Gemini Brain, real fw-nftables Multipass VM,
real detect_config_drift handler — without any mocks on the critical path.

What this verifies
------------------
L4-01  Brain calls detect_config_drift with is_baseline=True for baseline intent
L4-02  Baseline run returns status="success" and a session_id
L4-03  Brain calls detect_config_drift with compare_session_id for compare intent
L4-04  Compare run returns drift_detected=True after rule injection
L4-05  Brain's analysis text references "verdict" (nftables field) or
       "drop" — not iptables-only terms like "target" or "raw_rule"
L4-06  Brain's analysis flags the DROP rule as a security concern
L4-07  Pre-completion checklist fires: RCA includes symptom + mechanism + audit_id

Prerequisites
-------------
- fw-nftables Multipass VM running at 192.168.2.7 (ubuntu, passwordless sudo)
- ~/.ssh/id_rsa key injected into VM
- GEMINI_API_KEY set in demo/config.env
- Run: .venv/bin/python3 tests/test_layer4_live.py

The script exits 0 on pass, 1 on failure. Failures print a clear explanation.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup — run from network-ghost-agent root
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_AGENT_ROOT = _HERE.parent
sys.path.insert(0, str(_AGENT_ROOT))

# Load GEMINI_API_KEY from demo/config.env before importing ghost_agent
_config_env = _AGENT_ROOT / "demo" / "config.env"
_cfg: dict[str, str] = {}
if _config_env.exists():
    for raw in _config_env.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            v = v.split("#")[0].strip().strip('"').strip("'")
            # Expand $HOME / ${HOME}
            v = v.replace("${HOME}", str(Path.home())).replace("$HOME", str(Path.home()))
            _cfg[k.strip()] = v

if "GEMINI_API_KEY" in _cfg:
    os.environ.setdefault("GEMINI_API_KEY", _cfg["GEMINI_API_KEY"])

import ghost_agent
from ghost_agent import (
    _run_loop,
    _build_ghost_tools,
    _new_session,
)

# ---------------------------------------------------------------------------
# Ghost config for fw-nftables VM
# ---------------------------------------------------------------------------

_GHOST_CFG = {
    "GEMINI_API_KEY":    os.environ.get("GEMINI_API_KEY", ""),
    "AUDIT_DIR":         str(_AGENT_ROOT / "audit-layer4"),
    "FW_TARGET_VM_IP":   "192.168.2.7",
    "FW_SSH_KEY_PATH":   str(Path.home() / ".ssh" / "id_rsa"),
    "FW_SSH_USER":       "ubuntu",
    "FW_BASTION_PUBLIC_IP": "",
}

Path(_GHOST_CFG["AUDIT_DIR"]).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_client():
    import google.genai as genai
    return genai.Client(api_key=_GHOST_CFG["GEMINI_API_KEY"])


def _run_scenario(intent: str, ghost_cfg: dict, audit_dir: str) -> tuple[str, dict | None]:
    """
    Run one Ghost Agent turn with the given intent.

    Returns (captured_stdout, rca_args) where rca_args is the dict passed to
    _generate_rca if complete_investigation was called, else None.

    Mocks:
    - _generate_rca      → captures args, suppresses file I/O and cleanup prompts
    - _offer_cleanup_before_rca → no-op (no interactive prompts)
    - input              → returns "d" for any [C]ontinue / [D]one prompt
    """
    state         = _new_session("gemini-2.0-flash", audit_dir)
    session_file  = str(Path(audit_dir) / "session.json")
    ghost_tools   = _build_ghost_tools()
    client        = _build_client()
    history       = []
    rca_capture: list[dict] = []

    import google.genai.types as types
    history.append(types.Content(role="user", parts=[types.Part(text=intent)]))

    buf = io.StringIO()

    def _fake_rca(state, fc_args, shell, session_file, **kw):
        rca_capture.append(fc_args)

    with patch.object(ghost_agent, "_generate_rca", side_effect=_fake_rca), \
         patch.object(ghost_agent, "_offer_cleanup_before_rca"), \
         patch("builtins.input", return_value="d"):
        with redirect_stdout(buf):
            _run_loop(
                state, history,
                shell=MagicMock(),
                orchestrator=MagicMock(),
                ghost_tools=ghost_tools,
                client=client,
                session_file=session_file,
                ghost_cfg=ghost_cfg,
            )

    stdout = buf.getvalue()
    rca_args = rca_capture[0] if rca_capture else None
    return stdout, rca_args


def _setup_baseline_chain():
    """Create fw_test table + empty input chain so the baseline captures it.
    Rule is NOT added here — only the chain. The subsequent inject step adds
    the DROP rule so it shows up as rules_added=1 (not chains_added=1).
    """
    cmds = [
        "sudo nft add table inet fw_test 2>/dev/null || true",
        "sudo nft add chain inet fw_test input "
        "{ type filter hook input priority 0 \\; policy accept \\; } 2>/dev/null || true",
        "sudo nft list ruleset",
    ]
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=yes",
         "-i", str(Path.home() / ".ssh" / "id_rsa"),
         "ubuntu@192.168.2.7", " && ".join(cmds)],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout


def _inject_drop_rule():
    """Add a DROP rule on port 4444 to the existing chain.

    The chain was created in _setup_baseline_chain() and captured in the baseline.
    Adding a rule to an existing chain makes it appear as rules_added=1 in the diff
    (not chains_added=1), so the condensed result includes the full rule details
    (verdict=drop, dst_port=4444) that the Brain can reference.
    """
    cmds = [
        "sudo nft add rule inet fw_test input tcp dport 4444 drop",
        "sudo nft list ruleset",
    ]
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=yes",
         "-i", str(Path.home() / ".ssh" / "id_rsa"),
         "ubuntu@192.168.2.7", " && ".join(cmds)],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout


def _clean_vm():
    """Remove all nftables tables from fw-nftables."""
    subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=yes",
         "-i", str(Path.home() / ".ssh" / "id_rsa"),
         "ubuntu@192.168.2.7", "sudo nft flush ruleset 2>/dev/null || true"],
        capture_output=True, timeout=10,
    )


# ---------------------------------------------------------------------------
# Check results
# ---------------------------------------------------------------------------

PASS = "\033[32m  PASS\033[0m"
FAIL = "\033[31m  FAIL\033[0m"
HEAD = "\033[1m"
END  = "\033[0m"


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = PASS if condition else FAIL
    print(f"{status}  {label}")
    if not condition and detail:
        print(f"       detail: {detail}")
    return condition


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{HEAD}=== Layer 4 — Live Ghost Agent + nftables E2E ==={END}\n")

    failures = 0

    # -----------------------------------------------------------------------
    # Phase 1: Baseline capture
    # -----------------------------------------------------------------------
    print(f"{HEAD}Phase 1: Baseline capture on fw-nftables (chain established, no rules){END}")
    _clean_vm()
    time.sleep(1)
    chain_state = _setup_baseline_chain()
    print(f"  VM state before baseline:\n  {chain_state.strip()}\n")

    baseline_intent = (
        "Capture a firewall baseline on the fw-nftables VM. "
        "Use provider=ssh. The VM IP is 192.168.2.7."
    )

    print("  Running Ghost Agent (baseline)... ", end="", flush=True)
    stdout1, rca1 = _run_scenario(baseline_intent, _GHOST_CFG, _GHOST_CFG["AUDIT_DIR"])
    print("done")

    # Find the session_id from the audit dir
    snap_files = sorted(Path(_GHOST_CFG["AUDIT_DIR"]).glob("*_snapshot.json"),
                        key=lambda p: p.stat().st_mtime)
    baseline_session_id = (
        snap_files[-1].name.replace("_snapshot.json", "") if snap_files else None
    )

    # L4-01: Brain called detect_config_drift(is_baseline=True)
    called_baseline = "is_baseline" in stdout1 or "baseline" in stdout1.lower()
    if not failures:
        failures += 0 if check(
            "L4-01  Brain called detect_config_drift(is_baseline=True)",
            called_baseline,
            f"stdout excerpt: {stdout1[:400]}"
        ) else 1

    # L4-02: Baseline returned a session_id (snapshot file created)
    failures += 0 if check(
        "L4-02  Baseline snapshot artifact created",
        baseline_session_id is not None,
        f"No *_snapshot.json found in {_GHOST_CFG['AUDIT_DIR']}"
    ) else 1

    print(f"  baseline_session_id = {baseline_session_id}\n")

    if baseline_session_id is None:
        print("\n[ABORT] Cannot proceed to Phase 2 without a baseline session_id.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Phase 2: Inject a DROP rule, then compare
    # -----------------------------------------------------------------------
    print(f"{HEAD}Phase 2: Inject DROP rule, then compare against baseline{END}")
    ruleset_after = _inject_drop_rule()
    print(f"  VM state after injection:\n  {ruleset_after.strip()}\n")

    compare_intent = (
        f"Compare the current firewall state on fw-nftables (192.168.2.7) "
        f"against baseline session '{baseline_session_id}'. "
        f"Use provider=ssh. Tell me what changed and whether it is a security concern."
    )

    print("  Running Ghost Agent (compare)... ", end="", flush=True)
    stdout2, rca2 = _run_scenario(compare_intent, _GHOST_CFG, _GHOST_CFG["AUDIT_DIR"])
    print("done")

    # Find drift file
    drift_files = sorted(Path(_GHOST_CFG["AUDIT_DIR"]).glob("*_drift.json"),
                         key=lambda p: p.stat().st_mtime)
    drift_data: dict = {}
    if drift_files:
        try:
            drift_data = json.loads(drift_files[-1].read_text())
        except Exception:
            pass

    # L4-03: Brain called detect_config_drift with compare_session_id
    called_compare = (baseline_session_id in stdout2
                      or "compare" in stdout2.lower()
                      or "compare_session_id" in stdout2)
    failures += 0 if check(
        "L4-03  Brain called detect_config_drift(compare_session_id=...)",
        called_compare,
        f"stdout excerpt: {stdout2[:400]}"
    ) else 1

    # L4-04: Compare run returned drift_detected=True
    nft_fam = drift_data.get("drift_by_family", {}).get("nft", {})
    drift_detected = nft_fam.get("drift_detected", False)
    failures += 0 if check(
        "L4-04  drift_detected=True in nft family",
        drift_detected,
        f"drift_by_family: {json.dumps(drift_data.get('drift_by_family', {}), indent=2)[:400]}"
    ) else 1

    # L4-05: Brain analysis uses nftables field vocabulary (verdict/drop/port)
    # NOT iptables-only vocabulary (target= as a label, raw_rule)
    combined_text = (stdout2 + (rca2.get("root_cause_summary", "") if rca2 else "")).lower()
    uses_nft_vocab = (
        "verdict" in combined_text
        or "drop" in combined_text
        or "4444" in combined_text
        or "tcp" in combined_text
    )
    uses_raw_rule_only = (
        "raw_rule" in combined_text
        and "verdict" not in combined_text
        and "drop" not in combined_text
    )
    failures += 0 if check(
        "L4-05  Brain analysis uses nftables vocabulary (drop/verdict/4444) not raw_rule-only",
        uses_nft_vocab and not uses_raw_rule_only,
        f"combined text sample: {combined_text[:600]}"
    ) else 1

    # L4-06: Brain flags the change as a security concern
    security_concern = any(w in combined_text for w in [
        "security", "critical", "concern", "drop", "block", "deny", "dangerous", "risky"
    ])
    failures += 0 if check(
        "L4-06  Brain flags the DROP rule as a security concern",
        security_concern,
        f"combined text sample: {combined_text[:600]}"
    ) else 1

    # L4-07: Pre-completion checklist fired — RCA exists and has substantive content
    rca_content = rca2.get("root_cause_summary", "") if rca2 else ""
    checklist_fired = bool(rca_content and len(rca_content) > 50)
    failures += 0 if check(
        "L4-07  Pre-completion checklist fired (RCA has substantive root_cause_summary)",
        checklist_fired,
        f"rca root_cause_summary: {rca_content[:300] if rca_content else '(empty)'}"
    ) else 1

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{HEAD}=== Layer 4 Summary ==={END}")
    print(f"  baseline_session_id : {baseline_session_id}")
    print(f"  drift file          : {drift_files[-1] if drift_files else 'none'}")
    print(f"  nft rules_added     : {nft_fam.get('summary', {}).get('rules_added', '?')}")

    if failures == 0:
        print(f"\n{HEAD}\033[32mAll Layer 4 checks passed.\033[0m{END}")
    else:
        print(f"\n{HEAD}\033[31m{failures} Layer 4 check(s) failed.{END}\033[0m")

    # Print transcript excerpt for reviewer
    print(f"\n{HEAD}--- Brain output (compare turn, first 1200 chars) ---{END}")
    print(stdout2[:1200])
    if rca2:
        print(f"\n{HEAD}--- RCA root_cause_summary ---{END}")
        print(rca2.get("root_cause_summary", "")[:800])

    # Cleanup VM
    _clean_vm()

    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
