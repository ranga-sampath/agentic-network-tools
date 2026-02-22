#!/usr/bin/env python3
"""Unified Ghost Agent CLI — AI-driven network forensics investigator.

Usage:
    python ghost_agent.py [--resume SESSION_ID] [--model MODEL]
                          [--audit-dir PATH] [--storage-auth-mode {login,key}]

See docs/architecture.md and docs/design.md for full specification.
"""

import argparse
import glob
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types

# Sub-module directories live one level up (repo root), alongside this directory.
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "agentic-safety-shell"))
sys.path.insert(0, str(_ROOT / "agentic-cloud-orchestrator"))

from safe_exec_shell import SafeExecShell, HitlDecision   # noqa: E402
from cloud_orchestrator import CloudOrchestrator           # noqa: E402

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AUDIT_DIR = "./audit"
SESSION_FILE = "ghost_session.json"
DEFAULT_MODEL = "gemini-2.0-flash"
MAX_LOOP_TURNS = 50
MAX_DENIALS_PER_HYPOTHESIS = 3

# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _checksum(data: dict) -> str:
    """SHA-256 of sorted JSON, excluding the _checksum field itself."""
    payload = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def save_session(state: dict, path: str = SESSION_FILE):
    """Write session state with a SHA-256 integrity checksum."""
    base = {k: v for k, v in state.items() if k != "_checksum"}
    base["_checksum"] = _checksum(base)
    with open(path, "w") as f:
        json.dump(base, f, indent=2, default=str)


def _new_session(model: str, audit_dir: str) -> dict:
    sid = f"ghost_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    return {
        "session_id": sid,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resumed_from": None,
        "model": model,
        "audit_dir": audit_dir,
        "turn_count": 0,
        "rca_report_path": None,
        "audit_trail_path": None,
        "hypothesis_log": [],
        "denial_tracker": {},
        "consecutive_denial_counter": {},
        "active_hypothesis_ids": [],
        "active_task_ids": [],
        "evidence_conflicts": [],
        "is_resume": False,
        "manual_cleanup_pending": [],
        "denial_reasons": {},
        "investigation_audit_start_line": 0,
    }


def _load_session(session_file: str, resume_id: str) -> dict | None:
    """Load and verify a session for --resume. Returns None to signal start-fresh."""
    path = Path(session_file)
    if not path.exists():
        print(f"[ERROR] Session file not found: {session_file}")
        sys.exit(1)

    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError:
        print("Warning: session file corrupted.")
        if input("[F]resh session / [A]bort > ").strip().lower() == "a":
            sys.exit(1)
        return None  # start fresh

    # Checksum verification
    stored = raw.pop("_checksum", None)
    if stored is not None and _checksum(raw) != stored:
        print("Warning: session file checksum mismatch — file may have been modified externally.")
        choice = input("[C]ontinue anyway  [F]resh session  [A]bort > ").strip().lower()
        if choice == "a":
            sys.exit(1)
        if choice == "f":
            return None  # start fresh
        # continue — proceed with loaded data

    if raw.get("session_id") != resume_id:
        print(f"[ERROR] session_id mismatch: expected '{resume_id}', found '{raw.get('session_id')}'")
        sys.exit(1)

    raw["is_resume"] = True
    return raw

# ---------------------------------------------------------------------------
# HITL callback
# ---------------------------------------------------------------------------

def terminal_hitl_callback(command: str, reasoning: str, risk_explanation: str, tier: int) -> HitlDecision:
    """Block, print a safety alert box, and wait for engineer decision."""
    W = 71
    def _row(label: str, value: str):
        content = f"{label}{value}"[: W - 4]
        print(f"│  {content:<{W - 4}}│")

    print("\n┌" + "─" * (W - 2) + "┐")
    _row("", "SAFETY SHELL ALERT")
    _row(f"TIER: {tier}  │  ", "CLASSIFICATION: RISKY")
    _row("COMMAND:    ", command[:55] + ("…" if len(command) > 55 else ""))
    _row("RISK:       ", risk_explanation[:55] + ("…" if len(risk_explanation) > 55 else ""))
    _row("REASONING:  ", reasoning[:55] + ("…" if len(reasoning) > 55 else ""))
    print("│" + " " * (W - 2) + "│")
    _row("", "[A]pprove   [D]eny   [M]odify command")
    print("└" + "─" * (W - 2) + "┘")

    choice = input("Your choice: ").strip().lower()

    if choice == "a":
        terminal_hitl_callback.captured_reason = ""
        return HitlDecision(action="approve")

    if choice == "m":
        new_cmd = input("New command: ").strip()
        terminal_hitl_callback.captured_reason = ""
        return HitlDecision(action="modify", modified_command=new_cmd)

    # Deny — capture optional reason before returning
    reason = input("Denial reason (optional, press Enter to skip): ").strip()
    terminal_hitl_callback.captured_reason = reason
    return HitlDecision(action="deny")

terminal_hitl_callback.captured_reason = ""

# ---------------------------------------------------------------------------
# Tool declarations
# ---------------------------------------------------------------------------

def _build_ghost_tools() -> types.Tool:
    S, T = types.Schema, types.Type

    return types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="run_shell_cmd",
            description=(
                "Execute a single diagnostic or Azure read-only command through the Safe-Exec Shell. "
                "The Shell classifies it (SAFE/RISKY/FORBIDDEN) and applies HITL gating as needed. "
                "FORBIDDEN commands are blocked unconditionally — do not retry. "
                "cat on *_forensic_report.md or *_comparison.md in /tmp/captures/ is auto-approved (SAFE)."
            ),
            parameters=S(type=T.OBJECT, properties={
                "command":   S(type=T.STRING, description=(
                    "The complete shell command. Single command only — no && or ; chaining. No sudo."
                )),
                "reasoning": S(type=T.STRING, description=(
                    "One sentence explaining why this command is needed. "
                    "Shown to the engineer during HITL review and written to the audit trail."
                )),
                "hypothesis_id": S(type=T.STRING, description=(
                    "ID of the active hypothesis this command is attributed to (e.g. 'H1'). "
                    "Required when investigating multiple hypotheses simultaneously."
                )),
            }, required=["command", "reasoning"]),
        ),

        types.FunctionDeclaration(
            name="capture_traffic",
            description=(
                "Start an Azure Network Watcher packet capture. "
                "Blocks until the capture completes and forensic analysis is ready — "
                "no need to call check_task unless capture_traffic returns status=task_pending "
                "(burst limit expired; capture still running). "
                "For SINGLE-VM captures: use the VM name as target. "
                "For DUAL-END captures (only when the investigation explicitly requires simultaneous "
                "source AND destination wire evidence): use 'source_vm to dest_vm' as target. "
                "Do NOT escalate to dual-end capture for single-VM investigations — "
                "a single-end capture is almost always sufficient. "
                "IMPORTANT: Azure allows only ONE registered capture per VM at a time. "
                "Call cleanup_task on the previous capture before starting a new one on the same VM. "
                "Full resource IDs (/subscriptions/…) are unambiguous and preferred over short names."
            ),
            parameters=S(type=T.OBJECT, properties={
                "target": S(type=T.STRING, description=(
                    "VM name, full Azure resource ID, or 'source_vm to dest_vm'. "
                    "Full IDs required when multiple VMs share a name across resource groups."
                )),
                "resource_group":        S(type=T.STRING, description="Azure resource group containing the target VM(s)."),
                "storage_account":       S(type=T.STRING, description="Azure storage account name for the capture blob."),
                "duration_seconds":      S(type=T.INTEGER, description="Capture duration in seconds. Default 20. Max 300."),
                "investigation_context": S(type=T.STRING, description="One sentence describing what is being captured. Written to audit trail."),
                "hypothesis_id":         S(type=T.STRING, description=(
                    "ID of the active hypothesis this capture is attributed to (e.g. 'H2'). "
                    "Required when investigating multiple hypotheses simultaneously."
                )),
            }, required=["target", "resource_group", "storage_account"]),
        ),

        types.FunctionDeclaration(
            name="check_task",
            description=(
                "Poll an in-progress capture task. "
                "Only needed if capture_traffic returned status=task_pending "
                "(burst limit expired before capture finished). "
                "Call repeatedly until status is task_completed, task_failed, task_cancelled, or task_timed_out."
            ),
            parameters=S(type=T.OBJECT, properties={
                "task_id": S(type=T.STRING, description="The task_id returned by capture_traffic."),
            }, required=["task_id"]),
        ),

        types.FunctionDeclaration(
            name="cancel_task",
            description="Abort an in-progress Azure packet capture. Idempotent if already in a terminal state.",
            parameters=S(type=T.OBJECT, properties={
                "task_id":       S(type=T.STRING, description="The task_id to cancel."),
                "reason":        S(type=T.STRING, description="Brief reason for cancellation (written to audit trail)."),
                "hypothesis_id": S(type=T.STRING, description="ID of the active hypothesis this cancellation is attributed to."),
            }, required=["task_id"]),
        ),

        types.FunctionDeclaration(
            name="cleanup_task",
            description=(
                "Delete Azure resources (capture record, storage blob, local .pcap) for a completed task. "
                "Each deletion is RISKY — a HITL prompt appears per deletion. "
                "Call after the forensic report has been read. Idempotent."
            ),
            parameters=S(type=T.OBJECT, properties={
                "task_id":       S(type=T.STRING, description="The task_id whose resources should be cleaned up."),
                "hypothesis_id": S(type=T.STRING, description="ID of the active hypothesis this cleanup is attributed to."),
            }, required=["task_id"]),
        ),

        types.FunctionDeclaration(
            name="manage_hypotheses",
            description=(
                "Register new hypotheses, update their state, or remove them from the active list. "
                "Call this before issuing tool calls so denial counters are attributed correctly. "
                "Call on every state change: ACTIVE → CONFIRMED / REFUTED / UNVERIFIABLE / CONTRADICTED."
            ),
            parameters=S(type=T.OBJECT, properties={
                "add": S(type=T.ARRAY, items=S(type=T.OBJECT, properties={
                    "id":          S(type=T.STRING, description="Unique ID, e.g. 'H1'."),
                    "description": S(type=T.STRING, description="One sentence stating the hypothesis."),
                }, required=["id", "description"]),
                description="New hypotheses to register and mark ACTIVE."),
                "update": S(type=T.ARRAY, items=S(type=T.OBJECT, properties={
                    "id":    S(type=T.STRING, description="ID of the hypothesis to update."),
                    "state": S(type=T.STRING,
                               enum=["ACTIVE", "CONFIRMED", "REFUTED", "UNVERIFIABLE", "CONTRADICTED"],
                               description="New state."),
                }, required=["id", "state"]),
                description="State transitions for existing hypotheses. Terminal states remove from active list."),
                "remove_ids": S(type=T.ARRAY, items=S(type=T.STRING),
                                description="IDs to remove from active_hypothesis_ids without a state change."),
            }),
        ),

        types.FunctionDeclaration(
            name="complete_investigation",
            description=(
                "Signal that the investigation is complete and request RCA report generation. "
                "Call when: root cause is confirmed, all hypotheses are exhausted, "
                "or denial_threshold_reached=true for all active hypotheses."
            ),
            parameters=S(type=T.OBJECT, properties={
                "confidence":              S(type=T.STRING, enum=["high", "medium", "low"], description=(
                    "high=root cause confirmed with evidence. medium=probable cause. low=all hypotheses unverifiable."
                )),
                "root_cause_summary":      S(type=T.STRING, description="1-3 sentences summarising the finding."),
                "confirmed_hypotheses":    S(type=T.ARRAY, items=S(type=T.STRING), description="Hypothesis IDs confirmed by evidence."),
                "refuted_hypotheses":      S(type=T.ARRAY, items=S(type=T.STRING), description="Hypothesis IDs disproved by evidence."),
                "unverifiable_hypotheses": S(type=T.ARRAY, items=S(type=T.STRING), description="Hypothesis IDs blocked by repeated denials."),
                "contradicted_hypotheses": S(type=T.ARRAY, items=S(type=T.STRING), description=(
                    "Hypothesis IDs where tool results produced contradictory evidence. "
                    "Reference the specific audit_ids of the conflicting results in root_cause_summary."
                )),
                "recommended_actions":     S(type=T.ARRAY, items=S(type=T.STRING), description="Concrete next steps for the operator."),
            }, required=["confidence", "root_cause_summary"]),
        ),
    ])

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are the Ghost Agent — an AI network forensics investigator for Azure cloud environments.
Every action is audited. Every command you propose must have a clear reasoning string.

AUTONOMOUS OPERATION (CRITICAL):
- You are a fully autonomous investigator. NEVER ask the user clarifying questions.
- All information you need is in the problem statement. If something is ambiguous, make a
  reasonable assumption, state it briefly as reasoning, and proceed with tool calls.
- Your FIRST response must contain a manage_hypotheses(add=[...]) tool call registering
  2-4 hypotheses, followed in the same response by the first diagnostic tool call.
  A text-only first response with no tool calls is ALWAYS incorrect behaviour.
- Hypotheses exist ONLY when registered via manage_hypotheses. Listing them in text
  without calling manage_hypotheses does not register them — the RCA log will be empty.
- Every mid-investigation response MUST include at least one tool call. A text-only
  response that is not complete_investigation means the turn was wasted. If you have
  more to investigate, include the next tool call in the same response as your reasoning.
- Do NOT use pipe characters (|) in commands. run_shell_cmd runs a single command with
  its own arguments only. Use flags built into the command (e.g. ss -tulnp) and let the
  agent interpret the output — do not chain with grep or awk.

INVESTIGATION FRAMEWORK:
1. LOCAL DIAGNOSTICS FIRST — ping, dig, traceroute, ss, netstat, curl (GET only). Establish baseline before Azure operations.
2. AZURE READ OPERATIONS — az <service> list/show/get. Read NSG rules, route tables, VNet peering, DNS zones.
3. PACKET CAPTURE (only when local diagnostics are inconclusive AND failure is time-sensitive or intermittent):
   capture_traffic blocks until complete (download + forensic analysis done). On return:
   • status=task_completed → result contains report_path. Cat report_path directly — auto-approved (SAFE).
   • status=task_pending   → burst limit expired; capture still running. Call check_task until completed.
   Read forensic report:
   • cat the exact report_path from the result. Single capture: *_forensic_report.md. Dual capture: *_comparison.md.
   MANDATORY CLEANUP: call cleanup_task(task_id=...) for every completed capture:
   • IMMEDIATELY after reading the forensic report — before any further tool calls.
   • BEFORE starting another capture on the same VM (Azure allows only ONE registered capture per VM).
   • BEFORE calling complete_investigation.
   Do NOT skip cleanup. Do NOT create a new capture while a previous one on the same VM is uncleaned.
4. CONCLUDE — call complete_investigation ONLY after all capture tasks are cleaned up.

HYPOTHESIS MANAGEMENT:
- Form 2-4 specific, falsifiable hypotheses before issuing any tool calls.
- Register them immediately with manage_hypotheses(add=[...]). This is mandatory — the denial
  state machine and RCA hypothesis log both depend on structured session state, not free text.
- Always set hypothesis_id in every subsequent tool call to scope denial counters correctly.
- Transition state on every finding: manage_hypotheses(update=[{id, state}]).
  Terminal states (CONFIRMED/REFUTED/UNVERIFIABLE/CONTRADICTED) auto-remove from active list.
- When _meta.denial_threshold_reached=true: update that hypothesis to UNVERIFIABLE.
  If active_hypothesis_ids is now empty: call complete_investigation(confidence="low").
- RECOVERY RULE: At the start of any response, if active_hypothesis_ids is empty AND
  complete_investigation has not been called, you MUST call manage_hypotheses(add=[...])
  as the first tool call before any diagnostic command. This handles cases where the
  initial manage_hypotheses call was dropped (e.g., due to an API error on the first turn).

RESUME PROTOCOL (when is_resume=True):
- Network state may have changed since interruption. Do NOT assume prior evidence is current.
- Re-run the 2-3 most critical diagnostic commands from the prior session before continuing.
- Compare new results against prior audit_id references. If changed, update hypothesis states.
- If a previously CONFIRMED hypothesis is contradicted by new evidence, revert it to ACTIVE.

TOOL DECISION RULES:
Symptom                          First tool                                   If denied
───────────────────────────────────────────────────────────────────────────────────────────
Cannot reach Azure endpoint      az network nsg rule list (control plane)     capture_traffic
DNS resolution failure in Azure  az network dns zone list / vnet show         capture_traffic
Intermittent packet loss         capture_traffic (single-end first)           az network route-table
NSG/firewall suspected           az network nsg rule list --nsg-name <nsg>    az network nsg show
Routing anomaly                  az network route-table route list            capture_traffic
  → confirm with: az network nic show-effective-route-table (see ROUTE CONFIRMATION PATTERN)
TCP port blocked                 az network nsg rule list (check deny rules)  capture_traffic
"Is port X open on Azure VM?"    az network nsg rule list — NEVER ss/curl     capture_traffic
Azure Storage unreachable (VM)   az storage account show --query networkRuleSet  az network vnet subnet show --query serviceEndpoints

STORAGE SERVICE ENDPOINT PATTERN — when a VM cannot reach an Azure Storage account:
After checking NSG (clean) and routes (clean), ALWAYS query BOTH of the following before
considering packet capture:
  1. az storage account show --name <SA> -g <RG> --query "networkRuleSet"
     Look for: defaultAction=Deny AND virtualNetworkRules listing your subnet.
  2. az network vnet subnet show -g <RG> --vnet-name <VNet> --name <subnet> --query "serviceEndpoints"
     Look for: Microsoft.Storage in the list.
A VNet network rule on the storage account ONLY authenticates traffic when the subnet has a
matching Microsoft.Storage service endpoint. If the rule is present but the endpoint is absent,
VM traffic is routed to the public storage endpoint and rejected by defaultAction: Deny — even
though "the VNet is configured." This mismatch is invisible to NSG and route investigation.
Do NOT attempt packet capture for this class of failure — it is a control-plane configuration
mismatch. Wire-level data cannot disambiguate it.

ROUTE CONFIRMATION PATTERN — when a custom route is found in a route table:
After az network route-table route list reveals a suspicious route, ALWAYS confirm with:
  az network nic show-effective-route-table -g <RG> --name <NIC_NAME>
  (Get NIC name: az vm show -g <RG> --name <VM> --query "networkProfile.networkInterfaces[0].id" -o tsv
   then take the last path segment as the NIC name.)
This shows the ACTIVE effective routing table on the source VM's NIC — not just what routes
exist in the route table, but which route is actually winning. A /32 host route overrides the
system VnetLocal route: effective-route-table will show the custom route as "Active" and the
system VnetLocal route as "Invalid" for that prefix. This is the definitive proof that the
custom route is redirecting traffic — stronger than listing the route table alone.

NEVER use ss, curl, nc, ping, or traceroute to diagnose Azure VM connectivity.
These run on the engineer's LOCAL machine and cannot reach Azure private IPs.
For any question about what is reachable or listening inside Azure: use az network commands.

FILE READ RESTRICTION:
cat is permitted ONLY for paths under ./audit/ OR paths returned in result.report_path.
Do NOT cat: ~/.ssh/*, .env, /etc/*, /proc/*, or any path outside audit_dir.

LOCAL PROBE CONTEXT:
run_shell_cmd executes on the engineer's local machine, NOT inside Azure.
Results are subject to local DNS resolvers, ISP/VPN routing, and ICMP rate-limiting.
Always qualify local results: "from the engineer's local machine."
CRITICAL RULES — violating these is incorrect behaviour:
- A failing local ping or DNS lookup is NEVER conclusive evidence of an Azure VNet failure.
  Azure internal hostnames (e.g. tf-dest-vm, *.internal.cloudapp.net) do NOT resolve from
  outside the VNet. Expect NXDOMAIN. This is not a fault.
- Do NOT run ANY local network probes (ping, curl, nc, ss, traceroute) against RFC 1918
  private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x). These are Azure-internal
  addresses, 100% unreachable from the engineer's local machine. Results are always
  failure and prove nothing about the Azure VNet — they only waste turns.
- The ONLY useful local commands for Azure VNet investigation are Azure CLI reads:
  az network nsg rule list, az network vnet show, az network route-table list, az vm show.
  These call the Azure control plane over HTTPS and do not require VNet connectivity.
- After any local DNS failure or timeout to a private IP: do NOT conclude a fault.
  Skip directly to az network commands.

TARGETED QUERY RULE:
When output_metadata.truncation_applied=true, do NOT re-issue the same command.
Reformulate with a --query JMESPath filter to target exactly what you need:
  Broad:    az network nsg rule list --nsg-name <nsg> -o json
  Targeted: az network nsg rule list --nsg-name <nsg> --query "[?destinationPortRange=='6379']" -o json
JMESPATH SAFETY: Only use simple single-condition or two-condition AND filters.
Do NOT use nested projections, multi-level pipes (|), or complex sub-expressions.
Do NOT use -o table with --query; always use -o json or -o tsv.
If exit_code != 0 from a --query command: this is a JMESPath SYNTAX ERROR, not a missing resource.
Re-issue without --query to get full output, then formulate a correct query from the field names.

DENIAL RECOVERY:
When status="denied":
1. Acknowledge the constraint. Check _meta.denial_reason if present — incorporate it into your re-plan.
2. Do NOT retry the same command unless denial_reason explicitly tells you how to correct it.
3. Pivot to a lower-privilege diagnostic or capture_traffic (managed, no sudo required).
Specific pivots:
  sudo tcpdump → capture_traffic  |  az vm stop → az vm show --query powerState
  ip route add → az network route-table route list  |  rm {file} → note as manual cleanup

EVIDENCE HIERARCHY (highest fidelity first):
1. [CLOUD] PCAP forensic report — wire-level truth, unaffected by OS rate-limiting.
2. [CLOUD] Azure platform API — authoritative for NSG rules, routes, and peering state.
3. [LOCAL/CLOUD] Active probe — live path result; LOCAL probes subject to ISP/VPN/ICMP limits.
4. [LOCAL] Agent-reported state — engineer's machine view (ss, netstat, ip route).
KEY RULE: [LOCAL] results NEVER override [CLOUD] API or PCAP findings.

CONFLICT RESOLUTION:
When two results contradict, trust the higher-fidelity source. State explicitly which result you
rely on and why. Mark the hypothesis CONTRADICTED. Once a higher-fidelity result resolves it,
transition to CONFIRMED or REFUTED. Include contradicting audit_ids in complete_investigation.
"""

# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------

def _find_partially_cleaned_tasks(audit_dir: str) -> list[dict]:
    """CLI-side scan for tasks with cleanup_status='partial' (not detected by _detect_orphans)."""
    tasks_by_id: dict[str, dict] = {}
    for filepath in glob.glob(str(Path(audit_dir) / "orchestrator_tasks_*.jsonl")):
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        tid = rec.get("task_id")
                        if tid:
                            tasks_by_id[tid] = rec  # last-write-wins
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return [t for t in tasks_by_id.values() if t.get("cleanup_status") == "partial"]


def _classify_orphans(orphan_report: dict, audit_dir: str) -> dict:
    """Map orchestrator orphan report into 5 typed buckets."""
    buckets: dict[str, list] = {
        "abandoned_tasks":   [],
        "needs_cleanup":     [],
        "partially_cleaned": [],
        "untracked_azure":   [],
        "stale_local_files": [],
    }
    for o in orphan_report.get("orphans", []):
        otype = o.get("type", "")
        if otype == "abandoned_task":
            buckets["abandoned_tasks"].append(o["task"])
        elif otype == "needs_cleanup":
            buckets["needs_cleanup"].append(o["task"])
        elif otype == "untracked_azure_resource":
            buckets["untracked_azure"].append(o)
        elif otype == "stale_local_file":
            buckets["stale_local_files"].append(o)

    # Secondary scan — orchestrator._detect_orphans() misses cleanup_status="partial"
    buckets["partially_cleaned"] = _find_partially_cleaned_tasks(audit_dir)
    return buckets


def _present_orphan_report(buckets: dict) -> bool:
    """Print orphan summary. Returns True if any orphans exist."""
    total = sum(len(v) for v in buckets.values())
    if total == 0:
        print("  [OK] No orphaned resources found.")
        return False
    print(f"\nOrphaned resources from previous sessions ({total} total):")
    labels = [
        ("abandoned_tasks",   "Abandoned tasks (non-terminal)"),
        ("needs_cleanup",     "Needs cleanup (pending)"),
        ("partially_cleaned", "Partially cleaned (partial)"),
        ("untracked_azure",   "Untracked Azure resources"),
        ("stale_local_files", "Stale local files (>7 days)"),
    ]
    for key, label in labels:
        if buckets[key]:
            print(f"  {label}: {len(buckets[key])}")
    return True


def _run_batch_cleanup(buckets: dict, shell, orchestrator, state: dict, session_file: str,
                       location: str):
    """Silently clean all orphaned resources without HITL prompts (Fix B + D).

    Temporarily swaps the shell's HITL callback to auto-approve so every az delete
    and rm command executes without user interaction.  After all deletes, any task
    that is still in a partial state is force-marked as cleaned in the registry.
    Local files are removed in a single batched rm call.
    """
    original_hitl = shell._hitl_callback
    shell._hitl_callback = (
        lambda cmd, reasoning, risk, tier: HitlDecision(action="approve")
    )
    try:
        tasks_to_clean = (
            buckets["abandoned_tasks"]
            + buckets["needs_cleanup"]
            + buckets["partially_cleaned"]
        )
        if tasks_to_clean:
            print(f"  Auto-cleaning {len(tasks_to_clean)} registered task(s)...")
            for task in tasks_to_clean:
                tid = task.get("task_id", "")
                if not tid:
                    continue
                print(f"    {tid}")
                result = orchestrator.orchestrate({"intent": "cleanup_task", "task_id": tid})
                # Force-mark partial tasks (e.g. Azure resource already deleted)
                if result.get("cleanup_status") in ("partial", None):
                    orchestrator.mark_task_cleaned(tid)

        for o in buckets["untracked_azure"]:
            name = o.get("name", "unknown")
            loc  = location or "eastus"
            cmd  = f"az network watcher packet-capture delete --location {loc} --name {name}"
            print(f"  Deleting untracked Azure capture: {name}")
            shell.execute({"command": cmd,
                           "reasoning": f"Startup batch cleanup: untracked Azure capture {name}"})

        local_paths = [o.get("path", "") for o in buckets["stale_local_files"] if o.get("path")]
        if local_paths:
            print(f"  Removing {len(local_paths)} stale local file(s)...")
            quoted = " ".join(f'"{p}"' for p in local_paths)
            shell.execute({"command": f"rm -f {quoted}",
                           "reasoning": "Startup batch cleanup: stale local PCAP files"})
    finally:
        shell._hitl_callback = original_hitl

    save_session(state, session_file)
    print("  [OK] Startup cleanup complete.")


def _run_interactive_cleanup(buckets: dict, shell, orchestrator, state: dict, session_file: str,
                             location: str):
    """Review and clean each orphaned resource one by one ([R]eview path)."""

    def _confirm(label: str) -> bool:
        return input(f"  Clean {label}? [y/N] > ").strip().lower() == "y"

    for task in buckets["abandoned_tasks"] + buckets["needs_cleanup"]:
        tid = task.get("task_id", "")
        if _confirm(f"task {tid}"):
            print(f"  Cleaning: {tid}")
            orchestrator.orchestrate({"intent": "cleanup_task", "task_id": tid})

    for task in buckets["partially_cleaned"]:
        tid = task.get("task_id", "")
        if _confirm(f"partial task {tid}"):
            print(f"  Re-attempting partial cleanup: {tid}")
            result = orchestrator.orchestrate({"intent": "cleanup_task", "task_id": tid})
            if result.get("cleanup_status") == "partial":
                state.setdefault("manual_cleanup_pending", []).append(tid)
                print(f"  [WARN] {tid}: still partial — added to manual_cleanup_pending.")
            save_session(state, session_file)

    for o in buckets["untracked_azure"]:
        name = o.get("name", "unknown")
        loc  = location or "eastus"
        cmd  = f"az network watcher packet-capture delete --location {loc} --name {name}"
        if _confirm(f"Azure resource {name}"):
            shell.execute({"command": cmd,
                           "reasoning": f"Cleanup untracked Azure capture: {name}"})

    for o in buckets["stale_local_files"]:
        path = o.get("path", "")
        if path and _confirm(f"local file {Path(path).name}"):
            shell.execute({"command": f'rm "{path}"',
                           "reasoning": f"Remove stale local file: {path}"})


def _run_startup_cleanup(buckets: dict, shell, orchestrator, state: dict, session_file: str,
                         location: str = ""):
    """Execute cleanup per user choice."""
    choice = input("\n[C]lean up now  [S]kip  [R]eview each one > ").strip().lower()
    if choice == "s":
        return
    if choice == "r":
        _run_interactive_cleanup(buckets, shell, orchestrator, state, session_file, location)
        return
    # [C]lean — batch, no HITL prompts
    _run_batch_cleanup(buckets, shell, orchestrator, state, session_file, location)


def _count_shell_sequences(audit_dir: str, session_id: str) -> int:
    """Return the highest sequence number written to the shell audit JSONL for this session.

    Used on resume so SafeExecShell starts from the next available sequence number,
    preventing audit_id collisions with records from the original session.
    """
    path = Path(audit_dir) / f"shell_audit_{session_id}.jsonl"
    if not path.exists():
        return 0
    max_seq = 0
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    max_seq = max(max_seq, rec.get("sequence", 0))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return max_seq


def _handle_manage_hypotheses(tool_args: dict, state: dict) -> dict:
    """Apply hypothesis add/update/remove operations directly to session state.

    This is the write path for the Brain to register hypotheses and transition their
    states. No shell or orchestrator call — state mutation only.
    """
    added, updated, removed = [], [], []

    for h in tool_args.get("add", []):
        h_id = h.get("id", "")
        if not h_id:
            continue
        if not any(e.get("id") == h_id for e in state["hypothesis_log"]):
            state["hypothesis_log"].append({
                "id":          h_id,
                "description": h.get("description", ""),
                "state":       "ACTIVE",
                "denial_events": [],
            })
        if h_id not in state["active_hypothesis_ids"]:
            state["active_hypothesis_ids"].append(h_id)
        added.append(h_id)

    _TERMINAL = {"CONFIRMED", "REFUTED", "UNVERIFIABLE", "CONTRADICTED"}
    for upd in tool_args.get("update", []):
        h_id      = upd.get("id", "")
        new_state = upd.get("state", "")
        for entry in state["hypothesis_log"]:
            if entry.get("id") == h_id:
                entry["state"] = new_state
                break
        if new_state in _TERMINAL and h_id in state["active_hypothesis_ids"]:
            state["active_hypothesis_ids"].remove(h_id)
        updated.append(h_id)

    for h_id in tool_args.get("remove_ids", []):
        if h_id in state["active_hypothesis_ids"]:
            state["active_hypothesis_ids"].remove(h_id)
        removed.append(h_id)

    return {
        "status":               "ok",
        "active_hypothesis_ids": state["active_hypothesis_ids"],
        "added":   added,
        "updated": updated,
        "removed": removed,
    }


def _reconstruct_history(audit_dir: str, session_id: str, denial_reasons: dict | None = None) -> list:
    """Rebuild conversation history from both audit JSONL files for --resume.

    Shell commands → synthetic run_shell_cmd call/response pairs.
    Orchestrator tasks → one synthetic capture_traffic call/response per task_id (final state).
    Raw output is intentionally excluded (Zero-Cache rule — cite audit_id only).
    """
    denial_reasons = denial_reasons or {}
    history = []

    # --- Shell audit: run_shell_cmd pairs (output stripped) ---
    shell_path = Path(audit_dir) / f"shell_audit_{session_id}.jsonl"
    shell_count = 0
    if shell_path.exists():
        try:
            with open(shell_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    audit_id = f"{session_id}_{rec.get('sequence', 0):03d}"
                    history.append(types.Content(
                        role="model",
                        parts=[types.Part(function_call=types.FunctionCall(
                            name="run_shell_cmd",
                            args={"command": rec.get("command", ""), "reasoning": rec.get("reasoning", "")},
                        ))],
                    ))
                    # Response carries audit_id reference only — no raw output (context-window safety).
                    # denial_reason is restored from session state so the Brain recalls why past
                    # commands were denied (fix #9).
                    fn_response: dict = {
                        "audit_id":  audit_id,
                        "action":    rec.get("action", ""),
                        "status":    rec.get("status", ""),
                        "exit_code": rec.get("exit_code"),
                    }
                    if rec.get("action") == "user_denied":
                        reason = denial_reasons.get(audit_id, "")
                        if reason:
                            fn_response["denial_reason"] = reason
                    history.append(types.Content(
                        role="user",
                        parts=[types.Part(function_response=types.FunctionResponse(
                            name="run_shell_cmd",
                            response=fn_response,
                        ))],
                    ))
                    shell_count += 1
        except OSError as e:
            print(f"Warning: could not read shell audit ({shell_path.name}): {e}")
    else:
        print(f"Warning: shell audit not found ({shell_path.name}) — shell history unavailable.")

    # --- Orchestrator tasks: one capture_traffic pair per task_id (last-write-wins) ---
    task_path = Path(audit_dir) / f"orchestrator_tasks_{session_id}.jsonl"
    task_latest: dict[str, dict] = {}
    if task_path.exists():
        try:
            with open(task_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        tid = rec.get("task_id")
                        if tid:
                            task_latest[tid] = rec
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            print(f"Warning: could not read task registry ({task_path.name}): {e}")

    for task in task_latest.values():
        tid = task.get("task_id", "")
        history.append(types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(
                name="capture_traffic",
                args={
                    "target":                task.get("target", ""),
                    "resource_group":        task.get("resource_group", ""),
                    "storage_account":       task.get("storage_account", ""),
                    "investigation_context": task.get("investigation_context", ""),
                },
            ))],
        ))
        history.append(types.Content(
            role="user",
            parts=[types.Part(function_response=types.FunctionResponse(
                name="capture_traffic",
                response={
                    "task_id":        tid,
                    "state":          task.get("state", ""),
                    "report_path":    task.get("report_path"),
                    "local_pcap_path": task.get("local_pcap_path"),
                    "cleanup_status": task.get("cleanup_status"),
                },
            ))],
        ))

    print(f"  Reconstructed: {shell_count} shell command(s), {len(task_latest)} capture task(s).")
    return history

# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _dispatch_tool(tool_name: str, tool_args: dict, shell, orchestrator) -> dict:
    """Route a Gemini function call to shell.execute() or orchestrator.orchestrate()."""
    if tool_name == "run_shell_cmd":
        return shell.execute({
            "command":   tool_args["command"],
            "reasoning": tool_args["reasoning"],
        })

    if tool_name == "capture_traffic":
        return orchestrator.orchestrate({
            "intent":                "capture_traffic",
            "target":                tool_args["target"],
            "investigation_context": tool_args.get("investigation_context", ""),
            "parameters": {
                "resource_group":   tool_args["resource_group"],
                "storage_account":  tool_args["storage_account"],
                "duration_seconds": tool_args.get("duration_seconds", 20),
            },
        })

    if tool_name == "check_task":
        return orchestrator.orchestrate({"intent": "check_task",  "task_id": tool_args["task_id"]})

    if tool_name == "cancel_task":
        return orchestrator.orchestrate({"intent": "cancel_task", "task_id": tool_args["task_id"]})

    if tool_name == "cleanup_task":
        return orchestrator.orchestrate({"intent": "cleanup_task","task_id": tool_args["task_id"]})

    return {"status": "error", "error": "unknown_tool", "tool": tool_name}

# ---------------------------------------------------------------------------
# Denial detection
# ---------------------------------------------------------------------------

def _apply_denial_detection(tool_name: str, tool_args: dict, result: dict, state: dict):
    """Detect HITL denials, inject _meta hints, and update session state. Mutates in place."""
    is_user_denial = (
        (tool_name == "run_shell_cmd" and result.get("action") == "user_denied")
        or (tool_name in ("capture_traffic", "cancel_task") and result.get("status") == "task_cancelled")
    )

    # Scope to the attributed hypothesis when provided; fall back to all active ones.
    # This prevents a denial for H2 from penalising H1 (fix #6) and prevents a success
    # for H2 from resetting H1's consecutive counter (fix #10).
    h_id_attr = tool_args.get("hypothesis_id")
    if h_id_attr and h_id_attr in state["active_hypothesis_ids"]:
        h_ids = [h_id_attr]
    else:
        h_ids = state["active_hypothesis_ids"] or ["_"]

    if not is_user_denial:
        for h_id in h_ids:
            state["consecutive_denial_counter"][h_id] = 0
        return

    meta = result.setdefault("_meta", {})
    newly_unverifiable = []

    for h_id in h_ids:
        state["denial_tracker"].setdefault(h_id, 0)
        state["denial_tracker"][h_id] += 1
        count = state["denial_tracker"][h_id]
        meta["denial_count"] = count
        state["consecutive_denial_counter"].setdefault(h_id, 0)
        state["consecutive_denial_counter"][h_id] += 1

        if count == 1:
            meta["pivot_instruction"] = "Command denied. Consider an alternative diagnostic approach."
        elif count == 2:
            meta["approaching_threshold"] = True
            meta["warning"] = (
                f"Second denial for hypothesis {h_id}. "
                "One more denial marks it UNVERIFIABLE."
            )
        if count >= MAX_DENIALS_PER_HYPOTHESIS:
            meta["denial_threshold_reached"] = True
            newly_unverifiable.append(h_id)
            meta["instruction"] = (
                f"Hypothesis {h_id} is now UNVERIFIABLE. "
                "Move to next hypothesis or call complete_investigation if active_hypothesis_ids is empty."
            )

    for h_id in newly_unverifiable:
        if h_id in state["active_hypothesis_ids"]:
            state["active_hypothesis_ids"].remove(h_id)

    # Capture and forward denial reason from the HITL callback
    if tool_name == "run_shell_cmd" and result.get("action") == "user_denied":
        reason = getattr(terminal_hitl_callback, "captured_reason", "")
        if reason:
            meta["denial_reason"] = reason
            # Persist to session state so it survives resume (fix #9)
            audit_id_key = result.get("audit_id", "")
            if audit_id_key:
                state.setdefault("denial_reasons", {})[audit_id_key] = reason

    # Append denial event to each matching hypothesis in the log (M10)
    command     = tool_args.get("command", tool_args.get("target", ""))
    audit_id    = result.get("audit_id", "")
    denial_reason = meta.get("denial_reason", "")
    for h_entry in state.get("hypothesis_log", []):
        if h_entry.get("id") in h_ids:
            h_entry.setdefault("denial_events", []).append({
                "turn":         state["turn_count"],
                "command":      command,
                "denial_reason": denial_reason,
                "audit_id":     audit_id,
            })

# ---------------------------------------------------------------------------
# RCA generation
# ---------------------------------------------------------------------------

def _count_shell_audit_lines(audit_dir: str, session_id: str) -> int:
    """Count non-empty records in the shell audit file (marks the investigation boundary)."""
    path = Path(audit_dir) / f"shell_audit_{session_id}.jsonl"
    if not path.exists():
        return 0
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def _parse_session_dt(session_id: str) -> datetime | None:
    """Parse start datetime from session_id (format: ghost_YYYYMMDD_HHMMSS)."""
    try:
        parts = session_id.split("_")
        return datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
    except (ValueError, IndexError):
        return None


def _parse_task_dt(task_id: str) -> datetime | None:
    """Parse creation datetime from task_id (format: ghost_{vm}_{YYYYMMDDTHHMMSS})."""
    try:
        ts = task_id.rsplit("_", 1)[1]   # "20260221T083209"
        return datetime.strptime(ts, "%Y%m%dT%H%M%S")
    except (ValueError, IndexError):
        return None


def _read_shell_audit(audit_dir: str, session_id: str) -> list[dict]:
    """Read shell audit JSONL (read-only). Skips malformed lines."""
    records = []
    path = Path(audit_dir) / f"shell_audit_{session_id}.jsonl"
    if not path.exists():
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _read_task_registry(audit_dir: str, session_id: str | None = None) -> dict[str, dict]:
    """Read orchestrator JSONL files (read-only). Last-write-wins per task_id.

    If session_id is provided, reads only that session's file (used by RCA to prevent
    cross-session contamination). If None, reads all sessions (used by orphan detection).
    """
    tasks: dict[str, dict] = {}
    if session_id is not None:
        filepaths = glob.glob(str(Path(audit_dir) / f"orchestrator_tasks_{session_id}.jsonl"))
    else:
        filepaths = glob.glob(str(Path(audit_dir) / "orchestrator_tasks_*.jsonl"))
    for filepath in filepaths:
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        tid = rec.get("task_id")
                        if tid:
                            tasks[tid] = rec
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return tasks


def _read_forensic_report(report_path: str, shell, audit_dir: str) -> str | None:
    """Read the forensic report via shell.execute (auto-approved — SAFE).

    Paths are validated against known safe roots (audit_dir or /tmp/captures) to prevent
    path traversal while allowing forensic reports stored in the capture directory.
    Note: pcap_forensics.py only generates *_forensic_report.md — no executive summary file.
    """
    audit_root    = Path(audit_dir).resolve()
    captures_root = Path("/tmp/captures").resolve()
    resolved = Path(report_path).resolve()
    if not (resolved.is_relative_to(audit_root) or resolved.is_relative_to(captures_root)):
        print(f"[WARN] Blocked read — path outside allowed dirs: {report_path}")
        return None
    result = shell.execute({
        "command":   f'cat "{report_path}"',
        "reasoning": "Reading forensic report generated by this session — safe to approve.",
    })
    if result.get("status") == "denied":
        return None
    if result.get("exit_code") == 0 and result.get("output"):
        return result["output"]
    return None


def _generate_rca(state: dict, final_args: dict, shell, session_file: str):
    """RCA generation. Reads both JSONL files; writes two documents:

    - ghost_report_{sid}.md — Investigation report (findings, forensic analysis, actions)
    - ghost_audit_{sid}.md  — Audit trail (all commands, hypotheses log, integrity statement)
    """
    sid       = state["session_id"]
    audit_dir = state["audit_dir"]

    # Phase 1 — Shell audit (investigation records only — exclude startup cleanup)
    all_shell_records = _read_shell_audit(audit_dir, sid)
    start_line = state.get("investigation_audit_start_line", 0)
    shell_records = all_shell_records[start_line:]
    for rec in shell_records:
        rec["_ctx"] = "CLOUD" if rec.get("environment") == "azure" else "LOCAL"

    completed   = [r for r in shell_records if r.get("status") == "completed" and r.get("exit_code") == 0]
    failed_cmds = [r for r in shell_records if r.get("status") == "completed" and r.get("exit_code") != 0]
    denied      = [r for r in shell_records if r.get("status") == "denied"]
    forbidden   = [r for r in shell_records if r.get("status") == "error" and r.get("error") == "forbidden_command"]

    # Forensic consistency check heuristics
    advisory_notes = []
    local_fail = any(
        r.get("_ctx") == "LOCAL" and r.get("exit_code", 0) != 0
        and r.get("command", "").startswith(("ping", "traceroute"))
        for r in shell_records
    )
    cloud_permit = any(
        r.get("_ctx") == "CLOUD" and r.get("exit_code") == 0
        and "az network nsg" in r.get("command", "")
        and '"access": "Allow"' in r.get("output_summary", "")
        for r in shell_records
    )
    if local_fail and cloud_permit:
        advisory_notes.append(
            "Local probe failure detected alongside an Azure 'Allow' NSG rule. "
            "PCAP evidence may clarify whether the data path is actually blocked."
        )

    # Phase 2 — Task registry (session-scoped). Filter to tasks created in this session
    # by comparing task timestamp to session start — excludes orphan-cleanup victims from
    # prior sessions that get written into the current session's JSONL during startup.
    task_latest = _read_task_registry(audit_dir, sid)
    session_dt  = _parse_session_dt(sid)
    current_tasks = {
        tid: t for tid, t in task_latest.items()
        if session_dt is None or (
            _parse_task_dt(tid) is not None and _parse_task_dt(tid) >= session_dt
        )
    }

    # Phase 3 — Artifact paths from current-session completed tasks
    artifact_reports = [
        t["report_path"] for t in current_tasks.values()
        if t.get("state") in ("COMPLETED", "DONE") and t.get("report_path")
    ]

    # Phase 4 — Read forensic reports via shell (auto-approved SAFE)
    forensic_contents: dict[str, str | None] = {}
    for report_path in artifact_reports:
        content = _read_forensic_report(report_path, shell, audit_dir)
        forensic_contents[report_path] = content
        if content is None:
            advisory_notes.append(
                f"Forensic report unavailable for {Path(report_path).name} — cat was denied."
            )

    now_ts      = datetime.now(timezone.utc).isoformat()
    confidence  = final_args.get("confidence", "low")
    summary     = final_args.get("root_cause_summary", "Investigation complete.")
    rec_actions = final_args.get("recommended_actions") or []

    # Phase 5a — Build Investigation Report (user-facing: findings + forensic analysis)
    report_lines = [
        f"# Investigation Report — {sid}",
        f"_Generated: {now_ts}_",
        f"_Confidence: {confidence}_",
        "",
        "## Root Cause",
        summary,
        "",
    ]

    for label, key in [
        ("Confirmed",    "confirmed_hypotheses"),
        ("Refuted",      "refuted_hypotheses"),
        ("Unverifiable", "unverifiable_hypotheses"),
        ("Contradicted", "contradicted_hypotheses"),
    ]:
        items = final_args.get(key)
        if items:
            report_lines += [f"**{label}:** " + ", ".join(items), ""]

    for report_path, content in forensic_contents.items():
        if content:
            report_lines += [f"## Forensic Analysis: {Path(report_path).name}", "", content, ""]

    if advisory_notes:
        report_lines += ["## Advisory Notes"]
        for note in advisory_notes:
            report_lines += [f"- {note}"]
        report_lines.append("")

    if rec_actions:
        report_lines += ["## Recommended Actions"]
        for action in rec_actions:
            report_lines += [f"- {action}"]
        report_lines.append("")

    # Phase 5b — Build Audit Trail (compliance: all commands + hypotheses log + integrity)
    audit_lines = [
        f"# Audit Trail — {sid}",
        f"_Generated: {now_ts}_",
        "",
    ]

    if state.get("hypothesis_log"):
        audit_lines += [
            "## Hypotheses Log",
            "| ID | Description | State | Denials |",
            "|---|---|---|---|",
        ]
        for h in state["hypothesis_log"]:
            audit_lines.append(
                f"| {h.get('id','')} | {h.get('description','')} "
                f"| {h.get('state','')} | {h.get('denial_count',0)} |"
            )
        audit_lines.append("")

    evidence_rows = completed + failed_cmds + denied + forbidden
    if evidence_rows:
        audit_lines += [
            "## Command Evidence",
            "| Audit ID | Context | Command | Classification | Action | Exit Code | Outcome |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in evidence_rows:
            cmd = (r.get("command") or "")[:60]
            audit_lines.append(
                f"| {r.get('audit_id','—')} "
                f"| [{r.get('_ctx','?')}] "
                f"| `{cmd}` "
                f"| {r.get('classification','')} "
                f"| {r.get('action','')} "
                f"| {r.get('exit_code','—')} "
                f"| {r.get('status','')} |"
            )
        audit_lines += [
            "",
            "_[LOCAL] = engineer's machine context. [CLOUD] = Azure control/data plane._",
            "",
        ]

    if current_tasks:
        audit_lines += [
            "## Capture Evidence",
            "| Task ID | Target | State | Report |",
            "|---|---|---|---|",
        ]
        for t in current_tasks.values():
            audit_lines.append(
                f"| {t.get('task_id','—')} | {t.get('target','—')} "
                f"| {t.get('state','—')} | {t.get('report_path','—')} |"
            )
        audit_lines.append("")

    audit_lines += [
        "## Integrity Statement",
        "All evidence cited by audit_id from append-only JSONL files:",
        f"- Shell audit:    {Path(audit_dir) / f'shell_audit_{sid}.jsonl'}",
        f"- Task registry:  {Path(audit_dir) / 'orchestrator_tasks_*.jsonl'}",
        "Raw command output is retained in the JSONL audit trail; only summaries appear here.",
    ]

    # Phase 6 — Write both documents
    report_out = str(Path(audit_dir) / f"ghost_report_{sid}.md")
    audit_out  = str(Path(audit_dir) / f"ghost_audit_{sid}.md")
    try:
        Path(audit_dir).mkdir(parents=True, exist_ok=True)
        with open(report_out, "w") as f:
            f.write("\n".join(report_lines))
        with open(audit_out, "w") as f:
            f.write("\n".join(audit_lines))
    except (OSError, PermissionError) as e:
        print(f"[ERROR] Could not write report documents: {e}")
        print("\n" + "\n".join(report_lines))
        report_out = None
        audit_out  = None

    # Phase 7 — Update session
    state["rca_report_path"]  = report_out
    state["audit_trail_path"] = audit_out
    save_session(state, session_file)

    W = 60
    print("\n" + "═" * W)
    if report_out:
        print(f"  INVESTIGATION REPORT: {report_out}")
        print(f"  AUDIT TRAIL:          {audit_out}")
    else:
        print(f"  INVESTIGATION REPORT: written to stdout")
    print(f"  Confidence: {confidence}  |  Turns: {state['turn_count']}")
    print("═" * W)

# ---------------------------------------------------------------------------
# Pre-RCA cleanup gate
# ---------------------------------------------------------------------------

def _offer_cleanup_before_rca(state: dict, orchestrator, session_file: str):
    """If active_task_ids is non-empty, warn and offer cleanup before RCA is generated."""
    uncleaned = list(state.get("active_task_ids", []))
    if not uncleaned:
        return
    print(f"\n[Ghost Agent] WARNING: {len(uncleaned)} task(s) may still have Azure resources:")
    for tid in uncleaned:
        print(f"  {tid}")
    choice = input("[C]lean up now  [S]kip and generate RCA > ").strip().lower()
    if choice != "c":
        return
    for tid in list(uncleaned):
        print(f"  Cleaning: {tid}")
        result = orchestrator.orchestrate({"intent": "cleanup_task", "task_id": tid})
        state["active_task_ids"].remove(tid)
        if result.get("cleanup_status") == "partial":
            state.setdefault("manual_cleanup_pending", []).append(tid)
            print(f"  [WARN] {tid}: partial cleanup — added to manual_cleanup_pending.")
    save_session(state, session_file)


# ---------------------------------------------------------------------------
# Tool-use loop
# ---------------------------------------------------------------------------

def _run_loop(state: dict, history: list, shell, orchestrator, ghost_tools, client, session_file: str,
              effective_system_prompt: str = SYSTEM_PROMPT):
    """Main reasoning loop. Exits via complete_investigation or MAX_LOOP_TURNS."""
    model     = state["model"]
    max_turns = MAX_LOOP_TURNS
    consecutive_empty = 0   # tracks consecutive empty/blocked Gemini responses

    while True:
        # Turn limit check — offer extension before incrementing
        if state["turn_count"] >= max_turns:
            print(f"\n[Ghost Agent] Maximum investigation turns ({max_turns}) reached.")
            choice = input("[E]xtend 10 more turns / [G]enerate RCA now > ").strip().lower()
            if choice == "e":
                max_turns += 10
                continue
            _generate_rca(
                state,
                {"confidence": "medium", "root_cause_summary": "Investigation reached turn limit.", "recommended_actions": []},
                shell, session_file,
            )
            _offer_cleanup_before_rca(state, orchestrator, session_file)
            return

        state["turn_count"] += 1

        # Call Gemini — retry up to 3 times on 429 rate-limit before giving up
        response = None
        for _api_attempt in range(3):
            try:
                response = client.models.generate_content(
                    model    = model,
                    contents = history,
                    config   = types.GenerateContentConfig(
                        tools              = [ghost_tools],
                        system_instruction = effective_system_prompt,
                    ),
                )
                break  # success — exit retry loop
            except Exception as e:
                err_str = str(e)
                is_rate_limit = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str
                if is_rate_limit and _api_attempt < 2:
                    wait_sec = 30 * (2 ** _api_attempt)   # 30s, then 60s
                    print(f"\n[Ghost Agent] Rate limited (429). Waiting {wait_sec}s, "
                          f"then retrying ({_api_attempt + 2}/3)...")
                    time.sleep(wait_sec)
                else:
                    print(f"[ERROR] Gemini API error: {e}")
                    save_session(state, session_file)
                    print(f"Session saved. Resume with: "
                          f"python ghost_agent.py --resume {state['session_id']}")
                    sys.exit(1)
        if response is None:
            save_session(state, session_file)
            print(f"Session saved. Resume with: python ghost_agent.py --resume {state['session_id']}")
            sys.exit(1)

        if not response.candidates:
            consecutive_empty += 1
            # Log the block reason if the SDK exposes it
            feedback    = getattr(response, "prompt_feedback", None)
            block_reason = getattr(feedback, "block_reason", None) if feedback else None
            print(f"[WARN] Gemini empty response {consecutive_empty}/3"
                  f" — {block_reason or 'safety/quota'}. Saving session.")
            save_session(state, session_file)

            if consecutive_empty >= 3:
                print("[ERROR] Persistent empty responses after 3 attempts. Halting.")
                print(f"Resume with: python ghost_agent.py --resume {state['session_id']}")
                sys.exit(1)

            # Inject a synthetic bridge + targeted recovery nudge so the next call
            # has a valid alternating history and an explicit directive.
            history.append(types.Content(
                role="model", parts=[types.Part(text="[recovering]")]
            ))
            pending_tasks = state.get("active_task_ids", [])
            if pending_tasks:
                nudge = (
                    f"The capture task {pending_tasks[-1]} is in progress. "
                    f"Call check_task(task_id=\"{pending_tasks[-1]}\") now. "
                    f"Respond with only the function call — no text."
                )
            elif state.get("active_hypothesis_ids"):
                nudge = (
                    "Continue the investigation. Issue the next diagnostic tool call "
                    "with no accompanying text."
                )
            else:
                nudge = (
                    "Call complete_investigation(confidence=\"low\", "
                    "root_cause_summary=\"Investigation halted.\") now."
                )
            history.append(types.Content(role="user", parts=[types.Part(text=nudge)]))
            continue

        consecutive_empty = 0  # successful response — reset counter
        candidate = response.candidates[0]
        fc_parts  = [p for p in candidate.content.parts if p.function_call]
        txt_parts = [p for p in candidate.content.parts if hasattr(p, "text") and p.text]

        # Print any Brain reasoning text (present whether or not there are also function calls)
        for p in txt_parts:
            print(f"\n[Ghost Agent] {p.text.strip()}")

        # No function calls: text-only turn — offer to continue or finish
        if not fc_parts:
            history.append(candidate.content)
            save_session(state, session_file)

            total_text = " ".join(p.text for p in txt_parts).strip()
            has_active_work = (state.get("active_task_ids") or state.get("active_hypothesis_ids"))
            pending_tasks   = state.get("active_task_ids", [])

            # Trivial recovery artifact (e.g. "[recovering]"): auto-continue without
            # prompting the user.  Avoids a visible "hang" when the brain returns a
            # short text-only turn during a pending capture cycle.
            if has_active_work and len(total_text) < 200:
                if pending_tasks:
                    auto_nudge = (
                        f"Continue. Pending capture task(s): {', '.join(pending_tasks)}. "
                        f"Call check_task for each pending task now. "
                        f"Respond with only the function call — no text."
                    )
                else:
                    auto_nudge = (
                        "Continue the investigation. Issue the next diagnostic tool call now. "
                        "Respond with only the function call — no text."
                    )
                history.append(types.Content(role="user", parts=[types.Part(text=auto_nudge)]))
                continue

            # Meaningful reasoning text — ask user to continue or wrap up
            choice = input("\nContinue investigation? [C]ontinue / [D]one > ").strip().lower()
            if choice == "d":
                text_summary = total_text
                _generate_rca(
                    state,
                    {"confidence": "medium", "root_cause_summary": text_summary, "recommended_actions": []},
                    shell, session_file,
                )
                _offer_cleanup_before_rca(state, orchestrator, session_file)
                return
            # Auto-inject a continuation nudge — no second input() to avoid HITL buffer contamination
            if pending_tasks:
                auto_nudge = (
                    f"Continue. Pending task(s): {', '.join(pending_tasks)}. "
                    f"Call check_task for each pending task now."
                )
            else:
                auto_nudge = "Continue the investigation. Issue the next tool call now."
            history.append(types.Content(role="user", parts=[types.Part(text=auto_nudge)]))
            continue

        # Append model turn, then dispatch all function calls
        history.append(candidate.content)
        response_parts = []

        for fc_part in fc_parts:
            tool_name = fc_part.function_call.name
            tool_args = dict(fc_part.function_call.args)

            # State mutation — manage_hypotheses writes directly to session state
            if tool_name == "manage_hypotheses":
                result = _handle_manage_hypotheses(tool_args, state)
                response_parts.append(types.Part(
                    function_response=types.FunctionResponse(name=tool_name, response=result)
                ))
                continue

            # Exit trigger — complete_investigation never calls shell or orchestrator
            if tool_name == "complete_investigation":
                save_session(state, session_file)
                _generate_rca(state, tool_args, shell, session_file)
                _offer_cleanup_before_rca(state, orchestrator, session_file)
                return

            result = _dispatch_tool(tool_name, tool_args, shell, orchestrator)

            # Track task IDs for capture operations; clear on explicit cleanup
            if tool_name == "capture_traffic":
                for tid in [result.get("task_id")] + [t.get("task_id") for t in result.get("tasks", [])]:
                    if tid and tid not in state["active_task_ids"]:
                        state["active_task_ids"].append(tid)
            elif tool_name == "cleanup_task":
                tid = tool_args.get("task_id") or result.get("task_id")
                if tid and tid in state.get("active_task_ids", []):
                    state["active_task_ids"].remove(tid)

            _apply_denial_detection(tool_name, tool_args, result, state)

            # Console status line
            action = result.get("action", "")
            status = result.get("status", "?")
            aid    = result.get("audit_id") or result.get("task_id", "")
            if action == "auto_approved":
                print(f"[Shell] SAFE — auto-approved: {tool_args.get('command','')[:60]}")
            elif status == "denied":
                print(f"[Shell] DENIED: {tool_args.get('command','')[:50]}")
            elif action in ("user_approved", "user_modified"):
                verb = "MODIFIED" if action == "user_modified" else "APPROVED"
                cmd  = result.get("modified_command") or tool_args.get("command", "")
                print(f"[Shell] {verb}: {cmd[:50]}")
            else:
                id_suffix = f" | id={aid}" if aid else ""
                print(f"[{tool_name}] status={status}{id_suffix}")

            response_parts.append(types.Part(
                function_response=types.FunctionResponse(name=tool_name, response=result)
            ))

        # Append all function responses as a single user turn
        history.append(types.Content(role="user", parts=response_parts))
        save_session(state, session_file)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Unified Ghost Agent CLI — AI network forensics investigator")
    parser.add_argument("--resume",             metavar="SESSION_ID", help="Resume a previous session by session_id")
    parser.add_argument("--model",              default=DEFAULT_MODEL,  help=f"Gemini model (default: {DEFAULT_MODEL})")
    parser.add_argument("--audit-dir",          default=DEFAULT_AUDIT_DIR, help=f"Shared audit directory (default: {DEFAULT_AUDIT_DIR})")
    parser.add_argument("--storage-auth-mode",  choices=["login", "key"], default="login",
                        help="Azure storage authentication mode (default: login)")
    parser.add_argument("--resource-group",     default="",  metavar="RG",
                        help="Default Azure resource group for this investigation")
    parser.add_argument("--location",           default="",  metavar="LOCATION",
                        help="Azure region (e.g. eastus) — required for Network Watcher operations")
    parser.add_argument("--storage-account",    default="",  metavar="SA",
                        help="Default Azure storage account for packet captures")
    parser.add_argument("--storage-container",  default="",  metavar="CONTAINER",
                        help="Default Azure storage container for packet captures")
    args = parser.parse_args()

    # Guard: GEMINI_API_KEY must be present before any sub-module is instantiated
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY is not set.")
        print("        Set it in your environment or add GEMINI_API_KEY=... to a .env file.")
        sys.exit(1)

    # Step 1-2: Load or create session
    if args.resume:
        state = _load_session(SESSION_FILE, args.resume)
        if state is None:          # User chose [F]resh after checksum/parse failure
            state = _new_session(args.model, args.audit_dir)
    else:
        state = _new_session(args.model, args.audit_dir)

    audit_dir = state["audit_dir"]
    sid       = state["session_id"]

    W = 56
    print("\n" + "═" * W)
    print(f"  UNIFIED GHOST AGENT  |  Session: {sid}")
    print("═" * W)

    # Step 3: Instantiate SafeExecShell.
    # On resume, count the max sequence already written so new audit_ids don't collide.
    starting_seq = _count_shell_sequences(audit_dir, sid) if state.get("is_resume") else 0
    shell = SafeExecShell(
        session_id        = sid,
        audit_dir         = audit_dir,
        hitl_callback     = terminal_hitl_callback,
        starting_sequence = starting_seq,
    )

    # Step 4: Instantiate CloudOrchestrator (_detect_orphans() runs inside __init__)
    orchestrator = CloudOrchestrator(
        shell              = shell,
        session_id         = sid,
        task_dir           = audit_dir,
        storage_auth_mode  = args.storage_auth_mode,
        **({"storage_container": args.storage_container} if args.storage_container else {}),
        **({"location": args.location} if args.location else {}),
    )

    # Steps 5-8: Orphan detection and optional cleanup
    print("\nChecking for orphaned resources from previous sessions...")
    orphan_report = orchestrator.orchestrate({"intent": "list_tasks"})
    buckets       = _classify_orphans(orphan_report, audit_dir)
    has_orphans   = _present_orphan_report(buckets)

    if has_orphans:
        _run_startup_cleanup(buckets, shell, orchestrator, state, SESSION_FILE,
                             location=args.location or "eastus")

    save_session(state, SESSION_FILE)

    # Step 9: Reconstruct history (resume) or start fresh
    if state.get("is_resume"):
        print(f"\nResuming session {sid} (turn {state['turn_count']})…")
        history = _reconstruct_history(
            audit_dir, sid, denial_reasons=state.get("denial_reasons", {})
        )
        # Ensure the history ends on a model turn before we append a user turn.
        # _reconstruct_history always ends on a user turn (function_response); inserting
        # a synthetic model acknowledgment here prevents consecutive-user-role 400 errors.
        if history and history[-1].role == "user":
            history.append(types.Content(
                role="model",
                parts=[types.Part(text="[Ghost Agent] Resuming investigation from prior session.")],
            ))
    else:
        history = []

    # Step 10: Accept user intent.
    # On resume, the [RESUME] context and user_intent are combined into one user turn
    # so there is never more than one consecutive user turn after the model bridge above.
    print("\nWhat network problem should I investigate?")
    print("(Multi-line OK — finish with an empty line)")
    lines = []
    while True:
        try:
            line = input("> " if not lines else "  ")
            if line == "" and lines:
                break
            if line:
                lines.append(line)
        except EOFError:
            break
    user_intent = " ".join(lines).strip()
    if not user_intent:
        print("[ERROR] No intent provided. Exiting.")
        sys.exit(1)

    if state.get("is_resume"):
        resume_ctx = (
            f"[RESUME] Session {sid} resumed (turn {state['turn_count']} prior). "
            f"Network state may have changed since interruption. "
            f"Re-run the 2-3 most critical diagnostic commands before continuing.\n\n"
            f"Continuing investigation: {user_intent}"
        )
        history.append(types.Content(role="user", parts=[types.Part(text=resume_ctx)]))
    else:
        history.append(types.Content(role="user", parts=[types.Part(text=user_intent)]))
    save_session(state, SESSION_FILE)

    # Build effective system prompt — append environment context if CLI args were provided
    env_lines = []
    if args.resource_group:
        env_lines.append(f"- Default resource group: {args.resource_group}")
    if args.location:
        env_lines.append(f"- Azure region / location: {args.location}")
    if args.storage_account:
        env_lines.append(f"- Default storage account for captures: {args.storage_account}")
    if args.storage_container:
        env_lines.append(f"- Default storage container for captures: {args.storage_container}")

    if env_lines:
        env_block = (
            "\n\nAZURE ENVIRONMENT (provided at startup — use these as defaults for all "
            "capture_traffic calls unless the user specifies otherwise):\n"
            + "\n".join(env_lines)
        )
        effective_prompt = SYSTEM_PROMPT + env_block
    else:
        effective_prompt = SYSTEM_PROMPT

    # Record investigation boundary — audit lines written before this point are startup
    # cleanup commands (orphan sentinel). Recorded here so _generate_rca can exclude them
    # from the Command Evidence table (which should show only investigation commands).
    state["investigation_audit_start_line"] = _count_shell_audit_lines(state["audit_dir"], sid)
    save_session(state, SESSION_FILE)

    # Begin Tool-Use Loop
    client      = genai.Client(api_key=api_key)
    ghost_tools = _build_ghost_tools()

    try:
        _run_loop(state, history, shell, orchestrator, ghost_tools, client, SESSION_FILE,
                  effective_system_prompt=effective_prompt)
    except KeyboardInterrupt:
        print(f"\n\n[Ghost Agent] Interrupted — saving session…")
        save_session(state, SESSION_FILE)
        print(f"Resume with: python ghost_agent.py --resume {sid}")
        sys.exit(0)


if __name__ == "__main__":
    main()
