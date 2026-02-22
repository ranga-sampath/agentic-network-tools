# Architecture: Unified Ghost Agent CLI

> **Status:** Design specification — no implementation code.
> **Scope:** `ghost_agent.py` and its integration with the three existing sub-modules.
> **AI Brain:** Gemini (`gemini-2.0-flash` / `gemini-2.5-pro`) via the `google-genai` SDK.

---

## 1. Design Decision Table

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **AI model** | Gemini via `google-genai` SDK | Consistent with both existing sub-modules (`ai_safety_demo.py` uses `gemini-2.0-flash`; `pcap_forensics.py` uses Gemini). Single SDK dependency across the project. |
| **Single-file CLI** | `ghost_agent.py` at root | Minimal surface area. All three sub-modules are imported; no new package hierarchy. The CLI is an integrator, not a framework. |
| **Session state format** | `ghost_session.json` (flat JSON) | Human-readable, crash-recoverable. Holds `audit_id` references only — never raw command output. Source-of-truth for resume after process kill. |
| **Audit-trail-as-truth** | Both JSONL files are the forensic record | `shell_audit_{sid}.jsonl` and `orchestrator_tasks_{sid}.jsonl` are append-only and written by the sub-modules. The CLI reads them; it never writes to them. The RCA generator reads from JSONL, not from session state. |
| **Import coupling rule** | CLI imports `SafeExecShell` and `CloudOrchestrator` only | `subprocess` is never imported in `ghost_agent.py`. All process execution is delegated to `SafeExecShell`. `pcap_forensics.py` is invoked as a subprocess via `shell.execute()`, never imported. |
| **HITL mechanism** | Terminal callback (same pattern as `ai_safety_demo.py`) | Blocks the main thread at the exact moment a RISKY command is intercepted. No async HITL queue. Keeps the safety contract synchronous and auditable. |
| **Denial tracking** | In-loop counter per hypothesis, stored in session state | Hypothesis exhaustion (≥3 denials) is detected in the loop, not inside Shell. Shell reports `status == "denied"` per call; the CLI accumulates the pattern. |
| **Session resume** | `--resume <session_id>` CLI flag | Reads `ghost_session.json`, reconstructs conversation history from JSONL audit records, and restarts the Tool-Use Loop with full context. |
| **Max loop turns** | `MAX_LOOP_TURNS = 50` | Prevents runaway API calls. At 50 turns the agent emits a warning and offers the user a choice to extend or conclude. |
| **pcap_forensics integration** | Invoked via `shell.execute("python pcap_forensics.py ...")` | The Forensic Engine is treated as a CLI tool by the Orchestrator, which already implements this pattern in `_run_pcap_engine()`. No direct import. |

---

## 2. System Boundary Diagram (ASCII)

```
╔══════════════════════════════════════════════════════════════════╗
║              UNIFIED GHOST AGENT CLI  (ghost_agent.py)          ║
║                                                                  ║
║   ┌─────────────────┐   ┌──────────────────┐   ┌─────────────┐ ║
║   │ Startup Handler │   │  Tool-Use Loop   │   │ RCA Report  │ ║
║   │                 │   │                  │   │ Generator   │ ║
║   │ • Load/create   │   │ • Gemini API     │   │             │ ║
║   │   session state │   │ • Tool dispatch  │   │ • Reads     │ ║
║   │ • Orphan report │   │ • Denial detect  │   │   both JSONL│ ║
║   │ • Bulk cleanup  │   │ • save_session() │   │ • Writes    │ ║
║   │   offer         │   │   every turn     │   │   RCA .md   │ ║
║   └────────┬────────┘   └────────┬─────────┘   └──────┬──────┘ ║
║            │                     │                     │        ║
╚════════════╪═════════════════════╪═════════════════════╪════════╝
             │  shell.execute()    │  shell.execute()    │  (read-only)
             │  orchestrator       │  orchestrator       │
             │  .orchestrate()     │  .orchestrate()     │
             ▼                     ▼                     ▼
   ╔══════════════════╗   ╔═══════════════════╗   ./audit/
   ║  SafeExecShell   ║   ║ CloudOrchestrator ║
   ║                  ║   ║                   ║
   ║ 4-stage pipeline ║   ║ Task lifecycle    ║
   ║ Classify → Gate  ║   ║ Orphan Sentinel   ║
   ║ → Execute        ║   ║ HITL-gated Azure  ║
   ║ → Process Output ║   ║ operations        ║
   ╚════════╤═════════╝   ╚═════════╤═════════╝
            │                       │
            │ (subprocess, internal)│ (shell.execute() calls)
            ▼                       ▼
        System commands         pcap_forensics.py
        az CLI, ping, dig,      (invoked as subprocess
        traceroute, ss, etc.     via shell.execute,
                                 never imported)
            │                       │
            ▼                       ▼
  shell_audit_{sid}.jsonl   orchestrator_tasks_{sid}.jsonl
  (append-only, JSONL)       (append-only, JSONL)
            │                       │
            └───────────────────────┘
                        │
                        ▼
               ghost_rca_{sid}.md
               (written by RCA generator)
```

**Key boundary rule:** `ghost_agent.py` never crosses below the dashed line into direct process execution. All commands flow through `shell.execute()`. All long-running Azure tasks flow through `orchestrator.orchestrate()`.

---

## 3. Component Inventory Table

| Component | File | Method Exposed to CLI | CLI May | CLI May Not |
|-----------|------|-----------------------|---------|-------------|
| **SafeExecShell** | `agentic-safety-shell/safe_exec_shell.py` | `shell.execute({"command": str, "reasoning": str}) → dict` | Read `status`, `output`, `audit_id`, `exit_code`, `error`, `classification` from response | Call private methods; bypass HITL; write to audit file; import `subprocess` |
| **CloudOrchestrator** | `agentic-cloud-orchestrator/cloud_orchestrator.py` | `orchestrator.orchestrate({"intent": str, ...}) → dict` | Call any of the 5 public intents; read `task_id`, `status`, `result`, `orphans` from response | Access `_detect_orphans()` directly; read `_task_dir` internals; modify task state |
| **PCAP Forensic Engine** | `agentic-pcap-forensic-engine/pcap_forensics.py` | None — invoked via `shell.execute("python pcap_forensics.py ...")` | Read `result["report_path"]` from completed orchestrator task; cat report file via `shell.execute` | Import `pcap_forensics` module directly; call any of its functions |
| **Gemini API** | `google-genai` SDK | `client.models.generate_content(model, config, contents)` | Send conversation history; define tools; read `function_call` parts | Use any other AI provider; store raw model output in session state |
| **Session State** | `ghost_session.json` (root) | `load_session()`, `save_session()` — CLI-internal | Read/write session file; store `audit_id` references | Store raw command output; store full JSONL records; decrypt audit files |
| **Audit JSONL Files** | `./audit/shell_audit_{sid}.jsonl`, `./audit/orchestrator_tasks_{sid}.jsonl` | Read-only (RCA generator) | Open for reading during RCA generation | Write, append, delete, or modify any audit record |

---

## 4. Data Flow Diagrams

### 4a. Startup Flow

```
ghost_agent.py --resume <sid>?
        │
        ├─ YES: Load ghost_session.json
        │         Reconstruct conversation history from audit JSONL
        │         Set is_resume = True in session state
        │         NOTE: Network state may have changed since the session was
        │         interrupted. The Brain is instructed (via system prompt Resume
        │         Re-Validation Protocol) to re-run critical discovery commands
        │         before continuing. See design.md §2 for the instruction text.
        │
        └─ NO:  Generate new session_id = "ghost_{YYYYMMDD}_{HHMMSS}"
                Create ghost_session.json with empty state
                │
                ▼
        Instantiate SafeExecShell(session_id, hitl_callback, audit_dir="./audit/")
                │
                ▼
        Instantiate CloudOrchestrator(shell, session_id, task_dir="./audit/")
          └── __init__ calls _detect_orphans() automatically
                │
                ▼
        orchestrator.orchestrate({"intent": "list_tasks"})
          └── Returns: {tasks: [...], orphans: [...]}
                │
                ▼
        Classify orphans into 5 buckets:
          • abandoned_tasks     — non-terminal from previous sessions
          • needs_cleanup       — COMPLETED/FAILED with cleanup_status == "pending"
          • partially_cleaned   — COMPLETED/FAILED with cleanup_status == "partial"
                                  (CLI-side scan; not detected by _detect_orphans())
          • untracked_azure     — ghost_* resources not in task registry
          • stale_local_files   — ghost_* local files older than 7 days
                │
                ▼
        Present orphan report to user
          └── If orphans exist: offer bulk cleanup
                │
                ├─ User accepts: execute cleanup
                │    └── Each deletion is RISKY → HITL gate activates per deletion
                │
                └─ User declines: skip cleanup, note in session state
                │
                ▼
        Accept natural-language user intent
                │
                ▼
        save_session() → BEGIN TOOL-USE LOOP
```

### 4b. Tool-Use Loop Flow

```
TOOL-USE LOOP (repeats until complete_investigation or MAX_LOOP_TURNS)
        │
        ▼
client.models.generate_content(
    model=GEMINI_MODEL,
    config=GenerateContentConfig(tools=[ghost_tools], system_instruction=SYSTEM_PROMPT),
    contents=conversation_history
)
        │
        ├─ finish_reason == "STOP", no function_call parts:
        │       Print Brain text to user
        │       Offer: [C]ontinue / [D]one
        │         ├─ Done: trigger RCA generation → exit
        │         └─ Continue: append user message, loop
        │
        └─ Response contains function_call parts:
                │
                ▼
        For each function_call in response:
          Dispatch to:
            ├─ run_shell_cmd      → shell.execute(command, reasoning)
            ├─ capture_traffic    → orchestrator.orchestrate({intent: "capture_traffic", ...})
            ├─ check_task         → orchestrator.orchestrate({intent: "check_task", task_id})
            ├─ cancel_task        → orchestrator.orchestrate({intent: "cancel_task", task_id})
            ├─ cleanup_task       → orchestrator.orchestrate({intent: "cleanup_task", task_id})
            └─ complete_investigation → EXIT LOOP → RCA GENERATION
                │
                ▼
        Collect all tool results as function_response parts
                │
                ▼
        DENIAL DETECTION:
          For each result:
            if result["status"] == "denied" or result["status"] == "task_cancelled":
              denial_tracker[active_hypothesis_id] += 1
              Inject _meta.denial_count into function_response
              If denial_tracker[h] >= MAX_DENIALS_PER_HYPOTHESIS (3):
                Inject _meta.denial_threshold_reached = true
                Mark hypothesis as UNVERIFIABLE in session state
                │
        ▼
        Append function_response parts as a "user" role turn in conversation_history
        save_session()
        Loop
```

### 4c. Audit Trail Flow (RCA Generation)

```
RCA GENERATION TRIGGERED (complete_investigation called or user chooses Done)
        │
        ▼
Read ./audit/shell_audit_{sid}.jsonl (line by line)
  └── Classify each record by status:
        • completed   → evidence commands
        • denied      → blocked hypotheses
        • forbidden   → hard-blocked commands
        • error       → failed attempts
        (The "action" field distinguishes auto_approved / user_approved / user_denied)
        │
        ▼
Read ./audit/orchestrator_tasks_{sid}.jsonl (line by line)
  └── Build {task_id → latest_record} dict (last-write-wins per task_id)
        │
        ▼
Extract artifact paths from completed tasks:
  • result.report_path  → forensic report markdown
  • result.local_pcap_path → evidence capture file
        │
        ▼
cat forensic report (Executive Summary only) via shell.execute()
        │
        ▼
Build ghost_rca_{sid}.md:
  • Header: session_id, timestamp, investigation summary
  • Hypotheses log: each hypothesis with final state
  • Command evidence table: audit_id | command | outcome
  • Capture evidence: task_id | target | report_path
  • Integrity statement: "All evidence cited by audit_id from append-only JSONL"
        │
        ▼
Write ./audit/ghost_rca_{sid}.md
Update ghost_session.json["rca_report_path"]
```

---

## 5. Safety Constraint Enforcement Architecture

Six independent layers enforce the safety boundary. Each layer is designed so that the failure or bypass of any one layer is caught by the next.

| Layer | Name | Mechanism | Where Enforced |
|-------|------|-----------|----------------|
| **1** | Import Boundary | `ghost_agent.py` never imports `subprocess`. All process execution is delegated exclusively to `SafeExecShell`. `pcap_forensics.py` is invoked via `shell.execute()`, not as a Python module. | CLI design rule; enforced by code review and linting |
| **2** | Tool Schema Contract | The six Gemini function declarations map 1:1 to either `shell.execute()` or `orchestrator.orchestrate()`. No tool declaration bypasses this mapping. The Brain cannot construct arbitrary shell calls — it must use the declared tool interface. | Tool-Use Loop dispatch logic in `ghost_agent.py` |
| **3** | Shell Classification Pipeline | The 4-tier pipeline (Tier 0 FORBIDDEN → Tier 1 Allowlist → Tier 2 Azure Verb → Tier 3 Dangerous Patterns) gates every command before execution. FORBIDDEN commands are unconditionally blocked. RISKY commands require explicit HITL approval. | `SafeExecShell.execute()` in `safe_exec_shell.py` (unmodified) |
| **4** | Denial Detection | After each tool dispatch block, the loop inspects `result["status"]`. If `"denied"`, the denial counter for the active hypothesis is incremented. At count ≥ 3, the hypothesis is marked UNVERIFIABLE and `_meta.denial_threshold_reached = true` is injected into the tool response, signalling the Brain to call `complete_investigation`. | Tool-Use Loop in `ghost_agent.py` |
| **5** | Audit Trail Immutability | The CLI opens `shell_audit_{sid}.jsonl` and `orchestrator_tasks_{sid}.jsonl` in read-only mode during RCA generation. It never opens them for writing. The sub-modules write to these files; the CLI only reads. | `ghost_agent.py` file access mode; the sub-modules own their own writes |
| **6** | Zero-Cache Rule | Session state (`ghost_session.json`) stores only `audit_id` references, task IDs, and hypothesis metadata. Raw command output and full JSONL records are never stored in session state. The JSONL files are the authoritative record; session state is an index. | `save_session()` implementation discipline in `ghost_agent.py` |

**Design note on Layer 3 and output truncation.** The Shell applies format-aware truncation before output reaches the Brain (200-line limit, ~4,000-token estimate). This is a deliberate safety boundary, not a limitation to circumvent. When the Brain suspects the answer is buried in truncated output, the correct response is to issue a more targeted command using Azure CLI `--query` JMESPath filters — narrowing the result set at the source rather than requesting more of the same output. Storing raw untruncated output to support a pagination or search-in-output capability would violate the Zero-Cache Rule (Layer 6). The Brain's strategy for large outputs is always a better question, not more of the same answer. See the Targeted Query Rule in design.md §2.

---

## 6. Session State Model (ghost_session.json)

The session file provides crash-resume capability. It contains lightweight index data — not raw outputs.

### What Persists Between Turns

| Field | Type | Description | Survives Crash? |
|-------|------|-------------|----------------|
| `session_id` | string | Unique identifier: `ghost_{YYYYMMDD}_{HHMMSS}` | Yes |
| `created_at` | ISO-8601 string | Session creation timestamp | Yes |
| `resumed_from` | string or null | `session_id` of the session this resumed, if any | Yes |
| `model` | string | Gemini model name used in this session | Yes |
| `hypothesis_log` | array of objects | Each hypothesis: `{id, description, state, denial_count}` | Yes |
| `denial_tracker` | object | `{hypothesis_id: int}` — cumulative denial counts, keyed per hypothesis | Yes |
| `active_hypothesis_ids` | array of strings | Currently active hypotheses (up to 3 simultaneously); Brain removes an ID when that hypothesis reaches a terminal state | Yes |
| `active_task_ids` | array of strings | Orchestrator task IDs created this session | Yes |
| `turn_count` | integer | Total tool-use loop turns completed | Yes |
| `rca_report_path` | string or null | Path to generated RCA report, once available | Yes |
| `audit_dir` | string | Path to audit directory (default: `"./audit/"`) | Yes |

### What Is Reconstructed from JSONL on Resume

| Reconstructed Data | Source |
|-------------------|--------|
| Conversation history for Gemini | `shell_audit_{sid}.jsonl` — command, reasoning, outcome per turn |
| Task lifecycle state | `orchestrator_tasks_{sid}.jsonl` — last record per task_id |
| Evidence artifact paths | `orchestrator_tasks_{sid}.jsonl` — `report_path`, `local_pcap_path` fields |

### Why This Design

The Zero-Cache Rule (Layer 6) ensures that raw outputs never inflate `ghost_session.json`. A 200-line `az nsg list` output is referenced by `audit_id = "ghost_20250115_143022_007"`, not stored inline. This keeps the session file small, human-readable, and safe to inspect without exposing sensitive network data.

---

## 7. Integration Coupling Rules Table

| From | To | Direction | Mechanism | Constraints |
|------|----|-----------|-----------|-------------|
| `ghost_agent.py` | `SafeExecShell` | Outbound (call) | `shell.execute({"command": str, "reasoning": str})` | Must provide `reasoning` field; must not call private methods |
| `ghost_agent.py` | `CloudOrchestrator` | Outbound (call) | `orchestrator.orchestrate({"intent": str, ...})` | Must use one of the 5 declared intents; must not access `_task_dir` directly |
| `ghost_agent.py` | `ghost_session.json` | Read/Write | `json.load()` / `json.dump()` | Write on every loop turn; never store raw command output |
| `ghost_agent.py` | `shell_audit_{sid}.jsonl` | Read-only | Open for reading during RCA generation only | Must not open for append or write |
| `ghost_agent.py` | `orchestrator_tasks_{sid}.jsonl` | Read-only | Open for reading during RCA generation only | Must not open for append or write |
| `ghost_agent.py` | Gemini API | Outbound (call) | `client.models.generate_content(...)` | All tool declarations must map to shell or orchestrator; no other AI API |
| `CloudOrchestrator` | `SafeExecShell` | Outbound (call) | `shell.execute(...)` (same shell instance as CLI) | Orchestrator shares the CLI's shell instance; HITL callback applies to orchestrator calls too |
| `CloudOrchestrator` | `pcap_forensics.py` | Outbound (subprocess via Shell) | `shell.execute("python pcap_forensics.py ...")` | `pcap_forensics.py` is in `agentic-pcap-forensic-engine/`; orchestrator never imports it |
| `SafeExecShell` | System commands | Outbound (subprocess) | `subprocess.run(...)` with `shell=False` | Internal to Shell; CLI is never aware of subprocess |
| `SafeExecShell` | `shell_audit_{sid}.jsonl` | Write (append-only) | `json.dumps(record) + "\n"` appended on every `execute()` call | Shell owns this file; CLI must not write to it |
| `CloudOrchestrator` | `orchestrator_tasks_{sid}.jsonl` | Write (append-only) | `json.dumps(task) + "\n"` appended on every `_save_task()` call | Orchestrator owns this file; CLI must not write to it |

---

## 8. Intentional Omissions

The following capabilities were explicitly excluded from the design. Each exclusion is a deliberate constraint, not a gap.

| Omitted Feature | Why Excluded |
|-----------------|--------------|
| **Background threads / async execution** | The Tool-Use Loop is intentionally synchronous. HITL prompts block the main thread by design — an async queue would allow commands to execute before the user has responded. Burst-polling inside `CloudOrchestrator._burst_poll()` is the only blocking wait, and it is bounded by `poll_burst_limit` (45 seconds). |
| **Direct `subprocess` import in CLI** | All process execution must flow through `SafeExecShell` to guarantee the 4-tier classification pipeline fires. A direct subprocess call would bypass Tier 0–3 and the HITL gate. |
| **AI-based command classification** | Classification uses deterministic regex and allowlists (Tiers 0–3 in `safe_exec_shell.py`). Adding an AI classifier would introduce non-determinism, latency, and cost into the safety path. The safety gate must be predictable and auditable. |
| **Concurrent sessions** | `ghost_session.json` is a single file at the project root. Multiple concurrent sessions would race on this file and on the audit JSONL files. Session isolation requires a session-per-directory model, which is out of scope for the initial CLI. |
| **Direct write to audit JSONL files from CLI** | The CLI is a consumer of the audit trail, not a producer. Writing to the audit files from multiple code paths would corrupt the append-only contract and make the forensic record unreliable. |
| **In-memory output caching** | Raw command outputs are returned to the Brain as function_response parts in the conversation history managed by the Gemini SDK. The CLI does not cache outputs between turns. The Zero-Cache Rule prevents session state inflation and accidental exposure of sensitive data across sessions. |
| **Gemini streaming** | Streaming responses complicate tool-call detection. The CLI uses non-streaming `generate_content()` calls where the complete response (including all function_call parts) is available atomically before dispatch. |
| **Pagination / output search tool** | A `search_output` or `paginate_output` tool would require the CLI to cache raw, untruncated command output so the Brain can request additional pages. This directly violates the Zero-Cache Rule (Layer 6) — cached output inflates session state and can expose sensitive data across sessions. The correct response to truncation is a more targeted command (e.g., `az nsg rule list --query "[?destinationPortRange=='443']"`), not more of the same output. |
| **Burst-poll interrupt / signal handling** | The synchronous burst-poll window (`poll_burst_limit` = 45 seconds) blocks the main thread while the Orchestrator sleeps between Azure status checks. A SIGINT-based interrupt mechanism would require either (a) modifying `CloudOrchestrator._burst_poll()` — a module marked UNCHANGED — to be interruptible at sleep boundaries, or (b) introducing background threads, which are excluded for HITL safety reasons. The 45-second ceiling is an acceptable bound for a human-in-the-loop forensics tool. Signal-based interrupt and non-blocking poll patterns are deferred to a future async refactor when the HITL mechanism is redesigned for concurrent operation. |
| **Post-session audit log scrubbing** | Retroactively modifying `shell_audit_{sid}.jsonl` or `orchestrator_tasks_{sid}.jsonl` to remove sensitive data would violate Audit Trail Immutability (Layer 5). If those files can be edited after the fact, the evidentiary chain breaks and the RCA integrity statement becomes false. The correct mitigation for redaction failures is to improve the regex coverage in `SafeExecShell` before commands execute (a sub-module concern), and to restrict audit directory permissions to mode 700. The audit files are a forensic record, not a configurable output. |
