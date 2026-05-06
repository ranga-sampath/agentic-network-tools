# Architecture: Unified Ghost Agent CLI

> **Scope:** `ghost_agent.py`, `llm_adapter.py`, and integration with the three existing sub-modules.
> **AI Brain:** Pluggable via `llm_adapter.py` — Gemini (`gemini-2.0-flash`) by default; Anthropic Claude supported via `--llm-provider anthropic`.

---

## 1. Design Decision Table

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **AI Brain abstraction** | `llm_adapter.py` — pluggable provider adapter | The core reasoning loop (`_run_loop`) must have zero dependency on any LLM SDK's native types. Adding a new provider requires only a new adapter class; no changes to the loop or tool dispatch logic. |
| **LLM provider flag** | `--llm-provider {gemini,anthropic}` (default: `gemini`) | Distinct from `--provider` in `providers.py` (which is cloud infrastructure). Hyphenated per CLI convention; Python sees it as `args.llm_provider`. |
| **Internal history format** | Neutral Python dicts — no SDK type in the core loop | `_run_loop` constructs and appends history using plain dicts. Each adapter converts this neutral format to its provider-native wire format on every call, and converts the response back. `_reconstruct_history` also returns neutral dicts. This is the boundary: below `llm_adapter.py`, formats are provider-specific; above it, they are not. |
| **Default AI model** | `gemini-2.0-flash` | Consistent with both existing sub-modules (`ai_safety_demo.py` uses `gemini-2.0-flash`; `pcap_forensics.py` uses Gemini). |
| **Single-file CLI** | `ghost_agent.py` at root | Minimal surface area. All three sub-modules are imported; no new package hierarchy. The CLI is an integrator, not a framework. |
| **Session state format** | `ghost_session.json` (flat JSON) | Human-readable, crash-recoverable. Holds `audit_id` references only — never raw command output. Source-of-truth for resume after process kill. |
| **Audit-trail-as-truth** | Both JSONL files are the forensic record | `shell_audit_{sid}.jsonl` and `orchestrator_tasks_{sid}.jsonl` are append-only and written by the sub-modules. The CLI reads them; it never writes to them. The RCA generator reads from JSONL, not from session state. |
| **Import coupling rule** | `ghost_agent.py` imports `SafeExecShell`, `CloudOrchestrator`, and `create_adapter` — nothing else | `subprocess` is never imported in `ghost_agent.py`. All process execution is delegated to `SafeExecShell`. All LLM API calls are delegated to `llm_adapter.py`. `pcap_forensics.py` is invoked as a subprocess via `shell.execute()`, never imported. No LLM SDK types (`google.genai`, `anthropic`) appear in `ghost_agent.py`. |
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
║   │ • Load/create   │   │ • LLM Adapter    │   │             │ ║
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

**LLM API boundary (not shown above):** The Tool-Use Loop makes one additional outbound call per turn through `llm_adapter.py`, which reaches the Gemini or Anthropic API over HTTPS. This path is omitted from the ASCII diagram to preserve readability; see §7 Integration Coupling Rules for the complete call graph including `llm_adapter.py`.

---

## 3. Component Inventory Table

| Component | File | Method Exposed to CLI | CLI May | CLI May Not |
|-----------|------|-----------------------|---------|-------------|
| **SafeExecShell** | `agentic-safety-shell/safe_exec_shell.py` | `shell.execute({"command": str, "reasoning": str}) → dict` | Read `status`, `output`, `audit_id`, `exit_code`, `error`, `classification` from response | Call private methods; bypass HITL; write to audit file; import `subprocess` |
| **CloudOrchestrator** | `agentic-cloud-orchestrator/cloud_orchestrator.py` | `orchestrator.orchestrate({"intent": str, ...}) → dict` | Call any of the 5 public intents; read `task_id`, `status`, `result`, `orphans` from response | Access `_detect_orphans()` directly; read `_task_dir` internals; modify task state |
| **PCAP Forensic Engine** | `agentic-pcap-forensic-engine/pcap_forensics.py` | None — invoked via `shell.execute("python pcap_forensics.py ...")` | Read `result["report_path"]` from completed orchestrator task; cat report file via `shell.execute` | Import `pcap_forensics` module directly; call any of its functions |
| **Netfilter Inspector** | `netfilter-inspector/firewall-inspector/firewall_inspector.py` | None — invoked via `subprocess.run(["python", "firewall_inspector.py", ...])` in `_run_firewall_inspector_handler()` | Read `*_snapshot.json` and `*_drift.json` artifacts from `audit_dir`; return structured summary to Brain | Import the module directly; modify firewall rules; write to audit JSONL files |
| **LLM Adapter** | `llm_adapter.py` (new) | `adapter.generate(history, tools, system_prompt)` → normalized response; `adapter.convert_tools(tool_specs)` → provider-native schema | Call `generate()` with neutral-format history; call `convert_tools(GHOST_TOOL_SPECS)` at startup; read `tool_calls` and `text` from normalized response | Bypass the adapter to call a provider SDK directly; import `google.genai` or `anthropic` in `ghost_agent.py` |
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
adapter.generate(
    history       = conversation_history,   // neutral dict list
    tools         = native_tools,           // provider-native schema from adapter.convert_tools()
    system_prompt = effective_system_prompt
)
        │
        ├─ response.is_empty (provider returned blocked/empty response):
        │       Inject recovery nudge into conversation_history
        │       Increment consecutive_empty counter
        │       If consecutive_empty >= 3: save_session(), exit with error
        │       Loop
        │
        ├─ response.tool_calls is empty (text-only turn):
        │       Print response.text to user
        │       Offer: [C]ontinue / [D]one
        │         ├─ Done: trigger RCA generation → exit
        │         └─ Continue: append model text + nudge to conversation_history, loop
        │
        └─ response.tool_calls is non-empty:
                │
                ▼
        Append model turn to conversation_history as neutral dict
        (role="model", text, tool_calls=[{id, name, args}])
                │
                ▼
        For each tool_call in response.tool_calls:
          Dispatch to:
            ├─ run_shell_cmd      → shell.execute(command, reasoning)
            ├─ capture_traffic    → orchestrator.orchestrate({intent: "capture_traffic", ...})
            ├─ check_task         → orchestrator.orchestrate({intent: "check_task", task_id})
            ├─ cancel_task        → orchestrator.orchestrate({intent: "cancel_task", task_id})
            ├─ cleanup_task       → orchestrator.orchestrate({intent: "cleanup_task", task_id})
            └─ complete_investigation → EXIT LOOP → RCA GENERATION
                │
                ▼
        Collect all tool results (echoing tool_call_id → tool_result id)
                │
                ▼
        DENIAL DETECTION:
          For each result:
            if result["status"] == "denied" or result["status"] == "task_cancelled":
              denial_tracker[active_hypothesis_id] += 1
              Inject _meta.denial_count into tool result output
              If denial_tracker[h] >= MAX_DENIALS_PER_HYPOTHESIS (3):
                Inject _meta.denial_threshold_reached = true
                Mark hypothesis as UNVERIFIABLE in session state
                │
        ▼
        Append tool_results turn to conversation_history as neutral dict
        (role="tool_results", results=[{id, name, output}])
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
| **2** | Tool Schema Contract | The eight function declarations map 1:1 to either `shell.execute()`, `orchestrator.orchestrate()`, or a named subprocess handler. No tool declaration bypasses this mapping. The Brain cannot construct arbitrary shell calls — it must use the declared tool interface. The adapter converts the schema to the provider-native format, but the logical tool set is provider-invariant. | Tool-Use Loop dispatch logic in `ghost_agent.py`; schema conversion in `llm_adapter.py` |
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
| `llm_provider` | string | LLM provider used (`gemini` or `anthropic`) | Yes |
| `model` | string | Model name within the provider (e.g. `gemini-2.0-flash`, `claude-3-5-haiku-20251001`) | Yes |
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
| Conversation history (neutral dict format) | `shell_audit_{sid}.jsonl` — command, reasoning, outcome per turn |
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
| `ghost_agent.py` | `llm_adapter.py` | Outbound (call) | `create_adapter(provider, api_key, model)` at startup; `adapter.generate(history, tools, system_prompt)` each turn; `adapter.convert_tools(GHOST_TOOL_SPECS)` at startup | Call only these three adapter functions; never import provider SDKs directly in `ghost_agent.py` |
| `llm_adapter.py` | Gemini API | Outbound (call) | `genai.Client.models.generate_content(model, config, contents)` | Gemini adapter only; invoked when `--llm-provider gemini` |
| `llm_adapter.py` | Anthropic API | Outbound (call) | `anthropic.Anthropic.messages.create(model, messages, tools, system, max_tokens)` | Anthropic adapter only; invoked when `--llm-provider anthropic` |
| `CloudOrchestrator` | `SafeExecShell` | Outbound (call) | `shell.execute(...)` (same shell instance as CLI) | Orchestrator shares the CLI's shell instance; HITL callback applies to orchestrator calls too |
| `CloudOrchestrator` | `pcap_forensics.py` | Outbound (subprocess via Shell) | `shell.execute("python pcap_forensics.py ...")` | `pcap_forensics.py` is in `agentic-pcap-forensic-engine/`; orchestrator never imports it |
| `ghost_agent.py` | `firewall_inspector.py` | Outbound (direct subprocess) | `subprocess.run([sys.executable, "firewall_inspector.py", "--config", ...])` in `_run_firewall_inspector_handler()` | All operations are read-only (SAFE); no HITL gate required; handler writes a temp config file and deletes it after subprocess completes; reads `*_snapshot.json` / `*_drift.json` from `audit_dir` |
| `SafeExecShell` | System commands | Outbound (subprocess) | `subprocess.run(...)` with `shell=False` | Internal to Shell; CLI is never aware of subprocess |
| `SafeExecShell` | `shell_audit_{sid}.jsonl` | Write (append-only) | `json.dumps(record) + "\n"` appended on every `execute()` call | Shell owns this file; CLI must not write to it |
| `CloudOrchestrator` | `orchestrator_tasks_{sid}.jsonl` | Write (append-only) | `json.dumps(task) + "\n"` appended on every `_save_task()` call | Orchestrator owns this file; CLI must not write to it |

---

## 8. Intentional Omissions

The following capabilities were explicitly excluded from the design. Each exclusion is a deliberate constraint, not a gap.

| Omitted Feature | Why Excluded |
|-----------------|--------------|
| **Background threads / async execution** | The Tool-Use Loop is intentionally synchronous. HITL prompts block the main thread by design — an async queue would allow commands to execute before the user has responded. Burst-polling inside `CloudOrchestrator._burst_poll()` is the only blocking wait, and it is bounded by `poll_burst_limit` (45 seconds). |
| **Direct `subprocess` for interactive or mutative commands** | Commands that may require HITL approval (shell commands dispatched by the Brain, az CLI calls, packet capture operations) must flow through `SafeExecShell` to guarantee the 4-tier classification pipeline fires. Direct subprocess is permitted exclusively for known-safe, read-only external tool invocations (`_run_pipe_meter_handler`, `_run_firewall_inspector_handler`) whose operations are SAFE-classified and produce no side effects on infrastructure. These handlers are explicitly named; no new direct subprocess path may be added without a corresponding architecture entry. |
| **AI-based command classification** | Classification uses deterministic regex and allowlists (Tiers 0–3 in `safe_exec_shell.py`). Adding an AI classifier would introduce non-determinism, latency, and cost into the safety path. The safety gate must be predictable and auditable. |
| **Concurrent sessions** | `ghost_session.json` is a single file at the project root. Multiple concurrent sessions would race on this file and on the audit JSONL files. Session isolation requires a session-per-directory model, which is out of scope for the initial CLI. |
| **Direct write to audit JSONL files from CLI** | The CLI is a consumer of the audit trail, not a producer. Writing to the audit files from multiple code paths would corrupt the append-only contract and make the forensic record unreliable. |
| **In-memory output caching** | Raw command outputs are returned to the Brain as `tool_results` entries in the neutral history format. The CLI does not cache outputs between turns. The Zero-Cache Rule prevents session state inflation and accidental exposure of sensitive data across sessions. |
| **Streaming LLM responses** | Streaming complicates tool-call detection for all providers. The adapter uses non-streaming calls where the complete response (including all tool_call parts) is available atomically before dispatch. This applies to both Gemini (`generate_content`) and Anthropic (`messages.create`). |
| **Pagination / output search tool** | A `search_output` or `paginate_output` tool would require the CLI to cache raw, untruncated command output so the Brain can request additional pages. This directly violates the Zero-Cache Rule (Layer 6) — cached output inflates session state and can expose sensitive data across sessions. The correct response to truncation is a more targeted command (e.g., `az nsg rule list --query "[?destinationPortRange=='443']"`), not more of the same output. |
| **Burst-poll interrupt / signal handling** | The synchronous burst-poll window (`poll_burst_limit` = 45 seconds) blocks the main thread while the Orchestrator sleeps between Azure status checks. A SIGINT-based interrupt mechanism would require either (a) modifying `CloudOrchestrator._burst_poll()` — a module marked UNCHANGED — to be interruptible at sleep boundaries, or (b) introducing background threads, which are excluded for HITL safety reasons. The 45-second ceiling is an acceptable bound for a human-in-the-loop forensics tool. Signal-based interrupt and non-blocking poll patterns are deferred to a future async refactor when the HITL mechanism is redesigned for concurrent operation. |
| **Post-session audit log scrubbing** | Retroactively modifying `shell_audit_{sid}.jsonl` or `orchestrator_tasks_{sid}.jsonl` to remove sensitive data would violate Audit Trail Immutability (Layer 5). If those files can be edited after the fact, the evidentiary chain breaks and the RCA integrity statement becomes false. The correct mitigation for redaction failures is to improve the regex coverage in `SafeExecShell` before commands execute (a sub-module concern), and to restrict audit directory permissions to mode 700. The audit files are a forensic record, not a configurable output. |
