# Test Plan: Unified Ghost Agent CLI (`ghost_agent.py`)

> **Scope:** `ghost_agent.py` only. Sub-modules (`SafeExecShell`, `CloudOrchestrator`, `pcap_forensics.py`) are mocked/stubbed.
> **Reference:** `design.md` (all section numbers below refer to it).

## Priority Legend

| Priority | Meaning |
|----------|---------|
| **MUST** | Core safety or correctness contract. Failure blocks release. |
| **GOOD** | Important feature behaviour. Failure is a significant defect. |
| **OK** | Nice-to-have or hard-to-automate. Failure is a minor defect. |
| **SKIP** | Out-of-scope, relies on real external systems, or explicitly omitted by design. |

---

## 1. Session State (§8)

| # | Test | Priority |
|---|------|----------|
| S1 | `save_session()` writes all required fields to `ghost_session.json` and recomputes `_checksum` | MUST |
| S2 | `_checksum` is a valid SHA-256 hex of JSON content excluding the checksum field itself (`sort_keys=True`) | MUST |
| S3 | Modifying any field after save causes checksum recomputation on next `save_session()` call | MUST |
| S4 | Loading an unmodified session file verifies the checksum without error | MUST |
| S5 | Loading a tampered session file (field changed, checksum stale) triggers the `[C]/[F]/[A]` prompt | MUST |
| S6 | `[A]bort` on checksum mismatch exits with code 1 | MUST |
| S7 | `[F]resh` on checksum mismatch discards loaded data and starts a clean session | GOOD |
| S8 | `[C]ontinue` on checksum mismatch proceeds without crash; integrity warning appears in RCA | GOOD |
| S9 | Session file missing `_checksum` loads without error (backward-compat: checksum absent = skip check) | GOOD |
| S10 | `ghost_session.json` never contains raw command output (Zero-Cache Rule) | MUST |
| S11 | `is_resume` is set to `True` when `--resume` flag is provided | MUST |
| S12 | `turn_count` increments and is persisted after every loop turn | GOOD |

---

## 2. Startup / Handshake (§3)

| # | Test | Priority |
|---|------|----------|
| H1 | `SafeExecShell` is instantiated before `CloudOrchestrator` | MUST |
| H2 | `CloudOrchestrator` is instantiated with the same `shell` instance as the CLI | MUST |
| H3 | Orphan report is fetched via `orchestrator.orchestrate({"intent": "list_tasks"})`, not via private methods | MUST |
| H4 | `abandoned_tasks` bucket: tasks with non-terminal state from prior `session_id` are identified | MUST |
| H5 | `needs_cleanup` bucket: tasks with `cleanup_status == "pending"` are identified | MUST |
| H6 | `partially_cleaned` bucket: tasks with `cleanup_status == "partial"` are identified by CLI-side scan (not by `_detect_orphans`) | MUST |
| H7 | `untracked_azure` and `stale_local_files` buckets are populated from orphan report | GOOD |
| H8 | Zero orphans → no cleanup prompt; "No orphaned resources found." printed | GOOD |
| H9 | `cleanup_task` is called for each orphan in `abandoned_tasks` and `needs_cleanup` | MUST |
| H10 | `cleanup_task` is re-attempted for each `partially_cleaned` orphan | MUST |
| H11 | If re-attempt of `partially_cleaned` still returns `cleanup_status == "partial"`, task ID is added to `manual_cleanup_pending` and a warning is printed | GOOD |
| H12 | Individual cleanup denials during startup are skipped; remaining orphans still processed | GOOD |
| H13 | `--resume`: checksum verified before session loaded (S4/S5 above apply here) | MUST |
| H14 | `--resume`: conversation history reconstructed from `shell_audit_{sid}.jsonl`, not from session state | MUST |
| H15 | New session: `session_id` matches pattern `ghost_{YYYYMMDD}_{HHMMSS}` | OK |

---

## 3. Tool Dispatch (§1, §4)

| # | Test | Priority |
|---|------|----------|
| D1 | `run_shell_cmd` tool call routes to `shell.execute({"command": ..., "reasoning": ...})` — no other path | MUST |
| D2 | `capture_traffic` routes to `orchestrator.orchestrate({"intent": "capture_traffic", ...})` | MUST |
| D3 | `check_task` routes to `orchestrator.orchestrate({"intent": "check_task", "task_id": ...})` | MUST |
| D4 | `cancel_task` routes to `orchestrator.orchestrate({"intent": "cancel_task", "task_id": ...})` | MUST |
| D5 | `cleanup_task` routes to `orchestrator.orchestrate({"intent": "cleanup_task", "task_id": ...})` | MUST |
| D6 | `complete_investigation` does NOT call shell or orchestrator; exits the loop immediately | MUST |
| D7 | Unknown tool name returns `{"status": "error", "error": "unknown_tool"}` without crash | GOOD |
| D8 | `subprocess` is never imported in `ghost_agent.py` (static import check) | MUST |
| D9 | `pcap_forensics` is never imported in `ghost_agent.py` (static import check) | MUST |
| D10 | Multiple `function_call` parts in one response are all dispatched before any response is appended | GOOD |
| D11 | `storage_auth_mode` is forwarded to orchestrator when provided in `capture_traffic` args | GOOD |
| D12 | `storage_auth_mode` defaults to `"login"` when omitted from `capture_traffic` args | GOOD |

---

## 4. Denial State Machine (§6)

| # | Test | Priority |
|---|------|----------|
| M1 | `denial_tracker[h_id]` increments on `status == "denied"` with `action == "user_denied"` | MUST |
| M2 | `_meta.denial_count = 1` and `_meta.pivot_instruction` injected on first denial | MUST |
| M3 | `_meta.denial_count = 2` and `_meta.approaching_threshold = true` injected on second denial | MUST |
| M4 | `_meta.denial_threshold_reached = true` injected when `denial_count >= 3` | MUST |
| M5 | Hypothesis marked UNVERIFIABLE and removed from `active_hypothesis_ids` at threshold | MUST |
| M6 | Successful tool result resets `consecutive_denial_counter` (not `denial_tracker`) for active hypotheses | MUST |
| M7 | Denial counter applies to all entries in `active_hypothesis_ids`, not just the first | GOOD |
| M8 | UNVERIFIABLE hypothesis is terminal — no further tool calls are attributed to it | GOOD |
| M9 | Denial reason captured from HITL callback and injected as `_meta.denial_reason` when non-empty | MUST |
| M10 | Denial event `{turn, command, denial_reason, audit_id}` appended to correct hypothesis's `denial_events` list | MUST |
| M11 | Empty denial reason (user pressed Enter) → `_meta.denial_reason` is absent from result | GOOD |

---

## 5. Tool-Use Loop Control (§4)

| # | Test | Priority |
|---|------|----------|
| L1 | Loop exits when `complete_investigation` tool is called | MUST |
| L2 | `save_session()` is called after every loop turn (before next Gemini call) | MUST |
| L3 | Function responses are appended as a `"user"` role turn in conversation history | MUST |
| L4 | Model response parts are appended as a `"model"` role turn before function responses | MUST |
| L5 | `finish_reason == "STOP"` with no function calls → print Brain text, offer `[C]/[D]` | GOOD |
| L6 | At `MAX_LOOP_TURNS = 50`: loop pauses, offers `[E]xtend 10 more turns / [G]enerate RCA` | GOOD |
| L7 | `[E]xtend` increments `MAX_LOOP_TURNS` by 10 and continues loop | OK |
| L8 | Conflict detection block records `evidence_conflicts` entry when Brain marks a hypothesis CONTRADICTED | GOOD |

---

## 6. RCA Generation (§7)

| # | Test | Priority |
|---|------|----------|
| R1 | `shell_audit_{sid}.jsonl` is opened read-only; no write attempted | MUST |
| R2 | `orchestrator_tasks_{sid}.jsonl` is opened read-only; no write attempted | MUST |
| R3 | Malformed JSONL lines are skipped without crash | GOOD |
| R4 | Task registry uses last-write-wins per `task_id` | MUST |
| R5 | Each audit record gets `_evidence_context` tag: `"LOCAL"` for `environment == "local"`, `"CLOUD"` for `environment == "azure"` | MUST |
| R6 | Forensic Consistency Check Pattern A fires when LOCAL probe fail + CLOUD nsg Allow both present | GOOD |
| R7 | Forensic Consistency Check Pattern B fires when task COMPLETED but `executive_summary_text == None` | GOOD |
| R8 | Phase 4 tries `_executive_summary.md` path before falling back to full `report_path` | GOOD |
| R9 | Phase 4 cat is called via `shell.execute()`, not direct file I/O | MUST |
| R10 | If Phase 4 cat is denied, `"Report content unavailable (cat denied)"` appears in RCA Capture Evidence | MUST |
| R11 | RCA Markdown contains: header, Hypotheses Log, Command Evidence (with Context column), Capture Evidence, Recommended Actions, Integrity Statement | MUST |
| R12 | Command Evidence table Context column shows `[LOCAL]` / `[CLOUD]` from `_evidence_context` tag | GOOD |
| R13 | RCA never reproduces raw command output (only `audit_id` references) | MUST |
| R14 | `ghost_session.json["rca_report_path"]` is set after successful write | MUST |
| R15 | RCA write failure (permission error) → report printed to stdout; `rca_report_path` set to `null` | GOOD |

---

## 7. Error Recovery (§9)

| # | Test | Priority |
|---|------|----------|
| E1 | `KeyboardInterrupt` triggers `save_session()` in `finally`; session file is valid JSON after interrupt | MUST |
| E2 | `GoogleAPIError` from Gemini call triggers `save_session()` and prints resume instructions | MUST |
| E3 | Missing `GEMINI_API_KEY` at startup exits with code 1 before instantiating any sub-module | MUST |
| E4 | `json.JSONDecodeError` on session load offers `[F]resh / [A]bort` (distinct from checksum mismatch) | GOOD |
| E5 | `FileNotFoundError` on audit JSONL during resume continues with empty history; session metadata preserved | GOOD |
| E6 | Shell timeout (`result["error"] == "timeout"`) injects `_meta.timeout = true` into function response | GOOD |
| E7 | `exit_code == 127` from `run_shell_cmd("python pcap_forensics.py ...")` is surfaced as `task_failed` context to Brain | OK |

---

## 8. Integration / End-to-End

| # | Test | Priority |
|---|------|----------|
| I1 | Happy path: mock Gemini returns `run_shell_cmd` → mock Shell returns SAFE auto-approve → loop continues | MUST |
| I2 | Denial path: mock Shell returns `status == "denied"` three times → hypothesis marked UNVERIFIABLE → `complete_investigation` called | MUST |
| I3 | Resume path: existing session + JSONL loaded → `is_resume = True` → Brain receives reconstructed history | MUST |
| I4 | Full RCA path: `complete_investigation` called → both JSONL files read → `ghost_rca_{sid}.md` written | MUST |
| I5 | Real Azure CLI / Network Watcher end-to-end | SKIP |
| I6 | Real Gemini API end-to-end (cost, quota, latency) | SKIP |
| I7 | Concurrent sessions racing on `ghost_session.json` | SKIP |

---

## 9. Static / Structural Checks

| # | Test | Priority |
|---|------|----------|
| T1 | `ghost_agent.py` imports: only `SafeExecShell`, `CloudOrchestrator`, `google.genai`, stdlib — no `subprocess`, no `pcap_forensics` | MUST |
| T2 | Six `FunctionDeclaration` schemas include all `required` fields per design §1 | GOOD |
| T3 | `capture_traffic` schema: `storage_auth_mode` has `enum: ["login", "key"]` | GOOD |
| T4 | `complete_investigation` schema: `contradicted_hypotheses` parameter present | GOOD |
| T5 | `ghost_session.json` schema validates: all required fields present, `_checksum` is a 64-char hex string | GOOD |
