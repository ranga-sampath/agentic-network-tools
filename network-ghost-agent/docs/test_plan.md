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
| D10 | Multiple `tool_calls` in one normalized response are all dispatched before any turn is appended to history | GOOD |
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
| L2 | `save_session()` is called after every loop turn (before next `adapter.generate()` call) | MUST |
| L3 | Tool results are appended as `{"role": "tool_results", "results": [...]}` — a neutral dict turn, not a `"user"` role turn | MUST |
| L4 | Model response is appended as `{"role": "model", "text": ..., "tool_calls": [...]}` neutral dict before the tool_results turn | MUST |
| L5 | `response.tool_calls == []` and `response.is_empty == False` → Brain text printed, `[C]ontinue / [D]one` offered; loop does not exit silently | GOOD |
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
| E2 | LLM API error from `adapter.generate()` — `GoogleAPIError` (Gemini) or `anthropic.APIError` (Anthropic) — triggers `save_session()` and prints resume instructions; verified for both providers | MUST |
| E3 | Missing `GEMINI_API_KEY` when `--llm-provider gemini` (or default): exit code 1 before any sub-module is instantiated | MUST |
| E3b | Missing `ANTHROPIC_API_KEY` when `--llm-provider anthropic`: exit code 1 before any sub-module is instantiated | MUST |
| E4 | `json.JSONDecodeError` on session load offers `[F]resh / [A]bort` (distinct from checksum mismatch) | GOOD |
| E5 | `FileNotFoundError` on audit JSONL during resume continues with empty history; session metadata preserved | GOOD |
| E6 | Shell timeout (`result["error"] == "timeout"`) injects `_meta.timeout = true` into function response | GOOD |
| E7 | `exit_code == 127` from `run_shell_cmd("python pcap_forensics.py ...")` is surfaced as `task_failed` context to Brain | OK |

---

## 8. Integration / End-to-End

| # | Test | Priority |
|---|------|----------|
| I1 | Gemini happy path: mock Gemini SDK returns `run_shell_cmd` tool call → `GeminiAdapter` normalizes → loop dispatches → mock Shell returns SAFE auto-approve → neutral dict history updated correctly | MUST |
| I1b | Anthropic happy path: mock Anthropic SDK returns `tool_use` block → `AnthropicAdapter` normalizes → loop dispatches → mock Shell returns SAFE auto-approve → neutral dict history updated correctly | MUST |
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
| T1 | `ghost_agent.py` imports: only `SafeExecShell`, `CloudOrchestrator`, `create_adapter` (from `llm_adapter`), stdlib — `google.genai`, `google.genai.types`, and `anthropic` must NOT appear | MUST |
| T2 | `GHOST_TOOL_SPECS` in `ghost_agent.py` is a plain `list[dict]` — all 8 tool specs present; no `genai.types` objects appear in the list | MUST |
| T3 | `capture_traffic` spec in `GHOST_TOOL_SPECS`: `storage_auth_mode` has `enum: ["login", "key"]` | GOOD |
| T4 | `complete_investigation` spec in `GHOST_TOOL_SPECS`: `contradicted_hypotheses` parameter present | GOOD |
| T5 | `ghost_session.json` schema validates: all required fields present including `llm_provider`; `_checksum` is a 64-char hex string | GOOD |

---

## 10. LLM Adapter — Factory and CLI Flags (§12, architecture §1)

| # | Test | Priority |
|---|------|----------|
| A1 | `create_adapter("gemini", api_key, model)` returns a `GeminiAdapter` instance | MUST |
| A2 | `create_adapter("anthropic", api_key, model)` returns an `AnthropicAdapter` instance | MUST |
| A3 | `create_adapter` with an unsupported provider string raises `ValueError` — default-deny, not silent permit | MUST |
| A4 | `--llm-provider gemini` (explicit): `type(adapter) is GeminiAdapter`; mock SDK asserted called with `api_key` == value read from `config.env`, not from environment | MUST |
| A5 | `--llm-provider anthropic`: `AnthropicAdapter` instantiated; `ANTHROPIC_API_KEY` resolved from env or config.env | MUST |
| A6 | `--llm-provider` absent: `args.llm_provider == "gemini"`; `type(adapter) is GeminiAdapter`; `GEMINI_API_KEY` used | MUST |
| A7 | `ANTHROPIC_API_KEY` loaded from `config.env` when absent from environment — same resolution path as `GEMINI_API_KEY` | GOOD |
| A8 | `llm_provider` field written to `ghost_session.json` by `save_session()` for both providers | MUST |
| A9 | Session file without `llm_provider` field loads without error (backward compatibility with pre-adapter sessions) | GOOD |
| A10 | `llm_adapter.py` imports `google.genai` and `anthropic`; `ghost_agent.py` imports neither — static check | MUST |

---

## 11. Tool Schema Conversion — Neutral → Provider-Native (§12b, §12c)

| # | Test | Priority |
|---|------|----------|
| C1 | `GeminiAdapter.convert_tools(GHOST_TOOL_SPECS)` returns `genai.types.Tool` containing all 8 `FunctionDeclaration`s | MUST |
| C2 | `AnthropicAdapter.convert_tools(GHOST_TOOL_SPECS)` returns a `list` of 8 dicts, each with `name`, `description`, `input_schema` | MUST |
| C3 | `run_shell_cmd` conversion: `required: ["command", "reasoning"]` is present in both Gemini and Anthropic output schemas | MUST |
| C4 | `capture_traffic` conversion: `storage_auth_mode` enum `["login", "key"]` preserved in both output schemas | GOOD |
| C5 | `complete_investigation` conversion: `contradicted_hypotheses` array parameter present in both output schemas | GOOD |
| C6 | Type mapping — all five primitive types verified for both `GeminiAdapter.convert_tools` and `AnthropicAdapter.convert_tools`: `"string"`, `"integer"`, `"boolean"`, `"object"`, `"array"` | MUST |
| C7 | Nested object properties convert depth-first for both providers: given a neutral spec with `{"type": "object", "properties": {"foo": {"type": "string"}}}`, Gemini output is `Schema(type=OBJECT, properties={"foo": Schema(type=STRING)})` and Anthropic output is `{"type": "object", "properties": {"foo": {"type": "string"}}}` — verified with `capture_traffic`'s sub-parameter group | MUST |
| C8 | Anthropic output: every tool's `input_schema` has `"type": "object"` at the top level | MUST |
| C9 | `GeminiAdapter.convert_tools` with a neutral spec containing an unrecognised type value raises an error — does not silently drop the parameter | GOOD |
| C10 | `GHOST_TOOL_SPECS` definition in `ghost_agent.py` contains no `genai.types` objects — plain dicts only | MUST |
| C11 | `convert_tools([])` with an empty spec list: `GeminiAdapter` returns `genai.types.Tool` with empty `function_declarations`; `AnthropicAdapter` returns `[]`; neither raises an exception | GOOD |

---

## 12. Neutral History Format and History Conversion (§12a)

| # | Test | Priority |
|---|------|----------|
| N1 | New session: `conversation_history` initialised as `[]` — empty Python list, no `types.Content` objects | MUST |
| N2 | User intent appended as `{"role": "user", "text": "..."}` — plain dict | MUST |
| N3 | Model text-only response appended as `{"role": "model", "text": "..."}` | MUST |
| N4 | Model response with tool calls appended as `{"role": "model", "text": "...", "tool_calls": [{"id": ..., "name": ..., "args": {...}}]}` | MUST |
| N5 | Tool results appended as `{"role": "tool_results", "results": [{"id": ..., "name": ..., "output": {...}}]}` | MUST |
| N6 | `result["id"]` in tool_results matches `tool_call["id"]` from the same turn — id correlation preserved by the loop, not the adapter | MUST |
| N7 | Two `tool_calls` of the same tool name in one turn get distinct `id` values; their `tool_results` entries carry the correct distinct ids — no collision | MUST |
| N8 | History reconstructed from JSONL on `--resume` produces neutral dicts, not `types.Content` objects | MUST |
| N9 | `GeminiAdapter.generate()` — neutral user text turn → `types.Content(role="user", parts=[Part(text=...)])` constructed inside adapter | MUST |
| N9b | `GeminiAdapter.generate()` with a 4-turn neutral history (user → model+tool_calls → tool_results → user): constructed `types.Content` list is strictly alternating `user / model / user / model` — no two consecutive same-role turns; verified by inspecting `.role` on each element | MUST |
| N10 | `GeminiAdapter.generate()` — neutral model+tool_calls turn → `types.Content(role="model")` with `function_call` parts, one per tool call | MUST |
| N10b | `GeminiAdapter.generate()` — neutral model turn with 2 tool_calls: constructed `types.Content(role="model")` has exactly 2 `function_call` parts; both `name` and `args` match the two tool_calls; neither is dropped | MUST |
| N11 | `GeminiAdapter.generate()` — neutral tool_results turn → `types.Content(role="user")` with `function_response` parts; `FunctionResponse.name` matches `result["name"]` | MUST |
| N12 | `GeminiAdapter` synthetic id generation: sequential `tc_0001`, `tc_0002`... within a call; resets each `generate()` call | GOOD |
| N13 | `AnthropicAdapter.generate()` — neutral user text turn → `{"role": "user", "content": "..."}` | MUST |
| N14 | `AnthropicAdapter.generate()` — neutral model+tool_calls turn → `{"role": "assistant", "content": [text_block, tool_use_block, ...]}` | MUST |
| N14b | `AnthropicAdapter.generate()` — neutral model turn with 2 tool_calls: Anthropic messages list contains one assistant turn with exactly 2 `tool_use` content blocks; both `name` and `input` match the two tool_calls; neither is dropped | MUST |
| N14c | `AnthropicAdapter.generate()` with a history where a model+tool_calls turn is followed by a plain user text turn (not tool_results): adapter raises a clear exception before calling `messages.create` — invalid history is rejected at the adapter boundary, not silently passed to the API | MUST |
| N15 | `AnthropicAdapter.generate()` — neutral tool_results turn → `{"role": "user", "content": [{"type": "tool_result", "tool_use_id": result["id"], "content": json.dumps(result["output"])}]}`; `result["output"]` is JSON-serialized to a string, not passed as a raw dict | MUST |
| N16 | `AnthropicAdapter` tool_use_id: `result["id"]` used directly as `tool_use_id` — no name-keyed lookup; two same-name tool results in one turn each carry their own distinct id | MUST |

---

## 13. Provider Response Normalisation — `NormalizedResponse` (§12b)

| # | Test | Priority |
|---|------|----------|
| P1 | `GeminiAdapter.generate()` text-only response → `NormalizedResponse(text="...", tool_calls=[], is_empty=False)`; assert `response.tool_calls == []` (empty list, not `None`) | MUST |
| P2 | `GeminiAdapter.generate()` tool-call response → `NormalizedResponse(tool_calls=[{id, name, args}], is_empty=False)`; `id` is synthetic sequential | MUST |
| P3 | `GeminiAdapter.generate()` mixed text+tool-call response → `text` non-empty and `tool_calls` non-empty | GOOD |
| P4 | `GeminiAdapter.generate()` safety-blocked response (empty `candidates`) → `NormalizedResponse(is_empty=True)` | MUST |
| P5 | `AnthropicAdapter.generate()` `end_turn` response → `NormalizedResponse(text="...", tool_calls=[], is_empty=False)`; assert `response.tool_calls == []` (empty list, not `None`) | MUST |
| P6 | `AnthropicAdapter.generate()` `tool_use` response → `NormalizedResponse(tool_calls=[{id, name, args}], is_empty=False)`; `id` equals Anthropic `tool_use_id` | MUST |
| P7 | `AnthropicAdapter.generate()` mixed text+tool_use response → both `text` and `tool_calls` populated | GOOD |
| P8 | `AnthropicAdapter` — `is_empty` is always `False`; Anthropic surfaces errors as exceptions, not empty content | MUST |
| P9 | `type(response.tool_calls) is list` for all `NormalizedResponse` code paths — both adapters, all response shapes (text-only, tool-call, mixed, empty); `tool_calls` is never `None` | MUST |
| P10 | `AnthropicAdapter.generate()` — mock `anthropic.Anthropic.messages.create` and assert it is called with a `max_tokens` argument set to a positive integer; verify call kwargs directly | MUST |

---

## 14. Empty Response and Rate-Limit Retry (§4 pseudocode, §9)

| # | Test | Priority |
|---|------|----------|
| RL1 | `response.is_empty=True`: loop injects recovery nudge into `conversation_history` and continues; `consecutive_empty` increments to 1 | MUST |
| RL2 | Three consecutive `is_empty=True` responses: loop calls `save_session()` and exits with code 1 — no infinite loop | MUST |
| RL3 | Non-empty response after one empty: `consecutive_empty` resets to 0 | MUST |
| RL4a | Recovery nudge — pending capture task branch: `state["active_task_ids"]` non-empty → nudge references `check_task`; assert nudge text appended to `conversation_history` | GOOD |
| RL4b | Recovery nudge — active hypothesis branch: `state["active_task_ids"]` empty, `state["active_hypothesis_ids"]` non-empty → nudge says "Continue investigation"; assert nudge appended | GOOD |
| RL4c | Recovery nudge — neither branch: both task and hypothesis lists empty → nudge says "Call complete_investigation"; assert nudge appended | GOOD |
| RL5 | Gemini 429 / `RESOURCE_EXHAUSTED` error: mock `generate_content` to raise this error; assert mock called exactly 3 times before exception propagates; no call to `save_session()` during retry | MUST |
| RL6 | Anthropic `overloaded_error`: mock `messages.create` to raise this error; assert mock called exactly 3 times before exception propagates | MUST |
| RL7 | Non-rate-limit exception from either provider: propagates immediately without retry | MUST |
| RL8 | Third retry exhaustion (rate limit): adapter raises exception; loop catches, calls `save_session()`, exits with code 1 | MUST |
| RL9 | Backoff timing: second retry waits longer than first (exponential, not fixed interval) — verify ordering, not exact values | GOOD |

---

## 15. `--auto-approve` Mode (§9, §12c)

| # | Test | Priority |
|---|------|----------|
| AA1 | With `--auto-approve`: RISKY commands approved without blocking on `input()`; verified by mocking `input()` to raise `AssertionError` if called — test completes without triggering the mock | MUST |
| AA2 | With `--auto-approve`: audit record for auto-approved RISKY command has `action="auto_approved_eval_mode"` — label must be distinct from normal `"auto_approved"` | MUST |
| AA3 | With `--auto-approve`: FORBIDDEN commands are still blocked unconditionally — safety gate not bypassed | MUST |
| AA4 | With `--auto-approve`: every auto-approval written to audit trail; none silently omitted | MUST |
| AA5 | Without `--auto-approve`: original `terminal_hitl_callback` used; RISKY commands block on `input()`; no behavioral change | MUST |
| AA6 | `--auto-approve` is not persisted to `ghost_session.json` — it is a runtime flag, not session state | GOOD |
| AA7 | Without `--auto-approve`, a RISKY command approved through normal HITL has `action="user_approved"` in the audit record — `action` is NOT `"auto_approved_eval_mode"`; inverse of AA2 | MUST |

---

## 16. Provider Integration (§12, §4)

| # | Test | Priority |
|---|------|----------|
| PI1 | Gemini adapter integration: mock `genai.Client.models.generate_content` returns tool-call response → `GeminiAdapter` normalises → loop dispatches → `conversation_history` contains only neutral dicts | MUST |
| PI2 | Anthropic adapter integration: mock `anthropic.Anthropic.messages.create` returns tool_use response → `AnthropicAdapter` normalises → loop dispatches → `conversation_history` contains only neutral dicts | MUST |
| PI3 | Gemini denial path: mock Gemini returns `run_shell_cmd` three times → mock Shell returns `status="denied"` each time → hypothesis marked UNVERIFIABLE → `complete_investigation` called | MUST |
| PI4 | Anthropic denial path: same scenario as PI3 but using `AnthropicAdapter`; outcome identical — provider does not affect denial state machine | MUST |
| PI5 | Provider switch across sessions: session saved with `llm_provider="gemini"`, new run with `--llm-provider anthropic` → `type(adapter) is AnthropicAdapter`; `adapter.generate()` called with reconstructed neutral history returns a valid `NormalizedResponse` (`tool_calls` is a list, `is_empty` is `False` for a non-blocked mock); no exception raised | GOOD |
| PI6 | Real Anthropic Claude end-to-end against real Azure infrastructure | SKIP |
