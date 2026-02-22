# Test Plan: Cloud Orchestrator

> Golden test suite derived from `architecture.md` and `design.md`. Every test case traces to a specific specification clause. This plan is the acceptance gate — feature code ships only when the required tiers pass.

---

## Priority Tiers

| Tier | Label | Meaning | Ship Blocker? |
|------|-------|---------|---------------|
| P0 | **MUST PASS** | Safety-critical invariants. Failures mean the Orchestrator could bypass Shell safety, leak state, orphan cloud resources, or corrupt the task registry. | Yes — 100% pass rate required |
| P1 | **SHOULD PASS** | Behavioral correctness for the core pipeline. Failures indicate real bugs in state transitions, polling logic, command translation, or response contracts. | Yes — all must pass before merge |
| P2 | **GOOD TO PASS** | Quality and completeness. Covers metadata accuracy, console output formatting, configuration edge cases, and orphan detection nuances. Failures are acceptable during early iterations. | No — tracked as known gaps |
| P3 | **MAY FAIL** | Environmental dependencies. Tests that require real Azure CLI, real filesystem I/O, or timing-sensitive behavior. Intermittent failures expected in CI. | No — informational |

---

## Notation

- Each test has an ID: `{Section}.{Number}` (e.g., `CO.01`)
- `[spec: ...]` traces the test to a specific document clause
- All tests use `orchestrate(request) -> response` unless stated otherwise
- Shell is mocked: `shell.execute()` returns configurable responses
- Azure CLI output is simulated via Shell mock responses
- PCAP Engine output is simulated via Shell mock responses

---

## Section 1 — Shell Safety Boundary

### P0 — MUST PASS

The Orchestrator must never bypass the Shell. Every command goes through `shell.execute()`.

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CO.01 | Every Azure CLI command issued by the Orchestrator passes through `shell.execute()` — no direct `subprocess` calls anywhere in `cloud_orchestrator.py` | [spec: architecture.md — "The Orchestrator never bypasses the Shell"] |
| CO.02 | Every `pcap_forensics.py` invocation passes through `shell.execute()` — never imported as a library | [spec: architecture.md — PCAP Engine Integration decision] |
| CO.03 | The Orchestrator never modifies the Shell's classification, tier structure, or pipeline order | [spec: architecture.md — Shell compatibility guarantee] |
| CO.04 | When Shell returns `{ status: "denied" }` for a capture create command, the Orchestrator does NOT retry or re-submit the same command | [spec: architecture.md — user denial is final] |
| CO.05 | When Shell returns `{ status: "denied" }` for a blob download, the Orchestrator does NOT attempt an alternative download path | [spec: design.md — denial transitions to CANCELLED] |
| CO.06 | Capture create commands include a `reasoning` field that embeds the investigation context | [spec: design.md — "reasoning field embeds investigation context"] |

---

## Section 2 — Request Validation

### P1 — SHOULD PASS

| ID | Input | Expected | Rationale |
|----|-------|----------|-----------|
| RQ.01 | `{ intent: "capture_traffic" }` with no `target` | `{ status: "error", error: "missing_parameter" }` | [spec: design.md — target required for capture_traffic] |
| RQ.02 | `{ intent: "capture_traffic", target: "vm-01" }` with no `parameters.storage_account` | `{ status: "error", error: "missing_parameter" }` | [spec: design.md edge cases — Brain sends no storage_account] |
| RQ.03 | `{ intent: "check_task", task_id: "nonexistent" }` | `{ status: "error", error: "unknown_task" }` | [spec: design.md error handling] |
| RQ.04 | `{ intent: "unknown_thing" }` | `{ status: "error", error: "unknown_intent" }` | [spec: design.md error handling] |
| RQ.05 | `{ intent: "check_task" }` with no `task_id` | `{ status: "error", error: "missing_parameter" }` | task_id required for check_task |
| RQ.06 | Valid `capture_traffic` request with all required fields | `{ status: "task_pending" }` with a `task_id` starting with `ghost_` | [spec: design.md — resource naming convention] |

---

## Section 3 — Response Contract

### P1 — SHOULD PASS

Every response must conform to the documented schema.

| ID | Scenario | Assert Fields Present | Rationale |
|----|----------|-----------------------|-----------|
| RS.01 | Pending task (capture in progress) | `task_id`, `status`, `state`, `investigation_context`, `poll_count`, `max_polls`, `elapsed_seconds`, `message` | [spec: design.md — pending response example] |
| RS.02 | Completed task | `task_id`, `status`, `state`, `investigation_context`, `result` (with `local_pcap_path`, `semantic_json_path`, `report_path`), `cleanup_status`, `duration_seconds`, `message` | [spec: design.md — completed response example] |
| RS.03 | Failed task | `task_id`, `status`, `state`, `investigation_context`, `error_detail`, `cleanup_status`, `message` | [spec: design.md — failed response example] |
| RS.04 | Error (no task created) | `status`, `error`, `message` | [spec: design.md — error responses] |

**Field value constraints:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| RS.10 | `status` is one of: `task_pending`, `task_completed`, `task_failed`, `task_cancelled`, `task_timed_out`, `error` | [spec: design.md — response table] |
| RS.11 | `state` matches a valid lifecycle state from the state machine | [spec: design.md — state machine] |
| RS.12 | `investigation_context` in response matches the value provided in the original request, verbatim | [spec: design.md — "returned verbatim"] |
| RS.13 | `task_id` format is `ghost_{target}_{YYYYMMDDTHHMMSS}` | [spec: design.md — resource naming] |
| RS.14 | `cleanup_status` is one of: `pending`, `completed`, `partial`, `skipped`, or null | [spec: design.md — response table] |

---

## Section 4 — Task Lifecycle State Machine

### P0 — MUST PASS

| ID | Scenario | Expected State Transition | Rationale |
|----|----------|---------------------------|-----------|
| SM.01 | Shell returns `{ status: "denied" }` for capture create | State → CANCELLED | [spec: design.md state transition table — APPROVED → CANCELLED] |
| SM.02 | Shell returns error for `az resource show` (resource not found) | State → FAILED | [spec: design.md — DETECTING → FAILED] |
| SM.03 | Poll count reaches `max_polls` with Azure still Running | State → TIMED_OUT | [spec: design.md — WAITING → TIMED_OUT] |

### P1 — SHOULD PASS

| ID | Scenario | Expected State Transition | Rationale |
|----|----------|---------------------------|-----------|
| SM.10 | New capture request, target detected as VM, storage verified, user approves | CREATED → DETECTING → APPROVED → PROVISIONING | [spec: design.md state transition table] |
| SM.11 | Azure `provisioningState` returns `Running` | Remain in WAITING, poll_count incremented | [spec: design.md — WAITING → WAITING] |
| SM.12 | Azure `provisioningState` returns `Succeeded` | State → DOWNLOADING | [spec: design.md — WAITING → DOWNLOADING] |
| SM.13 | Azure `provisioningState` returns `Stopped` | Treat as Succeeded → DOWNLOADING | [spec: design.md — completion detection table] |
| SM.14 | Azure `provisioningState` returns `Failed` | State → FAILED | [spec: design.md — WAITING → FAILED] |
| SM.15 | Blob download succeeds | State → ANALYZING | [spec: design.md — DOWNLOADING → ANALYZING] |
| SM.16 | PCAP Engine succeeds | State → COMPLETED | [spec: design.md — ANALYZING → COMPLETED] |
| SM.17 | Cleanup completes | State → DONE | [spec: design.md — CLEANING_UP → DONE] |
| SM.18 | Blob download fails after retry | State → FAILED | [spec: design.md — DOWNLOADING → FAILED] |
| SM.19 | PCAP Engine returns non-zero exit code | State → FAILED | [spec: design.md — ANALYZING → FAILED] |
| SM.20 | Unrecognized `provisioningState` value | Remain in WAITING, log warning | [spec: design.md — completion detection table] |
| SM.21 | Storage verification fails during DETECTING | State → FAILED before any resources created | [spec: design.md — DETECTING → FAILED via storage check] |
| SM.22 | AKS target detected | Informational response returned, no capture attempted | [spec: architecture.md — AKS detection-only in Phase 2] |

### P2 — GOOD TO PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| SM.30 | `check_task` on a terminal state (DONE) | Return current state unchanged, no error | [spec: design.md — idempotent] |
| SM.31 | `cancel_task` on a terminal state | Return current state unchanged, no error | [spec: design.md — idempotent] |
| SM.32 | Full happy path: CREATED → ... → DONE | All intermediate states visited in order | End-to-end lifecycle validation |

---

## Section 5 — Command Translation

### P0 — MUST PASS

| ID | Shell Command Issued by Orchestrator | Expected Classification | HITL? | Rationale |
|----|--------------------------------------|------------------------|-------|-----------|
| CT.01 | `az resource show --ids {id} --query type -o tsv` | SAFE (Tier 2: `show`) | No | [spec: architecture.md sidecar pipeline table] |
| CT.02 | `az storage container exists --account-name {sa} --name {c} --auth-mode login -o tsv` | SAFE (Tier 2: `exists`) | No | [spec: design.md command templates] |
| CT.03 | `az network watcher packet-capture create ...` | RISKY (Tier 2: `create`) | Yes | [spec: architecture.md sidecar pipeline table] |
| CT.04 | `az network watcher packet-capture show ...` | SAFE (Tier 2: `show`) | No | [spec: architecture.md sidecar pipeline table] |
| CT.05 | `az storage blob download ...` | RISKY (Tier 2: `download`) | Yes | [spec: architecture.md sidecar pipeline table] |
| CT.06 | `python pcap_forensics.py {path} --semantic-dir {dir} --report-dir {dir}` | SAFE (Tier 1: allowlist) | No | [spec: architecture.md sidecar pipeline table] |
| CT.07 | `az network watcher packet-capture delete ...` | RISKY (Tier 2: `delete`) | Yes | [spec: architecture.md sidecar pipeline table] |
| CT.08 | `az storage blob delete ...` | RISKY (Tier 2: `delete`) | Yes | [spec: architecture.md sidecar pipeline table] |

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CT.10 | Capture name uses pattern `ghost_{target}_{YYYYMMDDTHHMMSS}` | [spec: design.md — resource naming] |
| CT.11 | Storage path uses `https://{sa}.blob.core.windows.net/captures/{capture_name}.pcap` | [spec: design.md — command templates] |
| CT.12 | PCAP Engine comparison mode uses `--compare` flag when both paired captures complete | [spec: design.md — command templates] |
| CT.13 | Every Shell command includes a `reasoning` field | [spec: design.md — reasoning field] |
| CT.14 | `reasoning` field contains the investigation context from the Brain's original request | [spec: design.md — reasoning field] |

---

## Section 6 — Polling Logic

### P1 — SHOULD PASS

**Exponential backoff:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.01 | First poll interval is 5 seconds | [spec: design.md — backoff formula] |
| PL.02 | Second poll interval is 10 seconds | `min(5 * 2^1, 30) = 10` |
| PL.03 | Third poll interval is 20 seconds | `min(5 * 2^2, 30) = 20` |
| PL.04 | Fourth poll interval is capped at 30 seconds | `min(5 * 2^3, 30) = 30` |
| PL.05 | All subsequent intervals remain at 30 seconds | Cap enforced |
| PL.06 | Max polls default is 20 | [spec: design.md — configuration table] |

**Burst polling:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.10 | A single `check_task` call polls multiple times within the burst window | [spec: design.md — burst polling] |
| PL.11 | Burst window expires after `poll_burst_limit` seconds (default: 45), returns `task_pending` | [spec: design.md — burst polling] |
| PL.12 | If operation completes during burst, `check_task` advances through download + analysis and returns final result in one call | [spec: design.md — "may advance through multiple states"] |
| PL.13 | Each individual poll within a burst is a separate `shell.execute()` call | [spec: architecture.md — "each Shell call within the burst is still synchronous"] |
| PL.14 | Poll count is incremented for every poll, including those within a burst | Accurate tracking |

**Completion detection:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| PL.20 | `provisioningState: "Succeeded"` advances state to DOWNLOADING | [spec: design.md — completion detection table] |
| PL.21 | `provisioningState: "Stopped"` treated as Succeeded | [spec: design.md — completion detection table] |
| PL.22 | `provisioningState: "Failed"` advances state to FAILED | [spec: design.md — completion detection table] |
| PL.23 | `provisioningState: "Running"` keeps state as WAITING | [spec: design.md — completion detection table] |
| PL.24 | `provisioningState: "Creating"` keeps state as WAITING | [spec: design.md — completion detection table] |

---

## Section 7 — Task Registry

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TR.01 | Every state transition appends a new JSONL record — previous records are never modified | [spec: design.md — "Append-only"] |
| TR.02 | `_load_task(task_id)` returns the last record for that task_id (not the first) | [spec: design.md — "read the last record for each task_id"] |
| TR.03 | Task Registry file is valid JSONL — each line parses independently as JSON | [spec: design.md — JSONL format] |

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TR.10 | File is named `orchestrator_tasks_{session_id}.jsonl` | [spec: design.md — file naming] |
| TR.11 | File is created in `task_dir` directory | [spec: design.md — storage format] |
| TR.12 | `_load_all_tasks()` returns one entry per unique task_id (last record wins) | [spec: design.md — _load_all_tasks] |
| TR.13 | `_load_task()` returns None for unknown task_id | [spec: design.md — _load_task signature] |
| TR.14 | `_save_task()` appends the full task dict as a single JSON line | [spec: design.md — _save_task] |
| TR.15 | Task record contains all schema fields: `task_id`, `session_id`, `intent`, `target`, `state`, `investigation_context`, `cleanup_plan`, `poll_count`, `timestamps`, etc. | [spec: design.md — task registry schema] |
| TR.16 | `shell_audit_ids` array is populated with audit IDs from each Shell call the task generates | [spec: design.md — task registry schema] |

### P2 — GOOD TO PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TR.20 | Corrupted JSONL lines are skipped during read; valid lines are still loaded | [spec: design.md edge cases — "skip corrupted lines"] |
| TR.21 | Registry file not writable: task proceeds in-memory, warning logged to stderr | [spec: design.md error handling — non-fatal] |
| TR.22 | `_save_task()` calls `flush()` (or `fsync()`) on the JSONL file handle immediately after every write — state transitions are durable on disk before the next `sleep()` or Shell call begins | A burst poll can last 45 seconds. If the process is killed during a `sleep()` between polls, a buffered write could be lost, leaving an orphan that the registry cannot recover. |

---

## Section 8 — Resource Lifecycle and Cleanup

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CL.01 | Cleanup plan is built at task creation time, before the first cloud resource is created | [spec: design.md — "built at task creation time"] |
| CL.02 | When a task reaches FAILED, cleanup executes automatically for any created resources | [spec: design.md cleanup triggers — FAILED] |
| CL.03 | When a task reaches TIMED_OUT, cleanup executes automatically | [spec: design.md cleanup triggers — TIMED_OUT] |
| CL.04 | Cleanup commands go through `shell.execute()` — each delete is HITL-gated | [spec: design.md cleanup execution rules] |

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CL.10 | Cleanup plan includes: packet capture delete, storage blob delete, local pcap file delete | [spec: design.md — cleanup plan registration table] |
| CL.11 | Cleanup order: cloud resources first, local files last | [spec: design.md — cleanup execution rule 4] |
| CL.12 | User denying a cleanup command results in `cleanup_status: "partial"`, not a task failure | [spec: design.md — cleanup execution rule 5] |
| CL.13 | Each cleanup command's `executed` flag is set to `true` after successful execution | [spec: design.md — cleanup execution rule 6] |
| CL.14 | When task is CANCELLED before PROVISIONING, no cleanup is needed (no resources exist) | [spec: design.md cleanup triggers — CANCELLED] |
| CL.15 | For a COMPLETED task, cleanup is not automatic — requires explicit `cleanup_task` intent | [spec: design.md cleanup triggers — COMPLETED] |
| CL.16 | Cleanup command for an already-deleted resource (Azure returns "not found"): treated as successful cleanup | [spec: design.md edge cases — already-deleted resource] |
| CL.17 | Analysis artifacts (semantic JSON, forensic report) are NOT automatically cleaned up | [spec: design.md — "Local analysis artifacts are NOT automatically cleaned up"] |

---

## Section 9 — Orphan Detection

### P1 — SHOULD PASS

**Layer 1 — Task Registry scan:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| OR.01 | On startup, non-terminal tasks from previous sessions are flagged as ABANDONED | [spec: design.md — Layer 1 table] |
| OR.02 | Tasks in COMPLETED with `cleanup_status: "pending"` are flagged as needing cleanup | [spec: design.md — Layer 1 table] |
| OR.03 | Tasks in DONE or CANCELLED are ignored (terminal states) | [spec: design.md — Layer 1 table] |

**Layer 2 — Azure resource scan:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| OR.10 | Startup queries Azure for `ghost_*` packet captures | [spec: design.md — Layer 2] |
| OR.11 | Azure resources not matching any known task are flagged as untracked orphans | [spec: design.md — Layer 2] |
| OR.12 | The `az ... list` command for orphan scan is classified SAFE (auto-approved) | [spec: design.md — Layer 2, "Tier 2: list verb"] |

**Layer 3 — Local file age scan:**

| ID | Assertion | Rationale |
|----|-----------|-----------|
| OR.20 | Files in `local_capture_dir` older than `local_artifact_max_age_days` with `ghost_*` prefix are flagged as stale | [spec: design.md — Layer 3] |
| OR.21 | Files without `ghost_*` prefix are ignored | [spec: design.md — Layer 3, "not Orchestrator-managed"] |
| OR.22 | Stale local file deletion goes through Shell HITL | [spec: design.md — Layer 3, "rm is classified RISKY by Tier 3"] |

### P2 — GOOD TO PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| OR.30 | Orphan detection runs once at init, not on every `orchestrate()` call | [spec: design.md — "runs once at Orchestrator initialization"] |
| OR.31 | Orphaned resources from all three layers are batched under a single reasoning context | [spec: design.md — bulk cleanup prompt] |

---

## Section 10 — HITL Gate Handling

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| HI.01 | Capture create (RISKY) triggers HITL | [spec: design.md approval categories table] |
| HI.02 | Poll status (SAFE) does NOT trigger HITL | [spec: design.md approval categories table] |
| HI.03 | Blob download (RISKY) triggers HITL | [spec: design.md approval categories table] |
| HI.04 | PCAP Engine invocation (SAFE) does NOT trigger HITL | [spec: design.md approval categories table] |
| HI.05 | Capture delete (RISKY) triggers HITL | [spec: design.md approval categories table] |
| HI.06 | Target detection (SAFE) does NOT trigger HITL | [spec: design.md approval categories table] |
| HI.07 | Storage verification (SAFE) does NOT trigger HITL | [spec: design.md approval categories table] |

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| HI.10 | Single-end capture: exactly 2 critical-path HITL interruptions (create + download) | [spec: design.md — user experience, "2 critical-path HITL interruptions"] |
| HI.11 | Cleanup: up to 2 additional HITL interruptions (delete capture + delete blob), only when `cleanup_task` is sent | [spec: design.md — user experience, "2 optional cleanup HITL"] |
| HI.12 | Dual-end capture: 4 critical-path HITL interruptions (2 per target) | [spec: design.md — dual-end captures user experience] |

---

## Section 11 — Storage Permission Smoke Test

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| ST.01 | `az storage container exists` is called during DETECTING phase, before capture creation | [spec: design.md — _handle_capture_traffic flow step 3] |
| ST.02 | Storage check failure → task FAILED immediately, no cloud resources created | [spec: design.md — DETECTING → FAILED via storage check] |
| ST.03 | Storage check success → normal flow continues to APPROVED | [spec: design.md — DETECTING → APPROVED] |
| ST.04 | If smoke test passes but download later fails (permissions revoked mid-capture), DOWNLOADING failure path handles it | [spec: design.md error handling — storage account entry] |

---

## Section 12 — Dual-End Capture

### P0 — MUST PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| DE.01 | Two independent tasks are created, linked by `paired_task_id` | [spec: design.md — dual-end capture] |
| DE.02 | Each task has its own HITL approval cycle — user can approve one and deny the other | [spec: design.md — lifecycle rule 1] |

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| DE.10 | Neither task proceeds to ANALYZING until both reach COMPLETED (happy path) | [spec: design.md — lifecycle rule 3] |
| DE.11 | When both complete, PCAP Engine is invoked in comparison mode with `--compare` flag | [spec: design.md — lifecycle rule 4] |
| DE.12 | When paired task fails, surviving COMPLETED task falls back to single-end analysis automatically | [spec: design.md — lifecycle rule 5, degraded fallback] |
| DE.13 | Degraded fallback response includes `mode: "single_end_fallback"` | [spec: design.md — degraded fallback response example] |
| DE.14 | Degraded fallback response includes the failed partner's status and error detail | [spec: design.md — degraded fallback response example] |
| DE.15 | When paired task is TIMED_OUT, surviving task falls back to single-end analysis | Same as DE.12 for timeout case |
| DE.16 | When paired task is CANCELLED (user denied), surviving task falls back to single-end analysis | Same as DE.12 for cancellation case |
| DE.17 | `check_task` response for a paired task includes the partner's current status | [spec: design.md — response for paired tasks] |
| DE.18 | Cleanup for paired tasks is independent — each task cleans only its own resources | [spec: design.md — lifecycle rule 7] |
| DE.19 | Comparison report path is stored in both tasks' `report_path` fields | [spec: design.md — lifecycle rule 6] |

### P2 — GOOD TO PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| DE.20 | One target is VM, other is AKS: AKS task returns informational message, VM task proceeds for single-end analysis | [spec: design.md edge cases — paired AKS/VM] |

---

## Section 13 — State Continuity

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| SC.01 | `investigation_context` stored at task creation survives across multiple `check_task` calls | [spec: architecture.md — state continuity] |
| SC.02 | `check_task` response includes `investigation_context` alongside status | [spec: architecture.md — "returns the full context alongside the status"] |
| SC.03 | Original `parameters` (duration, storage account, resource group) are preserved in the task record | [spec: architecture.md — state continuity table] |
| SC.04 | `result` paths (semantic JSON, report) are populated only when task reaches COMPLETED | [spec: design.md — response table, "Present only when status is task_completed"] |

---

## Section 14 — Error Handling

### P0 — MUST PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| EH.01 | Azure provisioning fails (non-zero exit from `az ... create`) | Task → FAILED, cleanup executes | [spec: design.md error handling] |
| EH.02 | User denies HITL for capture creation | Task → CANCELLED, no resources to clean | [spec: design.md error handling] |
| EH.03 | User denies HITL for blob download | Task → CANCELLED, capture resource cleaned up | [spec: design.md error handling] |

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| EH.10 | Azure provisioning fails mid-capture (poll returns Failed) | Task → FAILED, cleanup executes (capture resource exists) | [spec: design.md error handling] |
| EH.11 | Blob download fails first attempt | Retry once after 5 seconds | [spec: design.md error handling — "Retry once"] |
| EH.12 | Blob download fails both attempts | Task → FAILED, cloud resources cleaned up | [spec: design.md error handling] |
| EH.13 | PCAP Engine fails (non-zero exit) | Task → FAILED, cloud and local resources cleaned up | [spec: design.md error handling] |
| EH.14 | PCAP Engine produces empty output (0-byte pcap) | Task → COMPLETED (engine handles gracefully) | [spec: design.md error handling — empty output] |
| EH.15 | User denies HITL for cleanup deletion | `cleanup_status: "partial"`, resource persists, user warned | [spec: design.md error handling] |
| EH.16 | Resource group not found during detection | Task → FAILED in DETECTING, no resources created | [spec: design.md error handling] |
| EH.17 | Network Watcher not enabled in region | Task → FAILED in PROVISIONING | [spec: design.md error handling] |
| EH.18 | Network lost during polling (Shell call fails) | Does not advance state, does not count as Azure "Failed" | [spec: design.md edge cases — network lost during polling] |

### P2 — GOOD TO PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| EH.20 | Disk full during blob download | Task → FAILED, cloud resources cleaned up | [spec: design.md error handling] |
| EH.21 | `check_task` on a terminal state (DONE) | Return current state, no error, idempotent | [spec: design.md error handling] |
| EH.22 | `cancel_task` on a terminal state | Return current state, no error, idempotent | [spec: design.md error handling] |

---

## Section 15 — Configuration

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CF.01 | Default `task_dir` is `"./audit/"` | [spec: design.md — configuration table] |
| CF.02 | Default `max_polls` is `20` | [spec: design.md — configuration table] |
| CF.03 | Default `initial_poll_interval` is `5` | [spec: design.md — configuration table] |
| CF.04 | Default `max_poll_interval` is `30` | [spec: design.md — configuration table] |
| CF.05 | Default `local_capture_dir` is `"/tmp/captures"` | [spec: design.md — configuration table] |
| CF.06 | Default `storage_container` is `"captures"` | [spec: design.md — configuration table] |
| CF.07 | Default `capture_name_prefix` is `"ghost"` | [spec: design.md — configuration table] |
| CF.08 | Default `poll_burst_limit` is `45` | [spec: design.md — configuration table] |
| CF.09 | Default `local_artifact_max_age_days` is `7` | [spec: design.md — configuration table] |
| CF.10 | All configuration is via constructor parameters — no config file, no env vars | [spec: design.md — "No configuration file, no environment variables"] |

### P2 — GOOD TO PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| CF.20 | Overriding `max_polls` to 5 causes TIMED_OUT after 5 polls | Config override works |
| CF.21 | Overriding `poll_burst_limit` to 10 limits burst window to 10 seconds | Config override works |
| CF.22 | Overriding `capture_name_prefix` to `"diag"` produces task IDs starting with `diag_` | Config override works |

---

## Section 16 — Edge Cases

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| EC.01 | Non-existent VM (target not found in Azure) | Task → FAILED in DETECTING | [spec: design.md edge cases] |
| EC.02 | Concurrent captures on the same VM | Each gets a unique task_id (different timestamps), both tracked independently | [spec: design.md edge cases] |
| EC.03 | 0-byte capture file (no traffic during window) | PCAP Engine generates a "no traffic" report, task → COMPLETED | [spec: design.md edge cases] |
| EC.04 | `check_task` sent before first poll | Normal behavior — Orchestrator sends first poll | [spec: design.md edge cases] |
| EC.05 | Brain sends `check_task` rapidly (faster than backoff) | Orchestrator polls on every call; backoff is advisory | [spec: design.md edge cases] |
| EC.06 | Capture completes but blob not yet available | Retry once; if still unavailable, task → FAILED | [spec: design.md edge cases] |
| EC.07 | Empty Task Registry file (first task in session) | `_load_all_tasks()` returns empty list, `_load_task()` returns None | [spec: design.md edge cases] |

### P2 — GOOD TO PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| EC.10 | Task ID collision (same target, same second) | Second task overwrites first (last-record-wins) | [spec: design.md edge cases — "extremely unlikely"] |
| EC.11 | `local_capture_dir` does not exist | Created on first use | [spec: design.md configuration — "Created on first use"] |

---

## Section 17 — Instrumentation Detection

### P1 — SHOULD PASS

| ID | Assertion | Rationale |
|----|-----------|-----------|
| TD.01 | `az resource show` returning `Microsoft.Compute/virtualMachines` → `target_type = "vm"`, full capture pipeline | [spec: architecture.md — instrumentation table] |
| TD.02 | `az resource show` returning `Microsoft.ContainerService/managedClusters` → `target_type = "aks"`, informational response only | [spec: architecture.md — AKS deferred] |
| TD.03 | `az resource show` returning unknown type → task FAILED with descriptive error | Unsupported target type |
| TD.04 | Detection uses a single `az resource show` call, not pre-configured mappings | [spec: architecture.md — "runtime detection via az resource show"] |

---

## Section 18 — Integration (Cross-Cutting)

### P0 — MUST PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| IN.01 | Full happy path: capture_traffic → check_task (polls succeed) → task_completed with report paths → cleanup_task → DONE | All states visited, all Shell calls classified correctly, task registry has complete history | End-to-end pipeline |
| IN.02 | Full failure path: capture_traffic → check_task (Azure fails) → task_failed → cleanup executes | Cleanup runs, cloud resources deleted, task reaches terminal state | Error recovery pipeline |

### P1 — SHOULD PASS

| ID | Scenario | Expected | Rationale |
|----|----------|----------|-----------|
| IN.10 | Dual-end happy path: capture_traffic with two targets → both complete → comparison report generated | Both tasks track independently, comparison mode invoked, single report covers both | [spec: design.md — dual-end capture] |
| IN.11 | Dual-end degraded path: one target fails, other succeeds → single-end fallback | Surviving task analyzed independently, response indicates degraded mode | [spec: design.md — degraded fallback] |
| IN.12 | Brain calls Shell directly while Orchestrator task is WAITING | Shell is not blocked between polls — direct Shell calls succeed | [spec: architecture.md — Shell blocking scope] |
| IN.13 | Burst poll completes capture, downloads, and analyzes in a single `check_task` call | Multi-state advancement within one call | [spec: design.md — "may advance through multiple states"] |
| IN.14 | Orchestrator uses the same `execute({command, reasoning})` interface as Brain → Shell | Shell cannot distinguish Orchestrator calls from Brain calls | [spec: architecture.md — coupling rules] |

---

## Appendix A — Test Infrastructure

### Mocks and Stubs

| Component | Mock Strategy |
|-----------|---------------|
| Shell | Stub `execute({command, reasoning})` returning configurable responses per command pattern. Track call history for assertion (call count, command strings, reasoning fields). |
| Azure CLI output | Encoded in Shell mock: `az resource show` returns type string; `az ... show` returns JSON with `provisioningState`; `az storage blob download` returns success/failure. |
| PCAP Engine output | Encoded in Shell mock: `python pcap_forensics.py` returns exit code 0 with file paths in output. |
| Filesystem | Temp directory per test for Task Registry. Verify JSONL contents after each test. |
| Clock | Controllable clock for deterministic `task_id` timestamps, `elapsed_seconds`, `duration_seconds`, and burst polling window enforcement. |
| Sleep | Mock `time.sleep()` to avoid real delays during polling tests. Track sleep durations for backoff schedule assertions. |

### Test Data Fixtures

| Fixture | Purpose |
|---------|---------|
| Shell response: SAFE auto-approved | `{ status: "completed", classification: "SAFE", action: "auto_approved", exit_code: 0, output: "..." }` |
| Shell response: RISKY user-approved | `{ status: "completed", classification: "RISKY", action: "user_approved", exit_code: 0, output: "..." }` |
| Shell response: RISKY user-denied | `{ status: "denied", classification: "RISKY", action: "user_denied" }` |
| Shell response: error (non-zero exit) | `{ status: "completed", exit_code: 1, stderr: "..." }` |
| Azure provision state: Running | Shell output containing `"Running"` for provisioningState |
| Azure provision state: Succeeded | Shell output containing `"Succeeded"` for provisioningState |
| Azure provision state: Failed | Shell output containing `"Failed"` for provisioningState |
| PCAP Engine success | Shell output containing file paths to semantic JSON and report |

---

## Appendix B — Test Count Summary

| Section | P0 | P1 | P2 | P3 | Total |
|---------|----|----|----|----|-------|
| 1. Shell Safety Boundary | 6 | — | — | — | 6 |
| 2. Request Validation | — | 6 | — | — | 6 |
| 3. Response Contract | — | 9 | — | — | 9 |
| 4. Task Lifecycle | 3 | 12 | 3 | — | 18 |
| 5. Command Translation | 8 | 5 | — | — | 13 |
| 6. Polling Logic | — | 14 | — | — | 14 |
| 7. Task Registry | 3 | 7 | 3 | — | 13 |
| 8. Cleanup | 4 | 8 | — | — | 12 |
| 9. Orphan Detection | — | 6 | 2 | — | 8 |
| 10. HITL Gate Handling | 7 | 3 | — | — | 10 |
| 11. Storage Smoke Test | — | 4 | — | — | 4 |
| 12. Dual-End Capture | 2 | 10 | 1 | — | 13 |
| 13. State Continuity | — | 4 | — | — | 4 |
| 14. Error Handling | 3 | 9 | 3 | — | 15 |
| 15. Configuration | — | 10 | 3 | — | 13 |
| 16. Edge Cases | — | 7 | 2 | — | 9 |
| 17. Instrumentation Detection | — | 4 | — | — | 4 |
| 18. Integration | 2 | 5 | — | — | 7 |
| **Totals** | **38** | **127** | **17** | **0** | **182** |
