# Design: Cloud Orchestrator

> Read architecture.md first for structural context and design rationale.

---

## Brain-Orchestrator Interface Contract

### Request (Brain → Orchestrator)

```json
{
  "intent": "capture_traffic",
  "target": "web-vm-01",
  "parameters": {
    "duration_seconds": 60,
    "storage_account": "forensics-sa",
    "resource_group": "prod-rg"
  },
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary. Hypothesis: TCP retransmissions due to NSG misconfiguration."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `intent` | string | Yes | The operation type. Determines which handler the Orchestrator dispatches to. |
| `target` | string | Depends on intent | The infrastructure target — VM name, resource ID, or AKS cluster name. Required for `capture_traffic`. |
| `parameters` | object | Depends on intent | Operation-specific parameters. Required fields vary by intent. |
| `investigation_context` | string | No | Why the Brain is requesting this operation — the diagnostic thread, symptoms, hypotheses. Stored in the Task Registry and returned with every status check. Also included in the `reasoning` field of Shell commands for HITL visibility. |
| `task_id` | string | Depends on intent | Required for `check_task`, `cancel_task`, `cleanup_task`. Not used for `capture_traffic` or `list_tasks`. |

**Intent Enumeration**

| Intent | Purpose | Required Fields |
|--------|---------|-----------------|
| `capture_traffic` | Start a new packet capture on one or two targets | `target`, `parameters` (duration_seconds, storage_account, resource_group) |
| `check_task` | Poll a task's status and advance its state if ready | `task_id` |
| `cancel_task` | Cancel a pending or in-progress task | `task_id` |
| `list_tasks` | Return all tasks for the current session | (none) |
| `cleanup_task` | Execute cleanup plan for a completed/failed task | `task_id` |

### Response (Orchestrator → Brain)

**Pending task response:**

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_pending",
  "state": "WAITING",
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "poll_count": 3,
  "max_polls": 20,
  "elapsed_seconds": 45,
  "message": "Packet capture running on web-vm-01. Azure provisioning state: Running."
}
```

**Completed task response:**

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_completed",
  "state": "COMPLETED",
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "result": {
    "local_pcap_path": "/tmp/captures/web-vm-01.pcap",
    "semantic_json_path": "/tmp/captures/web-vm-01_semantic.json",
    "report_path": "/tmp/captures/web-vm-01_forensic_report.md"
  },
  "cleanup_status": "pending",
  "duration_seconds": 312,
  "message": "Capture complete. Forensic report generated."
}
```

**Failed task response:**

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_failed",
  "state": "FAILED",
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "error_detail": "Azure provisioning failed: NetworkWatcherNotEnabled in region westus2",
  "cleanup_status": "completed",
  "message": "Capture failed. Cloud resources cleaned up."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | string | Unique task identifier. Format: `ghost_{target}_{timestamp}`. |
| `status` | string | High-level outcome: `task_pending`, `task_completed`, `task_failed`, `task_cancelled`, `task_timed_out`, `error`. |
| `state` | string | Current lifecycle state (see State Machine below). |
| `investigation_context` | string | The Brain's original investigation context, returned verbatim. |
| `result` | object or null | File paths to produced artifacts. Present only when `status` is `task_completed`. |
| `cleanup_status` | string or null | `pending`, `completed`, `partial`, `skipped`. Null if cleanup has not been attempted. |
| `error_detail` | string or null | Human-readable error description. Null if no error. |
| `poll_count` | integer or null | Number of polls executed so far. Null if task is not in a polling state. |
| `max_polls` | integer or null | Maximum polls before timeout. Null if task is not in a polling state. |
| `elapsed_seconds` | float or null | Wall-clock time since task creation. |
| `duration_seconds` | float or null | Total task duration. Set when task reaches a terminal state. |
| `message` | string | Human-readable status summary for display. |

**Note:** The Orchestrator wraps Shell responses internally but does NOT expose Shell's response format to the Brain for orchestrated operations. The `result` object contains file paths and orchestration-level status — not raw Shell output fields like `classification`, `action`, or `exit_code`. The Brain can still call the Shell directly for simple commands and receive the standard Shell response format.

---

## Task Lifecycle State Machine

```
                                          User denies HITL (create)
                                         ┌────────────────────────────┐
                                         │                            │
                                         ▼                            │
CREATED ──> DETECTING ──> APPROVED ──> PROVISIONING ──> WAITING ──> DOWNLOADING ──> ANALYZING ──> COMPLETED
                │              │           │              │             │              │
                │              │           │              │             │              │
                ▼              ▼           ▼              ▼             ▼              ▼
             FAILED        CANCELLED    FAILED        TIMED_OUT      FAILED         FAILED
                │              │           │              │             │              │
                └──────────────┴───────────┴──────────────┴─────────────┴──────────────┘
                                                   │
                                                   ▼
                                             CLEANING_UP
                                                   │
                                                   ▼
                                                 DONE
```

**Terminal states:** DONE (cleanup completed), CANCELLED (user denied, cleanup not needed or completed), ABANDONED (session ended with active task).

**State Transition Table**

| From | To | Trigger | Shell Command(s) |
|------|----|---------|-------------------|
| CREATED | DETECTING | Task registered | `az resource show --ids {id} --query type -o tsv` |
| DETECTING | DETECTING | Target type detected, verifying storage | `az storage container exists --account-name {sa} --name {container} --auth-mode login -o tsv` |
| DETECTING | APPROVED | Target type detected and storage verified | (internal — no Shell call) |
| DETECTING | FAILED | Detection failed (resource not found) | (none — error from previous Shell call) |
| DETECTING | FAILED | Storage inaccessible (permission denied, account not found) | (none — error from storage check Shell call) |
| APPROVED | PROVISIONING | User approves HITL | `az network watcher packet-capture create --vm {target} --name {id} ...` |
| APPROVED | CANCELLED | User denies HITL | (none — Shell returned `{ status: "denied" }`) |
| PROVISIONING | WAITING | Azure returns provisioning ID | (internal — Shell call returned) |
| WAITING | WAITING | Poll returns Running/Creating | `az network watcher packet-capture show --name {id}` |
| WAITING | DOWNLOADING | Poll returns Succeeded/Stopped | `az network watcher packet-capture show --name {id}` |
| WAITING | FAILED | Poll returns Failed | `az network watcher packet-capture show --name {id}` |
| WAITING | TIMED_OUT | Max polls exceeded | (internal — poll count check) |
| DOWNLOADING | ANALYZING | Blob downloaded | `az storage blob download --account-name {sa} --container-name {c} --name {blob} --file {path}` |
| DOWNLOADING | FAILED | Download failed (after retry) | (same command, retried once) |
| ANALYZING | COMPLETED | PCAP Engine finished | `python pcap_forensics.py {path} --semantic-dir {dir} --report-dir {dir}` |
| ANALYZING | FAILED | PCAP Engine error | (same command — non-zero exit code) |
| COMPLETED | CLEANING_UP | Cleanup initiated | `az network watcher packet-capture delete`, `az storage blob delete` |
| FAILED | CLEANING_UP | Cleanup initiated | (same cleanup commands) |
| TIMED_OUT | CLEANING_UP | Cleanup initiated | (same cleanup commands) |
| CANCELLED | DONE | No cleanup needed | (none) |
| CLEANING_UP | DONE | All cleanup commands executed | (cleanup commands complete) |

---

## Orchestrator-to-Shell Command Translation

The Orchestrator translates intents and task states into concrete Shell commands. Every command uses the same `{ command, reasoning }` request format that the Brain uses.

**Command Templates**

| Operation | Shell Command Template | Classification | HITL? |
|-----------|----------------------|----------------|-------|
| Detect target type | `az resource show --ids {resource_id} --query type -o tsv` | SAFE (Tier 2: `show`) | No |
| Verify storage access | `az storage container exists --account-name {sa} --name {container} --auth-mode login -o tsv` | SAFE (Tier 2: `exists`) | No |
| Create capture (VM) | `az network watcher packet-capture create --vm {target} --resource-group {rg} --name {capture_name} --storage-account {sa} --storage-path https://{sa}.blob.core.windows.net/captures/{capture_name}.pcap --time-limit {duration}` | RISKY (Tier 2: `create`) | Yes |
| Poll capture status | `az network watcher packet-capture show --resource-group {rg} --name {capture_name} --query provisioningState -o tsv` | SAFE (Tier 2: `show`) | No |
| Download capture blob | `az storage blob download --account-name {sa} --container-name captures --name {capture_name}.pcap --file {local_path} --no-progress` | RISKY (Tier 2: `download`) | Yes |
| Analyze single capture | `python pcap_forensics.py {local_path} --semantic-dir {semantic_dir} --report-dir {report_dir}` | SAFE (Tier 1: allowlist) | No |
| Compare two captures | `python pcap_forensics.py {path_a} --compare {path_b} --semantic-dir {semantic_dir} --report-dir {report_dir}` | SAFE (Tier 1: allowlist) | No |
| Delete packet capture | `az network watcher packet-capture delete --resource-group {rg} --name {capture_name}` | RISKY (Tier 2: `delete`) | Yes |
| Delete storage blob | `az storage blob delete --account-name {sa} --container-name captures --name {capture_name}.pcap` | RISKY (Tier 2: `delete`) | Yes |

**Reasoning field:** Every Shell command includes a `reasoning` field that embeds the investigation context. This makes the Brain's intent visible during HITL approval:

```json
{
  "command": "az network watcher packet-capture create --vm web-vm-01 ...",
  "reasoning": "Creating packet capture for investigation: Investigating intermittent 502 errors from web-vm-01 to redis-primary. Duration: 60 seconds. Capture name: ghost_web-vm-01_20250115T143200."
}
```

**Resource naming:** All cloud resources use a deterministic naming pattern: `ghost_{target}_{timestamp}`. The `ghost_` prefix identifies Orchestrator-created resources. The timestamp format is `YYYYMMDDTHHMMSS` (compact ISO 8601). This enables orphan detection: any Azure resource starting with `ghost_` is Orchestrator-managed and can be matched to a Task Registry entry.

---

## Polling Logic

### Exponential Backoff

Poll interval formula: `min(5 * 2^(attempt-1), 30)` seconds.

| Poll Attempt | Interval (seconds) | Cumulative Wait |
|-------------|--------------------:|----------------:|
| 1 | 5 | 0:05 |
| 2 | 10 | 0:15 |
| 3 | 20 | 0:35 |
| 4 | 30 | 1:05 |
| 5 | 30 | 1:35 |
| 10 | 30 | 3:35 |
| 15 | 30 | 6:05 |
| 20 | 30 | 8:35 |

Maximum polls: 20. Total polling window: ~8 minutes 35 seconds. This covers the expected 5-10 minute packet capture duration with margin.

**The Orchestrator sleeps within burst windows.** During a `check_task` call, the Orchestrator internally loops: poll Azure, sleep for the backoff interval, poll again — up to `poll_burst_limit` seconds (default: 45). The backoff schedule governs sleep durations between polls within a single burst. If the Brain calls `check_task` after a burst expires, a new burst begins from the current poll count.

### Poll Trigger Modes

Brain-driven only. The Brain sends `{ intent: "check_task", task_id: "..." }` and the Orchestrator polls Azure in response. There is no background polling thread, no timer, no scheduler.

**Burst polling within `check_task`:** To avoid burning one LLM turn per poll, `check_task` performs an internal polling loop before returning. On each call, it polls Azure, and if the operation is still in progress, it sleeps and polls again — up to `poll_burst_limit` seconds (default: 45). If the operation completes during the burst, `check_task` immediately advances through subsequent states (download, analyze) and returns the final result. If the burst window expires with the operation still running, it returns `task_pending` and the Brain calls again later.

This means a typical capture requires 2-3 Brain turns (initiate, one or two check_tasks, then result), not 10-20. Each Shell call within the burst is still synchronous and individually classified.

**Shell availability during burst polling:** The Shell is blocked only during each individual `az ... show` call (1-3 seconds). Between polls within a burst, the Shell is in a sleep gap — but since the Orchestrator holds the call, the Brain cannot issue other Shell commands during this window. If the Brain needs the Shell during a capture wait, it simply does not call `check_task` until it is ready to dedicate the burst window to polling.

This design means:
- No thread safety concerns for the Task Registry
- No invisible state changes (the Brain sees every transition)
- No resource consumption when the Brain is idle
- Minimal LLM turns spent on polling overhead

### Completion Detection

The Orchestrator parses the `provisioningState` field from `az network watcher packet-capture show` output:

| Azure `provisioningState` | Orchestrator Action | Task State |
|--------------------------|---------------------|------------|
| `Succeeded` | Advance to DOWNLOADING | DOWNLOADING |
| `Stopped` | Treat as Succeeded (capture completed due to time limit) | DOWNLOADING |
| `Failed` | Record error, advance to cleanup | FAILED |
| `Running` | Remain in WAITING, increment poll count | WAITING |
| `Creating` | Remain in WAITING, increment poll count | WAITING |
| (unrecognized) | Remain in WAITING, log warning | WAITING |

---

## Task Registry Schema

Full JSONL record with all fields:

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "session_id": "sess_abc123",
  "intent": "capture_traffic",
  "target": "web-vm-01",
  "target_type": "vm",
  "state": "COMPLETED",
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "parameters": {
    "duration_seconds": 60,
    "storage_account": "forensics-sa",
    "resource_group": "prod-rg"
  },
  "azure_operation_id": "ghost_web-vm-01_20250115T143200",
  "storage_account": "forensics-sa",
  "storage_container": "captures",
  "storage_blob_name": "ghost_web-vm-01_20250115T143200.pcap",
  "local_pcap_path": "/tmp/captures/web-vm-01.pcap",
  "semantic_json_path": "/tmp/captures/web-vm-01_semantic.json",
  "report_path": "/tmp/captures/web-vm-01_forensic_report.md",
  "paired_task_id": null,
  "cleanup_plan": [
    { "command": "az network watcher packet-capture delete --resource-group prod-rg --name ghost_web-vm-01_20250115T143200", "executed": false },
    { "command": "az storage blob delete --account-name forensics-sa --container-name captures --name ghost_web-vm-01_20250115T143200.pcap", "executed": false },
    { "command": "rm /tmp/captures/web-vm-01.pcap", "executed": false }
  ],
  "poll_count": 8,
  "max_polls": 20,
  "shell_audit_ids": [
    "sess_abc123_012",
    "sess_abc123_013",
    "sess_abc123_014",
    "sess_abc123_015"
  ],
  "timestamps": {
    "created": "2025-01-15T14:32:00Z",
    "approved": "2025-01-15T14:32:15Z",
    "provisioned": "2025-01-15T14:32:45Z",
    "first_poll": "2025-01-15T14:32:50Z",
    "last_poll": "2025-01-15T14:37:20Z",
    "completed": "2025-01-15T14:37:30Z",
    "cleanup_started": null,
    "cleanup_completed": null
  },
  "error_detail": null,
  "duration_seconds": 330
}
```

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | string | Unique identifier. Format: `ghost_{target}_{YYYYMMDDTHHMMSS}`. |
| `session_id` | string | Agent session identifier. Matches the Shell's `session_id`. |
| `intent` | string | The operation type that created this task. |
| `target` | string | Infrastructure target name or resource ID. |
| `target_type` | string | Detected type: `"vm"` or `"aks"`. Set after DETECTING state. Note: `"aks"` is detection-only in Phase 2 — capture pipeline deferred. |
| `state` | string | Current lifecycle state (see State Machine). |
| `investigation_context` | string | Brain's investigation context, stored verbatim. |
| `parameters` | object | Operation parameters from the Brain's request. |
| `azure_operation_id` | string | Azure-side resource name for the capture. Same as `task_id` by convention. |
| `storage_account` | string | Azure storage account for capture blobs. |
| `storage_container` | string | Blob container name. Default: `"captures"`. |
| `storage_blob_name` | string | Blob name including `.pcap` extension. |
| `local_pcap_path` | string or null | Local file path after download. Null until DOWNLOADING completes. |
| `semantic_json_path` | string or null | Path to PCAP Engine's semantic JSON output. Null until ANALYZING completes. |
| `report_path` | string or null | Path to PCAP Engine's forensic report. Null until ANALYZING completes. |
| `paired_task_id` | string or null | Task ID of the paired capture (dual-end mode). Null for single-end captures. |
| `cleanup_plan` | array | List of `{ command, executed }` objects. Built at task creation. Each `command` is a Shell command string; `executed` is a boolean. |
| `poll_count` | integer | Number of polls executed so far. |
| `max_polls` | integer | Maximum polls before TIMED_OUT. Default: 20. |
| `shell_audit_ids` | array of strings | References to Shell audit log entries for all commands this task generated. Enables tracing from task to individual Shell executions. |
| `timestamps` | object | ISO 8601 timestamps for each state transition. Null for states not yet reached. |
| `error_detail` | string or null | Error description when task reaches FAILED, TIMED_OUT, or CANCELLED. Null otherwise. |
| `duration_seconds` | float or null | Total wall-clock duration from CREATED to terminal state. Null while task is active. |

**Storage format:**
- Format: JSONL (one JSON object per line)
- File naming: `orchestrator_tasks_{session_id}.jsonl`
- Location: Same directory as Shell audit logs (configurable `task_dir`)
- Write mode: Append-only. Each state transition appends a new record with the full updated task. To reconstruct current state, read the last record for each `task_id`.
- Rotation: One file per session; no intra-session rotation.

---

## Resource Lifecycle

### Cleanup Plan Registration

The cleanup plan is built at task creation time, before the first cloud resource is created. This ensures cleanup instructions exist even if the task fails during provisioning.

| Resource Type | Cleanup Command | When Created | When Cleaned |
|--------------|-----------------|--------------|--------------|
| Azure packet capture | `az network watcher packet-capture delete --resource-group {rg} --name {id}` | Task creation | After analysis or on failure |
| Azure storage blob | `az storage blob delete --account-name {sa} --container-name {c} --name {blob}` | Task creation | After analysis or on failure |
| Local pcap file | `rm {local_path}` | After download | After analysis or on failure |
| Local semantic JSON | `rm {semantic_json_path}` | After analysis | On explicit cleanup request |
| Local forensic report | `rm {report_path}` | After analysis | On explicit cleanup request |

**Note:** Local analysis artifacts (semantic JSON, forensic report) are NOT automatically cleaned up. They are the task's deliverables. Cleanup of these files requires an explicit `cleanup_task` intent from the Brain. Cloud resources and intermediate files (the raw pcap) are cleaned up automatically.

### Cleanup Triggers

| Trigger | Behavior |
|---------|----------|
| Task completed (COMPLETED) | Orchestrator offers cleanup to Brain. Brain can send `cleanup_task` or defer. |
| Task failed (FAILED) | Cleanup executes automatically — cloud resources are ephemeral and should not persist after failure. |
| Task cancelled (CANCELLED) | Cleanup executes for any resources already created. If cancelled before PROVISIONING, no cleanup needed. |
| Task timed out (TIMED_OUT) | Cleanup executes automatically. The capture may still be running on Azure — the delete command stops and removes it. |
| Session ends with active tasks | Detected on next session startup via orphan detection. Cleanup offered to user. |

### Cleanup Execution Rules

1. Cleanup commands go through the Shell one at a time.
2. Each `delete` command is classified RISKY by the Shell → HITL gate activates.
3. Batch approval UX: the Orchestrator presents all cleanup commands as a group with a single reasoning context:

```json
{
  "command": "az network watcher packet-capture delete --resource-group prod-rg --name ghost_web-vm-01_20250115T143200",
  "reasoning": "Cleanup for completed task ghost_web-vm-01_20250115T143200. Investigation: Investigating intermittent 502 errors. Analysis complete — removing transient cloud resources."
}
```

4. Cleanup order: cloud resources first, local files last. Cloud resources cost money; local files are free.
5. Failure is non-fatal. If the user denies a cleanup command, the resource persists. The task is marked `cleanup_status: "partial"`. The user is warned about the orphaned resource.
6. Each cleanup command's `executed` flag is set to `true` after successful execution, regardless of whether subsequent commands succeed or fail.

### Orphan Detection

On startup, the Orchestrator performs two-layer orphan detection:

**Layer 1 — Task Registry scan.** Read JSONL files for the current session and all previous sessions in the task directory. Identify tasks in non-terminal states:

| Condition | Classification | Action |
|-----------|---------------|--------|
| Task in non-terminal state (WAITING, PROVISIONING, etc.) from a previous session | ABANDONED | Flag as orphaned, offer cleanup |
| Task in COMPLETED with `cleanup_status: "pending"` | Needs cleanup | Offer cleanup |
| Task in FAILED/TIMED_OUT with `cleanup_status: null` | Needs cleanup | Offer cleanup |
| Task in DONE or CANCELLED | Terminal | No action |

**Layer 2 — Azure resource scan.** Query Azure directly for resources matching the `ghost_*` naming convention. This catches orphans that exist on Azure but are missing from the Task Registry (e.g., if the registry file was lost or corrupted, or the session crashed before the task was registered):

```json
{
  "command": "az network watcher packet-capture list --resource-group {rg} --query \"[?starts_with(name, 'ghost_')]\" -o json",
  "reasoning": "Startup orphan detection: scanning for ghost_* packet captures that may have been left by a previous session."
}
```

This command is classified SAFE by the Shell (Tier 2: `list` verb) and auto-approved. Any `ghost_*` resources found on Azure that do not correspond to a known task in the Registry are flagged as untracked orphans.

**Layer 3 — Local file age scan.** Scan `local_capture_dir` for files older than `local_artifact_max_age_days` (default: 7). This catches local pcap files, semantic JSONs, and reports that survived cleanup — either because cleanup was denied, partial, or the session crashed before cleanup. Files matching the `ghost_*` naming prefix are flagged as stale Orchestrator artifacts. This layer requires no Azure access and no Task Registry — it operates purely on local filesystem metadata.

| Condition | Action |
|-----------|--------|
| `.pcap` file older than max age, `ghost_*` prefix | Flag as stale capture artifact, offer deletion |
| `_semantic.json` or `_forensic_report.md` older than max age, `ghost_*` prefix | Flag as stale analysis artifact, offer deletion |
| Files without `ghost_*` prefix | Ignored — not Orchestrator-managed |

Deletion of stale local files goes through Shell HITL (`rm` is classified RISKY by Tier 3). The user approves or denies each deletion.

**Bulk cleanup prompt.** All orphaned resources (from all three layers) are presented to the user as a single batch for approval. Each individual deletion still goes through Shell HITL, but the Orchestrator groups them under a single reasoning context: "Startup cleanup: N orphaned resources from previous sessions."

Orphan detection runs once at Orchestrator initialization — not on every `orchestrate()` call. The Orchestrator returns a list of orphaned tasks to the Brain on the first interaction if any are found.

---

## HITL Gate Handling for Async Operations

### Approval Categories

| Phase | Shell Command | Classification | HITL Approval | Rationale |
|-------|--------------|----------------|---------------|-----------|
| Detect target | `az resource show` | SAFE | Auto-approved | Read-only query |
| Verify storage | `az storage container exists` | SAFE | Auto-approved | Read-only existence check |
| Create capture | `az network watcher packet-capture create` | RISKY | Full HITL | Creates cloud resource with cost implications |
| Poll status | `az network watcher packet-capture show` | SAFE | Auto-approved | Read-only query |
| Download blob | `az storage blob download` | RISKY | Full HITL | Writes to local disk; data transfer costs |
| Run PCAP Engine | `python pcap_forensics.py` | SAFE | Auto-approved | Local analysis tool in Tier 1 allowlist |
| Delete capture | `az network watcher packet-capture delete` | RISKY | Full HITL | Destroys cloud resource |
| Delete blob | `az storage blob delete` | RISKY | Full HITL | Destroys cloud data |
| Delete local file | `rm {path}` | RISKY | Full HITL | Tier 3: `rm` is a dangerous pattern |

### User Experience

A single capture task generates **2 critical-path HITL interruptions** (create + download) and **2 optional cleanup HITL interruptions** (delete capture + delete blob):

**Critical path (unavoidable):**

1. **Create** — "Create packet capture `ghost_web-vm-01_...` on web-vm-01 for 60 seconds?"
2. **Download** — "Download capture blob to `/tmp/captures/web-vm-01.pcap`?"

**Cleanup (deferred, opt-in):**

3. **Delete capture** — "Delete packet capture `ghost_web-vm-01_...` from Azure?"
4. **Delete blob** — "Delete storage blob `ghost_web-vm-01_....pcap`?"

Status checks (polls) never interrupt the user. Analysis runs silently (auto-approved). Cleanup is triggered only when the Brain explicitly sends `cleanup_task` — the user is not prompted for cleanup immediately after analysis completes. Cleanup can be deferred to session end or handled by orphan detection on next startup.

**Dual-end captures:** 4 critical-path interruptions (2 per target). Cleanup adds up to 4 more when explicitly requested. The two tasks' HITL prompts may interleave if the Brain checks them in alternation.

**Batch cleanup format:** When presenting cleanup commands, the `reasoning` field groups them:

```
Cleanup for task ghost_web-vm-01_20250115T143200:
  Investigation: Investigating intermittent 502 errors from web-vm-01 to redis-primary
  Analysis: Complete — forensic report generated
  Action: Removing transient cloud resources (2 resources)
```

---

## Dual-End Capture Orchestration

When the Brain requests a capture between two targets, the Orchestrator creates two independent tasks linked by `paired_task_id`:

```
Task A: ghost_web-vm-01_20250115T143200
  target: web-vm-01
  paired_task_id: ghost_redis-primary_20250115T143200

Task B: ghost_redis-primary_20250115T143200
  target: redis-primary
  paired_task_id: ghost_web-vm-01_20250115T143200
```

**Lifecycle rules:**

1. Each task has its own HITL approval cycle. The user may approve one and deny the other.
2. Each task progresses through the state machine independently. One may reach COMPLETED while the other is still WAITING.
3. Neither task proceeds to ANALYZING until both reach COMPLETED — unless the paired task reaches a terminal failure state (FAILED, TIMED_OUT, CANCELLED). If Task A completes but Task B is still WAITING, Task A remains in COMPLETED (download done, analysis deferred).
4. **Paired completion (happy path):** When both tasks reach COMPLETED, the Orchestrator invokes the PCAP Engine in comparison mode:

```json
{
  "command": "python pcap_forensics.py /tmp/captures/web-vm-01.pcap --compare /tmp/captures/redis-primary.pcap --semantic-dir /tmp/captures --report-dir /tmp/captures",
  "reasoning": "Comparing captures from both ends of the path: web-vm-01 → redis-primary. Investigation: Investigating intermittent 502 errors."
}
```

5. **Degraded fallback (one task fails):** If the paired task reaches a terminal failure state (FAILED, TIMED_OUT, CANCELLED), the surviving COMPLETED task automatically falls back to single-end analysis. The Orchestrator runs the PCAP Engine in single-capture mode on the surviving capture rather than leaving it indefinitely waiting for a partner that will never come. The response indicates degraded mode:

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_completed",
  "state": "COMPLETED",
  "paired_task": {
    "task_id": "ghost_redis-primary_20250115T143200",
    "state": "FAILED",
    "error_detail": "Azure provisioning failed"
  },
  "result": {
    "mode": "single_end_fallback",
    "report_path": "/tmp/captures/web-vm-01_forensic_report.md"
  },
  "message": "Destination capture failed. Single-end analysis completed on source capture only."
}
```

6. The comparison report (if both succeed) is stored in both tasks' `report_path` fields.
7. Cleanup for paired tasks is independent — each task's cleanup plan covers only its own resources.

**Response for paired tasks:**

When the Brain checks a paired task, the response includes the partner's status:

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_pending",
  "state": "COMPLETED",
  "paired_task": {
    "task_id": "ghost_redis-primary_20250115T143200",
    "state": "WAITING",
    "poll_count": 5
  },
  "message": "Source capture complete. Waiting for destination capture (redis-primary) to finish before comparison analysis."
}
```

---

## Function Map

```
orchestrate(request)
 ├── [intent: capture_traffic]
 │    ├── _handle_capture_traffic(request)
 │    │    ├── _detect_target_type(target, resource_group)
 │    │    │    └── shell.execute({ "az resource show ..." })
 │    │    ├── _verify_storage_access(storage_account, container)
 │    │    │    └── shell.execute({ "az storage container exists ..." })
 │    │    ├── _build_capture_command(task)
 │    │    ├── _build_cleanup_plan(task)
 │    │    ├── _save_task(task)
 │    │    └── shell.execute({ "az network watcher packet-capture create ..." })
 │    │
 │    └── [dual-end: two targets]
 │         ├── _handle_capture_traffic(request_a)
 │         └── _handle_capture_traffic(request_b)
 │
 ├── [intent: check_task]
 │    ├── _handle_check_task(request)
 │    │    ├── _load_task(task_id)
 │    │    ├── [state: WAITING]
 │    │    │    ├── _poll_azure_status(task)
 │    │    │    │    └── shell.execute({ "az network watcher packet-capture show ..." })
 │    │    │    ├── [Succeeded] → _download_capture(task)
 │    │    │    │    └── shell.execute({ "az storage blob download ..." })
 │    │    │    ├── [Downloaded] → _run_pcap_engine(task)
 │    │    │    │    └── shell.execute({ "python pcap_forensics.py ..." })
 │    │    │    └── [paired task] → _check_paired_ready(task)
 │    │    │         ├── _load_task(paired_task_id)
 │    │    │         ├── [both COMPLETED] → _run_pcap_engine(task, compare=True)
 │    │    │         └── [partner terminal failure] → _run_pcap_engine(task, fallback=True)
 │    │    └── _save_task(task)
 │    │
 │    └── _build_response(task)
 │
 ├── [intent: cancel_task]
 │    ├── _handle_cancel_task(request)
 │    │    ├── _load_task(task_id)
 │    │    ├── _execute_cleanup(task)
 │    │    └── _save_task(task)
 │    └── _build_response(task)
 │
 ├── [intent: list_tasks]
 │    ├── _handle_list_tasks(request)
 │    │    └── _load_all_tasks()
 │    └── _build_list_response(tasks)
 │
 └── [intent: cleanup_task]
      ├── _handle_cleanup_task(request)
      │    ├── _load_task(task_id)
      │    ├── _execute_cleanup(task)
      │    └── _save_task(task)
      └── _build_response(task)
```

---

## Function Signatures

### `CloudOrchestrator.__init__(shell, session_id, task_dir)`

```python
def __init__(self, shell, session_id: str, task_dir: str = "./audit/"):
    """
    Initialize the Cloud Orchestrator.

    Args:
        shell: Safe-Exec Shell instance. Must expose execute({command, reasoning}) -> response.
        session_id: Unique session identifier. Shared with the Shell for audit correlation.
        task_dir: Directory for Task Registry JSONL files. Defaults to the same
                  directory as Shell audit logs.

    On init, runs two-layer orphan detection:
      1. Reads previous session task files for non-terminal tasks and flags as ABANDONED.
      2. Queries Azure for ghost_* resources not tracked in the registry.
    """
```

### `orchestrate(request) -> response`

```python
def orchestrate(self, request: dict) -> dict:
    """
    Main entry point. Dispatches by intent to the appropriate handler.

    Args:
        request: Dict with keys: intent (required), target, parameters,
                 investigation_context, task_id — as specified in the
                 Brain-Orchestrator Interface Contract.

    Returns:
        Response dict with keys: task_id, status, state, investigation_context,
        result, cleanup_status, error_detail, message — as specified in the
        response contract.

    Raises:
        No exceptions. All errors are returned as { status: "error", ... }.
    """
```

### `_handle_capture_traffic(request) -> response`

```python
def _handle_capture_traffic(self, request: dict) -> dict:
    """
    Handle a capture_traffic intent. Creates a new task, detects the target type,
    builds the capture command, registers the cleanup plan, and initiates the
    capture via Shell.

    For dual-end captures (target contains two targets separated by ' to '),
    creates two linked tasks.

    Flow:
        1. Generate task_id (ghost_{target}_{timestamp})
        2. Detect target type via _detect_target_type()
        3. Verify storage access via _verify_storage_access() — fails fast
           if storage account or container is inaccessible
        4. Build cleanup plan via _build_cleanup_plan()
        5. Save task with state CREATED
        6. Send capture create command to Shell
        7. If Shell returns denied → state CANCELLED
        8. If Shell returns completed → state PROVISIONING, return task_pending
        9. If Shell returns error → state FAILED, execute cleanup
    """
```

### `_handle_check_task(request) -> response`

```python
def _handle_check_task(self, request: dict) -> dict:
    """
    Handle a check_task intent. Loads the task, advances its state if possible,
    and returns the current status.

    State advancement per check:
        WAITING → burst-poll Azure (up to poll_burst_limit seconds) →
                  may advance to DOWNLOADING or FAILED
        DOWNLOADING → (should not normally be in this state between checks)
        COMPLETED with paired task → check if paired task is also complete;
                  if paired task failed/timed_out/cancelled → single-end fallback
        COMPLETED without pair → return result

    A single check_task call may advance through multiple states (e.g.,
    WAITING → DOWNLOADING → ANALYZING → COMPLETED) if the burst poll
    detects completion and all subsequent Shell calls succeed.
    """
```

### `_detect_target_type(target, resource_group) -> str`

```python
def _detect_target_type(self, target: str, resource_group: str) -> str:
    """
    Detect whether the target is a VM or AKS cluster via az resource show.

    Args:
        target: Resource name or ID.
        resource_group: Azure resource group containing the target.

    Returns:
        "vm" if Microsoft.Compute/virtualMachines — full capture pipeline available
        "aks" if Microsoft.ContainerService/managedClusters — detection only in Phase 2,
              returns informational response without attempting capture

    Raises:
        Returns None on failure (resource not found, permission denied).
        Caller handles by transitioning task to FAILED.
    """
```

### `_verify_storage_access(storage_account, container) -> bool`

```python
def _verify_storage_access(self, storage_account: str, container: str) -> bool:
    """
    Verify the storage account and container are accessible before creating
    a capture. Sends az storage container exists to Shell (SAFE — auto-approved).

    Fails fast during DETECTING phase rather than failing after a 5-minute
    capture completes and the download is attempted.

    Returns:
        True if the container exists and is accessible.
        False if the storage account is not found, permission denied, or
        the container does not exist.
    """
```

### `_poll_azure_status(task) -> str`

```python
def _poll_azure_status(self, task: dict) -> str:
    """
    Poll Azure for the current provisioning state of the capture.

    Sends az network watcher packet-capture show to Shell.
    Parses provisioningState from output.
    Increments task poll_count.

    Returns:
        Provisioning state string: "Succeeded", "Running", "Failed", etc.
        Returns "error" if the Shell call itself fails.
    """
```

### `_download_capture(task) -> str`

```python
def _download_capture(self, task: dict) -> str:
    """
    Download the capture blob from Azure storage to local disk.

    Sends az storage blob download to Shell (RISKY — HITL gated).
    Retries once on failure.
    Updates task.local_pcap_path on success.

    Returns:
        Local file path on success.
        None on failure (after retry).
    """
```

### `_run_pcap_engine(task) -> dict`

```python
def _run_pcap_engine(self, task: dict) -> dict:
    """
    Run the PCAP Forensic Engine on a downloaded capture.

    Sends python pcap_forensics.py to Shell (SAFE — auto-approved).
    For paired tasks in comparison mode, uses --compare flag.

    Args:
        task: Task dict. Must have local_pcap_path set.
              If paired_task_id is set and both tasks are COMPLETED,
              runs in comparison mode.

    Returns:
        Dict with semantic_json_path and report_path on success.
        None on failure.
    """
```

### `_execute_cleanup(task) -> str`

```python
def _execute_cleanup(self, task: dict) -> str:
    """
    Execute the task's cleanup plan through the Shell.

    Iterates through cleanup_plan entries. Each command goes through
    Shell HITL. Sets executed=true for each successful command.

    Order: cloud resources first, local files last.

    Returns:
        "completed" — all commands executed successfully
        "partial" — some commands denied or failed
        "skipped" — no cleanup plan or all already executed
    """
```

### `_save_task(task)`

```python
def _save_task(self, task: dict):
    """
    Append the current task state to the Task Registry JSONL file.

    The full task dict is serialized as a single JSON line and appended.
    Previous records for the same task_id are NOT modified (append-only).
    To reconstruct current state, consumers read the last record per task_id.
    """
```

### `_load_task(task_id) -> dict`

```python
def _load_task(self, task_id: str) -> dict:
    """
    Load the most recent state of a task from the Task Registry.

    Reads the JSONL file, filters by task_id, returns the last record.

    Returns:
        Task dict if found.
        None if task_id not found.
    """
```

### `_load_all_tasks() -> list`

```python
def _load_all_tasks(self) -> list:
    """
    Load the most recent state of all tasks from the Task Registry.

    Reads the JSONL file. For each unique task_id, keeps only the last record.

    Returns:
        List of task dicts, one per unique task_id.
    """
```

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Azure provisioning fails (`az ... create` returns non-zero) | Task state → FAILED. Error detail extracted from Shell response stderr. Cleanup plan executes (no resources to clean if creation failed outright). |
| Azure provisioning fails mid-capture (poll returns `Failed`) | Task state → FAILED. Error detail from Azure's failure message. Cleanup executes — the capture resource exists and must be deleted. |
| Blob download fails (first attempt) | Retry once after 5 seconds. If second attempt fails, task state → FAILED. Cloud resources still cleaned up. |
| Blob download fails (retry) | Task state → FAILED. Error detail includes both attempt errors. Cloud capture resource cleaned up. |
| PCAP Engine fails (non-zero exit code) | Task state → FAILED. Error detail from stderr. Cloud resources cleaned up. Local pcap file cleaned up. |
| PCAP Engine produces empty output | Task state → COMPLETED. Semantic JSON and report paths recorded even if reports indicate "no anomalies." The PCAP Engine handles empty captures gracefully. |
| User denies HITL — capture creation | Task state → CANCELLED. No resources created, no cleanup needed. Brain receives `{ status: "task_cancelled", state: "CANCELLED" }`. |
| User denies HITL — blob download | Task state → CANCELLED. Capture resource on Azure cleaned up via Shell HITL (another approval). |
| User denies HITL — cleanup deletion | Specific cleanup command marked as not executed. Task cleanup_status → "partial". User warned: "Resource {name} not deleted. It may incur charges." |
| Unknown task_id in check_task | Return `{ status: "error", error: "unknown_task", message: "No task found with ID: ..." }`. No task state change. |
| Unknown intent | Return `{ status: "error", error: "unknown_intent", message: "Unsupported intent: ..." }`. No task created. |
| Storage account missing or inaccessible | Caught early during DETECTING phase via `az storage container exists` smoke test. Task state → FAILED before any resources are created. No cleanup needed. If the smoke test passes but download later fails (e.g., permissions revoked mid-capture), the existing DOWNLOADING failure path handles it. |
| Resource group not found | Task state → FAILED during DETECTING. Error detail from Azure CLI. No resources created. |
| Network Watcher not enabled in region | Task state → FAILED during PROVISIONING. Error detail: "NetworkWatcherNotEnabled." No capture to clean up. |
| Disk full during blob download | Task state → FAILED. Shell returns OS error. Cloud resources cleaned up. Partial local file cleaned up. |
| Task Registry file not writable | Log warning to stderr. Task proceeds in-memory only. State is lost on process exit. Non-fatal — matches Shell's behavior for audit log write failures. |
| Concurrent check_task for same task | No thread safety issue — the Orchestrator is single-threaded. Second call reads the state updated by the first. |
| check_task on a terminal state (DONE) | Return current state with all result fields. No state change. Idempotent. |
| cancel_task on a terminal state | Return current state unchanged. No error. Idempotent. |

---

## Configuration

All configuration is via constructor parameters. No configuration file, no environment variables (except Azure CLI's own authentication).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `task_dir` | string | `"./audit/"` | Directory for Task Registry JSONL files. Should match Shell's audit directory for co-location. |
| `max_polls` | integer | `20` | Maximum poll attempts before TIMED_OUT. 20 polls ≈ 8.5 minutes with exponential backoff. |
| `initial_poll_interval` | integer | `5` | First poll interval in seconds. Subsequent intervals: `min(initial * 2^(n-1), max_poll_interval)`. |
| `max_poll_interval` | integer | `30` | Cap on poll interval in seconds. |
| `local_capture_dir` | string | `"/tmp/captures"` | Directory for downloaded pcap files and analysis outputs. Created on first use. |
| `storage_container` | string | `"captures"` | Azure Blob Storage container name for capture files. |
| `capture_name_prefix` | string | `"ghost"` | Prefix for all Orchestrator-created Azure resources. Enables orphan detection. |
| `poll_burst_limit` | integer | `45` | Maximum seconds to spend burst-polling within a single `check_task` call. The Orchestrator loops (poll → sleep → poll) until the operation completes or this limit is reached. Capped at 45 seconds to stay well within typical LLM session timeouts (60-120s). |
| `local_artifact_max_age_days` | integer | `7` | Maximum age in days for local capture artifacts in `local_capture_dir`. Files older than this with `ghost_*` prefix are flagged as stale during Layer 3 orphan detection. |

---

## Console Output

Example progress output for a full capture lifecycle, showing Shell HITL prompts interleaved with Orchestrator status messages:

```
[Cloud Orchestrator] New task: ghost_web-vm-01_20250115T143200
      Intent: capture_traffic
      Target: web-vm-01 (detecting type...)

[Shell] SAFE — auto-approved: az resource show --ids /subscriptions/.../web-vm-01 --query type -o tsv
      Result: Microsoft.Compute/virtualMachines

[Cloud Orchestrator] Target type: VM. Using Network Watcher packet capture.
      Capture duration: 60 seconds
      Storage: forensics-sa/captures

┌──────────────────────────────────────────────────────────────┐
│  RISKY COMMAND — Approval Required                           │
│                                                              │
│  Command:   az network watcher packet-capture create         │
│             --vm web-vm-01                                   │
│             --resource-group prod-rg                          │
│             --name ghost_web-vm-01_20250115T143200            │
│             --storage-account forensics-sa                    │
│             --time-limit 60                                   │
│  Reason:    Creating packet capture for investigation:       │
│             Investigating intermittent 502 errors from       │
│             web-vm-01 to redis-primary                       │
│  Risk:      Tier 2: Azure verb 'create' is classified RISKY  │
│                                                              │
│  [A] Approve    [D] Deny    [M] Modify                      │
└──────────────────────────────────────────────────────────────┘

[Cloud Orchestrator] Task ghost_web-vm-01_20250115T143200: PROVISIONING
      Status: Packet capture starting. Check back in ~5-10 seconds.

--- (Brain does other work, then sends check_task) ---

[Shell] SAFE — auto-approved: az network watcher packet-capture show --name ghost_web-vm-01_20250115T143200
[Cloud Orchestrator] Poll 3/20: provisioningState = Running

--- (Brain checks again later) ---

[Shell] SAFE — auto-approved: az network watcher packet-capture show --name ghost_web-vm-01_20250115T143200
[Cloud Orchestrator] Poll 8/20: provisioningState = Succeeded

┌──────────────────────────────────────────────────────────────┐
│  RISKY COMMAND — Approval Required                           │
│                                                              │
│  Command:   az storage blob download                         │
│             --account-name forensics-sa                       │
│             --container-name captures                         │
│             --name ghost_web-vm-01_20250115T143200.pcap       │
│             --file /tmp/captures/web-vm-01.pcap               │
│  Reason:    Downloading capture for analysis. Investigation: │
│             Investigating intermittent 502 errors             │
│  Risk:      Tier 2: verb 'download' is classified RISKY      │
│                                                              │
│  [A] Approve    [D] Deny    [M] Modify                      │
└──────────────────────────────────────────────────────────────┘

[Cloud Orchestrator] Download complete: /tmp/captures/web-vm-01.pcap (2.4 MB)

[Shell] SAFE — auto-approved: python pcap_forensics.py /tmp/captures/web-vm-01.pcap --semantic-dir /tmp/captures --report-dir /tmp/captures

[Cloud Orchestrator] Task ghost_web-vm-01_20250115T143200: COMPLETED
      Semantic JSON: /tmp/captures/web-vm-01_semantic.json
      Forensic Report: /tmp/captures/web-vm-01_forensic_report.md
      Duration: 5m 30s
      Cleanup: 2 cloud resources pending deletion
```

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Non-existent VM (target not found in Azure) | Detection phase fails. `az resource show` returns non-zero. Task state → FAILED with error detail: "Resource not found." No resources to clean up. |
| VM exists but Network Watcher not enabled in its region | Capture creation fails. Azure returns `NetworkWatcherNotEnabled`. Task state → FAILED. No capture resource created. |
| Concurrent captures on the same VM | Each gets a unique `task_id` (different timestamps). Azure allows multiple concurrent captures on the same VM. Both tracked independently in the Task Registry. |
| Brain requests check_task before first poll | Task is in PROVISIONING or WAITING. Orchestrator sends the first poll command. Normal behavior. |
| Brain sends check_task rapidly (faster than backoff) | Orchestrator polls Azure on every check_task regardless of interval. Each poll is a SAFE Shell call — no HITL, minimal cost. The backoff interval is advisory, not enforced. |
| 0-byte capture file (no traffic during capture window) | Blob downloads successfully (0 bytes). PCAP Engine handles empty pcaps: generates a report noting "no traffic captured." Task state → COMPLETED. |
| Capture completes but blob not yet available | `provisioningState: "Succeeded"` but blob download fails. Orchestrator retries once. If still unavailable, task state → FAILED. Azure sometimes has a brief delay between capture completion and blob availability. |
| Empty Task Registry file (first task in session) | `_load_all_tasks()` returns empty list. `_load_task()` returns None. Normal behavior — file is created on first `_save_task()`. |
| Task Registry file corrupted (invalid JSON line) | Skip corrupted lines during read. Log warning. Return tasks from valid lines only. Append-only writes are unlikely to corrupt existing lines. |
| Network lost during polling | `az ... show` fails (Shell returns non-zero). Orchestrator treats as a poll failure, does not advance state. Next poll may succeed when network returns. Does not count as a "Failed" provisioningState — only Azure-reported failures trigger FAILED. |
| Disk full during PCAP Engine analysis | PCAP Engine fails with OS error. Task state → FAILED. Cloud resources cleaned up. Partial local files cleaned up. |
| Paired task: one target is VM, other is AKS | AKS capture is not supported in Phase 2. If one target detects as AKS, that task returns an informational message ("AKS capture pipeline not yet available"). The VM task can proceed independently for single-end analysis. |
| Paired task: one fails/cancels, other completed | Surviving task automatically falls back to single-end analysis. Response includes `mode: "single_end_fallback"` and the failed partner's status. No manual intervention needed. |
| Task ID collision (same target, same second) | Extremely unlikely given second-precision timestamps. If it occurs, the second task overwrites the first in the Task Registry (last-record-wins). Mitigation: none — the probability is negligible for a single-agent system. |
| Brain sends capture_traffic with no storage_account | Return `{ status: "error", error: "missing_parameter", message: "storage_account is required" }`. No task created. |
| Cleanup command refers to already-deleted resource | Azure CLI returns "not found." Shell returns non-zero exit code. Orchestrator treats as successful cleanup (resource is gone regardless of how). `executed` flag set to `true`. |
