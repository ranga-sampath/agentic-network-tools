# Architecture: Cloud Orchestrator

## Design Decisions

| Decision | Choice | Rationale (per sw-principles) |
|----------|--------|-------------------------------|
| Placement | Layer between Brain and Shell — wraps Shell without modifying it | Per sw-principles: additive feature design — new features as new code paths, not refactors. The Shell is a working component; the Orchestrator composes around it rather than extending it. |
| Async Model | Task Registry with polling (not webhooks, not async Shell) | Per sw-principles: simplicity over sophistication. Polling is stateless between calls, requires no callback infrastructure, and keeps the Shell's synchronous safety model intact. Webhooks would require a listener process, a public endpoint, and a new failure mode. |
| Task State Store | JSONL file on disk (not database, not in-memory only) | Per sw-principles: intermediate artifacts to disk. JSONL preserves task state across polls, survives process restarts, and is human-readable via `jq`. In-memory state vanishes on crash; a database adds deployment complexity with no benefit for a single-agent system. |
| Instrumentation Decision | Runtime detection via `az resource show` (not pre-configured) | Per sw-principles: avoid over-engineering. The target type determines the instrumentation method. Detecting at runtime via a single Azure CLI call eliminates configuration files, target inventories, and stale mappings. |
| Cleanup Strategy | Registered cleanup plans, best-effort execution through Shell HITL | Per sw-principles: confirm destructive actions. Every cloud resource created gets a cleanup plan registered at creation time. Cleanup commands go through the Shell's HITL gate — the user approves each deletion. Best-effort because a denied cleanup is not a fatal error. |
| Architecture | Library consumed by Brain (same as Shell) — `orchestrate(request) -> response` | Per sw-principles: monolithic until proven otherwise. Same pattern as the Shell: a function the Brain imports and calls. No network boundary, no serialization, no deployment complexity. |
| PCAP Engine Integration | Invoked via Shell (not imported directly) | Per sw-principles: stages with clear boundaries. The PCAP Engine is a command-line tool. Importing it as a library would create a tight coupling the architecture does not need. Invoking through the Shell means PCAP Engine execution gets classified, gated, logged, and output-processed like every other command. |
| Polling Interval | Exponential backoff with cap (5s → 10s → 20s → 30s → 30s...) | Per sw-principles: cost-consciousness first. Aggressive polling wastes API calls; fixed-interval polling is either too fast (wasted calls) or too slow (unnecessary latency). Exponential backoff starts responsive and settles to a sustainable rate. |
| Single-file | `cloud_orchestrator.py` | Per sw-principles: single-file until proven otherwise. The Orchestrator is a sequencer with a task registry — one file with clear function boundaries. No package structure, no `__init__.py` until there is a concrete reason to split. |

**Why a separate layer, not a Shell extension?** The Shell's architecture.md explicitly lists "Async execution / task queuing" in its intentional omissions table. That omission is deliberate — the Shell's synchronous blocking model is a safety feature, not a limitation. The Orchestrator composes around the Shell rather than modifying it: it decomposes long-running cloud operations into sequences of short, synchronous Shell calls, each governed by the Shell's HITL safety model. The Shell does not know the Orchestrator exists.

---

## System Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AI Brain (LLM)                                │
│                                                                         │
│   Sends: { intent, target, parameters, investigation_context }          │
│   Receives: { task_id, status, state, result, investigation_context }   │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Cloud Orchestrator                                │
│                                                                         │
│   Decomposes async operations into synchronous Shell call sequences     │
│                                                                         │
│   ┌──────────────┐    ┌───────────────┐    ┌────────────────────────┐   │
│   │   Dispatch    │    │  Task Lifecycle│    │  Command Translation  │   │
│   │   by Intent   │───>│  State Machine │───>│  Intent → Shell Calls │   │
│   └──────────────┘    └───────────────┘    └────────────────────────┘   │
│          │                                          │                    │
│          │          ┌──────────────────┐             │                    │
│          └─────────>│  Task Registry   │<────────────┘                    │
│                     │  (JSONL file)    │                                  │
│                     └──────────────────┘                                  │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Safe-Exec Shell                                 │
│                                                                         │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌──────────────────┐  │
│  │  Stage 1  │   │  Stage 2  │   │  Stage 3  │   │     Stage 4      │  │
│  │ CLASSIFY  │──>│   GATE    │──>│  EXECUTE  │──>│ PROCESS OUTPUT   │  │
│  │           │   │  (HITL)   │   │           │   │ truncate + redact│  │
│  └───────────┘   └───────────┘   └───────────┘   └──────────────────┘  │
│                                                                         │
│  (unchanged from Phase 1 — Shell is unaware Orchestrator exists)        │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Infrastructure                                   │
│                                                                         │
│   ┌───────────────────────┐    ┌────────────────────────────────────┐   │
│   │    Azure Cloud        │    │       Local Tools                  │   │
│   │                       │    │                                    │   │
│   │  az network watcher   │    │  pcap_forensics.py                │   │
│   │  az storage blob      │    │  tshark -r, tcpdump -r            │   │
│   │  az resource show     │    │  ping, traceroute, dig            │   │
│   └───────────────────────┘    └────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

The Orchestrator sits between the Brain and Shell as a new layer. It translates high-level intents (like "capture traffic between these two VMs") into sequences of Shell calls. The Shell's four-stage pipeline — Classify, Gate, Execute, Process — remains unchanged. The Shell processes each command from the Orchestrator exactly as it would process a command from the Brain directly.

---

## The Async Bridge Pattern

The core architectural contribution of the Cloud Orchestrator. Azure operations take 30-90 seconds to provision and 5-10 minutes for packet captures to complete. The Shell is synchronous and blocking by design — a safety feature. The Orchestrator bridges this gap by decomposing every async cloud operation into a sequence of discrete phases, each a standard synchronous Shell call.

### The Decomposition Principle

Every async cloud operation becomes a sequence of four phase types:

1. **Initiate** — One Shell call that starts the cloud operation. Classification: RISKY (creates a resource). HITL-gated. The Shell blocks until the user approves, then executes. The command returns immediately with a provisioning status — the cloud operation continues asynchronously on Azure's side.

2. **Poll** — Repeated Shell calls that check the operation's status. Classification: SAFE (read-only `show` verb). Auto-approved. Each poll is a complete Shell call cycle (classify → gate → execute → process). The Orchestrator examines the output and decides whether to poll again or advance to the next phase. To avoid burning an LLM turn per poll, a single `check_task` call can burst-poll internally — looping (poll → sleep → poll) for a bounded window before returning to the Brain.

3. **Act on completion** — One or more Shell calls that consume the operation's result. A mix of SAFE and RISKY commands (e.g., downloading a blob is RISKY, running the PCAP Engine is SAFE). Each command goes through the full Shell pipeline independently.

4. **Clean up** — One or more Shell calls that remove transient cloud resources. Classification: RISKY (delete verb). HITL-gated. The user approves each deletion. Cleanup is best-effort — a denied deletion does not fail the task.

**Key constraint:** The Orchestrator never bypasses the Shell. Every command — initiate, poll, act, clean up — flows through the Shell's classify → gate → execute → process pipeline. The Orchestrator is a sequencer, not an executor. It decides *what* to run and *when*; the Shell decides *whether* to run it and *how* to process the output.

**Shell blocking scope:** The Shell is blocked only for the duration of each individual command execution (typically 1-3 seconds for a status check, 10-30 seconds for a provisioning call). It is NOT blocked for the duration of the overall cloud operation (5-10 minutes for a capture). Between Orchestrator Shell calls, the Shell is completely free — the Brain or user can run `ping`, `nslookup`, or any other command directly through the Shell while an Orchestrator task is in a WAITING state.

### Task Registry

A local JSONL file that preserves task state across polls. Each task is a single JSON object appended to the file when created and re-appended (with updated state) after each state transition.

Schema preview (full schema in design.md):

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "intent": "capture_traffic",
  "state": "WAITING",
  "azure_operation_id": "packet-capture-abc123",
  "cleanup_plan": [
    { "command": "az network watcher packet-capture delete ...", "executed": false },
    { "command": "az storage blob delete ...", "executed": false }
  ],
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "timestamps": {
    "created": "2025-01-15T14:32:00Z",
    "last_polled": "2025-01-15T14:33:30Z"
  }
}
```

The Task Registry is append-only during a session. The Orchestrator reads the full file to reconstruct current task states and appends new records as tasks transition. This matches the Shell's audit log convention: JSONL, append-only, one file per session.

### Brain Interaction Flow

A packet capture lifecycle from the Brain's perspective:

1. Brain sends `{ intent: "capture_traffic", target: "web-vm-01", ... }` to the Orchestrator.
2. Orchestrator detects target type via Shell call (`az resource show`). Shell classifies as SAFE, auto-approves, executes.
3. Orchestrator builds the capture command and sends it to the Shell. Shell classifies as RISKY, presents HITL prompt to user.
4. User approves. Shell executes `az network watcher packet-capture create`. Azure returns a provisioning ID.
5. Orchestrator registers the task in the Task Registry with state PROVISIONING, records the cleanup plan.
6. Orchestrator returns `{ task_id: "ghost_web-vm-01_...", status: "task_pending", state: "PROVISIONING" }` to Brain.
7. Brain continues other work. Eventually asks: `{ intent: "check_task", task_id: "ghost_web-vm-01_..." }`.
8. Orchestrator sends a poll command to Shell (`az network watcher packet-capture show`). Shell classifies as SAFE, auto-approves.
9. Azure returns `provisioningState: "Running"`. Orchestrator updates task state to WAITING, returns `{ status: "task_pending", state: "WAITING" }` to Brain.
10. Brain asks again later. Orchestrator polls again. Azure returns `provisioningState: "Succeeded"`.
11. Orchestrator advances to download phase: sends `az storage blob download` to Shell. Shell classifies as RISKY, presents HITL.
12. User approves. Blob downloads to local disk. Orchestrator advances to analysis phase.
13. Orchestrator sends `python pcap_forensics.py {path}` to Shell. Shell classifies as SAFE (Tier 1 allowlist), auto-approves.
14. PCAP Engine produces semantic JSON and forensic report. Orchestrator records file paths in the task.
15. Orchestrator returns `{ status: "task_completed", state: "COMPLETED", result: { report_path, semantic_json_path } }` to Brain.
16. Orchestrator offers cleanup. Brain sends `{ intent: "cleanup_task", task_id: "..." }`. Cleanup commands go through Shell HITL.

The Brain never waits synchronously for the full duration of a cloud operation. It sends the intent, gets a task ID, and checks back when ready. Each `check_task` call can internally burst-poll (loop for up to 45 seconds with exponential backoff) before returning, so the Brain does not need to burn an LLM turn for every individual poll. There is no background thread — the Brain's `check_task` calls drive all polling.

---

## State Continuity

Cloud operations create a temporal gap between when the Brain requests an action and when the result arrives. A packet capture requested at 14:32 may not complete until 14:42. During those 10 minutes, the Brain may have processed other information, engaged the user in conversation, or run other diagnostic commands. When the capture finally completes, the Brain needs to remember *why* it requested it and *what* it was looking for.

The Task Registry preserves this investigation context:

| Field | Purpose |
|-------|---------|
| `intent` | The original request type (`capture_traffic`) |
| `investigation_context` | What the Brain was investigating when it made the request — the symptoms, hypotheses, and diagnostic thread. Example: "Investigating intermittent 502 errors from web-vm-01 to redis-primary. Hypothesis: TCP retransmissions due to NSG misconfiguration." |
| `target` | The infrastructure target (VM name, resource ID) |
| `parameters` | The specific parameters used (duration, storage account, resource group) |
| `result` | File paths to artifacts produced (semantic JSON, forensic report) |

When the Brain sends a `check_task` request, the Orchestrator returns the full context alongside the status:

```json
{
  "task_id": "ghost_web-vm-01_20250115T143200",
  "status": "task_completed",
  "state": "COMPLETED",
  "investigation_context": "Investigating intermittent 502 errors from web-vm-01 to redis-primary",
  "result": {
    "semantic_json_path": "/tmp/captures/web-vm-01_semantic.json",
    "report_path": "/tmp/captures/web-vm-01_forensic_report.md"
  }
}
```

This allows the Brain to resume reasoning without losing state. The Orchestrator acts as external memory for the Brain's async operations — the Brain stores its investigative thread in the task at creation time and retrieves it when the task completes.

---

## Instrumentation Decision Logic

### Target Type Detection

The Orchestrator does not require pre-configured target inventories. It detects the target type at runtime using a single Azure CLI call:

```
az resource show --ids <resource_id> --query type -o tsv
```

This returns the Azure resource type string, which determines the instrumentation method.

| Target Type | Azure Resource Type | Detection Command | Instrumentation Method |
|-------------|--------------------|--------------------|------------------------|
| Azure VM | `Microsoft.Compute/virtualMachines` | `az resource show --ids {id} --query type -o tsv` | Network Watcher packet capture — `az network watcher packet-capture create` |
| AKS Pod | `Microsoft.ContainerService/managedClusters` | `az resource show --ids {id} --query type -o tsv` | *Deferred — detection only in Phase 2* |

The detection command is classified SAFE by the Shell (Tier 2: `show` verb) and auto-approved. The Orchestrator parses the output and selects the appropriate instrumentation pipeline.

**AKS instrumentation is detection-only in Phase 2.** The Orchestrator detects AKS targets and reports the type, but the full AKS capture pipeline (ephemeral debug containers, capture data exfiltration from pod-local storage, volume mounting) is deferred to a future phase. Unlike the VM path — where Network Watcher automatically pipes captures to Azure Blob Storage — AKS capture requires solving a data exfiltration problem: `kubectl debug` dumps packets to the container's ephemeral filesystem, not to blob storage. This needs its own instrumentation pipeline and is out of scope for Phase 2. If an AKS target is detected, the Orchestrator returns an informational response indicating the target type without attempting capture.

**Why runtime detection?** Pre-configured target mappings grow stale. VMs are created and deleted. AKS clusters scale. A runtime check always reflects the current state of the environment. Per sw-principles: avoid over-engineering — build for current needs, not hypothetical inventories.

### Dual-End Capture

Network forensics often requires capturing traffic at both ends of a conversation — the source and the destination. The Orchestrator supports this by creating two independent tasks, one for each end:

```
Brain: "Capture traffic between web-vm-01 and redis-primary"
                              │
                              ▼
              ┌───────────────────────────────┐
              │       Orchestrator             │
              │                               │
              │  Task A: web-vm-01 (source)   │
              │  Task B: redis-primary (dest) │
              │                               │
              │  A.paired_task_id = B.task_id  │
              │  B.paired_task_id = A.task_id  │
              └───────────────────────────────┘
```

Each task is independent: it has its own HITL approval cycle, its own polling cadence, and its own cleanup plan. Neither proceeds to analysis until both complete — unless one fails, in which case the surviving task falls back to single-end analysis automatically. When both tasks reach COMPLETED, the Orchestrator invokes the PCAP Engine in comparison mode:

```
python pcap_forensics.py {source_pcap} --compare {dest_pcap}
```

This produces a comparative forensic report that identifies where packets are being lost, corrupted, or delayed between the two capture points.

---

## The Sidecar Pipeline

End-to-end sequence from "Brain requests capture" to "Report returned," showing every Shell interaction:

1. Brain sends `{ intent: "capture_traffic", target: "web-vm-01" }` to Orchestrator.
2. Orchestrator sends target type detection to Shell: `az resource show --ids /subscriptions/.../web-vm-01 --query type -o tsv`.
3. Shell classifies SAFE (Tier 2: `show`), auto-approves, returns `Microsoft.Compute/virtualMachines`.
4. Orchestrator verifies storage access: `az storage container exists --account-name forensics-sa --name captures --auth-mode login -o tsv`.
5. Shell classifies SAFE (Tier 2: `exists`), auto-approves. Returns `True`. (If `False` or error, task fails immediately — no resources created.)
6. Orchestrator selects VM capture pipeline, registers task with cleanup plan.
7. Orchestrator sends capture creation to Shell: `az network watcher packet-capture create --vm web-vm-01 --name ghost_web-vm-01_20250115T143200 --storage-account forensics-sa --time-limit 60`.
8. Shell classifies RISKY (Tier 2: `create`), presents HITL prompt. User approves.
9. Azure returns provisioning state. Orchestrator updates task state to PROVISIONING, returns `task_pending` to Brain.
10. Brain later sends `{ intent: "check_task" }`. Orchestrator polls: `az network watcher packet-capture show --name ghost_web-vm-01_20250115T143200`.
11. Shell classifies SAFE (Tier 2: `show`), auto-approves. Azure returns `provisioningState: "Running"`. Task state → WAITING.
12. (Repeat step 10-11 with exponential backoff until `provisioningState: "Succeeded"`)
13. Orchestrator sends blob download to Shell: `az storage blob download --account-name forensics-sa --container-name captures --name ghost_web-vm-01_20250115T143200.pcap --file /tmp/captures/web-vm-01.pcap`.
14. Shell classifies RISKY (Tier 2: `download` — not a read-only verb), presents HITL prompt. User approves.
15. Orchestrator sends PCAP Engine to Shell: `python pcap_forensics.py /tmp/captures/web-vm-01.pcap --semantic-dir /tmp/captures --report-dir /tmp/captures`.

**Shell classification at each step:**

| Step | Shell Command | Classification | HITL? | Rationale |
|------|--------------|---------------|-------|-----------|
| 2 | `az resource show` | SAFE | No | Tier 2: `show` is a read-only verb |
| 4 | `az storage container exists` | SAFE | No | Tier 2: `exists` is a read-only verb |
| 7 | `az network watcher packet-capture create` | RISKY | Yes | Tier 2: `create` is a mutative verb |
| 10 | `az network watcher packet-capture show` | SAFE | No | Tier 2: `show` is a read-only verb |
| 13 | `az storage blob download` | RISKY | Yes | Tier 2: `download` is not in SAFE verb list |
| 15 | `python pcap_forensics.py` | SAFE | No | Tier 1: `pcap_forensics.py` is in the command allowlist |
| Cleanup: capture delete | `az network watcher packet-capture delete` | RISKY | Yes | Tier 2: `delete` is a mutative verb |
| Cleanup: blob delete | `az storage blob delete` | RISKY | Yes | Tier 2: `delete` is a mutative verb |

**Total HITL interruptions per capture task:** 4 (create, download, delete capture, delete blob). All status checks are auto-approved and invisible to the user.

---

## Integration with Phase 1 Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Network Ghost Agent                                  │
│                                                                              │
│  ┌─────────────┐     ┌────────────────┐     ┌──────────────┐                │
│  │   AI Brain  │────>│    Cloud       │────>│  Safe-Exec   │                │
│  │   (LLM)     │<────│  Orchestrator  │<────│  Shell       │                │
│  │             │     │               │     │              │                │
│  │             │     │  (new in       │     │  (unchanged  │                │
│  │             │     │   Phase 2)     │     │   from       │                │
│  │             │     │               │     │   Phase 1)   │                │
│  └──────┬──────┘     └───────┬────────┘     └──────┬───────┘                │
│         │                    │                      │                         │
│         │                    │                      │                         │
│         │                    ▼                      ▼                         │
│         │            ┌──────────────┐       ┌──────────────┐                 │
│         │            │ Task Registry │       │  Audit Log   │                 │
│         │            │ (JSONL file)  │       │ (JSONL file) │                 │
│         │            └──────────────┘       └──────────────┘                 │
│         │                                          │                         │
│         │                                          ▼                         │
│         │                                  ┌────────────────────────┐        │
│         │                                  │  Infrastructure        │        │
│         │                                  │                        │        │
│         │                                  │  Azure CLI             │        │
│         │                                  │  PCAP Forensic Engine  │        │
│         │                                  │  Local tools           │        │
│         │                                  └────────────────────────┘        │
│         │                                                                    │
│         │            ┌──────────────┐                                        │
│         └───────────>│ Memory Layer │                                        │
│          writes      │              │                                        │
│          context     │  reads audit │                                        │
│                      │  logs + task │                                        │
│                      │  registry    │                                        │
│                      └──────────────┘                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Coupling rules:**

| Relationship | Direction | Mechanism |
|-------------|-----------|-----------|
| Brain → Orchestrator | Function call | `orchestrate(request) -> response` — same calling pattern as Brain → Shell |
| Brain → Shell (direct) | Function call | `shell.execute(request) -> response` — Brain can still call Shell directly for simple commands |
| Orchestrator → Shell | Function call | `shell.execute({command, reasoning})` — same contract as Brain → Shell. The Shell cannot distinguish Orchestrator calls from Brain calls. |
| Shell → Orchestrator | Never | Shell is unaware the Orchestrator exists. No code changes to Shell for Phase 2. |
| Orchestrator → PCAP Engine | Never directly | PCAP Engine is invoked through Shell as a subprocess command, not imported as a Python library. |
| Shell → PCAP Engine | Subprocess | Shell executes `python pcap_forensics.py` via `subprocess.run()` — classified as SAFE (Tier 1 allowlist). |
| Memory Layer → Task Registry | Read | Memory layer reads Orchestrator's JSONL files for persistent context, same pattern as reading Shell audit logs. |
| Orchestrator → Memory | Never | Orchestrator does not write to Memory's data structures. It writes to its own Task Registry. |

**Shell compatibility guarantee:** The Orchestrator uses the exact same `execute()` interface that the Brain uses. The Shell requires no code changes, no configuration changes, and no awareness of the Orchestrator for Phase 2. If the Orchestrator were removed, the Brain could still call the Shell directly — the system degrades gracefully to Phase 1 behavior.

**Brain routing:** The Brain decides whether to call the Orchestrator or the Shell directly based on the operation type:
- Simple, synchronous commands (diagnostics, queries) → Shell directly
- Long-running cloud operations (packet captures, provisioning) → Orchestrator

The Orchestrator does not intercept or proxy Shell calls. It is an additional tool available to the Brain, not a replacement for the Shell.

---

## Error Handling Strategy

| Error | Behavior | Impact on Task |
|-------|----------|----------------|
| Azure provisioning fails | Shell returns non-zero exit code. Orchestrator parses error from stderr. | Task state → FAILED. Cleanup plan executes (remove any partially-created resources). Error detail recorded in task. |
| Blob download fails | Shell returns non-zero exit code. Orchestrator retries once (single retry). | If retry succeeds, continue normally. If retry fails, task state → FAILED. Cloud resources still cleaned up. |
| PCAP Engine fails | Shell returns non-zero exit code with PCAP Engine's error output. | Task state → FAILED. Cloud resources still cleaned up (capture and blob deleted). Local partial files removed. |
| User denies HITL — capture creation | Shell returns `{ status: "denied" }`. | Task state → CANCELLED. No resources were created, so no cleanup needed. Denial reason recorded. |
| User denies HITL — blob download | Shell returns `{ status: "denied" }`. | Task state → CANCELLED. Capture resource on Azure still cleaned up (delete command sent through Shell HITL). |
| User denies HITL — cleanup deletion | Shell returns `{ status: "denied" }`. | Cleanup marked partial. Resource remains. User warned about orphaned resource. Non-fatal — the task result is still valid. |
| Session ends with pending tasks | Orchestrator cannot detect this (no background thread). | On next startup, orphan detection scans both the Task Registry (for non-terminal tasks) and Azure itself (for `ghost_*` resources). Orphaned resources are flagged and bulk cleanup is offered to the user. |
| Polling timeout (max polls exceeded) | 20 polls reached (~10 minutes elapsed). | Task state → TIMED_OUT. Cleanup plan executes. Error detail: "Azure operation did not complete within polling window." |
| Target type detection fails | `az resource show` returns error (resource not found, permission denied). | Task state → FAILED immediately. No resources created, no cleanup needed. |
| Storage account not accessible | Caught early: `az storage container exists` smoke test during DETECTING phase fails before any resources are created. | Task state → FAILED immediately. No resources created, no cleanup needed. |
| Unknown intent | Brain sends an intent not in the supported set. | Orchestrator returns `{ status: "error", error: "unknown_intent" }`. No task created. |

**Error philosophy:** Errors during cloud operations are expected, not exceptional. Azure resources fail to provision, blobs fail to download, permissions change. The Orchestrator treats every error as a state transition (to FAILED, TIMED_OUT, or CANCELLED) and always attempts cleanup. The Brain receives a structured error response and decides whether to retry the entire operation.

---

## What This Architecture Intentionally Omits

| Omitted | Why |
|---------|-----|
| Modifying the Safe-Exec Shell | The Shell's synchronous blocking model is a safety feature. Per sw-principles: stability over features. The Orchestrator composes around it. Adding async capabilities to the Shell would undermine its safety guarantees. |
| Webhook-based notifications | Webhooks require a listener process, a public endpoint, network reachability from Azure, and a callback authentication mechanism. Polling is simpler, works through firewalls, and requires no infrastructure beyond the CLI. Per sw-principles: simplicity over sophistication. |
| Parallel command execution | The Shell processes one command at a time, synchronously. The Orchestrator respects this constraint. Parallel execution would require the Shell to support concurrency, violating its sequential safety model. |
| Database for task state | A database adds deployment complexity (installation, schema management, connection pooling) with no benefit for a single-agent system producing tens of tasks per session. Per sw-principles: monolithic until proven otherwise. JSONL on disk is sufficient. |
| Streaming / real-time capture analysis | Packet captures are analyzed after completion, not during. Streaming analysis would require a persistent connection to the capture source, real-time protocol parsing, and incremental report generation — significant complexity for marginal diagnostic value. The PCAP Engine already produces comprehensive reports from complete captures. |
| Multi-cloud support (AWS, GCP) | Phase 2 targets Azure. Adding AWS VPC Traffic Mirroring or GCP Packet Mirroring would triple the instrumentation logic with different APIs, different state models, and different cleanup procedures. Per sw-principles: build for current needs, not hypothetical future needs. The architecture accommodates future providers via the target type detection pattern (new resource types map to new instrumentation pipelines). |
| Automatic retry with backoff (except blob download) | Retry logic is a policy decision. Most Azure provisioning failures are not transient — retrying `az network watcher packet-capture create` after a permission error produces the same error. The single-retry exception for blob downloads addresses the one common transient failure (network hiccup during large file transfer). For all other failures, the Orchestrator reports the error and the Brain decides. Per sw-principles: the Shell does not retry; the Orchestrator follows the same principle. |
| Background execution threads | Background threads would allow the Orchestrator to poll Azure independently of the Brain's requests. This creates concurrency (thread safety for the Task Registry), invisible state changes (task completes while the Brain is doing something else), and violates the principle that the Brain drives all activity. The Brain's conversational loop is the polling loop. |
