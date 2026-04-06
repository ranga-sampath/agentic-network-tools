# Architecture — Effective Network Inspector

> Document order: **Requirements → Architecture (this document) → Design → Code**
> Requirements source: `effective-network-inspector/docs/product-requirements.md`

---

## 1. Design Decision Table

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Module decomposition | Three files: `effective_network_inspector.py` (CLI + orchestration), `providers.py` (Azure boundary), `diff.py` (comparison engine) | Each file has a single testable responsibility. The Azure CLI boundary is isolated so it can be replaced or mocked without touching orchestration. The diff engine is isolated so it can be tested against synthetic snapshot pairs. Mirrors the proven firewall-inspector decomposition. |
| D2 | Azure data access | Shell out to `az` CLI; parse stdout JSON | The `az` CLI handles auth, token refresh, and output normalisation for Azure. Reimplementing REST calls would re-introduce all failure modes Azure SDK already absorbs. Structured output (`--output json`) gives a stable parse boundary. The `az` CLI does not provide configurable backoff on 429 throttle responses; that is the tool's responsibility (see D10). |
| D3 | Snapshot storage | Local filesystem (`./audit/` directory), JSON + SHA-256 sidecar | MVP scope is local only. SHA-256 sidecar makes tamper detection explicit and machine-readable without coupling to any storage backend. Blob storage is a future additive layer, not a refactor target. |
| D4 | Concurrency model | `ThreadPoolExecutor` with configurable `max_workers`; separate token-bucket semaphore for API call rate | NIC queries are I/O-bound. Threads are appropriate; async adds no benefit and complicates subprocess integration. `max_workers` bounds the thread count (default: 4). A separate semaphore limits Azure API calls per second to stay within the subscription's throttle budget — a thread can be live without making an API call. Each thread is independent; failures are isolated per-NIC. Progress output is serialised through a thread-safe counter. |
| D5 | Partial snapshot validity | A snapshot with per-NIC errors is a valid artifact | NIC queries can fail for stopped VMs or RBAC gaps without invalidating the rest of the fleet. Partial visibility is more useful than a hard abort. Errors are recorded in the artifact, not silently swallowed. |
| D6 | Diff as the primary artifact | Structured `_diff.json` written to disk, read back by Ghost Agent | The diff is consumed by both automation (Ghost Agent) and engineers. Writing it to disk decouples production from consumption, makes the output auditable, and allows re-running analysis without re-querying Azure. |
| D7 | No AI inside the tool | The diff output is semantically categorised structured JSON; Ghost Agent's brain reasons about it | AI belongs at the reasoning layer (Ghost Agent), not inside the data pipeline. Categorisation is deterministic (source field matching). Injecting an LLM here would make the output non-deterministic and untestable. |
| D8 | Ghost Agent integration | Subprocess invocation via `_run_effective_network_inspector_handler()`; reads output artifact at a deterministic path | Mirrors the firewall-inspector and pipe-meter handler patterns. The subprocess boundary is the integration contract. The handler always passes `--session-id` explicitly so the artifact path (`{session_id}_snapshot.json` or `{baseline}_vs_{compare}_diff.json`) is known before the subprocess runs. The handler reads the artifact file, not stdout, so output format is stable across future CLI changes. |
| D9 | `drift_detected: false` is explicit | The field is always written to the diff artifact, not omitted | An absent field and a `false` field are operationally different in compliance and change-record use cases. The diff artifact is the machine-readable change record. Absence of evidence must not be confused with evidence of absence. |
| D10 | Retry / backoff scope | Retry only on HTTP 429 (throttle); do not retry on 4xx auth or 5xx errors | 429 is recoverable and expected at scale. Auth failures (403) and platform errors (5xx) are not recoverable by waiting — they require human action. Retrying them wastes quota budget and delays surfacing real errors. |
| D11 | Human-readable console output | Print a diff summary table to stdout after the diff artifact is written | The PRD use cases show direct CLI invocation (maintenance window, post-incident). Engineers running the tool directly should not need to `cat` the JSON artifact to understand results. A summary table (change category, NIC name, change type, affected prefix or rule name) is printed to stdout after the artifact write. The JSON artifact remains the authoritative output; the console summary is derived from it. This satisfies the dual-output requirement for a system consumed by both engineers and automation. |
| D12 | VNet scope NIC inclusion | Include all NICs discovered via subnet traversal, regardless of whether the subnet has an associated route table | The effective route query returns valid results (system default routes at minimum) even when no UDR route table is attached to the subnet. Filtering out NICs on subnets without route tables would silently exclude NICs from the snapshot, producing incomplete baselines. The presence of a route table is not a precondition for effective route state. |

---

## 2. System Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Ghost Agent  (network-ghost-agent/ghost_agent.py)                       │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  _run_effective_network_inspector_handler()                       │    │
│  │                                                                   │    │
│  │   reads: ghost_cfg (RESOURCE_GROUP, DEST_VM_NAME,                 │    │
│  │                      ENI_VM_NAME, AUDIT_DIR, SUBSCRIPTION_ID)     │    │
│  │   invokes: subprocess (effective_network_inspector.py + CLI args) │    │
│  │   reads artifact: {AUDIT_DIR}/*_diff.json or *_snapshot.json     │    │
│  │   returns to Brain: { drift_detected, changes_count,             │    │
│  │                        changes_by_category, artifact }            │    │
│  └──────────────────────────┬─────────────────────────────────────────┘   │
└─────────────────────────────┼────────────────────────────────────────────┘
                              │ subprocess
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  effective_network_inspector.py  (CLI entry point + orchestrator)         │
│                                                                           │
│  Pipeline stages (sequential — each writes before next reads):           │
│                                                                           │
│  [1] Validate          parse + validate CLI args; resolve scope          │
│         │                                                                 │
│  [2] Discover NICs     call providers.py → list of NIC names             │
│         │                                                                 │
│  [3] Query State       ThreadPoolExecutor → per-NIC effective routes     │
│         │              + NSG rules via providers.py; backoff on 429      │
│         │                                                                 │
│  [4] Assemble Snapshot build snapshot dict; write _snapshot.json +       │
│         │              _snapshot.json.sha256 to audit_dir                │
│         │                                                                 │
│  [5] Diff (optional)   load baseline snapshot from disk; verify SHA-256  │
│                        call diff.py → diff dict; write _diff.json        │
│                                                                           │
│  ┌─────────────┐   ┌───────────────┐   ┌──────────────────────────────┐ │
│  │ providers.py │   │   diff.py     │   │  audit/  (local filesystem)  │ │
│  │             │   │               │   │                              │ │
│  │ LocalShell  │   │ canonicalise()│   │  {sid}_snapshot.json         │ │
│  │ AzureNetwork│   │ diff_routes() │   │  {sid}_snapshot.json.sha256  │ │
│  │ Provider    │   │ diff_nsg()    │   │  {b}_vs_{c}_diff.json        │ │
│  │             │   │ categorise()  │   │                              │ │
│  └──────┬──────┘   └───────────────┘   └──────────────────────────────┘ │
│         │ shell out (az CLI)                                              │
└─────────┼────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│  Azure Control Plane  (read-only queries)        │
│                                                  │
│  az network nic show-effective-route-table       │
│  az network nic list-effective-nsg               │
│  az vm nic list  (VM scope NIC discovery)        │
│  az network vnet subnet list  (VNet scope disc.) │
│  az network vnet subnet show  (NIC IDs per sub.) │
└─────────────────────────────────────────────────┘

Ownership boundaries
────────────────────
  Ghost Agent side:   subprocess invocation, artifact retrieval, result routing to Brain
  Tool side:          all Azure queries, snapshot assembly, diff computation, artifact writes
  Azure side:         computed effective state only — read-only, no mutations
```

---

## 3. Component Inventory

### 3.1 `effective_network_inspector.py` — CLI Entry Point and Orchestrator

**What it is:** The single executable entry point. Owns CLI argument parsing, pipeline orchestration, audit directory management, SHA-256 integrity, and exit code policy.

**What it exposes:**
- CLI interface (all flags defined in product requirements)
- Exit code semantics:
  - `0` = all NICs queried successfully; snapshot (and diff, if requested) written
  - `1` = one or more NIC queries failed; partial snapshot written with per-NIC `"error"` fields; diff (if requested) skips errored NICs
  - `2` = fatal error; no usable artifact written. Covers: invalid CLI arguments, NIC discovery returning zero NICs, baseline session ID not found, SHA-256 verification failure on a loaded baseline, unrecoverable provider failure before any NIC is queried

**What it may do:**
- Parse and validate CLI arguments
- Instantiate `AzureNetworkProvider` and pass it to the pipeline stages
- Write and read snapshot artifacts to/from `audit_dir`
- Compute and verify SHA-256 of artifacts
- Invoke `diff.py` functions to produce diff artifacts
- Print per-NIC progress to stdout (`Snapshotting NIC 3/12: tf-dest-vm-nic...`)
- Print structured RBAC error messages to stderr

**What it may not do:**
- Contain any Azure CLI invocations — all Azure calls go through `providers.py`
- Contain any diff logic — all comparison logic goes through `diff.py`
- Make decisions about what constitutes a change — that is `diff.py`'s concern
- Return data to Ghost Agent via stdout — the artifact file is the output contract

---

### 3.2 `providers.py` — Azure CLI Boundary

**What it is:** The isolation layer between the tool and the Azure CLI. Contains two classes: `LocalShell` (subprocess execution with retry/backoff) and `AzureNetworkProvider` (all Azure-specific queries and NIC discovery).

**What it exposes:**
- `LocalShell`: executes a shell command via argument vector (no interpolation); surfaces both stdout and stderr to callers on failure
- `AzureNetworkProvider.discover_nics_for_vm` — NIC names attached to a VM
- `AzureNetworkProvider.discover_nics_for_vnet` — all NIC names across all subnets of a VNet; includes NICs on subnets with no associated route table
- `AzureNetworkProvider.get_effective_routes` — effective route objects for a NIC, unwrapped from the az CLI response structure
- `AzureNetworkProvider.get_effective_nsg_rules` — effective security rule objects for a NIC, unwrapped from the az CLI response structure

**What it may do:**
- Shell out to `az` CLI with `--output json`
- Retry on HTTP 429 with exponential backoff; surface all other failures immediately
- Detect `AuthorizationFailed` in az CLI output and raise a typed error distinguishing RBAC failures from generic failures
- Parse stdout JSON; raise a typed error on non-JSON or unexpected schema

**What it may not do:**
- Write any files — it is a pure data retrieval layer
- Apply business logic about what routes or rules mean
- Make decisions about change categorisation
- Swallow errors — every failure surfaces as a typed exception to the orchestrator

---

### 3.3 `diff.py` — Comparison Engine

**What it is:** A pure-function module that takes two snapshot dicts and produces a diff dict. No I/O, no side effects.

**What it exposes:**
- `diff_snapshots` — accepts two snapshot dicts; returns a complete diff artifact dict ready for serialisation

**What it may do:**
- Normalise route and NSG rule objects to a canonical form before comparison (strip volatile fields such as timestamps or internal Azure identifiers that are not semantically meaningful)
- Classify route changes by `source` field: `VirtualNetworkGateway` → `bgp_route_change`; `User` → `udr_route_change`; `Default` → `system_route_change`
- Classify NSG rule changes as `security_rule_change`
- Skip NICs where either snapshot has `"error"` set; record skipped NIC names in `skipped_nics`
- Produce `drift_detected: false` explicitly when `changes_count == 0`

**What it may not do:**
- Perform any I/O — no file reads or writes
- Call any Azure APIs
- Use non-deterministic logic — classification is deterministic field matching only
- Infer intent or explain changes — that is Ghost Agent Brain's concern

---

## 4. Integration Coupling Rules

### 4.1 `effective_network_inspector.py` ↔ `providers.py`

**Contract:**
- The orchestrator passes `(nic_name: str, resource_group: str)` to each provider method. It does not pass subscription ID in the call; the provider is instantiated with subscription context at construction time.
- The provider returns plain Python dicts/lists matching the Azure CLI JSON schema. It does not post-process or filter fields.
- On any failure, the provider raises a typed exception distinguishing RBAC failures, throttle exhaustion, and generic provider errors. The orchestrator catches these per-NIC, records them in the snapshot under `"error"`, and continues.
- The provider never receives a list of NICs and iterates — it processes one NIC per call. Concurrency is the orchestrator's concern, not the provider's.

**Schema invariants:**

`get_effective_routes()` returns a flat list of route objects, unwrapped from the az CLI's top-level `"value"` key. Key fields include address prefixes (multi-valued), next-hop type, source (`VirtualNetworkGateway` / `User` / `Default`), and state. Full field-level schema is in `design.md`.

`get_effective_nsg_rules()` returns a flat list of effective security rule objects, unwrapped from `networkSecurityGroups[].effectiveSecurityRules` in the az CLI response. Address prefix and port range fields are multi-valued arrays, not scalars. Full field-level schema is in `design.md`.

**Permitted changes on either side without breaking the other:**
- Orchestrator may change concurrency strategy (pool size, semaphore) — provider is stateless per call
- Provider may add additional fields to returned dicts — orchestrator and diff.py use only the fields they need
- Provider may add new exception subtypes — orchestrator catches the base type

**Changes that break the contract (require both sides to update):**
- Renaming or removing fields from the returned dict schema
- Changing exception hierarchy in ways that collapse error types the orchestrator distinguishes

---

### 4.2 `effective_network_inspector.py` ↔ `diff.py`

**Contract:**
- The orchestrator passes two fully-assembled snapshot dicts (the same structure written to disk). `diff.py` does not receive file paths; it receives parsed dicts.
- `diff_snapshots()` returns a dict that is serialised directly to `_diff.json`. The orchestrator does not post-process the return value before writing.
- `diff.py` is a pure function: given identical inputs, it always returns identical output.

**Schema invariant:** The diff dict always contains: session IDs for both snapshots, `drift_detected` (always present, never omitted), a total change count, a per-category change count, a list of skipped NIC names, and per-NIC change lists. Categories with zero changes are omitted from the per-category count. Full schema is in `design.md`.

---

### 4.3 Ghost Agent ↔ `effective_network_inspector.py`

**Contract:**
- Ghost Agent invokes the tool as a subprocess with CLI arguments derived from `ghost_cfg`. It does not pass data via stdin.
- The handler always passes an explicit `--session-id` (generated before the subprocess call). Artifact paths are deterministic: `eni_{session_id}_snapshot.json` for baseline mode; `eni_{baseline}_vs_eni_{compare}_diff.json` for compare mode. The handler constructs these paths directly — no mtime scan.
- **Session ID namespace invariant:** `main()` enforces the `eni_` prefix on all session IDs before any file operation. Both `--session-id` and `--compare-baseline` values are normalised: if the supplied value does not start with `eni_`, the prefix is prepended. This ensures all ENI artifacts are namespaced separately from `fw_*` firewall-inspector artifacts that share the same audit directory. The invariant applies to user-supplied values and auto-generated values alike.
- The tool's exit code signals health: `0` = full success, `1` = partial (some NIC errors), `2` = fatal (no artifact written). Ghost Agent records the exit code in its response.
- The handler constructs its return dict by parsing the artifact JSON — it never parses stdout.

**What Ghost Agent may not assume:**
- That stdout contains structured data — stdout is for human progress output only
- That an artifact exists if exit code is `2` — the handler must check file existence before parsing

---

### 4.4 Snapshot Artifact Integrity

**Contract (orchestrator ↔ filesystem):**
- Every `_snapshot.json` write is immediately followed by a `_snapshot.json.sha256` write. These are always produced together.
- On load (for diff or compare), SHA-256 is verified before the snapshot dict is parsed. A verification failure is a fatal error — the snapshot is not used.
- The SHA-256 file format is: `{hex_digest}  {filename}` (two spaces, GNU `sha256sum` convention) so the file is verifiable with standard tools outside the Python code.

---

## 5. Intentional Omissions

The following capabilities were considered and explicitly excluded from MVP. Future contributors must not add these without revisiting this document.

| Capability | Excluded because |
|---|---|
| ARM resource property snapshots (peering state, service endpoint presence, NSG association state) | These are configured intent, not computed effective state. Azure Change Analysis covers them within 14 days and is the authoritative source for "who changed what, when." Adding ARM properties would dilute the unique moat of this tool — computed state that Change Analysis cannot see. |
| VPN / ExpressRoute BGP peer state and connection state | These are operational state, not effective route state. They answer "is the gateway up?" not "what routes did the gateway propagate?" The effective route table answers the latter without requiring a separate peer query. |
| Multi-subscription scope | Subscription traversal requires credential strategy decisions (cross-tenant, managed identity federation) that are out of scope for MVP. Adding it naively would introduce silent permission failures. |
| Azure Blob Storage for baseline artifacts | Local storage is sufficient for the target use cases (maintenance window bracketing, post-incident forensics). Blob Storage is an additive layer — it does not change the diff engine or provider logic. Design for it requires IAM, SAS token, and object lifecycle decisions that are post-MVP. |
| `--explain` AI flag | The diff output is already semantically categorised structured JSON. Ghost Agent's Brain reasons about it in the investigation chain. Adding AI inside the tool creates a second AI reasoning path outside Ghost Agent's observation, breaks deterministic testing, and adds provider coupling to a data pipeline stage. Post-MVP pattern: same as `iptables-parser --explain-diff`. |
| Blast radius annotation (graph traversal for affected subnets/VNets) | Requires VNet topology graph traversal, which is a separate compute-graph problem. The effective route diff already identifies which routes changed; blast radius analysis is a downstream reasoning step, not a data collection step. |
| Azure Firewall policy resolved state | Azure Firewall policy compilation is a separate API surface with different semantics than NIC-level effective routes and NSG rules. Adding it would widen the scope to three distinct computed-state surfaces. Out of scope until the NIC-layer tool is proven. |
| Private DNS zone A record tracking | DNS resolution is a separate layer from routing and security enforcement. It is not an effective-state API at the NIC level. Out of scope. |
| Load balancer backend pool membership | LB membership is ARM resource state, not computed NIC-level effective state. Same exclusion principle as ARM property snapshots above. |
| Stdout as the machine output interface | Stdout is reserved for human-readable progress output. Structured data lives in artifact files. Mixing them would couple the Ghost Agent handler to the tool's human output format — fragile and hard to version. |
| Retrying on 4xx auth errors or 5xx platform errors | These errors do not resolve by waiting. Retrying them consumes throttle budget and delays surfacing root causes. Only 429 is recoverable by backoff. |
