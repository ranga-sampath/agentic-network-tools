# Architecture — security-rule-inspector

> Document order: **Requirements → Architecture (this document) → Design → Code**
> Requirements source: `security-rule-inspector/docs/product-requirements.md`
> Module location: `nw-forensics/security-rule-inspector/`

---

## 1. Design Decision Table

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Module decomposition | Four files: `security_rule_inspector.py` (CLI + orchestrator), `providers.py` (Azure CLI boundary), `nsg_preprocessor.py` (JSON normaliser), `nsg_engine.py` (dual-gate evaluation + audit analysis) | Each file has a single testable responsibility. The Azure CLI boundary is isolated so it can be mocked without touching algorithm logic. The evaluation engine is isolated so it can be tested against synthetic rule sets without any I/O. The preprocessor is isolated so normalisation can be tested and updated independently. Mirrors the decomposition pattern proven in `effective-route-inspector`. |
| D2 | Azure data access | Shell out to `az` CLI; parse stdout JSON | The `az` CLI handles auth, token refresh, and output normalisation. Reimplementing REST calls would re-introduce all failure modes the CLI already absorbs. Argument vector invocation (no string interpolation) eliminates shell injection. Structured JSON output provides a stable parse boundary. |
| D3 | `nsg_preprocessor.py` — copy, not shared import | Copy the preprocessor from `azure-security-rule-resolver` into this module's directory; do not import across directory trees | The Claude Code skill lives in `/Users/rangas/aiApps/azure-security-rule-resolver/`, outside the `nw-forensics/` tree entirely. Importing across that boundary requires path manipulation that violates the `_ROOT` convention governing all `nw-forensics/` sub-modules. The preprocessor is stable and small. Duplication is cheaper than coupling two unrelated release cycles. Identical decision and rationale to `route_preprocessor.py` in `effective-route-inspector` (D8). |
| D4 | No AI inside the tool | The verdict and audit output are produced by deterministic evaluation of effective NSG rules | AI belongs at the reasoning layer (Ghost Agent Brain), not inside the data pipeline. Ghost Agent Brain synthesises findings from multiple tools into an RCA. If the NSG verdict were AI-generated, the Brain would be synthesising AI inference with AI inference — errors compound and the result is untestable. The verdict must be a trusted fact. This is an architectural invariant, not a convention. |
| D5 | Mode dispatch at entry point | Verdict mode and Audit mode share Stages 1–3 (validate, collect, preprocess); they diverge at Stage 4 where `nsg_engine.py` exposes a separate operation per mode | The shared stages are identical regardless of mode. Dispatching at the entry point keeps each mode's evaluation logic isolated, independently testable, and prevents the two modes from accumulating cross-cutting conditionals. |
| D6 | Intermediate raw artifact | Raw effective NSG JSON written to disk before preprocessing | Enables re-running preprocessing and evaluation without re-querying Azure. The raw artifact is the exact bytes Azure returned — the audit trail captures what Azure said, not what the preprocessor inferred. Both downstream stages can be tested in isolation against the raw file. |
| D7 | Verdict and audit as primary artifacts | Structured JSON written to disk per session; Ghost Agent reads the artifact, not stdout | Decouples production from consumption. The artifact is the authoritative output. Stdout is human-readable progress and table output. Ghost Agent reads the file, not stdout — so the CLI output format is free to evolve without breaking the integration contract. Same principle as `effective-route-inspector` (D6) and `effective-network-inspector` (D6). |
| D8 | Session ID namespace prefix `nsg_` | All artifact filenames begin with `nsg_`; enforced before any file operation | Prevents namespace collision with `fw_*` (firewall-inspector), `eni_*` (effective-network-inspector), and `rt_*` (effective-route-inspector) artifacts that share the same audit directory. The prefix is prepended if absent — not rejected. |
| D9 | Unresolvable rules default to INDETERMINATE, not ALLOW | When a rule uses an ASG or non-standard service tag that cannot be matched from the effective NSG JSON, the gate verdict is INDETERMINATE, not ALLOW | The correct failure mode for an unevaluable rule is to refuse to render a verdict rather than to assume the rule does not match. Assuming no-match (defaulting to ALLOW) would silently skip a rule that may actually block traffic. INDETERMINATE surfaces the ambiguity to the engineer and to Ghost Agent Brain, who can then request the missing information. Fail closed. |
| D10 | Primary NIC by default | The tool resolves the primary NIC from the VM's NIC list using the `primary` boolean flag; callers supply an explicit NIC name to bypass resolution | Azure marks exactly one NIC as primary via a `primary: true` flag on the NIC object. Selecting by array position is incorrect — Azure does not guarantee ordering. If the caller needs a secondary NIC, they supply the NIC name explicitly. Identical rationale to `effective-route-inspector` (D15). |
| D11 | Dual output | Structured JSON artifact for Ghost Agent; human-readable table printed to stdout for standalone CLI use | Both are produced from the same verdict or audit structure. The JSON artifact is the authoritative output; the console table is derived from it. Engineers running the tool directly should not need to parse JSON to read results. Both consumers are served from the same pipeline run. |
| D12 | Read-only Azure access | The tool issues only read queries to Azure; it never modifies NSG rules, associations, or any other resource | Investigation tools must not mutate the state they are inspecting. Modifying a resource during investigation changes the effective state being measured and may mask the original fault. Read-only scope is enforced structurally in `providers.py` — no write intent is expressible at the provider interface. |
| D13 | Retry only on throttle | Retry with exponential backoff on throttle responses from the `az` CLI; surface all other failures immediately | Auth failures and resource-not-found errors do not resolve by waiting — they require human action. Retrying them wastes quota and delays surfacing root causes. Only throttle is recoverable by backoff. Same policy as `effective-route-inspector` (D11) and `effective-network-inspector` (D10). |
| D14 | Ghost Agent integration via subprocess | `_run_security_rule_inspector_handler()` invokes the tool as a subprocess; reads the verdict or audit artifact at a deterministic path | Mirrors the established handler pattern for `detect_config_drift`, `detect_effective_network_drift`, and `effective_route_inspector`. The subprocess boundary is the integration contract. The handler constructs the artifact path from the session ID before the subprocess runs — no filesystem scan. |
| D15 | INDETERMINATE propagation — stop at first unresolvable | When an UNRESOLVABLE rule is encountered during gate evaluation, evaluation stops at that rule; the gate verdict is INDETERMINATE; Gate 2 is not evaluated when Gate 1 is INDETERMINATE | Continuing past an UNRESOLVABLE rule to find a definitive match at a lower priority would silently discard a rule that may have matched first. The conservative position is that any unresolvable rule in the evaluation path makes the gate outcome unknowable. Consistent with the fail-closed principle in D9. The full final-verdict combination table is in Section 3.4. |
| D16 | Engine owns rule sort order | The evaluation engine sorts rule sets by priority before evaluation; the preprocessor makes no ordering guarantee | Placing sort responsibility in the engine makes the algorithm self-contained. If the preprocessor were modified and its output order changed, the engine would still produce correct results. Placing a correctness-critical ordering dependency outside the component that depends on it creates a silent failure mode. |
| D17 | Session ID collision — fail, do not overwrite | If an artifact with the target session ID already exists in the audit directory, the tool exits with code 2 before any write | The artifact files are evidence in a forensics context. Silently overwriting a prior run's raw NSG capture or verdict would destroy evidence. The caller must supply a new session ID. |

---

## 2. System Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Ghost Agent  (network-ghost-agent/ghost_agent.py)                       │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  _run_security_rule_inspector_handler()                           │    │
│  │                                                                   │    │
│  │   reads: ghost_cfg (VM_NAME, RESOURCE_GROUP, AUDIT_DIR,          │    │
│  │                      and optionally SRC, DST, PROTO, DIRECTION)  │    │
│  │   generates: session_id → nsg_{session_id}                       │    │
│  │   invokes: subprocess (security_rule_inspector.py + args)        │    │
│  │   reads artifact: {AUDIT_DIR}/nsg_{session_id}_verdict.json      │    │
│  │                or  {AUDIT_DIR}/nsg_{session_id}_audit.json       │    │
│  │   returns to Brain: { mode, verdict | audit_findings,            │    │
│  │                        gate_results, shadowed_rules,             │    │
│  │                        unresolvable_rules, session_id }          │    │
│  └──────────────────────────┬─────────────────────────────────────────┘   │
└─────────────────────────────┼────────────────────────────────────────────┘
                              │ subprocess
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  security_rule_inspector.py  (CLI entry point + orchestrator)             │
│                                                                           │
│  Pipeline stages (sequential — each writes before next reads):           │
│                                                                           │
│  [1] Validate       validate inputs; enforce nsg_ prefix;                │
│         │           determine mode (verdict if full tuple, audit if not); │
│         │           check for session ID collision → exit 2 if conflict  │
│         │                                                                 │
│  [2] Collect        providers.py → VM primary NIC identity,              │
│         │           then effective NSG state for that NIC;               │
│         │           write raw artifact to audit_dir                      │
│         │                                                                 │
│  [3] Preprocess     nsg_preprocessor.py ← path to raw artifact           │
│         │           → normalised rule sets (subnet + NIC, both dirs)     │
│         │                                                                 │
│  [4] Evaluate ──────┬────────────────────────────────────────────────    │
│                     │                                                     │
│              [verdict mode]                      [audit mode]             │
│              nsg_engine.evaluate_verdict()        nsg_engine.audit()      │
│              → gate verdicts, decisive rule,      → full rule inventory,  │
│                shadowed rules, final verdict        posture findings       │
│                write verdict artifact               write audit artifact   │
│                                                                           │
│  [5] Output         print human-readable table to stdout                  │
│                     (derived from artifact; artifact already written)     │
│                                                                           │
│  ┌──────────────┐  ┌──────────────────────┐  ┌────────────────────────┐  │
│  │ providers.py │  │ nsg_preprocessor.py  │  │ nsg_engine.py          │  │
│  │              │  │                      │  │                        │  │
│  │ Azure CLI    │  │ Normalise rule sets  │  │ Sort by priority       │  │
│  │ boundary     │  │ Expand multi-value   │  │ Dual-gate evaluation   │  │
│  │ (read-only)  │  │ fields               │  │ Rule matching          │  │
│  └──────┬───────┘  └──────────────────────┘  │ Shadow detection       │  │
│         │ az CLI (arg vector, no interpolation)│ Permissive detection   │  │
└─────────┼────────────────────────────────────┴────────────────────────┴──┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│  Azure Control Plane  (read-only queries only)   │
│                                                  │
│  Query 1: VM primary NIC identity                │
│           (by VM name + resource group)          │
│                                                  │
│  Query 2: Effective NSG state for the NIC        │
│           (by NIC name + resource group)         │
└─────────────────────────────────────────────────┘

Audit directory (local filesystem — write-once per session ID)
──────────────────────────────────────────────────────────────
  nsg_{session_id}_raw.json       raw Azure CLI output    (Stage 2 write)
  nsg_{session_id}_verdict.json   gate-by-gate verdict    (Stage 4 write, verdict mode)
  nsg_{session_id}_audit.json     full rule inventory     (Stage 4 write, audit mode)

  Collision policy: if any artifact for the given session ID already exists,
  the tool exits with code 2 before any write occurs (D17).

Ownership boundaries
────────────────────
  Ghost Agent side:   subprocess invocation, session ID generation,
                      artifact retrieval, result routing to Brain
  Tool side:          all Azure queries, preprocessing, evaluation,
                      artifact writes — no mutations to Azure
  Azure side:         computed effective NSG state, read-only
```

---

## 3. Component Inventory

### 3.1 `security_rule_inspector.py` — CLI Entry Point and Orchestrator

**What it is:** The single executable entry point. Owns input validation, mode detection, pipeline orchestration, session ID enforcement, collision detection, and exit code policy.

**What it accepts:**
- A VM identifier and resource group — always required
- An optional traffic tuple consisting of source address, destination address and port, protocol, and direction — all four fields are required together for verdict mode; omit all for audit mode; a partial tuple (some but not all four fields) is a fatal input error
- An optional NIC name override — bypasses primary NIC resolution for multi-NIC VMs
- An optional session ID — auto-generated if absent; the `nsg_` prefix is enforced before any file operation; if artifacts for the session ID already exist, the tool exits with code 2 without writing (D17)
- An output directory path — where all artifacts are written

**Exit code semantics:**
- `0` — artifact written successfully; result is valid
- `2` — fatal error; no artifact written. Covers: invalid inputs, partial traffic tuple, session ID collision with existing artifact, VM not found, NIC resolution failed, Azure query failed after retries, preprocessor returned no usable rule sets

Exit code `1` is not used by this tool. A single-NIC invocation either fully succeeds or fatally fails — there is no partial-result scenario. If multi-NIC scope is added in future, exit code `1` semantics must be defined at that time.

**What it may do:**
- Validate inputs and detect mode
- Check for session ID collision before any write operation
- Orchestrate the pipeline stages in sequence
- Write raw, verdict, and audit artifacts to the output directory
- Print structured progress to stdout during collection
- Print a human-readable verdict or audit table to stdout in Stage 5

**What it may not do:**
- Contain any Azure CLI invocations — all Azure calls go through `providers.py`
- Contain any rule evaluation or audit logic — all algorithm logic goes through `nsg_engine.py`
- Contain any JSON normalisation logic — that belongs to `nsg_preprocessor.py`
- Return structured data to Ghost Agent via stdout — the artifact file is the output contract
- Accept a partial traffic tuple — all four fields or none

---

### 3.2 `providers.py` — Azure CLI Boundary

**What it is:** The isolation layer between the tool and the Azure CLI. Encapsulates all Azure-specific queries and the subprocess execution strategy (argument vector invocation, throttle retry, and backoff).

**What it exposes:**
- A subprocess execution capability: runs commands via argument vector with no string interpolation; returns stdout on success; raises typed exceptions on failure
- A VM primary NIC resolver: given a VM identifier and resource group, returns the primary NIC name by inspecting the `primary` boolean flag on the VM's NIC list; accepts an explicit NIC name override that bypasses resolution entirely
- An effective NSG retriever: given a NIC name and resource group, returns the raw effective NSG data as a parsed structure

**What it may do:**
- Shell out to the `az` CLI using argument vectors only — no string interpolation, no shell pass-through
- Retry with exponential backoff on throttle responses; surface all other failures immediately as typed exceptions
- Detect authorisation failures in CLI output and raise a typed error distinguishing them from generic failures
- Parse CLI JSON output; raise a typed error on non-JSON or unexpected schema

**What it may not do:**
- Write any files — it is a pure data retrieval layer
- Apply any evaluation logic about what NSG rules mean
- Swallow exceptions — every failure surfaces as a typed exception to the orchestrator
- Issue any write, update, or delete operations against Azure resources

---

### 3.3 `nsg_preprocessor.py` — JSON Normaliser

**What it is:** A copy of the NSG preprocessor from the `azure-security-rule-resolver` Claude Code skill, placed inside this module's directory (D3). Accepts a file path to the raw effective NSG artifact; returns normalised, structured rule sets or an error structure if the input is unparseable.

**What it exposes:**
- One operation: accept the path to the raw NSG artifact; return normalised rule sets separated by gate (subnet / NIC) and direction (inbound / outbound) with multi-value fields expanded; or an error structure with parse warnings if the input cannot be parsed into usable rule sets

**What it may do:**
- Unwrap Azure CLI response envelope variants to reach the rule arrays
- Expand multi-value fields (address prefix arrays, port range arrays) into a consistent representation per rule
- Normalise rule field names to consistent keys
- Emit parse warnings for unexpected field shapes or missing fields
- Return an error structure when the input cannot produce usable rule sets

**What it may not do:**
- Write any files — it reads one file path and returns a structure; all writes belong to the orchestrator
- Apply any matching or evaluation logic — rule evaluation belongs to `nsg_engine.py`
- Filter or discard rules based on action, direction, or priority — it normalises only; it does not interpret
- Sort rules — ordering responsibility belongs to `nsg_engine.py` (D16)

---

### 3.4 `nsg_engine.py` — Dual-Gate Evaluation and Audit Engine

**What it is:** A pure-function module implementing the Azure dual-gate NSG evaluation model and audit analysis. No I/O. No side effects.

**What it exposes:**
- A verdict mode operation: accepts a normalised rule sets structure and a traffic tuple; sorts rule sets by priority; applies the dual-gate model; returns a complete verdict including gate-by-gate results, the decisive rule, shadowed rules, UNRESOLVABLE rules, and the final verdict (ALLOW / DENY / INDETERMINATE)
- An audit mode operation: accepts a normalised rule sets structure; returns a full rule inventory across both gates and both directions with shadowed rules flagged, permissive custom ALLOW rules highlighted, and default-only gates identified

**What it may do:**
- Sort rule sets by priority ascending before evaluation — callers need not pre-sort (D16)
- Apply Azure dual-gate ordering: inbound (subnet gate first, NIC gate second); outbound (NIC gate first, subnet gate second)
- Match rules in ascending priority order; stop at the first matching rule per gate
- Short-circuit Gate 2 when Gate 1 returns DENY
- Flag a rule as UNRESOLVABLE when its source or destination is an ASG reference or a service tag other than `VirtualNetwork`, `Internet`, or `AzureLoadBalancer`

**INDETERMINATE propagation rules (D15):**

When an UNRESOLVABLE rule is encountered during gate evaluation, evaluation stops at that rule. The engine does not continue to lower-priority rules. The final verdict is determined by the following combination table:

| Gate 1 result | Gate 2 result | Final verdict |
|---|---|---|
| DENY | — (not evaluated) | DENY |
| ALLOW | ALLOW | ALLOW |
| ALLOW | DENY | DENY |
| ALLOW | INDETERMINATE | INDETERMINATE |
| INDETERMINATE | — (not evaluated) | INDETERMINATE |

Gate 2 is not evaluated when Gate 1 is DENY or INDETERMINATE. A Gate 1 DENY short-circuits because the traffic is already dropped. A Gate 1 INDETERMINATE halts because the gate outcome is unknowable — evaluating Gate 2 would produce a verdict on a false premise.

**What it may not do:**
- Perform any I/O
- Call any Azure APIs
- Infer intent, explain results, or generate human-readable text — that is Ghost Agent Brain's concern
- Continue past an UNRESOLVABLE rule to find a lower-priority match — this would silently discard a rule that may have matched first
- Treat UNRESOLVABLE as ALLOW
- Use non-deterministic logic — every classification and match decision is a pure function of the input

---

## 4. Integration Coupling Rules

### 4.1 `security_rule_inspector.py` ↔ `providers.py`

**Contract:**
- The orchestrator resolves the NIC name first, then retrieves the effective NSG state for that NIC. Subscription context, if needed, is passed at provider construction time — not per call.
- The provider returns raw Azure CLI output as a parsed structure without normalisation or filtering.
- On any failure the provider raises a typed exception. The orchestrator catches it, emits a structured error to stderr, and exits with code 2. There is no partial-result scenario — the tool inspects one NIC per invocation.
- The provider never receives a list of NICs to iterate — it processes one resource per call.

**Changes that break the contract (require both sides to update):**
- Changing the provider to return a pre-normalised structure — the orchestrator writes raw output to disk and passes the file path to the preprocessor; the provider must stay raw
- Collapsing exception subtypes that the orchestrator distinguishes

---

### 4.2 `security_rule_inspector.py` ↔ `nsg_preprocessor.py`

**Contract:**
- The orchestrator passes the path to the raw artifact (written in Stage 2) to the preprocessor. The preprocessor reads the file itself — the orchestrator does not parse the raw output and pass a dict. The file path is the handoff, matching the `route_preprocessor.py` convention in `effective-route-inspector`.
- The preprocessor returns either a usable rule sets structure or an error structure with parse warnings. The orchestrator checks for the error condition before proceeding. If an error is present and no rule sets were produced: exit code 2.
- Parse warnings are always carried through to the downstream artifact, even when empty.
- The preprocessor never returns a partial rule sets structure alongside an error — the result is either fully usable or fully failed.
- The preprocessor makes no guarantee about the ordering of rules within each rule set. The engine sorts before evaluation (D16). This is a formal contract invariant: callers of `nsg_engine.py` must not assume pre-sorted input.

---

### 4.3 `security_rule_inspector.py` ↔ `nsg_engine.py`

**Contract:**
- The orchestrator passes the normalised rule sets from the preprocessor to whichever engine operation matches the mode. It does not modify the rule sets before passing them, and it does not pre-sort them — sorting is the engine's responsibility (D16).
- The engine returns a verdict or audit structure. The orchestrator serialises it directly to the artifact file without post-processing. The console table in Stage 5 is derived from the same structure — never computed separately.
- The artifact is the source of truth. The console output is always derived from it.

**Sort order invariant:** The engine is the sole owner of priority-based ordering. If this invariant is violated — for example by a caller that pre-sorts or a preprocessor change that introduces an ordering side effect — the engine must still produce correct results, because it sorts unconditionally before evaluation.

**Schema invariants (direction for design):**
- Verdict structure always contains: mode, direction, traffic tuple, Gate 1 result, Gate 2 result (or a flag indicating it was not evaluated and why), final verdict (ALLOW / DENY / INDETERMINATE), decisive rule, shadowed rules list, unresolvable rules list
- Audit structure always contains: mode, VM identifier, NIC identifier, rule inventories keyed by gate and direction, findings (shadowed rules, permissive custom ALLOW rules, default-only gates)

> Field-level types and semantics: see `design.md`

---

### 4.4 Ghost Agent ↔ `security_rule_inspector.py`

**Contract:**
- Ghost Agent generates a session ID before the subprocess call. The `nsg_` prefix is enforced by the tool — not by the caller. If a conflicting artifact already exists, the tool exits with code 2 (D17); Ghost Agent must supply a new session ID.
- Artifact paths are deterministic and constructed by the handler before the subprocess runs — no filesystem scan.
  - Verdict mode: `{AUDIT_DIR}/nsg_{session_id}_verdict.json`
  - Audit mode: `{AUDIT_DIR}/nsg_{session_id}_audit.json`
- The handler reads the artifact and returns a structured result to the Brain. It never parses stdout.
- Exit code `0` means the artifact is present and usable. Exit code `2` means no artifact was written; the handler must check file existence before parsing.
- Ghost Agent passes either the full traffic tuple (all four fields: source, destination and port, protocol, direction) for verdict mode, or none of them for audit mode. Partial tuples are a fatal input error (exit code 2).

**Ghost Agent handling of INDETERMINATE final verdict:**

When the tool returns `final_verdict: INDETERMINATE`, Ghost Agent must not proceed to the host firewall layer. An INDETERMINATE verdict means the NSG evaluation is blocked — the engine encountered a rule whose match cannot be determined. Proceeding to the host firewall would incorrectly assume the NSG is clean.

Required Ghost Agent response to INDETERMINATE:
1. Surface the unresolvable rules list to the engineer, naming the ASG or service tag that blocked evaluation
2. Request the missing information (ASG member IP addresses or service tag scope) before proceeding
3. Do not synthesise a connectivity verdict until the NSG layer is resolved or the engineer has confirmed the unresolvable rules are not on the traffic path

**What Ghost Agent may not assume:**
- That stdout contains structured data — stdout is human-readable progress and table output only
- That an artifact exists when exit code is `2`
- That verdict mode and audit mode produce the same artifact filename — they produce different files
- That INDETERMINATE means the NSG is not the problem — it means the NSG cannot yet be ruled in or out

---

## 5. Intentional Omissions

The following capabilities were considered and explicitly excluded. Future contributors must not add these without revisiting this document.

| Capability | Excluded because |
|---|---|
| AI in the verdict | The NSG evaluation algorithm is deterministic. Injecting an LLM makes the verdict non-deterministic and untestable. Ghost Agent Brain is the reasoning layer — it synthesises the verdict with routing and DNS findings to produce an RCA. The tool produces facts; the Brain produces meaning. This is an architectural invariant. |
| ASG membership resolution | ASG membership requires a separate query per ASG. The effective NSG JSON does not contain membership data. Resolving it would widen the Azure query surface, introduce additional RBAC requirements, and could still fail for ASGs in peered VNets. The correct behaviour is UNRESOLVABLE — surfacing the gap is more honest than silently skipping the rule or fabricating a match. |
| Non-standard service tag resolution | Service tag membership (e.g., `Storage`, `Sql.EastUS`) is published by Azure as a file that changes weekly. Embedding or fetching it introduces a freshness problem and a download dependency. Tags other than the three resolvable inline (`VirtualNetwork`, `Internet`, `AzureLoadBalancer`) are flagged UNRESOLVABLE. |
| Drift and baseline comparison | Snapshot-and-diff against an NSG baseline is `detect_effective_network_drift`'s responsibility. That module already captures effective NSG data as part of its fleet-level snapshots. Adding a compare mode here would duplicate drift logic with no shared test surface. This tool answers "what is the current NSG verdict?" — the drift tool answers "did NSG rules change?". |
| Fleet or VNet scope | Querying all VMs in a VNet is the effective-network-inspector's scope. This tool is scoped to a single VM. Fleet scope would require NIC discovery, concurrency, partial-failure semantics, and session ID management across multiple NICs — all of which belong to the existing drift tool. |
| Remediation execution | The tool never modifies Azure resources. Applying a remediation is an infrastructure mutation that must go through Ghost Agent's HITL-gated `CloudOrchestrator` path, not through an investigation tool that runs autonomously and read-only. |
| Stdout as the machine output interface | Stdout is reserved for human-readable progress and table output. Ghost Agent reads the artifact file. Mixing structured data into stdout would couple the handler to the tool's human output format — fragile across CLI changes. Same exclusion as `effective-network-inspector` and `effective-route-inspector`. |
| Multi-subscription scope | Cross-subscription queries require credential strategy decisions (cross-tenant service principals, managed identity federation) that are out of scope. Adding it naively introduces silent permission failures. |
| SHA-256 artifact integrity sidecar | The raw and verdict artifacts are produced and consumed within the same invocation, or by the Ghost Agent handler immediately after. There is no long-lived NSG baseline needing tamper detection between sessions. Omitting SHA-256 keeps the file surface minimal. If NSG baseline diffing is added in future, integrity checking belongs in that scope. |
| Azure Firewall policy and WAF rules | These are separate enforcement surfaces with distinct APIs and semantics. They are not NIC-level NSG state. Each deserves a separate tool with its own data collection, normalisation, and evaluation model. |
| Retry on non-throttle errors | Auth failures and resource-not-found errors do not resolve by waiting. Retrying them wastes throttle quota and delays surfacing actionable errors. Only throttle is recoverable by backoff. |

