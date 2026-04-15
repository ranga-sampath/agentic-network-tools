# Architecture — effective-route-inspector

> Document order: **Requirements → Architecture (this document) → Design → Code**
> Requirements source: `effective-route-inspector/docs/product-requirements.md`

---

## 1. Design Decision Table

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| D1 | Module decomposition | Four files: `effective_route_inspector.py` (CLI + orchestrator), `providers.py` (Azure CLI boundary), `route_preprocessor.py` (JSON normaliser), `lpm_engine.py` (route selection algorithm + anomaly detection) | Each file has a single testable responsibility. The Azure boundary is isolated so it can be mocked in tests without touching algorithm logic. The algorithm is isolated so it can be tested against synthetic route tables without any I/O. The preprocessor is a copy of the module already proven in `azure-effective-route-summarizer` — isolated to keep its test surface separate from the algorithm. |
| D2 | Azure data access | Shell out to `az` CLI; parse stdout JSON | The `az` CLI handles auth, token refresh, and output normalisation. Reimplementing REST calls would reintroduce all failure modes the CLI already absorbs. Argument vector invocation (no string interpolation) eliminates shell injection. |
| D3 | Single-VM scope | One VM → one primary NIC → one effective route table query per invocation | This tool answers a point-in-time routing question for a specific VM. Fleet or VNet scope is `detect_effective_network_drift`'s job. Keeping scope to a single NIC eliminates the concurrency and partial-failure complexity needed for fleet queries. |
| D4 | No concurrency | Single sequential pipeline; no `ThreadPoolExecutor` | A single NIC query produces a single API call. There is nothing to parallelise. The ENI module uses a thread pool because it queries many NICs; this tool does not. |
| D5 | Intermediate raw artifact | Raw effective route table JSON written to `rt_{session_id}_raw.json` before preprocessing | Enables re-running preprocessing and analysis without re-querying Azure. Audit trail captures exactly what Azure returned. Stage 3 (preprocess) and Stage 4 (analyze) can be tested in isolation against the raw file. |
| D6 | Verdict as the primary artifact | Structured verdict dict written to `rt_{session_id}_verdict.json` | Consumed by both Ghost Agent (machine) and engineers (human). Writing to disk decouples production from consumption. Ghost Agent reads the file, not stdout. |
| D7 | No AI inside the tool | The verdict is deterministic Python end to end | AI belongs at the reasoning layer (Ghost Agent Brain), not inside the data pipeline. The LPM algorithm and anomaly checks are fully deterministic. Injecting an LLM here would make results non-deterministic and untestable. This is an architectural invariant, not a convention. |
| D8 | `route_preprocessor.py` is copied, not shared | Copy from `azure-effective-route-summarizer/.claude/skills/azure-effective-route-summarizer/route_preprocessor.py` into this module | The Claude Code skill and this Ghost Agent tool are in separate directory trees with separate test suites. Sharing via import would couple their release cycles and require path gymnastics that violate the `_ROOT` convention. The preprocessor is stable and small; duplication is cheaper than coupling. |
| D9 | Session ID prefix `rt_` | All artifact filenames begin with `rt_` | Prevents namespace collision with `eni_*` (effective-network-inspector) and `fw_*` (firewall-inspector) artifacts that share the same audit directory. Prefix is enforced in `main()` before any file operation — user-supplied values without the prefix have it prepended. |
| D10 | Ghost Agent integration via subprocess | `_run_effective_route_inspector_handler()` invokes the tool as a subprocess; reads the verdict artifact at a deterministic path | Mirrors the established handler pattern for `detect_config_drift` and `detect_effective_network_drift`. The subprocess boundary is the integration contract. The handler constructs the artifact path from the session ID before the subprocess runs — no filesystem scan. |
| D11 | Retry scope | Retry only on HTTP 429 (throttle); surface all other failures immediately | 429 is recoverable by waiting. Auth failures (403), platform errors (5xx), and VM-not-found (404) are not recoverable by waiting — they require human action. Retrying them wastes quota and delays surfacing root causes. |
| D12 | BGP tie: stop and flag | When two `VirtualNetworkGateway` routes share the same longest prefix, return `TIED_BGP` and do not select a winner | AS Path is not present in the effective route table JSON. Any selection would be a fabrication. The correct answer is to surface the ambiguity and direct the engineer to the gateway BGP peer status query. Fabricating a winner produces a confident wrong answer — the failure mode this tool was built to prevent. |
| D13 | Dual output | Structured JSON artifact for Ghost Agent; human-readable table printed to stdout for standalone CLI | Both are produced from the same verdict dict in Stage 5. The JSON artifact is the authoritative output; the console table is derived from it. Engineers running the CLI directly should not need to parse JSON to read results. |
| D14 | Unknown route state excluded from selection | Routes with `state = Unknown` (absent or null `state` field) are excluded from the LPM candidate set | Promoting a route with unverifiable state to Active status risks a wrong verdict. The preprocessor records a parse warning. The lpm_engine treats these routes as ineligible. Exclusion is the conservative choice. |
| D15 | Primary NIC selection | `az vm show` is used to extract the primary NIC resource ID | Azure marks one NIC as primary on multi-NIC VMs. The primary NIC is the correct default for routing analysis. If the caller needs a secondary NIC, they pass `--nic-name` explicitly. |

---

## 2. System Boundary Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Ghost Agent  (network-ghost-agent/ghost_agent.py)                        │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  _run_effective_route_inspector_handler()                            │  │
│  │                                                                      │  │
│  │   reads: ghost_cfg (RESOURCE_GROUP, VM_NAME, DST_IP,                 │  │
│  │                      AUDIT_DIR, SUBSCRIPTION_ID)                     │  │
│  │   generates: session_id → rt_{session_id}                           │  │
│  │   invokes: subprocess (effective_route_inspector.py + CLI args)      │  │
│  │   reads artifact: {AUDIT_DIR}/rt_{session_id}_verdict.json          │  │
│  │   returns to Brain: { mode, winning_route, selection_reason,        │  │
│  │                        anomaly_warnings, shadowed_candidates,        │  │
│  │                        findings (audit mode), session_id }           │  │
│  └──────────────────────────┬──────────────────────────────────────────┘  │
└─────────────────────────────┼─────────────────────────────────────────────┘
                              │ subprocess
                              ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  effective_route_inspector.py  (CLI entry point + orchestrator)            │
│                                                                            │
│  Pipeline (sequential — each stage writes before the next reads):         │
│                                                                            │
│  [1] Validate        parse + validate CLI args; enforce rt_ prefix        │
│         │                                                                  │
│  [2] Collect         providers.py → NIC name, raw route JSON;             │
│         │            write rt_{sid}_raw.json to audit_dir                 │
│         │                                                                  │
│  [3] Preprocess      route_preprocessor.py → normalised route list        │
│         │            (in-memory; input is the raw JSON dict)              │
│         │                                                                  │
│  [4] Analyze         lpm_engine.py → verdict dict                         │
│         │            (single-target: LPM + source precedence + anomaly)   │
│         │            (audit: sort by prefix_len + anomaly scan)           │
│         │            write rt_{sid}_verdict.json to audit_dir             │
│         │                                                                  │
│  [5] Output          print human-readable table to stdout                 │
│                      (derived from verdict dict; JSON artifact already     │
│                       written)                                             │
│                                                                            │
│  ┌──────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐ │
│  │ providers.py │  │ route_preprocessor  │  │ lpm_engine.py            │ │
│  │              │  │       .py           │  │                          │ │
│  │ get_nic_name │  │ preprocess()        │  │ select_route()           │ │
│  │ get_effective│  │ normalise entries   │  │ audit_routes()           │ │
│  │ _routes()    │  │ validate CIDRs      │  │ check_anomalies()        │ │
│  │              │  │ expand multi-prefix │  │                          │ │
│  └──────┬───────┘  └─────────────────────┘  └──────────────────────────┘ │
│         │ shell out (az CLI, arg vector)                                   │
└─────────┼─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────┐
│  Azure Control Plane  (read-only queries only)        │
│                                                       │
│  az vm show                                           │
│    --name <vm>  --resource-group <rg>                 │
│    --query "networkProfile.networkInterfaces[0].id"   │
│    --output tsv                                       │
│                                                       │
│  az network nic show-effective-route-table            │
│    --name <nic>  --resource-group <rg>                │
│    --output json                                      │
└──────────────────────────────────────────────────────┘

Audit directory (local filesystem — append-only writes by this tool)
───────────────────────────────────────────────────────────────────
  rt_{session_id}_raw.json       raw az CLI output (Stage 2 write)
  rt_{session_id}_verdict.json   algorithm verdict (Stage 4 write)

Ownership boundaries
────────────────────
  Ghost Agent side:   subprocess invocation, session ID generation,
                      artifact retrieval, result routing to Brain
  Tool side:          all Azure queries, preprocessing, algorithm,
                      artifact writes — no mutations to Azure
  Azure side:         computed effective state, read-only
```

---

## 3. Component Inventory

### 3.1 `effective_route_inspector.py` — CLI Entry Point and Orchestrator

**What it is:** The single executable entry point. Owns CLI argument parsing, pipeline orchestration, session ID enforcement, audit directory management, and exit code policy.

**What it exposes:**
- CLI interface: `--vm-name`, `--resource-group`, `--dst-ip` (optional), `--nic-name` (optional override), `--subscription-id` (optional), `--session-id` (optional, auto-generated if absent), `--audit-dir`
- Exit code semantics:
  - `0` — verdict written successfully
  - `2` — fatal error: no verdict written. Covers: invalid CLI arguments, VM not found, NIC name extraction failed, Azure query failed after retries, unrecoverable provider error

**What it may do:**
- Parse and validate CLI arguments
- Enforce `rt_` prefix on session ID before any file operation
- Instantiate `AzureRouteProvider` and pass it through pipeline stages
- Write `rt_{session_id}_raw.json` and `rt_{session_id}_verdict.json` to `audit_dir`
- Print human-readable verdict table to stdout (Stage 5)

**What it may not do:**
- Contain any `az` CLI invocations — all Azure calls go through `providers.py`
- Contain any route selection or anomaly logic — all algorithm logic goes through `lpm_engine.py`
- Contain any JSON normalisation logic — that belongs to `route_preprocessor.py`
- Return data to Ghost Agent via stdout — the verdict artifact is the output contract
- Use `..` in any path construction

---

### 3.2 `providers.py` — Azure CLI Boundary

**What it is:** The isolation layer between the tool and the Azure CLI. `AzureRouteProvider` with two query methods and a `LocalShell` helper for subprocess execution.

**What it exposes:**
- `LocalShell.run(args: list[str]) -> str` — executes a command via argument vector; returns stdout; raises typed exceptions on failure
- `AzureRouteProvider.get_nic_name(vm_name: str, resource_group: str) -> str` — resolves the primary NIC name from the VM's NIC resource ID
- `AzureRouteProvider.get_effective_routes(nic_name: str, resource_group: str) -> dict` — returns the raw effective route table JSON as a parsed Python dict

**What it may do:**
- Shell out to `az` CLI using argument vectors only — no string interpolation, no `shell=True`
- Retry on HTTP 429 with exponential backoff
- Detect `AuthorizationFailed` in az CLI stderr and raise `RBACError`
- Parse stdout JSON; raise `ProviderError` on non-JSON or unexpected schema

**What it may not do:**
- Write any files
- Apply any business logic about what routes mean
- Swallow exceptions
- Use string concatenation to build CLI commands

**Typed exceptions:**

| Exception | Raised when | What orchestrator receives |
|-----------|-------------|---------------------------|
| `RBACError` | `AuthorizationFailed` in az CLI output | Exit code 2; message names the missing permission |
| `ThrottleExhausted` | HTTP 429 after all retries exhausted | Exit code 2; message includes retry count and wait time |
| `VMNotFoundError` | `az vm show` returns no resource | Exit code 2; message names the VM and resource group |
| `NICResolutionError` | NIC ID present but name extraction fails | Exit code 2; message includes raw resource ID |
| `ProviderError` | Any other az CLI failure | Exit code 2; message includes az CLI stderr |

---

### 3.3 `route_preprocessor.py` — JSON Normaliser

**What it is:** A copy of the proven preprocessor from `azure-effective-route-summarizer`. Accepts a raw az CLI route JSON dict; returns a normalised flat list of route objects — one row per prefix.

**What it exposes:**
- `preprocess(data: dict) -> dict` — accepts the parsed raw JSON dict; returns `{ route_count, routes, invalid_route_count, parse_warnings }` on success, or `{ error, parse_warnings }` on failure

**What it may do:**
- Unwrap any of the four Azure CLI envelope variants (`value`, `effectiveRoutes`, raw list, single object)
- Expand multi-prefix entries into one row per prefix
- Normalise `state` to title-case; treat absent/null state as `Unknown`
- Validate each prefix as a valid CIDR; skip and warn on invalid values
- Emit parse warnings for ECMP next-hop addresses, absent fields, empty tables

**What it may not do:**
- Perform any I/O
- Apply route selection logic

---

### 3.4 `lpm_engine.py` — Route Selection Algorithm

**What it is:** A pure-function module that implements the Azure route selection algorithm and anomaly detection. No I/O, no side effects.

**What it exposes:**
- `select_route(routes: list[dict], dst_ip: str) -> dict` — applies the full selection algorithm for a destination IP; returns a verdict dict
- `audit_routes(routes: list[dict]) -> dict` — produces an audit verdict for the full route table without a destination IP

**Route selection algorithm (single-target mode), applied in strict order:**

1. **CIDR containment filter** — keep only routes where `state == "Active"` and `dst_ip` falls within `prefix`. If no route passes: verdict is `NO_ROUTE`.
2. **Longest Prefix Match** — select the route(s) with the maximum `prefix_length`. LPM is absolute — a `/32` Default route beats a `/24` UDR.
3. **Source precedence** (equal prefix length only) — `User` (Tier 1) beats `VirtualNetworkGateway` (Tier 2) beats `Default` (Tier 3).
4. **BGP tie-break** — two or more `VirtualNetworkGateway` routes with the same prefix after step 3: verdict is `TIED_BGP`. Do not select. Stop.

**Anomaly checks** (applied after winner selection):
- `next_hop_type == None` on the winning route → `BLACKHOLE_WARNING`
- A route exists with a longer prefix than the winner and `state == "Invalid"` → `INVALID_SHADOW_WARNING`
- `next_hop_type == "VirtualAppliance"` on the winning route → `NVA_WARNING`

**What it may not do:**
- Perform any I/O
- Call any Azure APIs
- Use non-deterministic logic

---

## 4. Integration Coupling Rules

### 4.1 `effective_route_inspector.py` ↔ `providers.py`

- Orchestrator passes `(vm_name, resource_group)` to `get_nic_name` and `(nic_name, resource_group)` to `get_effective_routes`. Subscription context is set at provider construction time.
- Provider returns a plain Python dict matching the raw az CLI JSON schema — no filtering or normalisation.
- On any failure the provider raises a typed exception. Orchestrator catches, emits to stderr, exits 2.

### 4.2 `effective_route_inspector.py` ↔ `route_preprocessor.py`

- Orchestrator passes the raw route JSON dict directly to `preprocess()`.
- `preprocess()` returns `{ route_count, routes, invalid_route_count, parse_warnings }` or `{ error, parse_warnings }`. Orchestrator checks for `error` key before proceeding.
- `parse_warnings` is always included in the verdict artifact.

### 4.3 `effective_route_inspector.py` ↔ `lpm_engine.py`

- Orchestrator passes the normalised route list and (for single-target) the validated destination IP string.
- The verdict dict is serialised directly to `rt_{session_id}_verdict.json`. The console table is always derived from the same dict — never computed separately.

**Verdict dict schema (single-target mode):**
```
{
  "mode": "single-target",
  "session_id": "rt_<id>",
  "vm_name": "<vm>",
  "resource_group": "<rg>",
  "nic_name": "<nic>",
  "dst_ip": "<ip>",
  "result": "WINNER" | "NO_ROUTE" | "TIED_BGP",
  "winning_route": { prefix, prefix_length, next_hop_type, next_hop_ip,
                     source, state, route_name } | null,
  "selection_reason": "LPM_ONLY" | "SOURCE_PRECEDENCE" | "TIED_BGP" | "NO_ROUTE",
  "shadowed_candidates": [ ...route objects... ],
  "anomaly_warnings": [ ...warning strings... ],
  "parse_warnings": [ ...warning strings... ]
}
```

**Verdict dict schema (audit mode):**
```
{
  "mode": "audit",
  "session_id": "rt_<id>",
  "vm_name": "<vm>",
  "resource_group": "<rg>",
  "nic_name": "<nic>",
  "route_count": <int>,
  "invalid_route_count": <int>,
  "routes_by_prefix_length": [ ...route objects, descending prefix_length... ],
  "invalid_routes": [ ...route objects... ],
  "findings": {
    "blackhole_routes": [ ...route objects... ],
    "nva_routes": [ ...route objects... ],
    "bgp_routes": [ ...route objects... ],
    "default_route_present": true | false,
    "default_route_source": "<source>" | null
  },
  "parse_warnings": [ ...warning strings... ]
}
```

### 4.4 Ghost Agent ↔ `effective_route_inspector.py`

- Ghost Agent passes `--session-id rt_{generated_id}`. The tool enforces the `rt_` prefix — no double-prefixing.
- Artifact paths are deterministic: `{AUDIT_DIR}/rt_{session_id}_verdict.json`. The handler constructs these paths directly — no filesystem scan.
- The handler reads the verdict artifact JSON and returns a structured dict to the Brain. It never parses stdout.
- Exit code semantics: `0` = verdict artifact present; `2` = fatal, no artifact.

**Ghost Agent FunctionDeclaration (11th tool):**
```
name:        "effective_route_inspector"
parameters:
  vm_name         (string, required)
  resource_group  (string, required)
  dst_ip          (string, optional) — omit for audit mode
  nic_name        (string, optional) — override primary NIC selection
  subscription_id (string, optional)
```

---

## 5. Intentional Omissions

| Capability | Excluded because |
|------------|-----------------|
| Drift / baseline comparison | `detect_effective_network_drift`'s responsibility. This tool answers "what is the current routing verdict?"; the drift tool answers "did routing change?". Adding a compare mode here would duplicate drift logic with no shared test surface. |
| Fleet or VNet scope | `detect_effective_network_drift`'s scope. Adding fleet scope requires concurrency, partial-failure handling, and NIC discovery logic that belongs to the existing drift tool. |
| AI inside the tool | The route selection algorithm is deterministic Python. Injecting an LLM makes the verdict non-deterministic and untestable. Ghost Agent Brain is the reasoning layer; this tool produces evidence. This is an architectural invariant. |
| `--explain` flag (AI narrative output) | Same principle as ENI architecture. Additive if needed post-MVP — same pattern as `iptables-parser --explain-diff`. Not in the main pipeline. |
| NSG rule evaluation | L4 state, not L3 routing. Requires a separate `az network nic list-effective-nsg` query. `security_rule_inspector`'s responsibility. |
| Stdout as machine output | Stdout is reserved for human-readable output. Ghost Agent reads the verdict artifact. Mixing structured data into stdout couples the handler to the human output format. |
| SHA-256 integrity sidecar | The artifact is consumed within the same invocation or immediately after. No long-lived baseline needing tamper detection (unlike ENI snapshots). |
| Retry on non-429 errors | Auth failures (403), VM-not-found (404), and platform errors (5xx) do not resolve by waiting. Retrying wastes quota and delays actionable error surfacing. |
| BGP AS Path tiebreaking | AS Path is not present in the effective route table JSON. `TIED_BGP` is the correct and complete response. Directing the engineer to the gateway BGP peer status query is Ghost Agent Brain's responsibility. |
