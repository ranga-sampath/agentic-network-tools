# Architecture: Agentic Pipe Meter

## Document Order

| Stage        | Document                  | Status          |
|--------------|---------------------------|-----------------|
| Requirements | `product-requirements.md` | ✓ Exists        |
| Architecture | `architecture.md`         | This document   |
| Design       | `design.md`               | Not yet produced |
| Code         | —                         | Not yet written |

---

## 1. Design Decision Table

| Decision | Choice | Rationale |
|---|---|---|
| AI/LLM in measurement path | **None** | Measurement, statistics, and baseline comparison are deterministic operations. An LLM makes correctness probabilistic where it must be exact. |
| SSH and command execution | **Shell-out via SafeExecShell (sibling library)** | SafeExecShell already provides classify → gate → execute → audit for every shell command. `ssh user@ip "qperf ..."` is a local shell command; it goes through SafeExecShell so HITL gating and the audit trail are structural, not optional. No separate SSH library or HITL re-implementation is needed. |
| NSG check method | **Effective rules via `az network nic list-effective-nsg`** | Configured rules (az network nsg rule list) represent intent; effective rules represent what Azure actually enforces on the NIC. The pre-flight check must test enforcement, not configuration. |
| Cloud abstraction | **CloudProvider Protocol + Azure impl only** | PRD §7 explicitly requires future multi-cloud support. The interface is defined now; only `AzureProvider` is implemented. Future providers are additive code paths in `providers.py` with no changes to the pipeline. |
| AzureProvider + SafeExecShell coupling | **AzureProvider takes SafeExecShell as a constructor parameter** | The provider must execute `az` CLI commands and return data structures (not command strings). All `az` calls route through SafeExecShell so they are classified, gated if needed, and audit-logged. `generate_port_open_commands` is the sole exception: it returns human-readable display strings only — never for execution. |
| Intermediate artifacts | **One JSON file per stage, written by each stage to disk** | Any stage can be re-run or debugged in isolation without reprocessing upstream stages. Each stage owns its own write. |
| Baseline storage | **Azure Blob via CloudProvider** | Specified in PRD §5.2. Routing through the provider interface keeps the storage location swappable per cloud. |
| Server process cleanup | **try/finally in measure stage** | The server process kill runs even if measurement fails. This is a code-path guarantee, not a convention. |
| Statistical method | **P90 + Gap Rule** | Specified in PRD §3.2–3.3. P90 filters transient spikes. The Gap Rule detects systemic instability that P90 alone masks. |
| Warm-up pass | **1 unrecorded iteration before N recorded** | Specified in PRD §3.3. Eliminates cold-start skew from connection establishment and tool initialisation. |
| Session ID | **Auto-generated at pipeline start as `pmeter_{YYYYMMDDTHHMMSS}`; overridable with `--session-id`** | Provides a stable prefix for all artifact filenames in a run without requiring user input in the common case. |

---

## 2. System Boundary Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│  Caller                                                                │
│  CLI args  ──or──  Ghost Agent tool call (future integration path)     │
└──────────────────────────┬─────────────────────────────────────────────┘
                           │ PipelineConfig
                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│  pipe_meter.py  ─  Pipeline Orchestrator                               │
│                                                                        │
│  validate → preflight → measure → compute → compare → report          │
│                                                                        │
│  Each stage writes one intermediate artifact to {audit_dir}/:         │
│    _preflight.json  _raw.json  _computed.json  _comparison.json        │
│    _result.json  (final artifact, also uploaded to blob)               │
│                                                                        │
│  ┌─────────────────────────────┐  ┌──────────────────────────────┐    │
│  │  SafeExecShell              │  │  CloudProvider (providers.py) │    │
│  │  (sibling library)          │  │  Protocol + AzureProvider     │    │
│  │  classify → gate → execute  │  │  AzureProvider(shell=...)     │    │
│  │  → audit                    │  │  - effective NSG queries       │    │
│  │                             │  │  - blob read / write          │    │
│  │  All SSH and az CLI calls   │  │  (all az calls via shell)     │    │
│  │  flow through this boundary │  │                               │    │
│  └──────────┬──────────────────┘  └──────────────┬───────────────┘    │
└─────────────┼────────────────────────────────────┼────────────────────┘
              │                                     │
   ┌──────────▼──────────┐            ┌─────────────▼──────────────┐
   │   Source VM (SSH)   │            │   Azure Control Plane       │
   │   qperf / iperf2    │            │   az network nic            │
   │   client            │            │   az storage blob           │
   └──────────┬──────────┘            └────────────────────────────┘
              │ network under test
   ┌──────────▼──────────┐
   │   Dest VM (SSH)     │
   │   qperf / iperf2    │
   │   server            │
   │   (killed in        │
   │    finally block)   │
   └─────────────────────┘
```

---

## 3. Component Inventory

### 3.1 `pipe_meter.py` — Pipeline Orchestrator and Entry Point

**Is:** CLI entry point, pipeline sequencer, and owner of all dataclass contracts.
Instantiates `SafeExecShell` and `CloudProvider` once per run, then calls stage functions in order.

**CLI:**
```
python pipe_meter.py
  --source-ip IP         IP of the client VM
  --dest-ip   IP         IP of the server VM
  --ssh-user  USER       SSH username valid on both VMs
  --test-type {latency,throughput,both}
  --storage-account NAME Azure storage account for artifacts
  --container NAME       Azure blob container for artifacts
  --resource-group RG    Azure resource group (required for NSG remediation)
  [--iterations N]       Default: 8
  [--is-baseline]        Flag: mark this run as the baseline for this IP pair
  [--session-id ID]      Default: auto-generated pmeter_{YYYYMMDDTHHMMSS}
  [--audit-dir PATH]     Default: ./audit
```

**Library entry point (for Ghost Agent integration):**
`run_pipeline(config: PipelineConfig, shell: SafeExecShell, provider: CloudProvider) → PipelineResult`

**Dataclass contracts (shared across all stages):**

| Dataclass | Fields |
|---|---|
| `PipelineConfig` | source_ip, dest_ip, ssh_user, test_type, iterations, is_baseline, storage_account, container, resource_group, session_id, audit_dir |
| `PreflightResult` | ports_open: bool, tools_ready: bool, actions_taken: list[str] |
| `MeasurementRaw` | latency_samples: list[float], throughput_samples: list[float], session_id: str |
| `ComputedStats` | latency_p90, latency_min, latency_max, throughput_p90, throughput_min, throughput_max, is_stable: bool, anomaly_type: Optional[str] |
| `ComparisonResult` | stats: ComputedStats, baseline_p90_latency: Optional[float], baseline_p90_throughput: Optional[float], delta_pct_latency: Optional[float], delta_pct_throughput: Optional[float], write_as_baseline: bool |
| `PipelineResult` | status: str, local_artifact_path: str, blob_url: str, session_id: str |

**Session manifest** — written to `{audit_dir}/{session_id}_manifest.json` at pipeline start, before any stage runs. Fields: `session_id`, `timestamp_utc`, `source_ip`, `dest_ip`, `test_type`, `iterations`, `is_baseline`, `storage_account`, `container`.

**May:**
- Instantiate exactly one `SafeExecShell` and one `CloudProvider` per run.
- Call pipeline stage functions in declared order.
- Abort after `preflight` if `PreflightResult.ports_open = False` or `PreflightResult.tools_ready = False`.

**May not:**
- Execute shell commands directly — all commands go through `SafeExecShell.execute()`.
- Call cloud APIs directly — all cloud operations go through `CloudProvider`.

---

### 3.2 `validate` stage

**Input:** Raw CLI args
**Output:** `PipelineConfig`

Pure function, no I/O. Validates: IPv4 format on both IPs, `test_type` ∈ `{latency, throughput, both}`, `iterations ≥ 1`, `storage_account` and `container` non-empty, `ssh_user` non-empty. Raises `ValueError` with a human-readable message on the first failure encountered.

**May not:** Perform network checks, read files, or call any external process.

---

### 3.3 `preflight` stage

**Input:** `PipelineConfig`, `SafeExecShell`, `CloudProvider`
**Output:** `PreflightResult`, writes `{audit_dir}/{session_id}_preflight.json`

**Sequence:**
1. Call `provider.check_nsg_ports(source_ip, dest_ip, [5001, 19765])` — returns `dict[int, bool]` based on effective security rules applied to both VMs' NICs.
2. If any port is blocked: call `provider.generate_port_open_commands(resource_group, blocked_ports)`, print the returned command strings to stdout for the operator to review, then call `shell.execute()` with each command — SafeExecShell will gate them as RISKY. If the operator declines any gate, set `PreflightResult.ports_open = False` and return immediately. Do not continue to the dependency check.
3. SSH to source VM and dest VM via `shell.execute()` to check for `qperf` and `iperf` binaries (`which qperf`, `which iperf`).
4. If any binary is missing on either VM: call `shell.execute()` with the install command (`apt-get install -y qperf iperf` or `yum install -y qperf iperf`). SafeExecShell presents the operator prompt from PRD §4.2 as the RISKY gate. If declined, set `PreflightResult.tools_ready = False` and return.
5. Write `_preflight.json` and return `PreflightResult`.

**May not:**
- Execute NSG or install commands without going through `SafeExecShell.execute()`.
- Proceed to `measure` if `ports_open = False` — the orchestrator enforces this gate; preflight only reports.

---

### 3.4 `measure` stage

**Input:** `PipelineConfig`, `SafeExecShell`
**Output:** `MeasurementRaw`, writes `{audit_dir}/{session_id}_raw.json`

**Sequence:**
1. **Pre-clean:** Check dest VM for any existing qperf or iperf processes bound to ports 19765/5001 via `shell.execute()` (`ss -tlnp` or `lsof -i`). If found, report the PID(s) to the operator and call `shell.execute()` with the kill command — SafeExecShell gates it as RISKY. If the operator declines, raise an error and abort. This guards against stale processes left by a previously interrupted run.
2. Start qperf server and/or iperf server on dest VM via `shell.execute()`. SafeExecShell gates these as RISKY (remote server process start). Operator approves once per run.
3. Execute 1 warm-up iteration from source VM via `shell.execute()`. Parse result but discard it.
4. Execute `config.iterations` recorded iterations. For each: call `shell.execute()`, parse stdout with a fixed regex to extract the metric value. For throughput (iperf2 with `-P 8`), the regex must target the `[SUM]` aggregate line — not individual stream lines. On parse failure, raise an error immediately — do not silently skip.
5. Write `{session_id}_raw.json` containing all iteration values (the write happens in the try block, before teardown).
6. `finally`: kill qperf and/or iperf server process(es) on dest VM via `shell.execute()`. Executes on success, failure, and exception.

**May not:**
- Record the warm-up iteration.
- Silently skip a failed iteration — a parse failure is a run failure.
- Leave server processes running on any exit path (finally guarantee).
- Parse iperf2 throughput from individual stream lines — only the `[SUM]` line is authoritative.

---

### 3.5 `compute` stage

**Input:** `MeasurementRaw`
**Output:** `ComputedStats`, writes `{audit_dir}/{session_id}_computed.json`

Computes for each active metric (latency if `test_type ∈ {latency, both}`, throughput if `test_type ∈ {throughput, both}`):

- **P90:** Sort samples ascending; select index `floor(0.90 × N)`.
- **Min, Max.**
- **Gap Rule and anomaly classification:**
  - If `min = 0`: set `is_stable = False`, `anomaly_type = "CONNECTIVITY_DROP"`. A zero value indicates a timeout or dropped connection — a more severe condition than variance, requiring a different diagnostic response from the investigator. The formula is not applied.
  - If `(max − min) / min > 0.50`: set `is_stable = False`, `anomaly_type = "HIGH_VARIANCE"`. Indicates the path is inconsistent but connected.
  - Otherwise: `is_stable = True`, `anomaly_type = None`.

For metrics not active in this run, all fields remain `None`.

Pure function over its input. No I/O beyond writing the artifact.

**May not:** Call any external process, cloud API, or re-run measurements.

---

### 3.6 `compare` stage

**Input:** `PipelineConfig`, `ComputedStats`, `CloudProvider`
**Output:** `ComparisonResult`, writes `{audit_dir}/{session_id}_comparison.json`

1. Construct baseline blob name: `{source_ip}_{dest_ip}_baseline.json` (dots in IPs replaced with underscores).
2. Call `provider.read_blob(account, container, blob_name)` — returns `None` if no baseline exists for this pair.
3. If baseline exists: parse it and compute `delta_pct = (current_p90 − baseline_p90) / baseline_p90 × 100` per active metric.
4. Set `ComparisonResult.write_as_baseline = config.is_baseline`.
5. **Baseline overwrite rule:** if `config.is_baseline = True` and a baseline already exists, the tool prints a warning showing the existing baseline's timestamp, then calls `shell.execute()` with the overwrite command — SafeExecShell gates it as RISKY, giving the operator the chance to decline. If declined, `write_as_baseline` is set to `False`; the result is still saved as a regular (non-baseline) run.
6. Write `_comparison.json` and return `ComparisonResult`.

**May not:** Write anything to blob — all blob writes belong to `report`.

---

### 3.7 `report` stage

**Input:** `ComparisonResult`, `PipelineConfig`, `CloudProvider`
**Output:** `{audit_dir}/{session_id}_result.json` on disk; blob upload(s); console summary printed to stdout.

1. Assemble the JSON artifact from `ComparisonResult` and `PipelineConfig` (schema per PRD §5.2).
2. Write the artifact to local disk first: `{audit_dir}/{session_id}_result.json`. The local write must succeed before any blob upload is attempted.
3. Call `provider.write_blob(account, container, result_blob_name, data)` to store the run result.
4. If `ComparisonResult.write_as_baseline = True`: call `provider.write_blob(account, container, baseline_blob_name, data)` to store the same artifact as the new baseline.
5. Print the console summary (PRD §5.1): test status, P90 per active metric with delta if a baseline was found, local artifact path.

**May not:** Compute or modify any statistics — it reads `ComparisonResult` as-is.

---

### 3.8 `providers.py` — Cloud Provider Abstraction

**Is:** A `typing.Protocol` (`CloudProvider`) and its Azure implementation (`AzureProvider`). No other implementations in this release.

**`AzureProvider` constructor:** `AzureProvider(shell: SafeExecShell, resource_group: str)`

All `az` CLI calls (both reads and writes) are routed through the injected `shell`. The provider constructs the command string, calls `shell.execute()`, and parses the JSON output. SafeExecShell classifies read-only `az` calls as SAFE (no gate) and write `az` calls as RISKY (gate presented to operator).

**CloudProvider Protocol:**

| Method | Signature | Returns | Notes |
|---|---|---|---|
| `check_nsg_ports` | `(source_ip, dest_ip, ports: list[int]) → dict[int, bool]` | True = port open | Uses `az network nic list-effective-nsg` on both VMs' NICs; checks inbound rules |
| `generate_port_open_commands` | `(resource_group, ports: list[int]) → list[str]` | Human-readable `az network nsg rule create` strings | Queries current NSG rules to find the lowest existing priority and computes a safe priority value below any existing DENY rule for the relevant ports. For display only — the orchestrator passes these to `shell.execute()` |
| `read_blob` | `(account, container, blob_name) → Optional[bytes]` | File bytes, or None if absent | Uses `az storage blob download` |
| `write_blob` | `(account, container, blob_name, data: bytes) → str` | Blob URL | Uses `az storage blob upload` |

**May not:**
- Execute commands directly — all `az` calls go through the injected `SafeExecShell`.
- Cache NSG state between calls.
- Contain business logic (P90, gap rule, delta calculation).

---

## 4. Integration Coupling Rules

| Boundary | Contract |
|---|---|
| `validate → preflight` | `preflight` receives a fully-validated `PipelineConfig`. It never re-validates inputs. |
| `preflight → measure` | The orchestrator calls `measure` only when `PreflightResult.ports_open = True` and `PreflightResult.tools_ready = True`. `measure` does not re-check pre-flight state. |
| `measure → compute` | `compute` receives `MeasurementRaw` where `latency_samples` and `throughput_samples` are populated per `test_type`. If `test_type = "latency"`, `throughput_samples` is an empty list; `compute` leaves all throughput fields as `None`. |
| `compute → compare` | `compare` receives fully-populated `ComputedStats`. It does not recompute statistics. |
| `compare → report` | `report` treats `baseline_p90_latency = None` and `baseline_p90_throughput = None` as "no baseline found" and omits delta lines from the console summary. |
| `pipe_meter → SafeExecShell` | All shell commands (SSH, `az` CLI) are strings constructed by either the orchestrator or a stage function and passed to `shell.execute({"command": ..., "reasoning": ...})`. SafeExecShell classifies, gates, executes, and writes the command-level audit record. No other code path may execute shell commands. |
| `pipe_meter → CloudProvider` | The orchestrator and stage functions call CloudProvider methods to get data structures back. CloudProvider methods may call `shell.execute()` internally (via the injected shell reference) for `az` queries, but the calling stage only sees the returned data structure. |
| `measure ↔ Dest VM` | The server process on dest VM is started and killed exclusively within the `measure` stage. No other stage may start or kill the measurement server. |
| Audit ownership | `SafeExecShell` writes command-level audit records. Each stage function writes its own stage artifact (`_preflight.json`, `_raw.json`, `_computed.json`, `_comparison.json`, `_result.json`). The orchestrator writes the session manifest (`_manifest.json`). No other writes occur. |

---

## 5. Intentional Omissions

| Capability | Excluded | Reason |
|---|---|---|
| LLM/AI anywhere in the pipeline | No AI call is made in any stage. | All operations are deterministic. An AI call would make correctness probabilistic where it must be exact. |
| Auto-remediation of NSG rules or package installs | All write actions go through SafeExecShell HITL gate. The tool never self-approves a write. | A gate that can be skipped by the tool itself is not a gate. |
| UDP testing | TCP only: qperf on port 19765, iperf2 on port 5001. | Not in PRD. UDP requires new pre-flight port rules, new parsing, and new result semantics — each a separate additive concern if ever needed. |
| Real-time iteration streaming to console | Iteration values are written to `_raw.json`; the console shows only the final P90 summary. | The console is for the operator; the JSON is for the engineer. Streaming raw iterations to the console serves neither. |
| GCP / AWS / OCI providers | Only `AzureProvider` is implemented. | PRD §7 requires a multi-cloud interface, not multi-cloud implementations. Speculative implementations embed untested platform constraints. |
| Markdown / HTML stakeholder report | Console summary + JSON artifact only. | PRD §5 specifies these two outputs. A narrative report is a new output contract, added only when a stakeholder explicitly requires it. |
| Parallel multi-pair testing | One source/destination pair per invocation. | Not in PRD. Fan-out requires session isolation, result aggregation, and baseline blob-name conflict rules — each a distinct design concern. |
| SSH credential management | SSH authentication is pre-configured in the environment (ssh-agent, VM identity). The tool constructs `ssh user@ip "cmd"` strings; it does not manage keys or certificates. | Credential lifecycle is an infrastructure concern outside this tool's boundary. |
| Silent retry on measurement failure | A failed iteration (parse error, SSH failure) is a run failure. No silent retry. | Silent retries mask real failures. The operator decides whether to re-run. |
| Time-series storage or result trending | Results are individual JSON blobs. Historical trending and alerting are deferred. | Not in PRD. |
