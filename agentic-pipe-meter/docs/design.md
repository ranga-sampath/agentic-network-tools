# Design: Agentic Pipe Meter

## Document Order

| Stage        | Document                  | Status        |
|--------------|---------------------------|---------------|
| Requirements | `product-requirements.md` | ✓ Exists      |
| Architecture | `architecture.md`         | ✓ Exists      |
| Design       | `design.md`               | This document |
| Code         | —                         | Not yet written |

---

## 1. File Inventory

| File | Responsibility |
|---|---|
| `pipe_meter.py` | CLI entry point, pipeline orchestrator, all stage functions, all dataclasses, parsing functions, HITL callback factory |
| `providers.py` | `CloudProvider` Protocol definition; `AzureProvider` implementation |

No other files are produced in this release.

---

## 2. Data Schemas

All dataclasses are defined in `pipe_meter.py`. Every field listed includes its type and semantics. `None` in an optional field always means "not applicable for this run" or "not found" — never "not yet computed."

### 2.1 `PipelineConfig`

Produced by `validate()`. Consumed read-only by all subsequent stages.

| Field | Type | Semantics |
|---|---|---|
| `source_ip` | `str` | IPv4 address of the client VM (private) — used for NSG check and as measurement source |
| `dest_ip` | `str` | IPv4 address of the server VM (private) — SSH target and measurement destination |
| `ssh_user` | `str` | SSH username valid on both VMs |
| `test_type` | `str` | `"latency"` \| `"throughput"` \| `"both"` |
| `iterations` | `int` | Number of recorded measurement runs; ≥ 1 |
| `is_baseline` | `bool` | If `True`, write this run's result as the new baseline blob |
| `storage_account` | `str` | Azure storage account name for all blob writes |
| `container` | `str` | Azure blob container name |
| `resource_group` | `str` | Azure resource group containing both VMs and their NSGs |
| `session_id` | `str` | Stable prefix for all artifact filenames; format `pmeter_{YYYYMMDDTHHMMSS}` (UTC) |
| `audit_dir` | `str` | Local path for all intermediate artifacts; default `./audit` |
| `source_public_ip` | `Optional[str]` | Public IP (or hostname) used to SSH to the source VM from outside the VNet. Falls back to `source_ip` if absent |
| `source_vm_key_path` | `Optional[str]` | Path to the SSH private key for the source VM. Used for direct SSH to the source and as the ProxyCommand key for reaching the dest VM |
| `dest_vm_key_path` | `Optional[str]` | Path to the SSH private key for the dest VM. Used via ProxyCommand through the source VM; the key never leaves the local machine |
| `subscription_id` | `Optional[str]` | Azure subscription ID passed as `--subscription` to all `az` CLI calls |
| `compare_baseline` | `bool` | If `True`, download and compare with an existing baseline. If `False` (default), no baseline interaction occurs even when one exists |

---

### 2.2 `PreflightResult`

Produced by `preflight()`. Consumed by the orchestrator to decide whether to proceed.

| Field | Type | Semantics |
|---|---|---|
| `ports_open` | `bool` | `True` if ports 5001 and 19765 are reachable inbound on dest VM and outbound from source VM |
| `tools_ready` | `bool` | `True` if `qperf` and `iperf` are present on both VMs |
| `actions_taken` | `list[str]` | Human-readable log of what was done (e.g., `"Installed qperf on 10.0.0.4"`) |

---

### 2.3 `MeasurementRaw`

Produced by `measure()`. Consumed by `compute()`.

| Field | Type | Semantics |
|---|---|---|
| `latency_samples` | `list[float]` | Per-iteration latency in **µs**. Empty list if `test_type == "throughput"` |
| `throughput_samples` | `list[float]` | Per-iteration throughput in **Gbps**. Empty list if `test_type == "latency"` |
| `session_id` | `str` | Copied from `PipelineConfig` for artifact traceability |

Invariant enforced by `measure()`: if `test_type` requires a metric, its sample list has exactly `iterations` elements (no more, no fewer).

---

### 2.4 `ComputedStats`

Produced by `compute()`. Consumed by `compare()`.

| Field | Type | Semantics |
|---|---|---|
| `latency_p90` | `Optional[float]` | 90th percentile latency in µs. `None` if `test_type == "throughput"` |
| `latency_min` | `Optional[float]` | Minimum latency in µs across all iterations |
| `latency_max` | `Optional[float]` | Maximum latency in µs |
| `throughput_p90` | `Optional[float]` | 90th percentile throughput in Gbps. `None` if `test_type == "latency"` |
| `throughput_min` | `Optional[float]` | Minimum throughput in Gbps |
| `throughput_max` | `Optional[float]` | Maximum throughput in Gbps |
| `is_stable` | `bool` | `False` if any active metric failed the Gap Rule or contained a zero value |
| `anomaly_type` | `Optional[str]` | `"CONNECTIVITY_DROP"` \| `"HIGH_VARIANCE"` \| `None`. Set for the **worst** anomaly found across active metrics. Priority: `CONNECTIVITY_DROP` > `HIGH_VARIANCE` > `None` |

---

### 2.5 `ComparisonResult`

Produced by `compare()`. Consumed by `report()`.

| Field | Type | Semantics |
|---|---|---|
| `stats` | `ComputedStats` | Passed through from `compute()` unchanged |
| `baseline_p90_latency` | `Optional[float]` | P90 latency from the stored baseline, in µs. `None` if no baseline exists or metric inactive |
| `baseline_p90_throughput` | `Optional[float]` | P90 throughput from the stored baseline, in Gbps. `None` if no baseline or metric inactive |
| `baseline_timestamp` | `Optional[str]` | ISO 8601 timestamp of the stored baseline. `None` if no baseline exists |
| `delta_pct_latency` | `Optional[float]` | `(current_p90 − baseline_p90) / baseline_p90 × 100`. Positive = degraded. `None` if no baseline or inactive |
| `delta_pct_throughput` | `Optional[float]` | Same formula for throughput. **Negative = degraded** (throughput went down). `None` if no baseline or inactive |
| `write_as_baseline` | `bool` | `True` if `report()` should write this result as the new baseline blob |

---

### 2.6 `PipelineResult`

Produced by `run_pipeline()` and `report()`. The return value to the caller.

| Field | Type | Semantics |
|---|---|---|
| `status` | `str` | `"success"` \| `"aborted_preflight"` \| `"error"` |
| `local_artifact_path` | `str` | Absolute path to `{session_id}_result.json`. Empty string if pipeline aborted before reaching `report()` |
| `blob_url` | `str` | URL of the uploaded result blob. Empty string if upload failed or pipeline aborted |
| `session_id` | `str` | The session ID for this run |
| `error_message` | `Optional[str]` | Set when `status == "error"`. Human-readable description of the failure |

---

## 3. JSON Artifact Schema

Written to `{audit_dir}/{session_id}_result.json` by `report()` and uploaded to Azure Blob.

```json
{
  "test_metadata": {
    "session_id": "pmeter_20260302140000",
    "source_ip": "10.0.0.4",
    "destination_ip": "10.0.0.5",
    "ssh_user": "azureuser",
    "test_type": "both",
    "is_baseline": false,
    "timestamp": "2026-03-02T14:00:00Z",
    "iterations": 8,
    "resource_group": "my-rg",
    "storage_account": "mystorage",
    "container": "pipe-meter-results"
  },
  "preflight": {
    "ports_open": true,
    "tools_ready": true,
    "actions_taken": []
  },
  "results": {
    "is_stable": false,
    "anomaly_type": "HIGH_VARIANCE",
    "latency_p90": 124.5,
    "latency_min": 105.0,
    "latency_max": 198.0,
    "throughput_p90": 9.4,
    "throughput_min": 9.1,
    "throughput_max": 9.7,
    "units": {
      "latency": "us",
      "throughput": "Gbps"
    },
    "iteration_data": [
      {"iteration": 1, "latency_us": 112.0, "throughput_gbps": 9.3},
      {"iteration": 2, "latency_us": 198.0, "throughput_gbps": 9.4}
    ]
  },
  "comparison": {
    "baseline_found": true,
    "baseline_timestamp": "2026-02-15T10:00:00Z",
    "baseline_latency_p90": 115.0,
    "baseline_throughput_p90": 9.5,
    "delta_pct_latency": 8.26,
    "delta_pct_throughput": -1.05
  }
}
```

**Null-handling rules:**
- If `test_type == "latency"`: all `throughput_*` fields in `results` are `null`; `throughput` fields in `comparison` are `null`.
- If `test_type == "throughput"`: all `latency_*` fields are `null`.
- If no baseline exists: `comparison.baseline_found = false`; all other `comparison` fields are `null`.

---

## 4. Blob Naming Convention

Dots in IP addresses are replaced with underscores to produce valid blob names.

| Blob | Name pattern | Example |
|---|---|---|
| Run result | `{src}_{dst}_{session_id}.json` | `10_0_0_4_10_0_0_5_pmeter_20260302140000.json` |
| Baseline | `{src}_{dst}_baseline.json` | `10_0_0_4_10_0_0_5_baseline.json` |

`{src}` and `{dst}` are derived from `source_ip` and `dest_ip` by replacing `.` with `_`.

---

## 5. Function Inventory

### 5.1 `pipe_meter.py`

---

**`main(argv: list[str]) → None`**
Parses CLI arguments with `argparse`. Calls `_generate_session_id()` if `--session-id` is absent. Instantiates `SafeExecShell` and `AzureProvider` (passing `ssh_user`, `source_public_ip or source_ip`, and `source_vm_key_path` so blob operations can be routed through the source VM — see §8). Calls `run_pipeline()`. Prints final status to stdout. Exits with code `0` on success, `1` on error or aborted preflight.

---

**`run_pipeline(config: PipelineConfig, shell: SafeExecShell, provider: CloudProvider) → PipelineResult`**
Top-level pipeline orchestrator. Calls:
1. `_write_manifest(config)`
2. `preflight(config, shell, provider)` → abort if `ports_open=False` or `tools_ready=False`; keep reference as `pre`
3. `measure(config, shell)` → raises on failure
4. `compute(raw, config.test_type, config.audit_dir)` → raises on contract violation
5. `compare(config, stats, provider)` → never raises (returns partial result on blob errors)
6. `report(result, config, provider, pre)` → returns `PipelineResult`

Wraps steps 2–6 in a `try/except Exception`. On any uncaught exception: returns `PipelineResult(status="error", error_message=str(e), local_artifact_path="", blob_url="", session_id=config.session_id)`.

---

**`validate(args: argparse.Namespace) → PipelineConfig`**
Pure function. Validates all CLI arguments in the order shown in §6.1. Raises `ValueError` with a human-readable message on the first validation failure. Returns a fully populated `PipelineConfig`.

---

**`preflight(config: PipelineConfig, shell: SafeExecShell, provider: CloudProvider) → PreflightResult`**
See §6.2 for full stage detail.

---

**`measure(config: PipelineConfig, shell: SafeExecShell) → MeasurementRaw`**
See §6.3 for full stage detail.

---

**`compute(raw: MeasurementRaw, test_type: str, audit_dir: str) → ComputedStats`**
See §6.4 for full stage detail.

---

**`compare(config: PipelineConfig, stats: ComputedStats, provider: CloudProvider) → ComparisonResult`**
See §6.5 for full stage detail.

---

**`report(result: ComparisonResult, config: PipelineConfig, provider: CloudProvider, preflight_result: PreflightResult) → PipelineResult`**
See §6.6 for full stage detail.

---

**`parse_qperf_latency(output: str) → float`**
Single responsibility: extract one latency value in µs from a qperf stdout string.
- Primary regex: `r'latency\s*=\s*([\d.]+)\s*(us|µs)'` → return `float(match.group(1))`
- Fallback regex: `r'latency\s*=\s*([\d.]+)\s*ms'` → return `float(match.group(1)) * 1000.0`
- If neither matches: raise `ParseError(f"Cannot parse qperf latency from output: {output[:300]!r}")`

---

**`parse_iperf2_throughput(output: str) → float`**
Single responsibility: extract the aggregate throughput value in Gbps from an iperf2 stdout string that may contain 8 individual stream lines plus one `[SUM]` line.
- Regex: `r'\[SUM\].*?([\d.]+)\s+(G|M)bits/sec'`
- If unit captured is `"M"`: return `float(match.group(1)) / 1000.0`
- If unit is `"G"`: return `float(match.group(1))`
- If no `[SUM]` line found: raise `ParseError(f"Cannot find [SUM] line in iperf2 output: {output[:300]!r}")`

---

**`_compute_p90(samples: list[float]) → float`**
Returns `sorted(samples)[floor(0.90 * len(samples))]`. Called by `compute()` for each active metric. Precondition: `len(samples) >= 1`. Does not validate — caller ensures.

---

**`_apply_gap_rule(samples: list[float]) → tuple[bool, Optional[str]]`**
Returns `(is_stable, anomaly_type)`.
- If `min(samples) == 0.0`: return `(False, "CONNECTIVITY_DROP")`
- If `(max - min) / min > 0.50`: return `(False, "HIGH_VARIANCE")`
- Otherwise: return `(True, None)`

---

**`_write_artifact(path: str, data: dict) → None`**
Creates parent directories if absent (`os.makedirs(parent, exist_ok=True)`). Writes `json.dumps(data, indent=2, default=str)` to `path`. Raises `RuntimeError(f"Failed to write artifact: {path}: {e}")` on `OSError`.

---

**`_generate_session_id() → str`**
Returns `f"pmeter_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"`.

---

**`_write_manifest(config: PipelineConfig) → None`**
Calls `_write_artifact()` with path `{config.audit_dir}/{config.session_id}_manifest.json` and payload:
```json
{
  "session_id": "...",
  "timestamp_utc": "...",
  "source_ip": "...",
  "dest_ip": "...",
  "ssh_user": "...",
  "test_type": "...",
  "iterations": 8,
  "is_baseline": false,
  "storage_account": "...",
  "container": "...",
  "resource_group": "..."
}
```

---

**`_make_hitl_callback() → Callable`**
Returns a HITL callback function for the `SafeExecShell` constructor. The returned callback:
1. Receives a proposed command string.
2. Checks it against `_PIPE_METER_AUTO_APPROVE_PATTERNS` (see §10).
3. If matched: returns `HitlDecision(action="approve")` without prompting.
4. If not matched: prints the command and reasoning to stdout, prompts `[approve/deny]:`, returns `HitlDecision(action="approve")` or `HitlDecision(action="deny")` based on operator input.

---

**`_ip_to_blob_prefix(ip: str) → str`**
Returns `ip.replace(".", "_")`. Example: `"10.0.0.4"` → `"10_0_0_4"`.

---

**`_assemble_artifact(result: ComparisonResult, config: PipelineConfig) → dict`**
Builds the final JSON artifact dict per §3. Assembles `test_metadata`, `preflight` (from `actions_taken` carried in `result.stats` — see note below), `results`, and `comparison` sections. All `None` fields are serialised as JSON `null`. Returns the dict; does not write to disk.

> **Note:** `_assemble_artifact` needs `PreflightResult.actions_taken` to populate the `preflight` section of the artifact. Pass `preflight_result` as a third argument: `_assemble_artifact(result, config, preflight_result)`. The orchestrator in `run_pipeline()` must keep a reference to the `PreflightResult` returned by `preflight()` and pass it through to `report()`.

---

**`_print_console_summary(result: ComparisonResult, config: PipelineConfig, local_path: str, blob_url: str) → None`**
Prints the formatted summary to stdout per §12. Applies conditional rendering rules: suppresses inactive metric lines, suppresses delta if no baseline, adds `(slower)`/`(faster)` labels to delta values (see §12), shows `[CONNECTIVITY_DROP]` or `[HIGH_VARIANCE]` tags per metric.

For latency: positive delta = slower (worse). For throughput: negative delta = slower (worse).

---

**`preflight_to_dict(result: PreflightResult) → dict`**
Returns `{"ports_open": bool, "tools_ready": bool, "actions_taken": list[str]}`. Called only by `preflight()`.

---

**`raw_to_dict(raw: MeasurementRaw) → dict`**
Returns:
```json
{
  "session_id": "...",
  "latency_samples_us": [112.0, 198.0, ...],
  "throughput_samples_gbps": [9.3, 9.4, ...]
}
```
Empty lists serialise as `[]`. Called only by `measure()` before writing `_raw.json`.

---

**`stats_to_dict(stats: ComputedStats) → dict`**
Returns a dict with all `ComputedStats` fields. `None` fields included as `null`. Called only by `compute()` before writing `_computed.json`.

---

**`comparison_to_dict(result: ComparisonResult) → dict`**
Returns a dict with all `ComparisonResult` fields (flattening `stats` inline). Called only by `compare()` before writing `_comparison.json`.

---

**`ParseError(Exception)`**
Custom exception raised by `parse_qperf_latency()` and `parse_iperf2_throughput()`.

---

### 5.2 `providers.py`

---

**`class CloudProvider(Protocol)`**
`typing.Protocol`. Four methods:

| Method | Signature | Returns |
|---|---|---|
| `check_nsg_ports` | `(source_ip: str, dest_ip: str, ports: list[int]) → dict[int, bool]` | `True` = port is open for measurement |
| `generate_port_open_commands` | `(resource_group: str, dest_ip: str, ports: list[int]) → list[str]` | Display-only `az` command strings |
| `read_blob` | `(account: str, container: str, blob_name: str) → Optional[bytes]` | Raw bytes or `None` if absent |
| `write_blob` | `(account: str, container: str, blob_name: str, data: bytes) → str` | Blob URL |

---

**`class AzureProvider`**

`__init__(shell, resource_group, subscription_id=None, ssh_user=None, source_public_ip=None, source_vm_key_path=None) → None`

Stores `shell`, `resource_group`, and `subscription_id` as instance state. If `ssh_user` and `source_public_ip` are provided, also builds three private SSH-related attributes:

- `_ssh_prefix` — complete `ssh -i {key} -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new {user}@{host}` prefix for running commands on the source VM
- `_scp_prefix` — `scp -i {key} -o ...` prefix for file transfers to/from the source VM
- `_ssh_target` — `{user}@{host}` string for SCP destination paths

When these are `None` (SSH params not provided), blob operations run locally.

---

**`AzureProvider._get_nic_name(vm_ip: str) → str`**
Resolves a VM private IP to the NIC name within the instance's resource group.
Command: see §8, template A1. Parses TSV output.
- Zero lines → `RuntimeError(f"No NIC found for IP {vm_ip} in resource group {rg}")`
- More than one line → `RuntimeError(f"Ambiguous: {count} NICs matched IP {vm_ip} in resource group {rg}. IPs may be reused across VNets. Resolve by scoping to a single VNet or specifying the NIC name directly.")`
- Exactly one line → return that NIC name.

---

**`AzureProvider._get_nsg_name(nic_name: str) → str`**
Retrieves the NSG associated with a NIC.
Command: see §8, template A2. Parses the NSG resource ID and extracts the NSG name from the last path segment. Raises `RuntimeError` if the NIC has no NSG attached.

---

**`AzureProvider._parse_effective_nsg(nsg_json: str, ports: list[int]) → dict[int, bool]`**
Pure function. Parses the JSON from `az network nic list-effective-nsg`. For each port, walks `effectiveSecurityRules` in **priority order** (ascending priority number = first processed). Returns `True` for the port if the first matching INBOUND rule has `access == "Allow"`. Returns `False` if the first match is `Deny`, or if no rule matches (default deny).

A rule matches a port if:
- `direction == "Inbound"`
- `protocol ∈ {"Tcp", "*"}`
- `destinationPortRange == str(port)` OR `destinationPortRange == "*"` OR `str(port)` is within the range `"low-high"` in `destinationPortRange`

---

**`AzureProvider._find_safe_nsg_priority(nsg_name: str, ports: list[int]) → int`**
Computes a safe priority for a new ALLOW rule. See §11 for the full algorithm.

---

**`AzureProvider.check_nsg_ports(source_ip, dest_ip, ports) → dict[int, bool]`**
For each port:
1. Check **INBOUND** rules on dest VM NIC (via effective NSG query, template A3).
2. Check **OUTBOUND** rules on source VM NIC (same call, filter `direction == "Outbound"`).
3. Port is `True` only if both inbound on dest AND outbound on source are `Allow`.

Returns `{5001: True, 19765: False}` for example.

---

**`AzureProvider.generate_port_open_commands(resource_group, dest_ip, ports) → list[str]`**
For each blocked port:
1. Gets NSG name for dest VM NIC.
2. Calls `_find_safe_nsg_priority()` to compute a safe priority.
3. Returns the `az network nsg rule create` command string for that port. See §8, template A4.

Returns a `list[str]`. These strings are never executed by `AzureProvider` — they are for display and operator execution.

---

**`AzureProvider.read_blob(account, container, blob_name) → Optional[bytes]`**
Routes to `_read_blob_via_ssh()` when SSH params were provided to `__init__`; otherwise calls `_read_blob_local()`.

**`AzureProvider._read_blob_local(account, container, blob_name) → Optional[bytes]`**
Downloads blob locally to a temp file, reads bytes, deletes temp file.
- If blob does not exist (exit code 3 or `BlobNotFound` in output): returns `None`.
- On auth error: raises `RuntimeError("Storage auth failed...")`.
- On other failure: raises `RuntimeError(f"Blob download failed: {output}")`.

**`AzureProvider._read_blob_via_ssh(account, container, blob_name) → Optional[bytes]`**
Three-step download routed through the source VM (which is inside the storage account's whitelisted VNet subnet):
1. SSH: run `az storage blob download --file {remote_tmp}` on source VM.
2. SCP: copy `{remote_tmp}` from source VM to a local temp file.
3. SSH: `rm -f {remote_tmp}` on source VM (best effort, always runs).
Reads and returns the local temp file bytes. Same `None` / error semantics as `_read_blob_local`.

---

**`AzureProvider.write_blob(account, container, blob_name, data: bytes) → str`**
Routes to `_write_blob_via_ssh()` when SSH params were provided to `__init__`; otherwise calls `_write_blob_local()`.

**`AzureProvider._write_blob_local(account, container, blob_name, data) → str`**
Writes `data` to a local temp file. Runs `az storage blob upload` (template A5). Returns the blob URL. On failure: raises `RuntimeError(f"Blob upload failed: {output}")`.

**`AzureProvider._write_blob_via_ssh(account, container, blob_name, data) → str`**
Three-step upload routed through the source VM:
1. SCP: copy local temp file to `{remote_tmp}` on source VM.
2. SSH: run `az storage blob upload --file {remote_tmp}` on source VM.
3. SSH: `rm -f {remote_tmp}` on source VM (best effort, runs only if SCP succeeded).
Returns blob URL. On SCP or upload failure: raises `RuntimeError`.

---

## 6. Pipeline Stage Detail

### 6.1 `validate(args: argparse.Namespace) → PipelineConfig`

**Processing logic:**

Validations in this order — raise `ValueError` with the specified message on the first failure:

| Check | Failure message |
|---|---|
| `source_ip` is valid IPv4 | `"--source-ip: invalid IPv4 address: {value}"` |
| `dest_ip` is valid IPv4 | `"--dest-ip: invalid IPv4 address: {value}"` |
| `source_ip != dest_ip` | `"--source-ip and --dest-ip must be different"` |
| `test_type ∈ {"latency","throughput","both"}` | `"--test-type must be one of: latency, throughput, both"` |
| `iterations >= 1` | `"--iterations must be >= 1"` |
| `ssh_user` non-empty | `"--ssh-user is required"` |
| `storage_account` non-empty | `"--storage-account is required"` |
| `container` non-empty | `"--container is required"` |
| `resource_group` non-empty | `"--resource-group is required"` |

IPv4 validation: use `socket.inet_aton()` wrapped in `try/except OSError`.

If `--session-id` absent: call `_generate_session_id()`.
If `--audit-dir` absent: default `"./audit"`.
If `--iterations` absent: default `8`.

**Output:** `PipelineConfig` with all fields set.
**Failure output:** `ValueError` propagates to `main()`, which prints `f"Error: {e}"` and exits 1.

---

### 6.2 `preflight(config, shell, provider) → PreflightResult`

**Input contract:** `config` is a validated `PipelineConfig`.

**Processing logic:**

```
actions_taken = []

STEP 1 — NSG port check
  port_status = provider.check_nsg_ports(config.source_ip, config.dest_ip, [5001, 19765])
  blocked = [p for p, open in port_status.items() if not open]

  if blocked:
    cmds = provider.generate_port_open_commands(config.resource_group, config.dest_ip, blocked)
    print each cmd  # show operator what will be run before the HITL gate
    for cmd in cmds:
      response = shell.execute({"command": cmd, "reasoning": "Open port for measurement"})
      if response["status"] == "denied":
        print(f"Port remediation declined. Ports {blocked} remain blocked.")
        → write _preflight.json with ports_open=False, tools_ready=False
        → return PreflightResult(ports_open=False, tools_ready=False, actions_taken)
      if response["exit_code"] != 0:
        print(f"Port open command failed: {response['output'][:200]}")
        → write _preflight.json with ports_open=False
        → return PreflightResult(ports_open=False, tools_ready=False, actions_taken)
    actions_taken.append(f"Opened ports {blocked} on NSG")  # appended once after all cmds succeed

STEP 2 — Tool presence check (per VM; install both tools at once if either is missing)
  For vm_ip in [config.source_ip, config.dest_ip]:
    qperf_ok = shell.execute({"command": SSH_WHICH(vm_ip, "qperf"), "reasoning": "Check qperf presence"})["exit_code"] == 0
    iperf_ok  = shell.execute({"command": SSH_WHICH(vm_ip, "iperf"),  "reasoning": "Check iperf presence"})["exit_code"] == 0

    if not qperf_ok or not iperf_ok:
      missing = [b for b, ok in [("qperf", qperf_ok), ("iperf", iperf_ok)] if not ok]
      print(f"Missing on {vm_ip}: {missing}")

      STEP 2a — Package manager detection (one call per VM)
        r = shell.execute({"command": SSH_WHICH_APT(vm_ip), "reasoning": "Detect package manager"})
        pkg_mgr = "apt" if r["exit_code"] == 0 else "yum"

      STEP 2b — Single install gate for this VM (installs both qperf and iperf)
        cmd = SSH_INSTALL(vm_ip, pkg_mgr)  # installs both regardless of which was missing
        response = shell.execute({"command": cmd, "reasoning": f"Dependencies missing on {vm_ip}. Install qperf/iperf2 via {pkg_mgr}? [Y/N]"})
        if response["status"] == "denied":
          print(f"Installation declined. Tools not available on {vm_ip}.")
          → write _preflight.json with tools_ready=False
          → return PreflightResult(ports_open=True, tools_ready=False, actions_taken)
        if response["exit_code"] != 0:
          print(f"Install failed on {vm_ip}: {response['output'][:200]}")
          → return PreflightResult(ports_open=True, tools_ready=False, actions_taken)
        actions_taken.append(f"Installed qperf and iperf on {vm_ip}")

    STEP 2c — iperf version check (runs regardless of whether install was needed)
      r = shell.execute({"command": SSH_IPERF_VERSION(vm_ip), "reasoning": "Verify iperf is version 2, not iperf3"})
      # SSH_IPERF_VERSION: ssh {opts} {user}@{vm_ip} "iperf -v 2>&1"
      # iperf2 prints "iperf version 2.x.x"; iperf3 prints "iperf3 ..." or "iperf 3.x"
      if "iperf version 2" not in r["output"].lower():
        print(f"Error: 'iperf' on {vm_ip} is not iperf2. Output: {r['output'][:100]!r}")
        print(f"  The measurement tool requires iperf2 (package: 'iperf'), not iperf3.")
        → return PreflightResult(ports_open=True, tools_ready=False, actions_taken)

_write_artifact(f"{config.audit_dir}/{config.session_id}_preflight.json", preflight_to_dict(result))
return PreflightResult(ports_open=True, tools_ready=True, actions_taken)
```

**Output artifact** — `{config.audit_dir}/{config.session_id}_preflight.json`:
```json
{
  "session_id": "...",
  "timestamp_utc": "...",
  "ports_open": true,
  "tools_ready": true,
  "actions_taken": ["Opened port 5001 on NSG", "Installed qperf and iperf on 10.0.0.4"]
}
```

---

### 6.3 `measure(config, shell) → MeasurementRaw`

**Input contract:** `preflight()` has returned `PreflightResult(ports_open=True, tools_ready=True)`.

**Design note — separated measurement loops:** Latency and throughput measurements run in two fully sequential loops. All latency iterations complete (including qperf server lifecycle) before the iperf server is started. This eliminates TCP state contamination (congestion window, kernel buffers) that would otherwise carry across iteration boundaries when both tools run interleaved.

**Processing logic:**

```
latency_samples = []
throughput_samples = []

STEP 1 — Pre-clean
  r = shell.execute({"command": SSH_CHECK_STALE(dest_ip), "reasoning": "Check for stale server processes"})
  pids = [line.strip() for line in r["output"].splitlines() if line.strip().isdigit()]
  if pids:
    print(f"Stale process(es) found on {dest_ip}: PIDs {pids}")
    r2 = shell.execute({"command": SSH_KILL_PIDS(dest_ip, pids), "reasoning": "Kill stale processes before test"})
    if r2["status"] == "denied":
      raise RuntimeError(f"Stale processes exist on {dest_ip} and kill was declined. Cannot proceed.")
    if r2["exit_code"] != 0:
      raise RuntimeError(f"Failed to kill stale processes on {dest_ip}: {r2['output'][:200]}")

LATENCY BLOCK (skipped if test_type == "throughput")
  qperf_pid = None
  try:
    STEP 2a — Start qperf server
      r = shell.execute({"command": SSH_START_QPERF(config.dest_ip), "reasoning": "Start qperf server for latency test"})
      if r["status"] == "denied" or r["exit_code"] != 0:
        raise RuntimeError(f"qperf server start failed: {r['output'][:200]}")
      qperf_pid = r["output"].strip()
      if not qperf_pid.isdigit():
        raise RuntimeError(f"qperf server returned non-integer PID: {qperf_pid!r}")
      time.sleep(2)  # allow server to reach listening state

    STEP 3a — Warm-up qperf (result discarded, but failure is fatal)
      r = shell.execute({"command": SSH_RUN_QPERF(config.source_ip, config.dest_ip), "reasoning": "Warm-up pass (discarded)"})
      if r["exit_code"] != 0:
        raise RuntimeError(f"Warm-up qperf failed — server may not be ready: {r['output'][:200]}")

    STEP 4a — Recorded latency iterations
      for i in range(1, config.iterations + 1):
        print(f"  Latency iteration {i}/{config.iterations}...")
        r = shell.execute({"command": SSH_RUN_QPERF(config.source_ip, config.dest_ip), "reasoning": f"Latency iteration {i}"})
        if r["exit_code"] != 0:
          raise RuntimeError(f"qperf client failed on iteration {i}: {r['output'][:200]}")
        latency_samples.append(parse_qperf_latency(r["output"]))  # raises ParseError on failure

  finally:
    STEP 5a — Kill qperf server (always runs)
      if qperf_pid:
        shell.execute({"command": SSH_KILL_SERVER(dest_ip, qperf_pid, "qperf"), "reasoning": "Teardown qperf server"})
      else:
        shell.execute({"command": SSH_KILL_BY_NAME(dest_ip, "qperf"), "reasoning": "Teardown qperf server (PID unknown)"})
      # Log failure but do not re-raise

THROUGHPUT BLOCK (skipped if test_type == "latency")
  iperf_pid = None
  try:
    STEP 2b — Start iperf server
      r = shell.execute({"command": SSH_START_IPERF(config.dest_ip), "reasoning": "Start iperf server for throughput test"})
      if r["status"] == "denied" or r["exit_code"] != 0:
        raise RuntimeError(f"iperf server start failed: {r['output'][:200]}")
      iperf_pid = r["output"].strip()
      if not iperf_pid.isdigit():
        raise RuntimeError(f"iperf server returned non-integer PID: {iperf_pid!r}")
      time.sleep(2)  # allow server to reach listening state

    STEP 3b — Warm-up iperf (result discarded, but failure is fatal)
      r = shell.execute({"command": SSH_RUN_IPERF(config.source_ip, config.dest_ip), "reasoning": "Warm-up pass (discarded)"})
      if r["exit_code"] != 0:
        raise RuntimeError(f"Warm-up iperf failed — server may not be ready: {r['output'][:200]}")

    STEP 4b — Recorded throughput iterations
      for i in range(1, config.iterations + 1):
        print(f"  Throughput iteration {i}/{config.iterations}...")
        r = shell.execute({"command": SSH_RUN_IPERF(config.source_ip, config.dest_ip), "reasoning": f"Throughput iteration {i}"})
        if r["exit_code"] != 0:
          raise RuntimeError(f"iperf client failed on iteration {i}: {r['output'][:200]}")
        throughput_samples.append(parse_iperf2_throughput(r["output"]))  # raises ParseError on failure

  finally:
    STEP 5b — Kill iperf server (always runs)
      if iperf_pid:
        shell.execute({"command": SSH_KILL_SERVER(dest_ip, iperf_pid, "iperf -s"), "reasoning": "Teardown iperf server"})
      else:
        shell.execute({"command": SSH_KILL_BY_NAME(dest_ip, "iperf -s"), "reasoning": "Teardown iperf server (PID unknown)"})
      # Log failure but do not re-raise

STEP 6 — Write artifact
  raw = MeasurementRaw(latency_samples, throughput_samples, config.session_id)
  _write_artifact(f"{config.audit_dir}/{config.session_id}_raw.json", raw_to_dict(raw))
  return raw
```

---

### 6.4 `compute(raw: MeasurementRaw, test_type: str, audit_dir: str) → ComputedStats`

**Input contract:** `raw.latency_samples` and `raw.throughput_samples` are populated per `test_type` (see §2.3).

**Precondition check (raises `RuntimeError` if violated — programming error, not user error):**
- `test_type in ("latency","both")` and `len(raw.latency_samples) == 0` → `RuntimeError("Latency samples expected but list is empty")`
- `test_type in ("throughput","both")` and `len(raw.throughput_samples) == 0` → `RuntimeError("Throughput samples expected but list is empty")`

**Processing logic:**

```
lat_p90 = lat_min = lat_max = None
thr_p90 = thr_min = thr_max = None
is_stable = True
anomaly_type = None

if test_type in ("latency", "both"):
  lat_p90 = _compute_p90(raw.latency_samples)
  lat_min = min(raw.latency_samples)
  lat_max = max(raw.latency_samples)
  stable_lat, anom_lat = _apply_gap_rule(raw.latency_samples)
  if not stable_lat:
    is_stable = False
    anomaly_type = anom_lat  # CONNECTIVITY_DROP or HIGH_VARIANCE

if test_type in ("throughput", "both"):
  thr_p90 = _compute_p90(raw.throughput_samples)
  thr_min = min(raw.throughput_samples)
  thr_max = max(raw.throughput_samples)
  stable_thr, anom_thr = _apply_gap_rule(raw.throughput_samples)
  if not stable_thr:
    is_stable = False
    # Priority: CONNECTIVITY_DROP > HIGH_VARIANCE
    if anomaly_type is None or anom_thr == "CONNECTIVITY_DROP":
      anomaly_type = anom_thr

stats = ComputedStats(lat_p90, lat_min, lat_max, thr_p90, thr_min, thr_max, is_stable, anomaly_type)
_write_artifact(f"{audit_dir}/{raw.session_id}_computed.json", stats_to_dict(stats))
return stats
```

---

### 6.5 `compare(config, stats, provider) → ComparisonResult`

**Input contract:** `stats` is fully populated per `test_type`.

**Processing logic:**

```
blob_prefix = f"{_ip_to_blob_prefix(config.source_ip)}_{_ip_to_blob_prefix(config.dest_ip)}"
baseline_blob_name = f"{blob_prefix}_baseline.json"

baseline_bytes = None
if config.compare_baseline:
  try:
    baseline_bytes = provider.read_blob(config.storage_account, config.container, baseline_blob_name)
    if baseline_bytes is None:
      print("Note: No baseline found for this source/dest pair. Proceeding without comparison.")
  except RuntimeError as e:
    print(f"Warning: Could not read baseline: {e}. Proceeding without comparison.")
    baseline_bytes = None
# If compare_baseline is False, baseline_bytes stays None — no blob read attempted.

baseline_p90_lat = baseline_p90_thr = baseline_ts = None
delta_lat = delta_thr = None

if baseline_bytes:
  try:
    baseline = json.loads(baseline_bytes)
    baseline_p90_lat = baseline["results"].get("latency_p90")
    baseline_p90_thr = baseline["results"].get("throughput_p90")
    baseline_ts = baseline["test_metadata"]["timestamp"]
  except (json.JSONDecodeError, KeyError):
    print("Warning: Baseline file is malformed. Proceeding without comparison.")
    baseline_bytes = None

  if baseline_p90_lat is not None and stats.latency_p90 is not None:
    delta_lat = (stats.latency_p90 - baseline_p90_lat) / baseline_p90_lat * 100
  if baseline_p90_thr is not None and stats.throughput_p90 is not None:
    delta_thr = (stats.throughput_p90 - baseline_p90_thr) / baseline_p90_thr * 100

write_as_baseline = config.is_baseline

if config.is_baseline and baseline_bytes is not None:
  print(f"\nNote: A baseline already exists for {config.source_ip} → {config.dest_ip}")
  print(f"  Recorded: {baseline_ts}. It will be overwritten (--is-baseline was set).")
  # No input() prompt here. The operator's explicit --is-baseline flag is the consent.
  # SafeExecShell's HITL gate is not required for blob uploads (see §10).

result = ComparisonResult(
  stats, baseline_p90_lat, baseline_p90_thr, baseline_ts, delta_lat, delta_thr, write_as_baseline
)
_write_artifact(f"{config.audit_dir}/{config.session_id}_comparison.json", comparison_to_dict(result))
return result
```

**Note on baseline overwrite consent:** the operator's `--is-baseline` flag is the single, explicit consent for overwriting the baseline blob. There is no `input()` gate in `compare()`. The PRD's HITL requirement names binary installs and NSG port opens as gated actions; blob writes are not listed. Blob uploads are in the auto-approve list (see §10) — no SafeExecShell gate fires for them. This eliminates the double-gate UX problem (an `input()` prompt immediately followed by a SafeExecShell gate for the same logical action).

---

### 6.6 `report(result, config, provider, preflight_result) → PipelineResult`

**Processing logic:**

```
artifact = _assemble_artifact(result, config, preflight_result)  # builds dict per §3

# Write local artifact first — must succeed before any blob upload
local_path = f"{config.audit_dir}/{config.session_id}_result.json"
_write_artifact(local_path, artifact)            # raises RuntimeError on failure

# Construct blob prefix (same logic as compare())
blob_prefix = f"{_ip_to_blob_prefix(config.source_ip)}_{_ip_to_blob_prefix(config.dest_ip)}"
blob_name = f"{blob_prefix}_{config.session_id}.json"
blob_url = ""
try:
  blob_url = provider.write_blob(config.storage_account, config.container, blob_name, json.dumps(artifact).encode())
except RuntimeError as e:
  print(f"Warning: Blob upload failed: {e}. Local artifact at {local_path}")

# Upload as baseline if flagged
if result.write_as_baseline:
  baseline_name = f"{blob_prefix}_baseline.json"
  try:
    provider.write_blob(config.storage_account, config.container, baseline_name, json.dumps(artifact).encode())
  except RuntimeError as e:
    print(f"Warning: Baseline blob upload failed: {e}. Local artifact at {local_path}")

_print_console_summary(result, config, local_path, blob_url)

return PipelineResult(status="success", local_artifact_path=os.path.abspath(local_path),
                      blob_url=blob_url, session_id=config.session_id, error_message=None)
```

---

## 7. SSH Command Templates

All templates produce a complete string passed to `shell.execute()["command"]`. Base SSH options (`_SSH_BASE_OPTS`) applied to every SSH command: `-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new`.

**Two SSH option sets per pipeline run:**

| Variable | Built by | Used for |
|---|---|---|
| `opts_src` | `_make_ssh_opts(source_vm_key_path)` | Direct SSH to source VM via its public IP |
| `opts_dst` | `_make_ssh_opts(dest_vm_key_path, ssh_user, source_ssh_ip, source_vm_key_path)` | SSH to dest VM via ProxyCommand through source VM |

`opts_dst` uses `ProxyCommand` (`ssh -i {source_key} -W %h:%p {user}@{jump_host}`) so both private keys are used locally on the originating machine — neither key is forwarded to the jump host. This is distinct from `-J` (ProxyJump), which requires the jump host to authenticate onward via ssh-agent.

`source_ssh_ip = config.source_public_ip or config.source_ip` — the public IP is used for the direct hop to the source VM; `config.source_ip` (private) is used as the measurement address in qperf/iperf commands.

| ID | Purpose | Command string |
|---|---|---|
| S1 | Check stale processes on dest VM | `ssh {opts_dst} {user}@{dest_ip} "lsof -ti :5001,:19765 2>/dev/null"` |
| S2 | Kill PIDs (stale or teardown) | `ssh {opts_dst} {user}@{dest_ip} "kill {' '.join(pids)} 2>/dev/null; true"` |
| S3 | Kill by process name (teardown fallback) | `ssh {opts_dst} {user}@{dest_ip} "pkill -f '{name}' 2>/dev/null; true"` |
| S4 | Check binary present | `ssh {opts} {user}@{vm_ip} "which {binary}"` (opts_src for source, opts_dst for dest) |
| S5 | Detect package manager | `ssh {opts} {user}@{vm_ip} "which apt-get"` |
| S6 | Install qperf and iperf (apt) | `ssh {opts} {user}@{vm_ip} "sudo apt-get install -y qperf iperf"` |
| S7 | Install qperf and iperf (yum) | `ssh {opts} {user}@{vm_ip} "sudo yum install -y qperf iperf"` |
| S8 | Start qperf server | `ssh {opts_dst} {user}@{dest_ip} "nohup qperf </dev/null > /tmp/qperf_server.log 2>&1 & echo $!"` |
| S9 | Start iperf server | `ssh {opts_dst} {user}@{dest_ip} "nohup iperf -s </dev/null > /tmp/iperf_server.log 2>&1 & echo $!"` |
| S10 | Run qperf latency test | `ssh {opts_src} {user}@{source_ssh_ip} "qperf {dest_ip} -m 1024 tcp_lat"` |
| S11 | Run iperf throughput test | `ssh {opts_src} {user}@{source_ssh_ip} "iperf -c {dest_ip} -P 8 -t 10"` |
| S12 | Verify iperf is version 2 | `ssh {opts} {user}@{vm_ip} "iperf -v 2>&1"` |

**Timeout overrides from SafeExecShell defaults:**
- S6, S7 (install): require up to 120 seconds. Initialise `SafeExecShell` with `timeout_seconds=120`.
- All other SSH commands complete within 30 seconds under normal conditions.

**Teardown:** each measurement block has its own `try/finally`. qperf server is started, used for all latency iterations, and killed before the iperf server is ever started. This guarantees no residual qperf traffic contaminates throughput measurements. In each `finally`: attempt PID kill (S2) first. If the PID is `None` (server start failed before PID was captured), fall back to name-based kill (S3). Both can be called without risk — `2>/dev/null; true` at the end of S2 and S3 ensures exit code 0 regardless.

---

## 8. Azure CLI Command Templates

All `az` commands are called via `AzureProvider`'s injected `SafeExecShell`. All use `--output json` unless noted.

| ID | Purpose | Command string |
|---|---|---|
| A1 | Resolve VM IP to NIC name | `az network nic list --resource-group {rg} --query "[?ipConfigurations[?privateIPAddress=='{ip}']].name" --output tsv` |
| A2 | Get NSG ID from NIC | `az network nic show --resource-group {rg} --name {nic_name} --query "networkSecurityGroup.id" --output tsv` |
| A3 | List effective NSG rules on NIC | `az network nic list-effective-nsg --resource-group {rg} --name {nic_name} --output json` |
| A4 | Create NSG allow rule (template) | `az network nsg rule create --resource-group {rg} --nsg-name {nsg_name} --name AllowPipeMeter{port} --priority {priority} --direction Inbound --access Allow --protocol Tcp --destination-port-ranges {port}` |
| A5 | Upload blob | `az storage blob upload --account-name {account} --container-name {container} --name {blob_name} --file {remote_tmp} --overwrite true --auth-mode login` |
| A6 | Download blob | `az storage blob download --account-name {account} --container-name {container} --name {blob_name} --file {remote_tmp} --auth-mode login --no-progress` |
| A7 | List NSG security rules (for priority scan) | `az network nsg show --resource-group {rg} --name {nsg_name} --query "securityRules" --output json` |

**Blob routing via source VM (A5, A6):**
When `AzureProvider` is constructed with SSH params, A5 and A6 do not run locally. Instead they run on the source VM via SSH, because the source VM is inside the storage account's whitelisted VNet subnet (`virtualNetworkRules`) while the originating machine may be blocked by `defaultAction: Deny`. The three-step flow for each direction is:

- *Upload (A5):* `scp {local_tmp} {user}@{src_host}:{remote_tmp}` → `ssh {src_host} "az storage blob upload --file {remote_tmp} ..."` → `ssh {src_host} "rm -f {remote_tmp}"`
- *Download (A6):* `ssh {src_host} "az storage blob download --file {remote_tmp} ..."` → `scp {user}@{src_host}:{remote_tmp} {local_tmp}` → `ssh {src_host} "rm -f {remote_tmp}"`

All six commands pass through `SafeExecShell` and are auto-approved (see §10). The source VM must be logged into Azure CLI (`az login`) or have a managed identity with the Storage Blob Data Contributor role.

**NSG name extraction from resource ID (template A2):**
The `--query` returns a resource ID of the form:
`/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}`
Extract `nsg_name` as the last path segment: `resource_id.split("/")[-1]`.

---

## 9. Output Parsing Specifications

### 9.1 qperf latency (`parse_qperf_latency`)

Expected stdout from `qperf {dest_ip} -m 1024 tcp_lat`:
```
tcp_lat:
    latency         =  124 us
    msg_rate        = 8.06 K/sec
    ...
```

Regex 1 (µs, normal path): `r'latency\s*=\s*([\d.]+)\s*(us|µs)'`
→ Return `float(group(1))`

Regex 2 (ms, high-latency fallback): `r'latency\s*=\s*([\d.]+)\s*ms'`
→ Return `float(group(1)) * 1000.0`

No match → `raise ParseError(...)`.

### 9.2 iperf2 throughput (`parse_iperf2_throughput`)

Expected stdout from `iperf -c {dest} -P 8 -t 10` (8 stream lines + 1 SUM line):
```
[  3] 0.0-10.0 sec  1.44 GBytes  1.24 Gbits/sec
...
[SUM] 0.0-10.0 sec  11.6 GBytes  9.94 Gbits/sec
```

Regex: `r'\[SUM\].*?([\d.]+)\s+(G|M)bits/sec'`
- Unit `"G"` → return `float(group(1))`
- Unit `"M"` → return `float(group(1)) / 1000.0`

No `[SUM]` match → `raise ParseError(...)`.

---

## 10. HITL Callback: Auto-Approve and Manual-Gate Patterns

`_make_hitl_callback()` returns a callback used by the `SafeExecShell` instance. This allows measurement-only SSH commands to run without per-iteration operator prompts while keeping all mutative commands gated.

### Auto-approve patterns (no operator prompt)

| Pattern | Matches |
|---|---|
| `r'^ssh\s+.*qperf\s+\S+\s+-m\s+1024\s+tcp_lat'` | qperf latency client run (S10) |
| `r'^ssh\s+.*iperf\s+-c\s+\S+\s+-P\s+8'` | iperf throughput client run (S11) |
| `r'^ssh\s+.*which\s+(qperf\|iperf\|apt-get)'` | Tool presence check (S4) and package manager detection (S5) |
| `r'^ssh\s+.*iperf\s+-v\b'` | iperf version check (S12) |
| `r'^ssh\s+.*lsof\s+-ti'` | Stale process port scan (S1) |
| `r'^ssh\s+.*nohup\s+qperf\b'` | qperf server start (S8) |
| `r'^ssh\s+.*nohup\s+iperf\s+-s\b'` | iperf server start (S9) |
| `r'^ssh\s+.*kill\s+[\d ]+2>/dev/null'` | Kill stale processes or teardown by PID (S2) |
| `r'^ssh\s+.*pkill\s+-f\s+'` | Kill by name (teardown fallback, S3) |
| `r'^az\s+network\s+nic\s+(list\|show)'` | NIC read (A1, A2) |
| `r'^az\s+network\s+nic\s+list-effective-nsg'` | NSG effective rules read (A3) |
| `r'^az\s+network\s+nsg\s+show'` | NSG configuration read (A7) |
| `r'^az\s+storage\s+blob\s+download'` | Blob read locally (A6, local path only) |
| `r'^az\s+storage\s+blob\s+upload'` | Blob write locally (A5, local path only) |
| `r'^scp\s+.*pmeter_blob_'` | SCP of temporary blob files to/from source VM (blob SSH routing) |
| `r'^ssh\s+.*"az\s+storage\s+blob\s+(upload\|download)'` | SSH-wrapped A5/A6 running on source VM (blob SSH routing) |
| `r'^ssh\s+.*"rm\s+-f\s+/tmp/pmeter_blob_'` | SSH cleanup of temporary blob files on source VM |

**Rationale for auto-approving S2/S3/S8/S9:** these commands are integral to every measurement run (server lifecycle and teardown). They appear at predictable points in the pipeline, affect only the two VMs in scope, and are bounded in effect (kill a specific PID or named process, or start a server that `finally` always stops). Gating them per-iteration would create excessive operator burden with no meaningful safety benefit.

### Manual-gate patterns (operator prompt required)

All commands not matching the auto-approve list are gated, including but not limited to:

| Command | Classification |
|---|---|
| `ssh ... sudo apt-get install ...` | Package install — RISKY |
| `ssh ... sudo yum install ...` | Package install — RISKY |
| `az network nsg rule create ...` | NSG write — RISKY |

---

## 11. NSG Priority Discovery Algorithm

Used by `AzureProvider._find_safe_nsg_priority(nsg_name, ports)`.

```
1. Run template A7 to get all user-defined security rules for the NSG.
   Parse response as list[dict] with fields: priority (int), access (str), direction (str),
   destinationPortRange (str), destinationPortRanges (list[str]).

2. For each target port, find all INBOUND DENY rules whose port range includes the port.
   deny_priorities = [r["priority"] for r in rules
                      if r["access"] == "Deny"
                      and r["direction"] == "Inbound"
                      and port_in_range(port, r)]

3. If deny_priorities is non-empty:
   target_priority = min(deny_priorities) - 10
   If target_priority < 100:
     raise RuntimeError(f"Cannot place ALLOW rule above DENY at priority {min(deny_priorities)}.
                         The DENY rule is already at Azure's minimum user priority (100).
                         Manual NSG editing is required.")

4. If deny_priorities is empty:
   # No explicit deny for this port; any valid priority works. Use 200 as a sensible default.
   # The collision check in step 5 handles any conflict with existing rules.
   target_priority = 200

5. Check for collision: if target_priority is already in use by any rule:
   Decrement by 1 up to 10 times. If all still collide:
   raise RuntimeError(f"Cannot find a free NSG priority near {target_priority}. Manual editing required.")
   # Decrement by 1 (not 10) to handle densely packed NSG rules where skipping
   # slots would unnecessarily exhaust the search range.

6. Return target_priority.
```

**Helper `port_in_range(port, rule)`:**
- `destinationPortRange == "*"` → True
- `destinationPortRange == str(port)` → True
- `destinationPortRange` contains `-`: split, check `low <= port <= high` → True/False
- Check `destinationPortRanges` list with same logic
- Otherwise → False

---

## 12. Console Output Format

Printed by `_print_console_summary()` after `report()` completes.

```
=== Agentic Pipe Meter — Results ===
Session:    pmeter_20260302140000
Source:     10.0.0.4  →  10.0.0.5
Test:       both  |  8 iterations
Status:     SUCCESS

Latency  (P90):    124.5 µs    ← +8.3% vs baseline (slower)  [HIGH_VARIANCE]
Throughput (P90):    9.4 Gbps  ← -1.1% vs baseline (slower)  [STABLE]

Stability:  UNSTABLE — HIGH_VARIANCE
Audit:      ./audit/pmeter_20260302140000_result.json
Blob:       https://mystorage.blob.core.windows.net/pipe-meter-results/10_0_0_4_10_0_0_5_pmeter_20260302140000.json
=====================================
```

**Conditional rendering rules:**
- Metric line suppressed entirely if metric is not active in this run.
- `← X% vs baseline` portion suppressed if no baseline was found.
- Delta label: for **latency**, positive delta → `(slower)`; negative → `(faster)`. For **throughput**, negative delta → `(slower)`; positive → `(faster)`. This eliminates sign-convention ambiguity for the operator.
- `[HIGH_VARIANCE]` / `[CONNECTIVITY_DROP]` tag shown per-metric only if that metric's anomaly_type is set.
- `Stability:` line shows `STABLE` if `is_stable == True`, else `UNSTABLE — {anomaly_type}`.
- `Blob:` line shows `(upload failed — see audit file)` if `blob_url` is empty.

**Aborted preflight format:**
```
=== Agentic Pipe Meter — Preflight Failed ===
Session:    pmeter_20260302140000
Reason:     Ports [19765] remain blocked. Run the commands above to open them, then re-run.
Audit:      ./audit/pmeter_20260302140000_preflight.json
=============================================
```

---

## 13. Error Handling Table

### `validate()`

| Error | Behavior | Caller receives |
|---|---|---|
| Invalid IPv4 | Print nothing; raise | `ValueError("--source-ip: invalid IPv4 address: 10.0.0.999")` |
| source_ip == dest_ip | Raise | `ValueError("--source-ip and --dest-ip must be different")` |
| Bad test_type | Raise | `ValueError("--test-type must be one of: latency, throughput, both")` |
| iterations < 1 | Raise | `ValueError("--iterations must be >= 1")` |

### `preflight()`

| Error | Behavior | Caller receives |
|---|---|---|
| NIC lookup returns no result for `source_ip` or `dest_ip` | Print error; return | `PreflightResult(ports_open=False, tools_ready=False)` |
| NSG shell command fails (non-zero exit) | Print stderr; return | `PreflightResult(ports_open=False, tools_ready=False)` |
| Port blocked, operator declines fix | Print message | `PreflightResult(ports_open=False, tools_ready=False)` |
| Port fix command fails | Print stderr | `PreflightResult(ports_open=False, tools_ready=False)` |
| SSH to VM fails (exit 255) | Print: `"SSH to {ip} failed (exit 255). Verify ssh-agent or key in ~/.ssh/"` | `PreflightResult(ports_open=True, tools_ready=False)` |
| Tool missing, operator declines install | Print message | `PreflightResult(tools_ready=False)` |
| Install command fails (non-zero exit) | Print stderr | `PreflightResult(tools_ready=False)` |

### `measure()`

| Error | Behavior | Caller receives |
|---|---|---|
| Stale process found, operator declines kill | Print message | `RuntimeError("Stale processes exist ... kill was declined")` — `finally` runs |
| Server start: operator denies | Print message | `RuntimeError("... server start failed")` — `finally` runs |
| Server start: non-zero exit | Print stderr (first 200 chars) | `RuntimeError` — `finally` runs |
| Server PID is not a valid integer (unexpected output) | Print raw output | `RuntimeError("qperf server returned non-integer PID: {output}")` — `finally` runs |
| qperf/iperf client: non-zero exit on any iteration | Print iteration number and stderr | `RuntimeError` — `finally` runs |
| `ParseError` on any iteration | Print iteration number and raw output | Propagates as `RuntimeError` — `finally` runs |
| Server kill fails in `finally` | Print warning; continue `finally` | Logged only; does not re-raise |
| `_write_artifact` fails (STEP 6) | Print error | `RuntimeError` — propagates to `run_pipeline()` |

### `compute()`

| Error | Behavior | Caller receives |
|---|---|---|
| Active metric has empty sample list | Print: `"Internal error: {metric} samples expected but empty"` | `RuntimeError` (programming error — measure() guarantee was violated) |
| `_write_artifact` fails | Propagate | `RuntimeError` |

### `compare()`

| Error | Behavior | Caller receives |
|---|---|---|
| Blob read fails (network, auth) | Print warning | `ComparisonResult` with all baseline fields `None` — pipeline continues |
| Baseline JSON malformed | Print warning | Same as above |
| `_write_artifact` fails | Propagate | `RuntimeError` — pipeline aborts |

### `report()`

| Error | Behavior | Caller receives |
|---|---|---|
| Local artifact write fails | Propagate | `RuntimeError` — pipeline aborts |
| Run result blob upload fails | Print warning with local path | `PipelineResult` with `blob_url=""`, `status="success"` |
| Baseline blob upload fails | Print warning with local path | Same as above — baseline not updated but run is still reported as success |

### `AzureProvider`

| Error | Behavior | Caller receives |
|---|---|---|
| NIC not found for IP | Print error | `RuntimeError("No NIC found for IP {ip} in resource group {rg}")` |
| NSG not attached to NIC | Print error | `RuntimeError("NIC {nic_name} has no NSG attached")` |
| Blob 404 (not found) | No output | `None` returned from `read_blob()` |
| Blob auth error (`AuthorizationPermissionMismatch` or `403` in output) | No explicit print | `RuntimeError("Storage auth failed...")` — message surfaced by `compare()` or `report()` |
| Priority collision exhausted (all slots taken) | No explicit print | `RuntimeError` propagates to `preflight()` |
| SCP to source VM fails (blob SSH routing, upload path) | No print | `RuntimeError("Blob upload failed (SCP to source VM): {detail}")` |
| SCP from source VM fails (blob SSH routing, download path) | No print | `RuntimeError("Blob download failed (SCP from source VM): {detail}")` |
| SSH `az storage blob` command fails on source VM | No print | `RuntimeError("Blob upload/download failed: {detail}")` — same semantics as local failure |

---

## 14. Edge Cases

| # | Case | Handling |
|---|---|---|
| 1 | `test_type = "latency"` | `throughput_samples = []`; all throughput fields in `ComputedStats` are `None`; throughput line suppressed in console output |
| 2 | `test_type = "throughput"` | `latency_samples = []`; all latency fields are `None`; latency line suppressed |
| 3 | `iterations = 1` | P90 = only value (index 0 of sorted list). `max = min`. Gap Rule: `(max - min) / min = 0` → `is_stable = True`. Valid run; single-iteration P90 has no statistical meaning but is not an error |
| 4 | No baseline exists, `is_baseline = False` | `compare()` returns all baseline fields as `None`. Console omits delta. `write_as_baseline = False`. No baseline blob written |
| 5 | No baseline exists, `is_baseline = True` | `compare()` does not prompt (nothing to overwrite). `write_as_baseline = True`. `report()` writes both run result and baseline blobs |
| 6 | Baseline exists, `is_baseline = True`, operator declines overwrite | `write_as_baseline = False`. Delta is still computed and shown (the read happened). Run result blob is uploaded; baseline blob is unchanged |
| 7 | `latency_min = 0.0` (timeout or drop) | `anomaly_type = "CONNECTIVITY_DROP"`, `is_stable = False`. Formula not applied. Console shows `[CONNECTIVITY_DROP]` |
| 8 | `throughput_min = 0.0` with `latency` also failing | `anomaly_type` takes the higher-severity value: `CONNECTIVITY_DROP` wins over `HIGH_VARIANCE` |
| 9 | iperf2 reports in `Mbits/sec` (slow link) | Parser detects `"M"` unit and divides by 1000 to convert to Gbps |
| 10 | qperf reports in `ms` (high-latency link) | Parser detects `ms` and multiplies by 1000 to convert to µs |
| 11 | Stale process found, operator declines kill | `RuntimeError` raised in step 1 of `measure()`. `finally` still runs (no server was started so both PIDs are `None`; teardown SSH calls are skipped) |
| 12 | Server start returns non-integer PID | `RuntimeError` raised before any iterations. `finally` uses name-based kill (S3) as fallback since PID is None |
| 13 | Both VMs are in different resource groups | Not supported: `resource_group` is a single value. The NIC lookup (A1) searches only one resource group. If VMs span resource groups, the NIC lookup for one will fail. Caller receives a `RuntimeError` from `preflight()` |
| 14 | `audit_dir` does not exist | `_write_artifact()` calls `os.makedirs(parent, exist_ok=True)` before writing. Created on first artifact write |
| 15 | iperf2 produces no `[SUM]` line (very short test or truncated output) | `parse_iperf2_throughput` raises `ParseError`. Run aborts. Teardown runs |
| 16 | SSH `BatchMode=yes` fails — key not loaded | Exit code 255. Detected in `preflight()` step 2 and reported: `"SSH to {ip} failed (exit 255). Verify ssh-agent or key in ~/.ssh/"` |
| 17 | Multiple NICs match the same IP | VMs in different VNets within the same resource group may share the same private IP (e.g., two VNets with overlapping CIDR ranges). `_get_nic_name` (template A1) returns all matching NIC names. If more than one line is returned, `_get_nic_name` raises `RuntimeError` with a diagnostic message. The pipeline aborts during `preflight()`. Resolution: narrow the resource group scope or split the VNets. |
| 18 | `az` CLI not installed or not logged in | `az network nic list` returns a non-zero exit code. Detected in `preflight()`. Error message from `az` stderr is surfaced to the operator |
| 19 | `compare_baseline = False` (default) | `compare()` makes no blob read attempt. No baseline messages are printed. Baseline fields in `ComparisonResult` are all `None`. Console omits delta lines. This is the default for plain measurement runs |
| 20 | `compare_baseline = True`, no baseline blob exists | `read_blob()` returns `None`. `compare()` prints `"Note: No baseline found..."`. Delta fields remain `None`. Pipeline continues normally |
| 21 | Storage account `defaultAction: Deny`, local machine not in `ipRules` | Blob ops routed through source VM via SSH (§8). Requires SSH params in `AzureProvider.__init__`. If SSH params are absent, blob upload fails with a network error from `az storage blob upload` |
| 22 | `az login` not current on source VM (blob SSH routing) | `az storage blob upload/download` on source VM exits non-zero with `AuthorizationPermissionMismatch`. Surfaces as `RuntimeError("Storage auth failed on source VM...")`. Run still succeeds; local artifact is preserved |

---

## 15. Intentional Omissions

| Capability | Excluded | Reason |
|---|---|---|
| Per-iteration metric values in console | Iteration-level latency/throughput values are written to `_raw.json` only. The console shows `Iteration N/M...` progress lines during the loop, then the final P90 summary. Raw values are not streamed to the console. | The console is for the operator (summary); the JSON is for the engineer (data). Streaming metric values to the console serves neither cleanly. |
| IPv6 support | `validate()` rejects IPv6 addresses (socket.inet_aton fails). | IPv6 changes blob naming, SSH command format, and NSG rule syntax. Each is a distinct concern and not in PRD. |
| Support for package managers other than `apt` / `yum` | Only `apt-get` and `yum` are tried. `snap`, `zypper`, `brew` are not. | Two package managers cover the Azure VM image library (Ubuntu, RHEL, CentOS, Debian). Others are additive if needed. |
| Cross-resource-group VM pairs | Both VMs must be in the same `resource_group`. | NIC lookup (template A1) and NSG operations use a single `--resource-group` parameter. Supporting two resource groups requires a new CLI argument and provider method — a separate additive concern. |
| Custom SSH port | Port 22 is assumed. | `--ssh-port` is not in the architecture. Supporting it would require threading a new parameter through every SSH template. Additive if needed. |
| iperf test duration configurability | `-t 10` (10 seconds) is hard-coded. | PRD specifies "multi-threaded TCP throughput" without specifying duration. 10 seconds is the iperf default and standard for stable measurement. Making it configurable is a new CLI parameter — additive. |
| Retry on SafeExecShell denial | If the operator denies a gate, the pipeline aborts. There is no "re-prompt after modification." | `SafeExecShell.HitlDecision` supports `action="modify"` but handling this requires looping logic in the caller. The pipe meter does not implement this path — a denied gate is a definitive stop. |
