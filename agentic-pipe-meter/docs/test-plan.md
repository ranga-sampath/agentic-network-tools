# Test Plan: Agentic Pipe Meter

## Document Order

| Stage        | Document                  | Status        |
|--------------|---------------------------|---------------|
| Requirements | `product-requirements.md` | ✓ Exists      |
| Architecture | `architecture.md`         | ✓ Exists      |
| Design       | `design.md`               | ✓ Exists      |
| Test Plan    | `test-plan.md`            | This document |
| Code         | —                         | Not yet written |

---

## 1. Priority Tiers

Every test carries one of four priority labels in the `P` column.

| Tier | Label | Definition |
|---|---|---|
| **MUST Pass** | `M` | Safety gate behavior, server cleanup guarantees, core pipeline correctness, measurement data integrity, HITL enforcement. Tool is unsafe, produces incorrect results, or silently corrupts data without these. Blocks any release. |
| **GOOD to Pass** | `G` | Error message quality, secondary behavioral paths, resilience under failure, audit completeness, console UX correctness. Should all pass before GA. A failure here has a user-visible workaround but represents an incomplete implementation. |
| **OK to Pass** | `O` | Stage isolation quality, edge case handling with low production likelihood, tests that verify a behavior covered from another direction. Best-effort for v1.0; carry forward without blocking. |
| **OK to Fail** | `F` | Implementation details not observable by the operator, cosmetic output detail, paths already fully covered by another test. Deferred without risk to correctness or safety. |

**Release gate:** All `M` tests must pass. At least 80% of `G` tests must pass. `O` and `F` tests do not gate release.

---

## 2. Scope

### In Scope

| Area | What is tested |
|---|---|
| `validate()` | All validation rules, first-failure ordering, defaults |
| `preflight()` | NSG port queries (effective rules), effective NSG A3 query failure, tool presence, iperf2 version verification, install gating, artifact output |
| `measure()` | Pre-clean, server lifecycle, separated loops (latency before throughput), PID capture, warm-up non-pollution, sample count invariant, teardown in all failure paths, artifact output |
| `compute()` | P90 formula (note: `floor(0.9 × N)` with N=8 always returns the max; the Gap Rule carries the stability signal), Gap Rule boundaries, anomaly priority precedence, empty-sample precondition |
| `compare()` | `compare_baseline` flag gating, baseline read, delta sign conventions, baseline-write intent, no-gate on overwrite, artifact output |
| `report()` | Artifact assembly and schema (including `iteration_data`), local write, blob upload naming and payload, baseline conditional upload, console rendering |
| `AzureProvider._parse_effective_nsg` | Priority-order processing, first-match-wins, direction filter (Inbound and Outbound), protocol wildcard, port range, `destinationPortRanges` plural form, default deny, Azure JSON envelope formats |
| `AzureProvider.check_nsg_ports` | Both-VM composition: inbound-dest AND outbound-source both required |
| `AzureProvider.read_blob` / `write_blob` | BlobNotFound returns None, auth error, SSH routing path (SCP+SSH three-step flow), routing selector |
| NSG priority discovery | No deny rule, deny above/at 100, collision resolution, collision exhaustion, range matching |
| Parsers | qperf µs / ms paths, iperf2 Gbits / Mbits paths, SUM-line selection, failure modes |
| HITL auto-approve patterns | Measurement and read commands, server lifecycle (S8/S9), kill/pkill (S2/S3), blob SSH routing (SCP, SSH-wrapped az, SSH rm) |
| HITL manual-gate patterns | Package install, NSG write; default-deny for unknown commands; boundary test between auto-approve and manual-gate |
| Blob naming | `_ip_to_blob_prefix`, run result name, baseline name, prefix consistency across stages |
| Pipeline stage isolation | Each stage drivable from its intermediate artifact without upstream reprocessing |
| SSH command template structure | `</dev/null` in nohup, SSH options, measurement flags, ProxyCommand for dest VM |
| Pipeline orchestrator | Session manifest write before preflight, catch-all error path, orchestrator gate (measure not called on preflight fail), CLI exit codes, session ID format |

### Out of Scope

| Area | Reason |
|---|---|
| SafeExecShell internals | Sibling library; tested by its own suite. Mocked at its interface boundary. |
| qperf / iperf2 measurement accuracy | Tool property, not application property |
| Azure platform availability | Infrastructure pre-condition |
| GCP / AWS / OCI provider implementations | Not built in this release |
| SSH key provisioning | Pre-condition, not a pipe-meter responsibility |
| Concurrent pipeline runs | Not a supported mode |

---

## 3. Test Environment Requirements

### Unit / Component Tests

- Python 3.12+, `pytest` + `pytest-mock`
- No live Azure infrastructure required
- Mock contracts:
  - `SafeExecShell.execute(cmd_dict) → dict` returns `{"status": str, "output": str, "exit_code": int, "audit_id": str}`
  - `CloudProvider.check_nsg_ports`, `.generate_port_open_commands`, `.read_blob`, `.write_blob`
- `tmp_path` pytest fixture for artifact writes

### Integration Tests (`@pytest.mark.integration`, opt-in only)

- Two Azure VMs reachable via SSH; `az login` active; identity with `Network Contributor` + `Storage Blob Data Contributor`
- Storage account and container pre-created
- Run with `pytest -m integration`; excluded from CI by default

---

## 4. Test Categories

| Category | Description |
|---|---|
| **VAL** | Input validation — `validate()` |
| **PRE** | Preflight stage |
| **MEA** | Measure stage |
| **COM** | Compute stage |
| **CMP** | Compare stage |
| **REP** | Report stage |
| **PAR** | Output parsers |
| **HIT** | HITL safety |
| **AZP** | AzureProvider — `_parse_effective_nsg`, `check_nsg_ports`, `read_blob`, `write_blob` |
| **NSG** | NSG priority discovery algorithm |
| **BLB** | Blob naming |
| **ISO** | Pipeline stage isolation |
| **EDG** | Residual edge cases not fully covered above |
| **SSH** | SSH command template structure |
| **PLO** | Pipeline orchestrator — error path, exit codes, session ID |

---

## 5. Test Cases

---

### 5.1 VAL — validate()

| P | ID | Name | Input | Expected outcome |
|---|---|---|---|---|
| M | VAL-01 | All valid args, all defaults | `--source-ip 10.0.0.4 --dest-ip 10.0.0.5 --ssh-user azureuser --test-type both --storage-account sa --container c --resource-group rg` | `PipelineConfig` with `iterations=8`, `is_baseline=False`, `audit_dir="./audit"`, `session_id` matches `pmeter_\d{8}T\d{6}` |
| M | VAL-02 | Invalid source IPv4 | `--source-ip 10.0.0.999` | `ValueError("--source-ip: invalid IPv4 address: 10.0.0.999")` |
| M | VAL-03 | Invalid dest IPv4 | `--dest-ip not-an-ip` | `ValueError("--dest-ip: invalid IPv4 address: not-an-ip")` |
| M | VAL-04 | source_ip == dest_ip | both `10.0.0.4` | `ValueError("--source-ip and --dest-ip must be different")` |
| M | VAL-05 | Bad test_type | `--test-type ping` | `ValueError("--test-type must be one of: latency, throughput, both")` |
| M | VAL-06 | iterations < 1 | `--iterations 0` (and separately `-1`) | `ValueError("--iterations must be >= 1")` for both inputs |
| M | VAL-07 | Empty required string fields | `--ssh-user ""` | `ValueError("--ssh-user is required")`; same pattern for empty `--storage-account`, `--container`, `--resource-group` |
| G | VAL-08 | Custom session_id bypasses generation | `--session-id my_session` | `config.session_id == "my_session"` |
| M | VAL-09 | --is-baseline flag sets field | `--is-baseline` | `config.is_baseline == True` |
| O | VAL-10 | iterations=1 is valid | `--iterations 1` | `config.iterations == 1`; no error |
| F | VAL-11 | First validation failure stops at first | `--source-ip bad --dest-ip also-bad` | Only source_ip error raised; dest_ip not evaluated. *(Implementation detail; not operator-observable.)* |
| M | VAL-12 | --compare-baseline sets flag | `--compare-baseline` (all other required args present) | `config.compare_baseline == True`; no error |

---

### 5.2 PRE — preflight()

#### Port checking

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | PRE-01 | All ports open | `check_nsg_ports` returns `{5001: True, 19765: True}` | No gate fired; no remediation printed; proceeds to tool check |
| M | PRE-02 | One port blocked — operator approves fix | `{5001: False, 19765: True}`; fix shell command returns `exit_code=0` | Gate fires once; `actions_taken` contains exactly one entry `"Opened ports [5001] on NSG"`; `ports_open=True` |
| M | PRE-03 | One port blocked — operator denies | Fix command returns `status="denied"` | `PreflightResult(ports_open=False, tools_ready=False)`; message printed |
| G | PRE-04 | Port fix command fails (non-zero exit) | Fix command returns `exit_code=1` | `PreflightResult(ports_open=False, tools_ready=False)`; stderr printed |
| G | PRE-05 | Both ports blocked — both approved | `{5001: False, 19765: False}`; both fix commands succeed | Two fix commands issued; `actions_taken` has **one** entry (appended once after both succeed) |
| M | PRE-06 | NIC lookup: no result for source_ip | `_get_nic_name` raises `RuntimeError("No NIC found...")` | `PreflightResult(ports_open=False, tools_ready=False)`; error printed |
| G | PRE-07 | NIC lookup: multiple results (IP reused across VNets) | `_get_nic_name` raises `RuntimeError("Ambiguous: 2 NICs matched IP...")` | Same abort outcome as PRE-06; message includes "IPs may be reused across VNets" |
| M | PRE-08 | Effective NSG query (A3) shell command fails | `az network nic list-effective-nsg` returns `exit_code=1` | `PreflightResult(ports_open=False, tools_ready=False)`; stderr surfaced; ports not silently treated as open |

#### Tool presence and installation

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | PRE-09 | Both tools present on both VMs | `which qperf`, `which iperf` all `exit_code=0`; `iperf -v` returns "iperf version 2.1.9" | No install gate fired; `tools_ready=True` |
| M | PRE-10 | One tool missing on source VM — install gate fires | `which qperf` on source returns `exit_code=1`; install succeeds | Single gate fired for source VM (installs both tools); `actions_taken` has one entry |
| M | PRE-11 | Install declined by operator | Install returns `status="denied"` | `PreflightResult(ports_open=True, tools_ready=False)`; message printed |
| G | PRE-12 | Install command fails (non-zero) | Install returns `exit_code=1` | `PreflightResult(ports_open=True, tools_ready=False)` |
| M | PRE-13 | SSH to VM fails (exit 255) | `which qperf` returns `exit_code=255` | `PreflightResult(tools_ready=False)`; message: `"SSH to {ip} failed (exit 255). Verify ssh-agent or key in ~/.ssh/"` |
| M | PRE-14 | iperf version is iperf3 — detected and rejected | `iperf -v 2>&1` returns "iperf3 3.14"; no "iperf version 2" in output | `PreflightResult(tools_ready=False)`; message includes "not iperf2" and "package: 'iperf'" |
| M | PRE-15 | iperf2 version check passes | `iperf -v 2>&1` returns "iperf version 2.1.9 (14 March 2023)" | `tools_ready=True`; no error |
| G | PRE-16 | apt-get detected as package manager | `which apt-get` returns `exit_code=0` | Install command uses `apt-get install -y qperf iperf` |
| G | PRE-17 | yum detected as package manager | `which apt-get` returns `exit_code=1` | Install command uses `yum install -y qperf iperf` |

#### Artifact

| P | ID | Name | Expected outcome |
|---|---|---|---|
| G | PRE-18 | Artifact written on success | `_preflight.json` contains `{"ports_open": true, "tools_ready": true, "actions_taken": [...]}` |
| O | PRE-19 | Artifact written on early exit (ports blocked) | Artifact written with `ports_open=false` before `preflight()` returns. *(Abort itself is the critical behavior; artifact content on abort is secondary.)* |

---

### 5.3 MEA — measure()

#### Pre-clean

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | MEA-01 | No stale processes | `lsof` returns empty | No kill command issued; measure proceeds |
| M | MEA-02 | Stale processes — kill approved | `lsof` returns "1234\n5678"; kill `exit_code=0` | Kill issued with PIDs "1234 5678"; measure proceeds |
| M | MEA-03 | Stale processes — kill denied | Kill returns `status="denied"` | `RuntimeError("Stale processes exist ... kill was declined")`; no server started |
| G | MEA-04 | Stale kill command fails (non-zero) | Kill returns `exit_code=1` | `RuntimeError("Failed to kill stale processes")` |

#### Server start and PID capture

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | MEA-05 | qperf server: valid PID | nohup command returns "9876" | `qperf_pid = "9876"`; measure proceeds |
| M | MEA-06 | qperf server: start denied | Returns `status="denied"` | `RuntimeError("qperf server start failed")`; qperf finally block runs |
| M | MEA-07 | qperf server: non-zero exit | Returns `exit_code=1` | Same as MEA-06 |
| M | MEA-08 | qperf server: non-integer PID | Output is "qperf: address in use" | `RuntimeError` containing "non-integer PID"; finally uses name-based kill (S3) since `qperf_pid = None` |

#### Separated measurement loops

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | MEA-09 | test_type="latency" — iperf block skipped entirely | qperf server start + N iterations | `throughput_samples = []`; no iperf server start command ever issued |
| M | MEA-10 | test_type="throughput" — qperf block skipped entirely | iperf server start + N iterations | `latency_samples = []`; no qperf server start command ever issued |
| M | MEA-11 | test_type="both" — qperf killed before iperf starts | Record shell call order via mock side effects | `SSH_KILL_SERVER(qperf)` appears in call log **strictly before** `SSH_START_IPERF`; order enforced |
| M | MEA-12 | test_type="both" — partial failure: latency OK, throughput fails | iperf client iteration 1 returns `exit_code=1` | `RuntimeError` propagates; qperf already killed (latency loop completed); iperf finally kills iperf server; `_raw.json` **not written** |
| M | MEA-13 | Sample count invariant | N=8 qperf iterations, 1 warm-up | `len(latency_samples) == 8` exactly; warm-up run not included |
| M | MEA-14 | Iteration failure mid-run | Iteration 4 of 8 returns `exit_code=1` | `RuntimeError("qperf client failed on iteration 4")`; finally runs; server killed |

#### Warm-up

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | MEA-15 | Warm-up passes — sample not added | Warm-up returns `exit_code=0`; then N recorded iterations | After completion: `len(latency_samples) == N` (not N+1) |
| M | MEA-16 | Warm-up fails — fatal | Warm-up returns `exit_code=1` | `RuntimeError("Warm-up qperf failed — server may not be ready")`; finally runs |

#### Teardown (finally blocks)

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | MEA-17 | qperf killed by PID after latency loop | `qperf_pid = "9876"` | S2-style kill (`kill 9876`) issued in qperf finally block |
| M | MEA-18 | qperf kill falls back to name-based if PID is None | qperf server start fails before PID captured | S3-style kill (`pkill -f 'qperf'`) issued; no `None` dereference |
| M | MEA-19 | Kill fails in finally — does not re-raise | Kill command returns `exit_code=1` | Warning logged; original exception propagates unchanged out of finally; no new exception raised |
| G | MEA-20 | iperf finally block is independent of qperf | test_type="both" | qperf finally completes after latency loop; iperf finally completes after throughput loop; neither cancels the other |

#### Artifact

| P | ID | Name | Expected outcome |
|---|---|---|---|
| G | MEA-21 | Raw artifact written on success | `_raw.json` contains `{"session_id": ..., "latency_samples_us": [...], "throughput_samples_gbps": [...]}` |
| M | MEA-22 | Raw artifact NOT written if exception raised | RuntimeError in any iteration block → finally kills server → STEP 6 unreached; `_raw.json` does not exist |

---

### 5.4 COM — compute()

#### P90 formula

> **Note:** `floor(0.9 × N)` gives index N−1 for all N ≤ 10. With the default 8 iterations, P90 always equals the maximum sample. The Gap Rule is the primary stability filter; P90 is more meaningful at N > 11.

| P | ID | Name | Samples | Expected P90 |
|---|---|---|---|---|
| M | COM-01 | 8 samples, ascending | `[100, 110, 120, 130, 140, 150, 160, 170]` | `170` — `sorted[floor(7.2)] = sorted[7]` = last element |
| G | COM-02 | 8 samples, unsorted — sort happens | `[170, 100, 160, 110, 150, 120, 140, 130]` | `170` — same result; verifies sort step executes |
| G | COM-03 | 1 sample (iterations=1) | `[124.5]` | `124.5` |

#### Gap Rule

| P | ID | Name | Samples | `is_stable` | `anomaly_type` |
|---|---|---|---|---|---|
| M | COM-04 | 50% spread exactly — stable boundary | `[100, 150]` | `True` | `None` — rule is `> 50%`, not `≥ 50%` |
| M | COM-05 | Spread just above 50% — HIGH_VARIANCE | `[100, 151]` | `False` | `"HIGH_VARIANCE"` |
| M | COM-06 | Zero value — CONNECTIVITY_DROP | `[0.0, 100, 100, 100, 100, 100, 100, 100]` | `False` | `"CONNECTIVITY_DROP"` — min=0 check precedes gap ratio |
| M | COM-07 | Zero with wide spread — CONNECTIVITY_DROP wins, not HIGH_VARIANCE | `[0.0, 200]` | `False` | `"CONNECTIVITY_DROP"` — min=0 is checked first |

#### Anomaly priority (test_type="both", two metrics active)

| P | ID | Name | Latency | Throughput | Expected `anomaly_type` |
|---|---|---|---|---|---|
| M | COM-08 | Both stable | stable | stable | `None` |
| G | COM-09 | Latency HIGH_VARIANCE only | HIGH_VARIANCE | stable | `"HIGH_VARIANCE"` |
| G | COM-10 | Throughput CONNECTIVITY_DROP only | stable | CONNECTIVITY_DROP | `"CONNECTIVITY_DROP"` |
| M | COM-11 | Cross-metric: CONNECTIVITY_DROP overrides HIGH_VARIANCE | HIGH_VARIANCE | CONNECTIVITY_DROP | `"CONNECTIVITY_DROP"` — throughput result overrides |
| M | COM-12 | CONNECTIVITY_DROP not overwritten by lower-severity result | CONNECTIVITY_DROP | HIGH_VARIANCE | `"CONNECTIVITY_DROP"` — already set; throughput HIGH_VARIANCE does not overwrite |

#### Precondition enforcement

| P | ID | Name | Input | Expected outcome |
|---|---|---|---|---|
| M | COM-13 | test_type="latency", latency_samples empty | `latency_samples=[]` | `RuntimeError("Latency samples expected but list is empty")` |
| M | COM-14 | test_type="throughput", throughput_samples empty | `throughput_samples=[]` | `RuntimeError("Throughput samples expected but list is empty")` |
| G | COM-15 | test_type="latency" — throughput fields None | `throughput_samples=[]` | No error; all throughput fields in `ComputedStats` are `None` |

#### Artifact

| P | ID | Name | Expected outcome |
|---|---|---|---|
| O | COM-16 | Computed artifact — None fields serialised as JSON null | `_computed.json` has `None` fields as JSON `null`, not the string `"None"`. *(Correctness important but caught quickly in any downstream consumer.)* |

---

### 5.5 CMP — compare()

#### Baseline read and intent

> **Precondition for CMP-01 through CMP-09:** `compare_baseline=True` in all tests below unless the test name explicitly states otherwise. With `compare_baseline=False`, `read_blob` is never called; that path is covered by CMP-12 and CMP-13.

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | CMP-01 | No baseline, is_baseline=False | `compare_baseline=True`; `read_blob` returns `None` | All baseline fields `None`; `write_as_baseline=False` |
| M | CMP-02 | No baseline, is_baseline=True | `compare_baseline=True`; `read_blob` returns `None` | `write_as_baseline=True`; no overwrite warning printed; no prompt |
| M | CMP-03 | Baseline exists, is_baseline=False | `compare_baseline=True`; `read_blob` returns valid baseline bytes | Delta computed; `write_as_baseline=False` |
| M | CMP-04 | Baseline exists, is_baseline=True — warning printed, no gate, write proceeds | `compare_baseline=True`; `read_blob` returns valid baseline bytes | Stdout contains "A baseline already exists" and baseline timestamp; `write_as_baseline=True`; `input` mock never called |
| M | CMP-05 | Baseline read fails — pipeline continues | `compare_baseline=True`; `read_blob` raises `RuntimeError` | Warning printed; all baseline fields `None`; pipeline continues to report |
| G | CMP-06 | Baseline JSON malformed | `compare_baseline=True`; `read_blob` returns `b"not json"` | Warning printed; all baseline fields `None`; pipeline continues |
| G | CMP-07 | Baseline missing latency key — partial data handled | `compare_baseline=True`; `{"results": {"throughput_p90": 9.4}, "test_metadata": {...}}` | `baseline_p90_lat = None`; `delta_lat = None`; `delta_thr` computed |

#### Delta sign convention

| P | ID | Name | Current P90 | Baseline P90 | Expected delta | Sign semantics |
|---|---|---|---|---|---|---|
| M | CMP-08 | Latency degraded | 135.0 µs | 120.0 µs | `+12.5` | Positive = degraded for latency (`compare_baseline=True` assumed) |
| M | CMP-09 | Throughput degraded | 8.0 Gbps | 10.0 Gbps | `−20.0` | Negative = degraded for throughput — sign inverted vs latency (`compare_baseline=True` assumed) |

#### No double-gate (structural invariant)

| P | ID | Name | Setup | Expected outcome |
|---|---|---|---|---|
| M | CMP-10 | `input()` never called on any path | Monkeypatch `builtins.input` to raise `AssertionError` | Must not trigger under any of CMP-01 through CMP-07 scenarios |

#### Artifact

| P | ID | Name | Expected outcome |
|---|---|---|---|
| G | CMP-11 | Comparison artifact written | `_comparison.json` exists; all `ComparisonResult` fields present; `None` fields as JSON `null` |

#### compare_baseline=False gate

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | CMP-12 | compare_baseline=False — read_blob never called | `compare_baseline=False`; `read_blob` mock instrumented | `read_blob` call count = 0; all baseline fields `None`; `write_as_baseline=False` |
| M | CMP-13 | compare_baseline=False, is_baseline=True — write intent set, read not attempted | `compare_baseline=False`, `is_baseline=True` | `write_as_baseline=True`; `read_blob` call count = 0; no baseline delta fields |

---

### 5.6 REP — report()

#### Artifact assembly and local write

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | REP-01 | Result artifact written with correct top-level structure | All mocks succeed | `_result.json` contains keys: `test_metadata`, `preflight`, `results`, `comparison`; `results.iteration_data` is a list with `len == config.iterations` |
| M | REP-02 | Local write fails — pipeline aborts; no blob upload attempted | `_write_artifact` raises `RuntimeError` | `RuntimeError` propagates; `write_blob` never called |

#### Blob uploads

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | REP-03 | Result blob: correct name and payload | `write_blob` mock; inspect call args | Called with `blob_name = "{src}_{dst}_{session_id}.json"`; `data` argument equals the JSON-encoded bytes of the `_result.json` local write (same content, independently verified) |
| M | REP-04 | Result blob upload fails — degraded success | `write_blob` raises | Warning printed with local path; `PipelineResult(blob_url="", status="success")` |
| M | REP-05 | Baseline blob uploaded when `write_as_baseline=True` | `write_blob` called twice; inspect args | Second call uses `blob_name = "{src}_{dst}_baseline.json"`; `data` argument equals the same JSON bytes as the run result (baseline and run result share the same payload) |
| M | REP-06 | Baseline blob NOT uploaded when `write_as_baseline=False` | `write_blob` mock; inspect call count | Called exactly once (run result only); baseline name never appears |
| G | REP-07 | Baseline blob upload fails — run still success | Second `write_blob` raises | Warning printed; `status="success"` (run result already uploaded) |

#### Console output

| P | ID | Name | Input state | Expected stdout |
|---|---|---|---|---|
| G | REP-08 | test_type="latency" — throughput line suppressed | `throughput_p90=None` | Throughput line not printed; latency line present |
| G | REP-09 | test_type="throughput" — latency line suppressed | `latency_p90=None` | Latency line not printed; throughput line present |
| G | REP-10 | No baseline — delta block suppressed | `delta_pct_latency=None` | `← X% vs baseline` absent from all metric lines |
| G | REP-11 | Latency positive delta → (slower) | `delta_pct_latency=+8.3` | Output contains `(slower)` |
| G | REP-12 | Latency negative delta → (faster) | `delta_pct_latency=−5.0` | Output contains `(faster)` |
| G | REP-13 | Throughput negative delta → (slower) | `delta_pct_throughput=−10.0` | Output contains `(slower)` |
| G | REP-14 | Throughput positive delta → (faster) | `delta_pct_throughput=+5.0` | Output contains `(faster)` |
| M | REP-15 | CONNECTIVITY_DROP stability tag shown to operator | `anomaly_type="CONNECTIVITY_DROP"` | `Stability:  UNSTABLE — CONNECTIVITY_DROP`; `[CONNECTIVITY_DROP]` on affected metric line |
| M | REP-16 | HIGH_VARIANCE stability tag shown to operator | `anomaly_type="HIGH_VARIANCE"` | `Stability:  UNSTABLE — HIGH_VARIANCE`; `[HIGH_VARIANCE]` on affected metric line |
| O | REP-17 | Blob URL empty — fallback text shown | `blob_url=""` | `Blob:` line contains `(upload failed — see audit file)`. *(Cosmetic; REP-04 already asserts blob_url="" on failure.)* |
| G | REP-18 | Aborted preflight console format | `status="aborted_preflight"` | Header shows "Preflight Failed"; reason and audit path shown; no metrics block |
| O | REP-19 | Full output — both metrics, both deltas, stable | `test_type="both"`, both deltas non-None, `is_stable=True` | Latency and throughput lines present; correct delta labels; `Stability:  STABLE`. *(Composite of REP-08 through REP-16; add value only if individual tests pass.)* |

---

### 5.7 PAR — Output Parsers

#### `parse_qperf_latency()`

| P | ID | Name | Input string | Expected |
|---|---|---|---|---|
| M | PAR-01 | µs path with decimal (normal) | `"tcp_lat:\n    latency = 124.5 us\n"` | `124.5` |
| G | PAR-02 | µs with Unicode µ symbol | `"latency = 124 µs"` | `124.0` |
| M | PAR-03 | ms fallback — high-latency link | `"latency = 2.5 ms"` | `2500.0` |
| M | PAR-04 | No match → ParseError; not silent | `"tcp_lat:\n    msg_rate = 1000 K/sec\n"` | `ParseError`; message contains first 300 chars of output |
| F | PAR-05 | Empty string → ParseError | `""` | `ParseError`. *(Subset of PAR-04's no-match case; adds no new code coverage.)* |

#### `parse_iperf2_throughput()`

| P | ID | Name | Input string | Expected |
|---|---|---|---|---|
| M | PAR-06 | Gbits/sec path | `"[SUM] 0.0-10.0 sec  11.6 GBytes  9.94 Gbits/sec"` | `9.94` |
| M | PAR-07 | Mbits/sec conversion | `"[SUM] 0.0-10.0 sec  125 MBytes  105 Mbits/sec"` | `0.105` |
| M | PAR-08 | 8 stream lines before SUM — SUM selected, not a stream | Full 8-stream + SUM output | Returns `[SUM]` value; not the value from any individual stream line |
| M | PAR-09 | No SUM line → ParseError | `"[  3] 0.0-10.0 sec  1.44 GBytes  1.24 Gbits/sec\n"` | `ParseError` |
| F | PAR-10 | Empty string → ParseError | `""` | `ParseError`. *(Subset of PAR-09; adds no new code coverage.)* |

---

### 5.8 HIT — HITL Safety

**All HIT tests are MUST Pass.** HITL gating is a PRD §6 safety requirement and an architectural invariant. A tool that auto-approves a mutative command is a broken tool, not a degraded one.

**Test method:** drive command strings through `_make_hitl_callback()` directly. Auto-approve: `input` mock call count = 0. Manual-gate: `input` mock call count ≥ 1.

#### Auto-approve patterns (§10)

| P | ID | Pattern | Example command |
|---|---|---|---|
| M | HIT-01 | qperf client run | `ssh ... "qperf 10.0.0.5 -m 1024 tcp_lat"` |
| M | HIT-02 | iperf client run | `ssh ... "iperf -c 10.0.0.5 -P 8 -t 10"` |
| M | HIT-03 | `which qperf` and `which iperf` (both variants, one test) | `ssh ... "which qperf"` and `ssh ... "which iperf"` |
| M | HIT-04 | lsof stale check | `ssh ... "lsof -ti :5001,:19765 2>/dev/null"` |
| M | HIT-05 | `az network nic list` and `az network nic show` (one test) | `az network nic list ...` and `az network nic show ...` |
| M | HIT-06 | `az network nic list-effective-nsg` | `az network nic list-effective-nsg ...` |
| M | HIT-07 | `az network nsg show` | `az network nsg show ...` |
| M | HIT-08 | `az storage blob download` | `az storage blob download ...` |
| M | HIT-09 | `az storage blob upload` | `az storage blob upload ...` |
| M | HIT-10 | qperf server start (S8) — auto-approved | `ssh ... "nohup qperf </dev/null > /tmp/qperf_server.log 2>&1 & echo $!"` |
| M | HIT-11 | iperf server start (S9) — auto-approved | `ssh ... "nohup iperf -s </dev/null > /tmp/iperf_server.log 2>&1 & echo $!"` |
| M | HIT-12 | kill PIDs (S2) — auto-approved | `ssh ... "kill 1234 2>/dev/null; true"` |
| M | HIT-13 | pkill by name (S3) — auto-approved | `ssh ... "pkill -f 'qperf' 2>/dev/null; true"` |
| M | HIT-14 | SCP pmeter_blob_ temp file — auto-approved | `scp -o BatchMode=yes ... /tmp/pmeter_blob_a1b2.json azureuser@10.0.1.4:/tmp/pmeter_blob_a1b2.json` |
| M | HIT-15 | SSH-wrapped az storage blob upload/download — auto-approved | `ssh ... "az storage blob upload --file /tmp/pmeter_blob_a1b2.json ..."` |
| M | HIT-16 | SSH rm -f pmeter_blob_ temp file — auto-approved | `ssh ... "rm -f /tmp/pmeter_blob_a1b2.json"` |
| M | HIT-17 | SCP non-pmeter filename — boundary: manual gate fires | `scp ... /tmp/other_file.json azureuser@10.0.1.4:/tmp/other_file.json` |

#### Manual-gate patterns

| P | ID | Pattern | Example command |
|---|---|---|---|
| M | HIT-18 | apt-get install | `ssh ... "sudo apt-get install -y qperf iperf"` |
| M | HIT-19 | yum install | `ssh ... "sudo yum install -y qperf iperf"` |
| M | HIT-20 | `az network nsg rule create` | `az network nsg rule create ...` |
| M | HIT-21 | Unknown command — default-deny | `curl https://example.com` |

#### Denial behavior

| P | ID | Name | Setup | Expected outcome |
|---|---|---|---|---|
| M | HIT-22 | Operator denies server start — measure aborts | Callback returns `HitlDecision(action="deny")` | `{"status": "denied"}` returned; caller raises `RuntimeError`; measure aborts |
| M | HIT-23 | Operator denies port fix — preflight aborts | Callback returns `HitlDecision(action="deny")` | `PreflightResult(ports_open=False)` returned; fix command not executed |

---

### 5.9 AZP — AzureProvider

#### `_parse_effective_nsg` — the port-open/closed decision engine

All tests supply a synthetic `effectiveSecurityRules` list and call `_parse_effective_nsg(nsg_json, ports)` directly. These tests have no mocks — they are pure function tests.

> **Why this section exists:** PRE tests mock the entire `CloudProvider` interface. `_parse_effective_nsg` — the logic that decides "is this port actually open?" — is not exercised by any other section. Getting the priority order or direction filter wrong produces silent false positives (port reported open when blocked) or false negatives (port reported blocked when open).

| P | ID | Name | Rules | Port | Expected |
|---|---|---|---|---|---|
| M | AZP-01 | First matching Inbound Allow → open | `[{prio:100, dir:Inbound, access:Allow, proto:Tcp, destPortRange:"5001"}]` | 5001 | `{5001: True}` |
| M | AZP-02 | First matching Inbound Deny → closed | `[{prio:100, dir:Inbound, access:Deny, proto:Tcp, destPortRange:"5001"}]` | 5001 | `{5001: False}` |
| M | AZP-03 | First-match-wins: Deny at priority 100, Allow at 200 — Deny wins | Both rules; 100 < 200 so Deny is processed first | 5001 | `{5001: False}` — Allow never reached |
| M | AZP-04 | Outbound rule ignored for inbound query | `[{prio:100, dir:Outbound, access:Allow, destPortRange:"5001"}]` | 5001 | `{5001: False}` — direction filter excludes Outbound |
| M | AZP-05 | No matching rule → default deny | `[]` | 5001 | `{5001: False}` |
| G | AZP-06 | Protocol `*` wildcard matches TCP port | `[{prio:100, dir:Inbound, access:Allow, proto:"*", destPortRange:"5001"}]` | 5001 | `{5001: True}` |

#### `AzureProvider.read_blob` error paths (local routing)

| P | ID | Name | Shell mock | Expected outcome |
|---|---|---|---|---|
| M | AZP-07 | BlobNotFound (exit code 3) → None, no exception | `az storage blob download` returns `exit_code=3` | Returns `None`; no `RuntimeError` raised |
| G | AZP-08 | Auth error → RuntimeError with actionable message | stderr contains "AuthorizationPermissionMismatch" | `RuntimeError` message contains "Storage auth failed" and "Storage Blob Data Contributor" |

#### `_parse_effective_nsg` — Outbound direction

| P | ID | Name | Rules | Port | Expected |
|---|---|---|---|---|---|
| M | AZP-09 | First matching Outbound Allow → open | `[{prio:100, dir:Outbound, access:Allow, proto:Tcp, destPortRange:"5001"}]`, direction="Outbound" | 5001 | `{5001: True}` |
| M | AZP-10 | First matching Outbound Deny → closed | `[{prio:100, dir:Outbound, access:Deny, proto:Tcp, destPortRange:"5001"}]`, direction="Outbound" | 5001 | `{5001: False}` |

#### `AzureProvider.check_nsg_ports` — both-VM composition

`check_nsg_ports` calls `_parse_effective_nsg` twice: `direction="Inbound"` for the dest VM NIC, `direction="Outbound"` for the source VM NIC. A port is `True` only if both return `True`.

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | AZP-11 | Inbound-dest Allow AND Outbound-source Allow → port True | `_parse_effective_nsg` stubbed: Inbound `{5001: True}`, Outbound `{5001: True}` | `check_nsg_ports(...)` returns `{5001: True}` |
| M | AZP-12 | Inbound-dest Allow, Outbound-source Deny → port False | Inbound `{5001: True}`; Outbound `{5001: False}` | `{5001: False}` |
| M | AZP-13 | Inbound-dest Deny, Outbound-source Allow → port False | Inbound `{5001: False}`; Outbound `{5001: True}` | `{5001: False}` |

#### `_parse_effective_nsg` — Azure JSON envelope formats

| P | ID | Name | Input format | Expected |
|---|---|---|---|---|
| M | AZP-14 | `networkSecurityGroups` envelope | `{"networkSecurityGroups": [{"effectiveSecurityRules": [{prio:100, dir:Inbound, access:Allow, destPortRange:"5001"}]}]}` | Rules extracted; returns `{5001: True}` |
| M | AZP-15 | `value` envelope | `{"value": [{"effectiveSecurityRules": [{prio:100, dir:Inbound, access:Allow, destPortRange:"5001"}]}]}` | Rules extracted; returns `{5001: True}` |

#### `_parse_effective_nsg` — `destinationPortRanges` plural form

| P | ID | Name | Rules | Port | Expected |
|---|---|---|---|---|---|
| G | AZP-16 | `destinationPortRanges` (plural list) contains the port — open | `[{prio:100, dir:Inbound, access:Allow, proto:Tcp, destinationPortRanges:["5001","8080"]}]` | 5001 | `{5001: True}` |

#### `AzureProvider.write_blob` / `read_blob` — SSH routing

| P | ID | Name | Mock setup | Expected outcome |
|---|---|---|---|---|
| M | AZP-17 | `write_blob` via SSH — success | `ssh_user` and `source_public_ip` set; SCP returns `exit_code=0`; SSH az upload returns `exit_code=0` | Returns blob URL (`https://{account}.blob.core.windows.net/...`); SSH rm cleanup command issued |
| M | AZP-18 | `write_blob` via SSH — SCP step fails | SCP returns `exit_code=1` | `RuntimeError` message contains "SCP to source VM"; SSH az upload never called; SSH rm not called (`remote_copied=False`) |
| M | AZP-19 | `write_blob` via SSH — az upload step fails; remote temp cleaned up | SCP `exit_code=0`; SSH az upload `exit_code=1` | `RuntimeError` raised; SSH rm cleanup IS called (`remote_copied=True`) |
| M | AZP-20 | `read_blob` via SSH — success | SSH az download `exit_code=0`; SCP returns file bytes | Returns bytes matching blob content; SSH rm cleanup called |
| M | AZP-21 | `read_blob` via SSH — SSH download fails | SSH az download `exit_code=1` | `RuntimeError` raised |
| M | AZP-22 | `read_blob` via SSH — BlobNotFound → None | SSH az download `exit_code=3` | Returns `None`; no `RuntimeError` raised |
| G | AZP-23 | `write_blob` via SSH — auth error → actionable message | SSH az upload stderr contains "AuthorizationPermissionMismatch" | `RuntimeError` message contains actionable text (role assignment or permission details) |
| M | AZP-24 | Routing selector: SSH params → `_via_ssh`; absent → `_local` | Two `AzureProvider` instances: one with `ssh_user`/`source_public_ip`; one without | With params: SCP command issued (not direct `az storage blob upload`); without: direct `az storage blob upload` issued; `input` mock call count = 0 in both |

---

### 5.10 NSG — Priority Discovery Algorithm

All tests call `AzureProvider._find_safe_nsg_priority()` directly with a synthetic A7 response.

| P | ID | Name | A7 rules | Expected |
|---|---|---|---|---|
| M | NSG-01 | No user-defined rules | `[]` | `200` |
| M | NSG-02 | Deny rule at priority 300 for port 5001 | `[{prio:300, access:Deny, dir:Inbound, destPortRange:"5001"}]` | `290` (300 − 10; 290 is free) |
| M | NSG-03 | Deny rule at Azure minimum priority (100) | `[{prio:100, access:Deny, dir:Inbound, destPortRange:"5001"}]` | `RuntimeError("Cannot place ALLOW rule above DENY at priority 100")` |
| M | NSG-04 | Target slot (200) occupied — one collision resolved | Rules include `{prio:200}` (any access); no deny for 5001 | `199` (200 − 1) |
| G | NSG-05 | Dense cluster: 10 consecutive slots (200–191) occupied | Rules at priorities 200, 199, …, 191 | `190` (10th decrement; slot 190 is free) |
| M | NSG-06 | Collision exhaustion: 11 consecutive slots (200–190) all occupied | Rules at 200, 199, …, 190 | `RuntimeError("Cannot find a free NSG priority near 200")` |
| M | NSG-07 | Port matched via `*` wildcard deny | `[{prio:300, access:Deny, dir:Inbound, proto:"*", destPortRange:"*"}]` | `290` — `*` matches port 5001; deny is detected |
| M | NSG-08 | Port matched via range `"5000-5010"` deny | `[{prio:300, access:Deny, dir:Inbound, destPortRange:"5000-5010"}]` | `290` — port 5001 is within range |
| G | NSG-09 | Range `"5002-5010"` excludes port 5001 — not a match | `[{prio:300, access:Deny, dir:Inbound, destPortRange:"5002-5010"}]` | `200` — deny does not cover 5001; no deny found |
| G | NSG-10 | Deny rule for different port (8080) — not a match | `[{prio:300, access:Deny, dir:Inbound, destPortRange:"8080"}]` | `200` — deny does not cover 5001 |

---

### 5.11 BLB — Blob Naming

| P | ID | Name | Input | Expected |
|---|---|---|---|---|
| M | BLB-01 | IP to blob prefix | `"10.0.0.4"` | `"10_0_0_4"` |
| M | BLB-02 | Run result blob name | src=`"10.0.0.4"`, dst=`"10.0.0.5"`, session=`"pmeter_20260302140000"` | `"10_0_0_4_10_0_0_5_pmeter_20260302140000.json"` |
| M | BLB-03 | Baseline blob name | same src/dst | `"10_0_0_4_10_0_0_5_baseline.json"` |
| O | BLB-04 | Prefix consistent across `compare()` and `report()` | Same `PipelineConfig` used in both stages | `blob_prefix` strings are identical. *(Divergence would be caught by BLB-02/03 failing in separate tests.)* |

---

### 5.12 ISO — Pipeline Stage Isolation

Each test writes the upstream artifact to `tmp_path`, then drives the target stage from disk — no upstream stage runs.

| P | ID | Name | Artifact written | Stage driven | Assertions |
|---|---|---|---|---|---|
| O | ISO-01 | compute() from raw artifact | `_raw.json`: `{"session_id":"...", "latency_samples_us":[100..170], "throughput_samples_gbps":[]}` | `compute()` | Correct P90; `_computed.json` written; no `KeyError` |
| O | ISO-02 | compare() from computed artifact | `_computed.json` | `compare()` with mock `read_blob` | Correct deltas; `_comparison.json` written |
| O | ISO-03 | report() from comparison + preflight artifacts | `_comparison.json` + `_preflight.json` | `report()` | `_result.json` written; `test_metadata`, `preflight`, `results`, `comparison` keys present |
| O | ISO-04 | Raw artifact schema contract | `_raw.json` produced by `measure()` stub | Parsed by `compute()` harness | Fields `session_id` (str), `latency_samples_us` (list), `throughput_samples_gbps` (list) all present and correct type |

---

### 5.13 EDG — Residual Edge Cases

These edge cases are not fully covered by the sections above.

| P | ID | §14 # | Name | Expected outcome |
|---|---|---|---|---|
| G | EDG-01 | 3 | iterations=1 — Gap Rule at boundary | P90 = single sample; `max = min`; gap = 0; `is_stable=True` |
| F | EDG-02 | 5 | No baseline, is_baseline=True — no warning printed | Stdout does NOT contain "already exists". *(CMP-02 already covers write_as_baseline=True; absence of a warning is the trivially expected behavior when there's nothing to warn about.)* |
| G | EDG-03 | 6 | Baseline exists, is_baseline=True — warning message text | Stdout contains "A baseline already exists" and the baseline ISO timestamp. *(CMP-04 covers the behavioral assertions; EDG-03 pins the exact message wording.)* |
| M | EDG-04 | 7 | latency_min=0.0 — operator alert in console | `anomaly_type="CONNECTIVITY_DROP"`; `is_stable=False`; console shows `[CONNECTIVITY_DROP]` on latency line |
| G | EDG-05 | 14 | audit_dir does not exist — created automatically | `_write_artifact` calls `os.makedirs(exist_ok=True)`; artifact written successfully |

---

### 5.14 SSH — Command Template Structure

Tests assert string content without executing SSH commands.

| P | ID | Name | Assertion |
|---|---|---|---|
| M | SSH-01 | S8 qperf server start contains `</dev/null` | Template string contains `</dev/null` before the stdout redirect — prevents SSH hang |
| M | SSH-02 | S9 iperf server start contains `</dev/null` | Same |
| G | SSH-03 | All SSH templates (S1–S12) contain all three SSH options | `-o BatchMode=yes`, `-o ConnectTimeout=15`, `-o StrictHostKeyChecking=accept-new` in every template |
| M | SSH-04 | qperf client uses correct measurement flags | S10 contains `-m 1024 tcp_lat` |
| M | SSH-05 | iperf client uses correct parallelism and duration flags | S11 contains `-P 8 -t 10` |
| F | SSH-06 | Server start templates trigger auto-approve | Driving S8, S9 through `_make_hitl_callback()` triggers auto-approve; `input` mock call count = 0. *(Fully covered by HIT-10, HIT-11. No new coverage.)* |
| M | SSH-07 | ProxyCommand present when dest VM key provided | `_make_ssh_opts(jump_host="10.0.0.5", jump_key="/home/user/.ssh/dest_key")` | Returned string contains `-o ProxyCommand='ssh -i /home/user/.ssh/dest_key -W %h:%p user@10.0.0.5'` |
| M | SSH-08 | ProxyCommand absent when no dest VM key provided | `_make_ssh_opts(jump_host=None, jump_key=None)` | Returned string does not contain `ProxyCommand` |

---

### 5.15 PLO — Pipeline Orchestrator

| P | ID | Name | Setup | Expected outcome |
|---|---|---|---|---|
| M | PLO-01 | Unhandled exception caught — error result returned | `measure()` raises `RuntimeError("disk full")` | `run_pipeline()` returns `PipelineResult(status="error", error_message="disk full", local_artifact_path="", blob_url="")` |
| M | PLO-02 | CLI exit codes | Success → `sys.exit(0)`; `status="error"` → `sys.exit(1)`; `status="aborted_preflight"` → `sys.exit(1)` | Exit codes match exactly; caller scripts can rely on these |
| G | PLO-03 | `_generate_session_id()` format | Call function | Matches `^pmeter_\d{8}T\d{6}$`; timestamp is UTC (within 5 seconds of `datetime.now(timezone.utc)`) |
| M | PLO-04 | Session manifest written before preflight | `run_pipeline()` with mocked `preflight()` | `_manifest.json` exists in `audit_dir` before any stage artifact; contains `session_id`, `source_ip`, `dest_ip`, `timestamp` fields |
| M | PLO-05 | Orchestrator gate: measure not called when preflight fails | `preflight()` mocked to return `PreflightResult(ports_open=False, tools_ready=False)` | `measure()` never called; `run_pipeline()` returns `PipelineResult(status="aborted_preflight")` |

---

## 6. Coverage Matrix

| Requirement | Covered by |
|---|---|
| §3.1 qperf: `-m 1024 tcp_lat` | SSH-04 (M), HIT-01 (M), MEA-13 (M) |
| §3.1 iperf2: 8 parallel streams `-P 8` | SSH-05 (M), HIT-02 (M), MEA-13 (M) |
| §3.2 Default 8 iterations | VAL-01 (M) |
| §3.2 P90 calculation | COM-01 (M) |
| §3.3 1 warm-up pass, unrecorded | MEA-15 (M), MEA-16 (M) |
| §3.3 Gap Rule >50% → UNSTABLE | COM-04 (M), COM-05 (M) |
| §3.3 Zero value → CONNECTIVITY_DROP | COM-06 (M), EDG-04 (M) |
| §4.1 All input parameters validated | VAL-01–VAL-09 (all M) |
| §4.2 NSG effective rules check | PRE-01–PRE-08, AZP-01–AZP-06 |
| §4.2 Ports 5001 and 19765 | PRE-01 (M); both ports in mock |
| §4.2 Install with HITL confirmation | PRE-10 (M), PRE-11 (M), HIT-14 (M), HIT-15 (M) |
| §4.3 Baseline read from blob storage | CMP-01–CMP-07 |
| §4.3 Delta percentage | CMP-08 (M), CMP-09 (M) |
| §5.1 Console summary | REP-08–REP-19 |
| §5.2 JSON artifact schema | REP-01 (M), ISO-03 (O) |
| §6 Process cleanup | MEA-17–MEA-20 |
| §6 Gated actions: install, NSG rule | HIT-14 (M), HIT-15 (M), HIT-16 (M) |
| §6 Gated actions: only on explicit confirmation | HIT-18 (M), HIT-19 (M) |
| §7 Cloud abstraction | ISO tests use mock CloudProvider, not AzureProvider |
| Design S8/S9 `</dev/null` fix | SSH-01 (M), SSH-02 (M) |
| Design §10 blob upload auto-approved | HIT-09 (M) |
| Design §10 no double-gate | CMP-10 (M), EDG-03 (G) |
| Design §11 NSG priority algorithm | NSG-01–NSG-10 |
| Design `_parse_effective_nsg` logic | AZP-01–AZP-06 |
| Design `compare_baseline` flag gating | VAL-12 (M), CMP-12 (M), CMP-13 (M) |
| Design blob SSH routing (`_write_blob_via_ssh`, `_read_blob_via_ssh`) | AZP-17–AZP-24 |
| Design `_parse_effective_nsg` Outbound direction | AZP-09 (M), AZP-10 (M) |
| Design `check_nsg_ports` both-VM composition | AZP-11 (M), AZP-12 (M), AZP-13 (M) |
| Design `_parse_effective_nsg` Azure envelope formats | AZP-14 (M), AZP-15 (M) |
| Design §10 S2/S3/S8/S9 reclassified to auto-approve | HIT-10–HIT-13 (all M) |
| Design §10 blob SSH routing auto-approve patterns | HIT-14 (M), HIT-15 (M), HIT-16 (M), HIT-17 (M boundary) |
| Design §7 ProxyCommand for dest VM SSH | SSH-07 (M), SSH-08 (M) |
| Design session manifest written before preflight | PLO-04 (M) |
| Design orchestrator gate (measure not called on preflight fail) | PLO-05 (M) |

---

## 7. Pass/Fail Criteria

**A test passes if and only if all of the following hold:**

1. Return value or side effect exactly matches the stated expected outcome.
2. Error paths: exact exception type raised AND message substring verified.
3. Auto-approve tests: `input` mock call count is exactly 0.
4. Manual-gate tests: `input` mock call count is ≥ 1.
5. Artifact tests: file exists at the expected path, is valid JSON, and every field listed in the expected outcome is present with the correct type.
6. `None` serialisation: JSON `null`, never the string `"None"`.
7. Teardown tests: kill command verified issued to mock shell **regardless of whether an exception was raised**.
8. Sample count: `len(latency_samples)` or `len(throughput_samples)` equals `config.iterations` exactly; warm-up result is not included.

**A test fails if any of the following occur:**

- Expected exception not raised, or unexpected exception raised.
- `input()` called during `compare()` under any circumstances (any path, any scenario).
- Kill command not issued after a server was successfully started.
- Blob written under a name not matching §4 convention.
- `_raw.json` written when `measure()` raises.
- `PipelineResult.status` does not match the expected string exactly.
- A `None` field serialised as the string `"None"` rather than JSON `null`.

---

## 8. Priority Summary

| Tier | Count | Release gate |
|---|---|---|
| **M — MUST Pass** | 138 | All must pass |
| **G — GOOD to Pass** | 41 | ≥ 80% must pass |
| **O — OK to Pass** | 10 | Best-effort; carry forward |
| **F — OK to Fail** | 5 | Deferred; no release impact |
| **Total** | **194** | |

**M breakdown by category:** VAL 9 · PRE 11 · MEA 19 · COM 10 · CMP 10 · REP 8 · PAR 7 · HIT 23 · AZP 20 · NSG 7 · BLB 3 · EDG 1 · SSH 6 · PLO 4

**The 5 F tests and why:**
- VAL-11: Error-ordering implementation detail; not operator-observable.
- PAR-05, PAR-10: Empty-string cases; no new code path over the no-match tests (PAR-04, PAR-09).
- EDG-02: Absence of a warning when nothing exists to warn about; trivially expected.
- SSH-06: Cross-reference redundant with HIT-10/11.

---

## 9. Intentional Test Omissions

| Omitted test | Reason |
|---|---|
| SafeExecShell audit log format and classification | Sibling library; tested by its own suite |
| qperf / iperf2 accuracy against known network conditions | Tool property, not application property |
| Azure RBAC and subscription permissions | Infrastructure pre-condition |
| `--is-baseline` + `Overwrite? [y/N]` prompt | Removed in design; CMP-10 and EDG-03 confirm no gate fires |
| SSH key provisioning | Pre-condition, tested separately |
