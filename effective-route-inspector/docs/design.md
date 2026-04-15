# Design — effective-route-inspector

> Document order: **Requirements → Architecture → Design (this document) → Code**
> Architecture source: `effective-route-inspector/docs/architecture.md`
> Requirements source: `effective-route-inspector/docs/product-requirements.md`

Sections in this document supersede architecture-level schema sketches. Where the
architecture names a schema or function, this document is the authoritative specification.

---

## 1. Module and Function Inventory

### 1.1 `effective_route_inspector.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `main` | `() -> None` | Parse CLI args, drive pipeline stages, exit with correct code |
| `_enforce_session_prefix` | `(session_id: str) -> str` | Return session_id unchanged if it starts with `rt_`; prepend `rt_` otherwise |
| `_generate_session_id` | `() -> str` | Return `rt_YYYYMMDD_HHMMSS` using `datetime.utcnow()` |
| `_ensure_audit_dir` | `(audit_dir: str) -> Path` | Create directory if absent (`exist_ok=True`); raise `SystemExit(2)` if creation fails |
| `_run_pipeline` | `(args: Namespace, provider: RouteProvider \| None = None) -> int` | Execute Stages 2–5 in sequence; return exit code |
| `_render_table` | `(verdict: SingleTargetVerdict \| AuditVerdict) -> str` | Produce human-readable text from verdict dict for stdout output |

`main()` calls `_enforce_session_prefix`, `_ensure_audit_dir`, then `_run_pipeline`, then
`sys.exit` with the returned code. It never catches exceptions from `_run_pipeline` — all
error handling is inside `_run_pipeline`, which returns 0 or 2.

---

### 1.2 `providers.py`

#### `RouteProvider` (protocol / abstract base)

Defines the interface that any provider implementation must satisfy. Both methods must
match these exact signatures. `AzureRouteProvider` implements this protocol. A
`MockRouteProvider` can implement it for testing without real az CLI calls.

| Method | Signature | Responsibility |
|--------|-----------|----------------|
| `get_nic_name` | `(vm_name: str, resource_group: str) -> str` | Resolve primary NIC name |
| `get_effective_routes` | `(nic_name: str, resource_group: str) -> dict` | Return raw effective route table as parsed dict |

`_run_pipeline` accepts `provider: RouteProvider | None = None`. When `None`, it
instantiates `AzureRouteProvider(subscription_id=args.subscription_id)` internally.
When provided, it uses the supplied instance. This is the test seam — no other component
needs to change when substituting a mock or adding a second cloud provider.

---

#### `is_throttle` (module-level function)

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `is_throttle` | `(stderr: str) -> bool` | Return `True` if stderr matches a known throttle pattern |

Patterns matched (case-insensitive, against `stderr.lower()`):
- `"throttling"`, `"too many requests"`, `"rate limit"`, `"429"`

This function is called only by `_call_with_retry`. It is module-level (not a method)
so it can be patched in tests independently of the provider instance.

⚠️ **See Unknown U1** — these patterns are assumptions, not empirically confirmed.

---

#### `LocalShell`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `run` | `(args: list[str]) -> str` | Execute command via argument vector; return stdout on success; raise `ProviderError` on failure |

`LocalShell.run()` uses `subprocess.run(args, capture_output=True, text=True)`. It never
uses `shell=True` or string interpolation. On non-zero exit code, it raises `ProviderError`
with the stderr content. It performs no error classification and no retry — those are
`AzureRouteProvider`'s responsibilities.

#### `AzureRouteProvider`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `__init__` | `(subscription_id: str \| None = None)` | Store subscription context; instantiate `LocalShell` |
| `get_nic_name` | `(vm_name: str, resource_group: str) -> str` | Resolve the primary NIC name for a VM |
| `get_effective_routes` | `(nic_name: str, resource_group: str) -> dict` | Return raw effective route table JSON as a parsed dict |
| `_call_with_retry` | `(args: list[str], context: str) -> str` | Run `LocalShell.run(args)` with throttle retry; raise `ThrottleExhausted` after max retries |
| `_classify_error` | `(stderr: str, context: str) -> None` | Inspect stderr for known patterns; raise the most specific typed exception |

`_call_with_retry` and `_classify_error` are private helpers. No other component calls
them. `get_nic_name` and `get_effective_routes` both call `_call_with_retry`, then
`_classify_error` if `ProviderError` is caught.

#### Exception hierarchy

```
ProviderError(RuntimeError)
  ├── RBACError
  ├── ThrottleExhausted
  ├── VMNotFoundError
  └── NICResolutionError
```

All exceptions carry a human-readable `message` attribute. `ThrottleExhausted` also
carries `attempts: int` and `last_wait_seconds: float`.

---

### 1.3 `route_preprocessor.py` (copied as-is)

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `preprocess` | `(path: str) -> dict` | Read raw JSON file; return normalised route list or error dict |

This module is copied unchanged from
`azure-effective-route-summarizer/.claude/skills/azure-effective-route-summarizer/route_preprocessor.py`.
Its interface is fixed. The design does not modify it.

Return structure on success:
```
{
  "route_count":        int,
  "routes":             list[RouteObject],
  "invalid_route_count": int,
  "parse_warnings":     list[str]
}
```

Return structure on failure (no usable routes):
```
{
  "error":          str,
  "parse_warnings": list[str]   # may be empty
}
```

The orchestrator checks for the `"error"` key before proceeding. If present: print
`error` to stderr, exit 2.

---

### 1.4 `lpm_engine.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `select_route` | `(routes: list[RouteObject], dst_ip: str) -> SingleTargetVerdict` | Apply Azure route selection algorithm for a destination IP |
| `audit_routes` | `(routes: list[RouteObject]) -> AuditVerdict` | Produce full route table audit without a destination IP |
| `_check_anomalies` | `(winner: RouteObject, all_routes: list[RouteObject], dst_ip: str) -> list[str]` | Run anomaly checks against winning route; return warning strings |

`_check_anomalies` is a private helper called only by `select_route`. All three functions
are pure: no I/O, no side effects, deterministic output for identical inputs.

Both public functions receive the **full** normalised route list (Active + Invalid +
Unknown). `select_route` filters internally for Active routes during CIDR containment;
the full list is needed for the `INVALID_SHADOW_WARNING` anomaly check.

---

## 2. Data Schemas

### 2.1 `RouteObject` — normalised route (produced by `route_preprocessor.py`)

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `prefix` | `str` | `addressPrefix[n]` | CIDR string, normalised by `ipaddress.ip_network()` |
| `prefix_length` | `int` | derived from `prefix` | Used for LPM comparison |
| `next_hop_type` | `str` | `nextHopType` | E.g. `"VnetLocal"`, `"Internet"`, `"None"`, `"VirtualAppliance"` |
| `next_hop_ip` | `str \| None` | `nextHopIpAddress[0]` | First address only; see parse warning for ECMP |
| `source` | `str` | `source` | `"User"`, `"VirtualNetworkGateway"`, `"Default"`, or as returned |
| `state` | `str` | `state` | `"Active"`, `"Invalid"`, or `"Unknown"` (absent/null normalised) |
| `route_name` | `str \| None` | `name` | May be null for system routes |
| `is_zero_route` | `bool` | derived | `True` if prefix is `"0.0.0.0/0"` |

One `RouteObject` per prefix. Azure entries with multiple `addressPrefix` values are
expanded into one object per prefix by the preprocessor.

---

### 2.2 `SingleTargetVerdict` — output of `select_route()`

| Field | Type | Present when | Notes |
|-------|------|-------------|-------|
| `mode` | `str` | always | `"single-target"` |
| `session_id` | `str` | always | Populated by orchestrator before write |
| `vm_name` | `str` | always | Populated by orchestrator |
| `resource_group` | `str` | always | Populated by orchestrator |
| `nic_name` | `str` | always | Populated by orchestrator |
| `dst_ip` | `str` | always | The queried destination IP |
| `result` | `str` | always | `"WINNER"`, `"NO_ROUTE"`, or `"TIED_BGP"` |
| `winning_route` | `RouteObject \| None` | `result == "WINNER"` | `null` for NO_ROUTE and TIED_BGP |
| `selection_reason` | `str` | always | `"LPM_ONLY"`, `"SOURCE_PRECEDENCE"`, `"TIED_BGP"`, or `"NO_ROUTE"` |
| `tied_routes` | `list[RouteObject] \| None` | `result == "TIED_BGP"` | The unresolvable VirtualNetworkGateway routes; `null` otherwise |
| `shadowed_candidates` | `list[RouteObject]` | always | Routes that matched but lost at LPM or source precedence; empty for NO_ROUTE; populated for TIED_BGP (contains routes that lost at LPM before the tie was reached) |
| `anomaly_warnings` | `list[str]` | always | Empty list if no anomalies |
| `parse_warnings` | `list[str]` | always | Forwarded from preprocessor; empty list if none |

`lpm_engine.select_route()` returns this dict **without** `session_id`, `vm_name`,
`resource_group`, and `nic_name`. The orchestrator adds those four fields before
serialising to disk.

---

### 2.3 `AuditVerdict` — output of `audit_routes()`

| Field | Type | Notes |
|-------|------|-------|
| `mode` | `str` | `"audit"` |
| `session_id` | `str` | Populated by orchestrator before write |
| `vm_name` | `str` | Populated by orchestrator |
| `resource_group` | `str` | Populated by orchestrator |
| `nic_name` | `str` | Populated by orchestrator |
| `route_count` | `int` | Total routes in normalised list (Active + Invalid + Unknown) |
| `invalid_route_count` | `int` | Count of routes where `state == "Invalid"` |
| `routes_by_prefix_length` | `list[RouteObject]` | All routes sorted by `prefix_length` descending |
| `invalid_routes` | `list[RouteObject]` | Routes where `state == "Invalid"`, same sort order |
| `findings` | `AuditFindings` | See below |
| `parse_warnings` | `list[str]` | Forwarded from preprocessor |

`AuditFindings` sub-schema:

| Field | Type | Notes |
|-------|------|-------|
| `blackhole_routes` | `list[RouteObject]` | Active routes where `next_hop_type == "None"` |
| `nva_routes` | `list[RouteObject]` | Active routes where `next_hop_type == "VirtualAppliance"` |
| `bgp_routes` | `list[RouteObject]` | Active routes where `source == "VirtualNetworkGateway"` |
| `default_route_present` | `bool` | True if any active route has `is_zero_route == True` |
| `default_route_source` | `str \| None` | Source of the first active default route; `null` if absent |

Same orchestrator enrichment applies: `audit_routes()` returns the dict without the
identity fields; orchestrator adds them.

---

### 2.4 CLI arguments

| Flag | Type | Required | Default | Notes |
|------|------|----------|---------|-------|
| `--vm-name` | `str` | Yes | — | Azure VM name |
| `--resource-group` | `str` | Yes | — | Azure resource group |
| `--dst-ip` | `str` | No | `None` | Valid IPv4 or IPv6 address; triggers single-target mode |
| `--nic-name` | `str` | No | `None` | Override primary NIC lookup; skips `get_nic_name` call |
| `--subscription-id` | `str` | No | `None` | Azure subscription ID; defaults to active az CLI subscription |
| `--session-id` | `str` | No | auto-generated | `rt_` prefix enforced; auto-generated if absent |
| `--audit-dir` | `str` | No | `./audit` | Directory for artifact writes |

`--dst-ip` validation: pass value through `ipaddress.ip_address()`. On `ValueError`:
print `"Invalid destination IP: {value}"` to stderr, exit 2 immediately (before any
Azure call).

---

### 2.5 Session ID format

Auto-generated format: `rt_YYYYMMDD_HHMMSS` (UTC, zero-padded).

Rationale over UUID: timestamp IDs are human-readable and self-documenting in the audit
directory listing. Two invocations within the same second will collide — see Edge Cases §6.

User-supplied session IDs: `_enforce_session_prefix` prepends `rt_` if absent. If the
user passes `rt_myid`, it is used unchanged. If the user passes `myid`, it becomes
`rt_myid`.

---

## 3. Pipeline Stage Detail

### Stage 1 — Validate

**Input:** raw `sys.argv`

**Processing:**
1. Parse with `argparse`. Required flags missing → argparse prints usage and exits 2.
2. If `--dst-ip` is provided: `ipaddress.ip_address(args.dst_ip)`. On `ValueError`: stderr message, exit 2.
3. `args.session_id = _enforce_session_prefix(args.session_id or _generate_session_id())`
4. `audit_path = _ensure_audit_dir(args.audit_dir)`

**Output:** populated `args` Namespace; `audit_path` as `pathlib.Path`

**Failure modes:**

| Condition | Exit | Stderr message |
|-----------|------|----------------|
| Required flag missing | 2 | argparse default usage |
| `--dst-ip` not a valid IP | 2 | `"Invalid destination IP: {value}"` |
| `audit_dir` not creatable | 2 | `"Cannot create audit directory: {path}: {reason}"` |

No Azure calls in this stage.

---

### Stage 2 — Collect

**Input:** `args` Namespace, `audit_path: Path`

**Processing:**
1. Resolve provider: use `provider` argument if supplied (test / alternative-provider
   seam); otherwise instantiate `AzureRouteProvider(subscription_id=args.subscription_id)`.
2. Resolve NIC name:
   - If `args.nic_name` is set: use directly (skip `get_nic_name`; VM name still recorded for audit).
   - Else: `nic_name = provider.get_nic_name(args.vm_name, args.resource_group)`.
3. `raw_dict = provider.get_effective_routes(nic_name, args.resource_group)`.
4. Write `raw_dict` as JSON to `audit_path / f"{session_id}_raw.json"`.
   Print progress to stdout: `"Querying effective routes for {nic_name}..."` (before the az call).

**Output:** `raw_file_path: Path`, `nic_name: str`

**Failure modes:** any `ProviderError` subtype → print message to stderr, exit 2. The
raw file is only written after a successful query; no partial write on failure.

---

### Stage 3 — Preprocess

**Input:** `raw_file_path: Path`

**Processing:**
1. Call `route_preprocessor.preprocess(str(raw_file_path))`.
2. If result contains `"error"` key: print `result["error"]` to stderr, exit 2.
3. Extract `routes = result["routes"]`, `parse_warnings = result["parse_warnings"]`.

**Output:** `routes: list[RouteObject]`, `parse_warnings: list[str]`

**Failure modes:**

| Condition | Exit | Stderr message |
|-----------|------|----------------|
| Raw file not found | 2 | `"Raw artifact not found: {path}"` (preprocessor returns error dict) |
| Raw file not valid JSON | 2 | `"Raw artifact is not valid JSON: {reason}"` |
| No routes parseable from file | 2 | `"No routes could be parsed from {path}"` |

---

### Stage 4 — Analyze

**Input:** `routes: list[RouteObject]`, `parse_warnings: list[str]`, `args`, `nic_name: str`, `audit_path: Path`

**Processing:**
1. Call algorithm based on mode:
   - `args.dst_ip` set: `verdict = lpm_engine.select_route(routes, args.dst_ip)`
   - `args.dst_ip` absent: `verdict = lpm_engine.audit_routes(routes)`
2. Enrich verdict with identity fields: `session_id`, `vm_name`, `resource_group`, `nic_name`.
3. Merge `parse_warnings` into `verdict["parse_warnings"]`.
4. Serialise verdict to `audit_path / f"{session_id}_verdict.json"` (JSON, indent=2).

**Output:** `verdict: dict`, `verdict_path: Path`

**Failure modes:** `lpm_engine` functions are pure and do not raise. The only failure
path here is the file write. If write fails: print to stderr, exit 2.

---

### Stage 5 — Output

**Input:** `verdict: dict`

**Processing:**
1. Call `_render_table(verdict)` → text string.
2. Print to stdout.

`_render_table` reads from the verdict dict only — it never re-reads the artifact file.

**Single-target table format:**
```
VM: {vm_name}   NIC: {nic_name}   Destination: {dst_ip}
Result:   {result}
Winner:   {prefix} → {next_hop_type} [{source}] {state}
Reason:   {selection_reason}
Warnings: {anomaly_warnings joined by newline, or "none"}
Shadowed: {count} route(s)
```
On TIED_BGP: show tied routes instead of winner. On NO_ROUTE: show `"No active route matches destination"`.

**Audit table format:**
```
VM: {vm_name}   NIC: {nic_name}   Mode: audit
Routes: {route_count} total  ({invalid_route_count} invalid)
  {prefix_length:>3}  {prefix:<20}  {next_hop_type:<22}  {source:<22}  {state}
  ... (all routes_by_prefix_length)

Findings:
  Blackhole routes : {count}
  NVA routes       : {count}
  BGP routes       : {count}
  Default route    : {present/absent} ({source or n/a})
```

**Failure modes:** `_render_table` does not raise. Any missing field defaults to `"n/a"`.

---

## 4. `providers.py` — Detailed Specification

### 4.1 `LocalShell.run(args: list[str]) -> str`

- Calls `subprocess.run(args, capture_output=True, text=True, timeout=60)`.
- On `FileNotFoundError` (az CLI not installed): raises `ProviderError("az CLI not found. Install the Azure CLI.")`.
- On timeout (`subprocess.TimeoutExpired`): raises `ProviderError("az CLI timed out after 60s")`.
- On non-zero `returncode`: raises `ProviderError(stderr_content)`.
- On zero `returncode`: returns `result.stdout` (may be empty string).

No retry. No error classification. Returns raw stdout string or raises `ProviderError`.

---

### 4.2 `AzureRouteProvider.__init__(subscription_id: str | None = None)`

Stores `self._subscription_id = subscription_id` and instantiates `self._shell = LocalShell()`.

---

### 4.3 `AzureRouteProvider.get_nic_name(vm_name: str, resource_group: str) -> str`

**az CLI command (argument vector):**
```
["az", "vm", "show",
 "--name",           vm_name,
 "--resource-group", resource_group,
 "--query",          "networkProfile.networkInterfaces[?primary].id | [0]",
 "--output",         "tsv"]
```
If `self._subscription_id` is set, append `["--subscription", self._subscription_id]`.

**Processing:**
1. Call `self._call_with_retry(args, context="get_nic_name")` → `stdout: str`.
2. Strip whitespace from stdout.
3. If stdout is empty or `"None"` (az CLI returns literal `"None"` for null JMESPath
   results): raise `VMNotFoundError(f"VM '{vm_name}' not found in resource group '{resource_group}', or has no NIC marked primary")`.
   ⚠️ **See Unknown U3** — single-NIC VMs may not always carry the `primary` flag.
4. NIC name extraction: `resource_id.split("/")[-1]`. The resource ID format is
   `.../providers/Microsoft.Network/networkInterfaces/{nic-name}`.
5. If extracted name is empty string: raise `NICResolutionError(f"Could not extract NIC name from resource ID: {stdout}")`.
6. Return extracted NIC name string.

---

### 4.4 `AzureRouteProvider.get_effective_routes(nic_name: str, resource_group: str) -> dict`

**az CLI command (argument vector):**
```
["az", "network", "nic", "show-effective-route-table",
 "--name",           nic_name,
 "--resource-group", resource_group,
 "--output",         "json"]
```
If `self._subscription_id` is set, append `["--subscription", self._subscription_id]`.

**Processing:**
1. Call `self._call_with_retry(args, context="get_effective_routes")` → `stdout: str`.
2. Parse stdout as JSON: `json.loads(stdout)` → raw dict.
3. On `json.JSONDecodeError`: raise `ProviderError(f"az CLI returned non-JSON output: {stdout[:200]}")`.
4. Return the parsed dict. Do not unwrap or normalise — pass raw structure to preprocessor.

---

### 4.5 `AzureRouteProvider._call_with_retry(args: list[str], context: str) -> str`

Retry policy:

| Parameter | Value |
|-----------|-------|
| Max attempts | 4 (1 initial + 3 retries) |
| Retry condition | `ProviderError` raised AND `is_throttle(stderr)` returns `True` |
| Backoff formula | `min(2 ** (attempt + 1), 30)` seconds — attempt 0→2s, 1→4s, 2→8s |
| Non-throttle errors | Passed immediately to `_classify_error`; no retry |

Pseudo-logic:
```
for attempt in range(4):
    try:
        return self._shell.run(args)
    except ProviderError as e:
        stderr = str(e)
        if is_throttle(stderr):
            if attempt == 3:
                raise ThrottleExhausted(attempts=4, last_wait_seconds=min(2 ** attempt, 30))
            sleep(min(2 ** (attempt + 1), 30))
            continue
        self._classify_error(stderr, context=context)
        raise   # re-raises the original ProviderError if _classify_error didn't raise
```

`ThrottleExhausted` carries: `attempts=4`, `last_wait_seconds` = last sleep duration.

---

### 4.6 `AzureRouteProvider._classify_error(stderr: str, context: str) -> None`

Inspects `stderr` (lowercased) for known patterns and raises the appropriate typed
exception. `context` is the caller name (`"get_nic_name"` or `"get_effective_routes"`),
used to select the semantically correct exception when the same pattern can arise from
different callers. If no known pattern matches, returns without raising (caller re-raises
the original `ProviderError`).

| Pattern (case-insensitive) | context | Exception raised |
|---------------------------|---------|-----------------|
| `"authorizationfailed"` or `"authorization_failed"` | any | `RBACError(f"Authorization failed during {context}. Ensure the caller has 'Microsoft.Network/networkInterfaces/effectiveRouteTable/action' and 'Microsoft.Compute/virtualMachines/read'.")` |
| `"resourcenotfound"` or `"resource not found"` | `"get_nic_name"` | `VMNotFoundError(f"VM not found during NIC lookup. Check VM name and resource group.")` |
| `"resourcenotfound"` or `"resource not found"` | `"get_effective_routes"` | `NICResolutionError(f"NIC not found when querying effective routes. Verify NIC name and resource group.")` |
| `"throttling"` or `"too many requests"` or `"rate limit"` or `"429"` | any | Not raised here — handled by `_call_with_retry` loop before `_classify_error` is called |

⚠️ **See Unknown U1** — throttle and authorization error patterns in az CLI stderr must
be empirically verified. The patterns above are reasonable but unconfirmed.

---

## 5. `lpm_engine.py` — Algorithm Specification

### 5.1 `select_route(routes: list[RouteObject], dst_ip: str) -> SingleTargetVerdict`

Receives the full normalised route list (Active + Invalid + Unknown). Returns a
`SingleTargetVerdict` dict without identity fields (orchestrator adds those).

**Step 1 — CIDR containment filter**

```
dst = ipaddress.ip_address(dst_ip)
candidates = [
    r for r in routes
    if r["state"] == "Active"
    and dst in ipaddress.ip_network(r["prefix"])
]
```

If `candidates` is empty: return `NO_ROUTE` verdict immediately.
`dst_ip` was validated at Stage 1; `ipaddress.ip_address()` will not raise here.

**Step 2 — Longest Prefix Match**

```
max_len = max(r["prefix_length"] for r in candidates)
lpm_winners = [r for r in candidates if r["prefix_length"] == max_len]
shadowed    = [r for r in candidates if r["prefix_length"] < max_len]
```

**Step 3 — Source precedence** (applied only when `len(lpm_winners) > 1`)

Source tier mapping:

| Source value | Tier |
|-------------|------|
| `"User"` | 1 |
| `"VirtualNetworkGateway"` | 2 |
| `"Default"` | 3 |
| Any other value | 4 |

```
tier = lambda r: SOURCE_TIER.get(r["source"], 4)
min_tier = min(tier(r) for r in lpm_winners)
final_winners  = [r for r in lpm_winners if tier(r) == min_tier]
shadowed      += [r for r in lpm_winners if tier(r) > min_tier]
```

If `len(final_winners) == 1`: winner determined; proceed to anomaly checks.

**Step 4 — BGP tie-break**

Applies only when `len(final_winners) > 1`.

If all `final_winners` have `source == "VirtualNetworkGateway"`: AS Path is not
available in the effective route table JSON. Return `TIED_BGP` verdict with
`tied_routes = final_winners`. Do not select.

If `final_winners` contains routes with tier-4 (unknown source) values: this is an
unexpected Azure state. Return `TIED_BGP` as the fallback result code (no new result
codes are added at design level) with `tied_routes = final_winners` and a
`parse_warning` that notes the tie involves routes of unknown source type, not BGP
routes. This case is practically impossible in a valid Azure effective route table.

**Step 5 — Anomaly checks** (only on a confirmed single winner)

Delegated to `_check_anomalies(winner, routes, dst_ip)`. All three checks are run;
results are accumulated into `anomaly_warnings`. Checks are not mutually exclusive.

**Return for WINNER:**
```python
{
    "mode": "single-target",
    "dst_ip": dst_ip,
    "result": "WINNER",
    "winning_route": winner,
    "selection_reason": "LPM_ONLY" if len(lpm_winners) == 1 else "SOURCE_PRECEDENCE",
    "tied_routes": None,
    "shadowed_candidates": shadowed,
    "anomaly_warnings": anomaly_warnings,
    "parse_warnings": []   # orchestrator merges preprocessor warnings
}
```

**Return for NO_ROUTE:**
```python
{
    "mode": "single-target",
    "dst_ip": dst_ip,
    "result": "NO_ROUTE",
    "winning_route": None,
    "selection_reason": "NO_ROUTE",
    "tied_routes": None,
    "shadowed_candidates": [],
    "anomaly_warnings": [],
    "parse_warnings": []
}
```

**Return for TIED_BGP:**
```python
{
    "mode": "single-target",
    "dst_ip": dst_ip,
    "result": "TIED_BGP",
    "winning_route": None,
    "selection_reason": "TIED_BGP",
    "tied_routes": final_winners,
    "shadowed_candidates": shadowed,
    "anomaly_warnings": [],
    "parse_warnings": []
}
```

---

### 5.2 `_check_anomalies(winner: RouteObject, all_routes: list[RouteObject], dst_ip: str) -> list[str]`

Run all three checks. Return a list of warning strings (empty list if no anomalies).

| Check | Condition | Warning string |
|-------|-----------|----------------|
| Blackhole | `winner["next_hop_type"] == "None"` | `"BLACKHOLE_WARNING: winning route {prefix} has next_hop_type 'None' — Azure will silently drop traffic"` |
| Invalid shadow | Any route in `all_routes` where `prefix_length > winner["prefix_length"]` AND `state == "Invalid"` AND `ipaddress.ip_address(dst_ip) in ipaddress.ip_network(route["prefix"])` | `"INVALID_SHADOW_WARNING: route {prefix} has longer prefix than winner but is Invalid — traffic falls to less specific path"` |
| NVA | `winner["next_hop_type"] == "VirtualAppliance"` | `"NVA_WARNING: winning route {prefix} points to a Virtual Appliance ({next_hop_ip}) — verify IP forwarding is enabled and return path is symmetric"` |

The INVALID_SHADOW check requires all three conditions: (1) a longer prefix than the
winner, (2) state `Invalid`, and (3) the destination IP falls within that Invalid route's
prefix (CIDR containment). Without condition (3), an Invalid /28 for an unrelated address
space would incorrectly trigger the warning when querying a completely different /24.
The `dst_ip` is pre-validated at Stage 1; `ipaddress.ip_address()` will not raise here.

---

### 5.3 `audit_routes(routes: list[RouteObject]) -> AuditVerdict`

```
active  = [r for r in routes if r["state"] == "Active"]
invalid = [r for r in routes if r["state"] == "Invalid"]
sorted_all = sorted(routes, key=lambda r: r["prefix_length"], reverse=True)

findings = {
    "blackhole_routes":      [r for r in active if r["next_hop_type"] == "None"],
    "nva_routes":            [r for r in active if r["next_hop_type"] == "VirtualAppliance"],
    "bgp_routes":            [r for r in active if r["source"] == "VirtualNetworkGateway"],
    "default_route_present": any(r["is_zero_route"] for r in active),
    "default_route_source":  next((r["source"] for r in active if r["is_zero_route"]), None),
}
```

Return:
```python
{
    "mode": "audit",
    "route_count": len(routes),
    "invalid_route_count": len(invalid),
    "routes_by_prefix_length": sorted_all,
    "invalid_routes": sorted(invalid, key=lambda r: r["prefix_length"], reverse=True),
    "findings": findings,
    "parse_warnings": []   # orchestrator merges preprocessor warnings
}
```

---

## 6. Ghost Agent Integration

### 6.1 FunctionDeclaration (11th tool in `ghost_agent.py`)

Added immediately after the 10th FunctionDeclaration in the tool list initialisation.

```
name: "effective_route_inspector"

description:
  "Inspect the effective route table for an Azure VM. In single-target mode
   (dst_ip provided), applies the Azure route selection algorithm and returns the
   winning route, the selection reason, anomaly warnings, and shadowed candidates.
   In audit mode (no dst_ip), returns all routes sorted by prefix length with
   findings for blackholes, NVA routes, BGP routes, and default route presence.
   Call this tool when the symptom is consistent with a routing-layer cause:
   silent packet drop, traffic taking an unexpected path, or suspected NVA bypass."

parameters:
  vm_name         string   required   Azure VM name
  resource_group  string   required   Resource group containing the VM
  dst_ip          string   optional   Destination IP (IPv4 or IPv6). Omit for audit mode.
  nic_name        string   optional   Override primary NIC auto-selection.
  subscription_id string   optional   Azure subscription ID. Defaults to active az CLI subscription.
```

---

### 6.2 `_run_effective_route_inspector_handler(tool_call: dict, ghost_cfg: dict) -> dict`

**Reads from `tool_call["parameters"]`:** `vm_name`, `resource_group`, `dst_ip`
(optional), `nic_name` (optional), `subscription_id` (optional).

**Reads from `ghost_cfg`:** `AUDIT_DIR`.

**Session ID:** `"rt_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")`
Generated in the handler before subprocess call.

**Verdict path:** `Path(ghost_cfg["AUDIT_DIR"]) / f"{session_id}_verdict.json"`
Constructed deterministically before subprocess invocation. No filesystem scan.

**Subprocess args construction:**
```
[sys.executable,
 str(_ROOT / "effective-route-inspector" / "effective_route_inspector.py"),
 "--vm-name",        tool_call["parameters"]["vm_name"],
 "--resource-group", tool_call["parameters"]["resource_group"],
 "--session-id",     session_id,
 "--audit-dir",      ghost_cfg["AUDIT_DIR"]]
```
Append conditionally (only if present in tool_call parameters):
- `["--dst-ip", dst_ip]`
- `["--nic-name", nic_name]`
- `["--subscription-id", subscription_id]`

**On exit code 0:**
Read `verdict_path`, parse JSON, return verdict dict to Brain.

**On exit code 2 (or any non-zero):**
Check if `verdict_path` exists (guarded read). If file absent:
```python
{
    "tool_error": True,
    "session_id": session_id,
    "error": "effective_route_inspector exited with code 2 — no verdict written. Check stderr output above."
}
```
If file exists despite non-zero exit (should not occur by design): read and return it
with an added `"tool_warning": "non-zero exit but verdict file present"` field.

**Stdout and stderr:** passed through to the terminal for human visibility. The handler
does not parse stdout. Ghost Agent Brain receives only the verdict dict or the error dict.

---

## 7. Error Handling Table

| Condition | Detected at | Exception / exit | Stderr message | Verdict written |
|-----------|-------------|-----------------|----------------|-----------------|
| Missing required flag | Stage 1 (argparse) | `SystemExit(2)` | argparse usage | No |
| Invalid `--dst-ip` | Stage 1 | `SystemExit(2)` | `"Invalid destination IP: {value}"` | No |
| `audit_dir` not creatable | Stage 1 | `SystemExit(2)` | `"Cannot create audit directory: {path}: {reason}"` | No |
| VM not found | Stage 2 (`get_nic_name`) | `VMNotFoundError` → exit 2 | `"VM '{name}' not found in '{rg}', or has no NIC marked primary"` | No |
| NIC name unextractable | Stage 2 (`get_nic_name`) | `NICResolutionError` → exit 2 | `"Could not extract NIC name from resource ID: {raw}"` | No |
| RBAC insufficient | Stage 2 (either provider call) | `RBACError` → exit 2 | `"Authorization failed. Ensure caller has effectiveRouteTable/action and VMs/read."` | No |
| Throttle exhausted | Stage 2 (either provider call) | `ThrottleExhausted` → exit 2 | `"Azure throttled after 4 attempts. Last wait: {t}s"` | No |
| az CLI not installed | Stage 2 (`LocalShell.run`) | `ProviderError` → exit 2 | `"az CLI not found. Install the Azure CLI."` | No |
| az CLI timed out | Stage 2 (`LocalShell.run`) | `ProviderError` → exit 2 | `"az CLI timed out after 60s"` | No |
| az CLI generic failure | Stage 2 | `ProviderError` → exit 2 | `"az CLI error: {stderr}"` | No |
| Raw file write failure | Stage 2 (after query) | `IOError` → exit 2 | `"Could not write raw artifact: {path}: {reason}"` | No |
| Raw file not found | Stage 3 (preprocessor) | error dict → exit 2 | `"File not found: {path}"` | No |
| Raw file invalid JSON | Stage 3 (preprocessor) | error dict → exit 2 | `"File is not valid JSON: {reason}"` | No |
| No parseable routes | Stage 3 (preprocessor) | error dict → exit 2 | `"No routes could be parsed from {path}"` | No |
| Verdict file write failure | Stage 4 | `IOError` → exit 2 | `"Could not write verdict: {path}: {reason}"` | No |

No exit-1 conditions exist for this tool. All non-success paths exit 2.

---

## 8. Edge Cases

| Case | Behaviour |
|------|-----------|
| VM has zero NICs | `get_nic_name` receives empty stdout from JMESPath → `VMNotFoundError` |
| Single-NIC VM where `primary` flag is absent | JMESPath `[?primary]` returns empty → stdout empty → `VMNotFoundError`. ⚠️ See Unknown U3 — may require `--nic-name` workaround |
| `--nic-name` supplied | `get_nic_name` call is skipped entirely; `vm_name` is still written to the verdict for audit trail |
| Empty route table (no routes) | Preprocessor returns `route_count: 0` with a warning; `select_route` receives empty list → NO_ROUTE; `audit_routes` → all findings empty, `default_route_present: false` |
| All routes Invalid | CIDR filter (Step 1) returns empty candidates → NO_ROUTE verdict; audit mode lists all as `invalid_routes` |
| All routes Unknown state | Same as all Invalid — excluded from LPM filter, NO_ROUTE verdict |
| `dst_ip` is IPv6 | `ipaddress.ip_address()` parses it correctly; effective route table contains IPv6 prefixes; `ipaddress.ip_network()` handles them. ⚠️ See Unknown U4 — mixed IPv4/IPv6 tables: verify LPM engine handles correctly |
| Session ID collision (same second) | Raw and verdict files for the second invocation overwrite the first. Rare in production; possible in automated tests. Workaround: caller passes explicit `--session-id` with a unique suffix |
| `audit_dir` already exists | `os.makedirs(exist_ok=True)` — silently succeeds |
| Multiple ECMP next-hop addresses | Preprocessor records first address, emits parse warning. NVA warning triggers if `next_hop_type == "VirtualAppliance"` regardless of ECMP count |
| Two User routes with identical prefix | Source precedence (Step 3) selects both at Tier 1; Step 4 would apply the BGP tie-break logic but both are User tier. This produces `TIED_BGP` with non-VirtualNetworkGateway routes in `tied_routes` plus a parse_warning. Practically impossible in Azure (UDR tables reject duplicate prefixes), but the engine handles it without crashing |

---

## 9. Unknowns and Assumptions to Verify Before Implementation

These are design assumptions that have not been empirically verified. Each must be
confirmed during initial development or test setup before the relevant code path is
considered correct.

| # | Unknown | Risk if wrong | How to verify |
|---|---------|--------------|---------------|
| U1 | Throttle error string patterns in `az network nic show-effective-route-table` stderr — assumed patterns are `"Throttling"`, `"Too Many Requests"`, `"429"`, `"Rate limit"` | Throttle errors silently pass through as `ProviderError` instead of triggering retry | Deliberately saturate Azure API in a test environment and capture raw stderr |
| U2 | `az network nic show-effective-route-table -o json` returns routes under `"value"` key (not `"effectiveRoutes"`) | Preprocessor handles both, so functional risk is low — but document which key is actually observed | Run against a real NIC and inspect the raw JSON envelope |
| U3 | The `primary` boolean field is present on single-NIC VMs | JMESPath `[?primary]` returns empty on a single-NIC VM without the flag → `VMNotFoundError` | Run `az vm show` against a single-NIC VM and inspect `networkProfile.networkInterfaces` |
| U4 | `ipaddress` LPM engine handles an effective route table containing both IPv4 and IPv6 prefixes correctly when `dst_ip` is IPv4 | IPv6 prefix parse failures surface as parse warnings; no incorrect match | Test `select_route` with a mixed IPv4/IPv6 route list and an IPv4 dst_ip |

---

## 10. Intentional Omissions

Features explicitly out of scope for this design. Do not add without revising the
architecture document first.

| Capability | Reason |
|------------|--------|
| Drift / baseline comparison | `detect_effective_network_drift`'s responsibility — different question, different tool |
| Fleet or VNet scope | Single-VM scope is the design contract; adding NIC discovery and concurrency belongs to the ENI module |
| AI narrative output (`--explain`) | Deterministic tool; Ghost Agent Brain is the reasoning layer |
| NSG rule evaluation | L4 concern, separate query and schema; `security_rule_inspector`'s responsibility (planned) |
| SHA-256 artifact integrity | Artifacts are consumed immediately; no long-lived baseline requiring tamper detection |
| BGP AS Path tiebreaking | AS Path absent from effective route table JSON; `TIED_BGP` is the complete and correct response |
| Retry on non-throttle errors | Non-throttle errors are not recoverable by waiting |
| Stdout as Ghost Agent's data channel | Stdout is for human output; verdict file is the machine contract |
