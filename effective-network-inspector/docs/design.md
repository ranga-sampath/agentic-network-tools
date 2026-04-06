# Design — Effective Network Inspector

> Document order: **Requirements → Architecture → Design (this document) → Code**
> Architecture source: `effective-network-inspector/docs/architecture.md`

---

## 1. Component and Function Inventory

### 1.1 `effective_network_inspector.py`

| Function | Signature | Single Responsibility |
|---|---|---|
| `main` | `() → None` | Parse args, load config file if `--config` provided, instantiate provider, route to snapshot or diff pipeline, set exit code |
| `parse_args` | `() → argparse.Namespace` | Declare and parse all CLI flags including `--config` |
| `validate_args` | `(args: argparse.Namespace) → None` | Assert required flag combinations; exit 2 with message on violation |
| `_load_config_file` | `(path: Path) → dict` | Parse a `KEY=VALUE` config file; return dict of recognised keys mapped to Python values; warn to stderr and ignore unrecognised keys. Raises: `FileNotFoundError` if path absent → `sys.exit(1)` |
| `generate_session_id` | `() → str` | Return `eni_YYYYMMDD_HHMMSS_{4-char hex}` from UTC now; the hex suffix is 4 random hex characters to prevent same-second collisions in CI |
| `run_snapshot_pipeline` | `(args: argparse.Namespace, provider: AzureNetworkProvider) → SnapshotResult` | Orchestrate stages 2–4; return path to written snapshot and NIC error count |
| `run_diff_pipeline` | `(args: argparse.Namespace, new_snapshot: dict) → None` | Load baseline, verify integrity, call `diff_snapshots`, write diff artifact, print summary |
| `save_snapshot` | `(snapshot: dict, audit_dir: Path) → Path` | Serialise snapshot to `{session_id}_snapshot.json`; write SHA-256 sidecar; return artifact path |
| `load_snapshot` | `(session_id: str, audit_dir: Path) → dict` | Locate and verify `{session_id}_snapshot.json`; return parsed dict. Raises: `FileNotFoundError` if snapshot absent; `IntegrityError` if SHA-256 fails; `json.JSONDecodeError` if not valid JSON |
| `write_sha256` | `(target: Path) → None` | Compute SHA-256 of `target`; write `{target}.sha256` in GNU format |
| `verify_sha256` | `(target: Path) → None` | Read `{target}.sha256`; recompute digest; raise `IntegrityError` on mismatch or missing sidecar |
| `print_progress` | `(lock: threading.Lock, current: int, total: int, nic_name: str) → None` | Under lock, print `Snapshotting NIC {current}/{total}: {nic_name}...` to stdout |
| `print_diff_summary` | `(diff: dict) → None` | Print human-readable summary table of changes to stdout after diff artifact is written |

**`SnapshotResult` (internal named tuple):**

| Field | Type | Meaning |
|---|---|---|
| `snapshot` | `dict` | Fully assembled snapshot dict |
| `artifact_path` | `Path` | Path of written `_snapshot.json` |
| `nic_error_count` | `int` | Count of NICs where `"error"` is non-null |

---

### 1.2 `providers.py`

#### Exception Hierarchy

```
ProviderError(Exception)               # Base: any failure from the provider layer
  ├── RBACError(ProviderError)         # AuthorizationFailed in az CLI output
  └── ThrottleExhausted(ProviderError) # 429 persisted after max retries

IntegrityError(Exception)              # SHA-256 verification failure; owned by
                                       # effective_network_inspector.py
  fields: path: Path, expected: str | None, actual: str | None
  # expected is None when the sidecar file is missing entirely
```

`RBACError.message` includes the missing permission name extracted from the az CLI error text.

#### `LocalShell`

| Method | Signature | Single Responsibility |
|---|---|---|
| `run` | `(cmd: list[str], timeout: int = 60) → str` | Execute `cmd` as an argument vector via `subprocess.run`; return stdout on exit code 0; raise `ProviderError(stderr)` on non-zero exit |

**Contract:**
- `cmd` is always an argument vector — never passed through `shell=True`. Shell interpolation is prohibited.
- Returns stdout as a raw string. Callers parse JSON.
- On non-zero exit: captures stderr, raises `ProviderError` with the full stderr text as the message. This allows callers to inspect for `AuthorizationFailed` or other az-specific error strings.
- On timeout: raises `ProviderError("timeout after {timeout}s")`.

#### `AzureNetworkProvider`

| Method | Signature | Single Responsibility |
|---|---|---|
| `__init__` | `(resource_group: str, shell: LocalShell, subscription_id: str \| None = None)` | Store config; build base az flag list |
| `discover_nics_for_vm` | `(vm_name: str) → list[str]` | Return NIC names attached to the VM via `az vm nic list` |
| `discover_nics_for_vnet` | `(vnet_id: str) → list[str]` | Return all NIC names across all subnets of the VNet; includes NICs on subnets with no route table |
| `get_effective_routes` | `(nic_name: str) → list[dict]` | Return flat list of route objects unwrapped from az CLI `"value"` array |
| `get_effective_nsg_rules` | `(nic_name: str) → list[dict]` | Return flat list of effective security rule objects unwrapped from `networkSecurityGroups[].effectiveSecurityRules` |
| `_run_az` | `(cmd: list[str]) → Any` | Run az command with retry/backoff on 429; parse stdout JSON; detect RBAC errors; return raw parsed JSON (list or dict — callers extract the fields they need) |
| `_build_base_flags` | `() → list[str]` | Return `["--resource-group", rg, "--output", "json"]` plus optional `["--subscription", sub_id]`; used only for `az network` subcommands — not for `az vm nic list` which takes different flags |

**`_run_az` retry policy (implements D10):**
- On exit code 0: parse stdout JSON and return.
- On `"AuthorizationFailed"` in stderr: immediately raise `RBACError` (do not retry).
- On stderr containing `"Too Many Requests"` or `"TooManyRequests"` (exact strings — az CLI formats the HTTP 429 status as one of these across versions): wait with exponential backoff (`initial_delay=2s`, multiplier `2`, jitter `±0.5s`), retry up to `max_retries=5`. After exhausting retries, raise `ThrottleExhausted`.
- On any other non-zero exit: raise `ProviderError(stderr)` immediately.

**VNet NIC discovery — `discover_nics_for_vnet` traverse order:**
1. Parse `vnet_id` (ARM resource ID) to extract `vnet_rg` (resource group of the VNet) and `vnet_name`.
2. `az network vnet subnet list --vnet-name {vnet_name} --resource-group {vnet_rg} --output json` → list of subnet objects.
3. For each subnet: extract `ipConfigurations[].id` fields (NIC IP config resource IDs). Each ID has the form `/subscriptions/{sub}/resourceGroups/{nic_rg}/providers/Microsoft.Network/networkInterfaces/{nic_name}/ipConfigurations/{ipcfg_name}`.
4. Parse each IP config ID to extract both `nic_name` and `nic_rg` from the path segments. Return a list of `(nic_name, nic_rg)` tuples, deduplicated.
5. NICs on subnets with no `ipConfigurations` entry contribute nothing (no NIC attached); subnets with no route table are included — route table presence is not a filter condition.

**Cross-resource-group NICs:** In hub-spoke topologies, the VNet lives in one resource group and the NICs live in spoke resource groups. `get_effective_routes` and `get_effective_nsg_rules` must use the NIC's own resource group (`nic_rg`) — not the global `--resource-group` CLI flag, which is the VNet's resource group. The `get_effective_routes` and `get_effective_nsg_rules` signatures accept `nic_rg` as a separate parameter when called from the VNet scope path.

**Consequence for `get_effective_routes` and `get_effective_nsg_rules` signatures:**
These methods accept an optional `resource_group: str | None = None` override. When `None`, the provider's default `self.resource_group` is used (VM scope). When provided, it overrides for that call (VNet scope cross-RG case).

Note: `--vnet-id` (full ARM resource ID) is required for VNet scope rather than `--vnet-name` to make the resource group of the VNet unambiguous at the CLI level.

---

### 1.3 `diff.py`

| Function | Signature | Single Responsibility |
|---|---|---|
| `diff_snapshots` | `(baseline: dict, compare: dict) → dict` | Top-level entry; produce a complete diff artifact dict |
| `_diff_nic` | `(baseline_nic: dict, compare_nic: dict) → list[dict]` | Return list of change objects for one NIC pair |
| `_diff_routes` | `(baseline: list[dict], compare: list[dict]) → list[dict]` | Return route change objects (added/removed only); a changed next-hop produces removed + added |
| `_diff_nsg_rules` | `(baseline: list[dict], compare: list[dict]) → list[dict]` | Return NSG rule change objects (added/removed only); a priority shift produces removed + added |
| `_canonicalise_route` | `(route: dict) → dict` | Return a stable comparison dict: retain `addressPrefix` (sorted), `nextHopType`, `nextHopIpAddress` (sorted), `source`, `state`; drop all other fields |
| `_canonicalise_nsg_rule` | `(rule: dict) → dict` | Return a stable comparison dict: use `expandedSourceAddressPrefix` if non-empty else `sourceAddressPrefixes` (sorted); same for destination; retain `name`, `protocol`, `sourcePortRanges` (sorted), `destinationPortRanges` (sorted), `access`, `priority`, `direction` |
| `_route_key` | `(route: dict) → tuple` | Return `(tuple(sorted(addressPrefix)), source)` — the identity key for route matching |
| `_nsg_key` | `(rule: dict) → tuple` | Return `(name, direction)` — the identity key for NSG rule matching |
| `_categorise_route` | `(route: dict) → str` | Map `source` field to diff category string |

All functions in `diff.py` are pure: no I/O, no side effects, deterministic output for identical inputs.

---

## 2. Data Schemas

### 2.1 Snapshot Artifact — `{session_id}_snapshot.json`

**Owner:** `effective_network_inspector.py` (sole writer)

```
{
  "session_id":      str               -- e.g. "eni_20260325_140000"
  "scope":           "vm" | "vnet"
  "scope_target":    str               -- VM name or VNet resource ID
  "resource_group":  str
  "timestamp":       str               -- ISO 8601 UTC, e.g. "2026-03-25T14:00:00Z"
  "nics": [
    {
      "nic_name":            str
      "effective_routes":    list[RouteObject] | null   -- null iff error is set
      "effective_nsg_rules": list[NsgRuleObject] | null -- null iff error is set
      "error":               str | null                 -- null iff query succeeded
    }
  ]
}
```

**Invariant:** For any NIC entry, exactly one of `(error == null, effective_routes != null, effective_nsg_rules != null)` or `(error != null, effective_routes == null, effective_nsg_rules == null)` holds. Both fields are either both present or both null — they are never split.

---

### 2.2 `RouteObject` — fields stored per route in snapshot

**Source:** `az network nic show-effective-route-table`, unwrapped from top-level `"value"` array.

| Field | Type | Notes |
|---|---|---|
| `addressPrefix` | `list[str]` | CIDR prefixes; may contain multiple entries per route |
| `nextHopType` | `str` | e.g. `VirtualNetworkGateway`, `VnetLocal`, `Internet`, `None` |
| `nextHopIpAddress` | `list[str]` | Empty list when not applicable |
| `source` | `str` | `VirtualNetworkGateway` \| `User` \| `Default` |
| `state` | `str` | `Active` \| `Invalid` |

Fields present in az CLI output but not stored: none — all semantically relevant fields are retained. Fields not in this list that az CLI returns (e.g. `disableBgpRoutePropagation`, `name` for null-named system routes) are stored as-is and not used by the diff engine.

---

### 2.3 `NsgRuleObject` — fields stored per effective security rule in snapshot

**Source:** `az network nic list-effective-nsg`, unwrapped from `networkSecurityGroups[].effectiveSecurityRules`.

| Field | Type | Notes |
|---|---|---|
| `name` | `str` | Qualified rule name including NSG prefix |
| `protocol` | `str` | `Tcp` \| `Udp` \| `Icmp` \| `All` |
| `sourceAddressPrefixes` | `list[str]` | May contain service tags (e.g. `VirtualNetwork`) |
| `destinationAddressPrefixes` | `list[str]` | May contain service tags |
| `sourcePortRanges` | `list[str]` | Port or range strings, e.g. `"22"`, `"1024-65535"` |
| `destinationPortRanges` | `list[str]` | Port or range strings |
| `expandedSourceAddressPrefix` | `list[str]` | Resolved CIDR ranges from service tag expansion; may be empty |
| `expandedDestinationAddressPrefix` | `list[str]` | Resolved CIDR ranges; may be empty |
| `access` | `str` | `Allow` \| `Deny` |
| `priority` | `int` | |
| `direction` | `str` | `Inbound` \| `Outbound` |

**Canonicalisation rule for diff:** If `expandedSourceAddressPrefix` is non-empty, use it as the comparison value instead of `sourceAddressPrefixes`. Same for destination. This ensures that a service tag whose resolved CIDRs changed is detected as drift, even when the tag name itself is unchanged. Sort all list fields before comparison.

---

### 2.4 SHA-256 Sidecar — `{session_id}_snapshot.json.sha256`

**Owner:** `effective_network_inspector.py` (sole writer)

Format: `{hex_digest}  {basename}\n` — two spaces, GNU `sha256sum` compatible.

Example: `a3f2...  eni_20260325_140000_snapshot.json`

The basename (not full path) is used so the file is verifiable with `sha256sum -c` regardless of where `audit_dir` is mounted.

---

### 2.5 Diff Artifact — `{baseline_session_id}_vs_{compare_session_id}_diff.json`

**Owner:** `effective_network_inspector.py` (sole writer)

```
{
  "baseline_session_id": str
  "compare_session_id":  str
  "drift_detected":      bool          -- always present; never omitted
  "changes_count":       int           -- total across all NICs and categories
  "changes_by_category": {             -- only categories with count > 0 are present
    "bgp_route_change":    int,        -- optional
    "udr_route_change":    int,        -- optional
    "system_route_change": int,        -- optional
    "security_rule_change": int        -- optional
  },
  "skipped_nics": [str],               -- NIC names skipped because either snapshot has error
  "nic_diffs": [
    {
      "nic_name": str,
      "changes": [ChangeObject]        -- empty list if no changes for this NIC
    }
  ]                                    -- only NICs with changes appear here
}
```

**`ChangeObject`:**

```
{
  "change_type": "added" | "removed",
  "category":    "bgp_route_change" | "udr_route_change" |
                 "system_route_change" | "security_rule_change",
  "route":       RouteObject | null,    -- populated for route changes; null for NSG changes
  "rule":        NsgRuleObject | null   -- populated for security_rule_change; null for route changes
}
```

A UDR route whose next-hop changes between snapshots produces two change objects: one `removed` (the old route) and one `added` (the new route). There is no `modified` type — all changes are expressed as removed + added pairs. This matches the PRD diff artifact schema and keeps the `ChangeObject` flat and consistent for all consumers.

---

### 2.6 Diff Category Mapping

| `source` field value | Category |
|---|---|
| `VirtualNetworkGateway` | `bgp_route_change` |
| `User` | `udr_route_change` |
| `Default` | `system_route_change` |
| *(any NSG rule change)* | `security_rule_change` |

Source values are matched exactly (case-sensitive). Any `source` value not in the table is treated as `system_route_change` (defensive fallback — does not silently discard).

---

## 3. Pipeline Stage Detail

### Stage 1 — Validate

**Input:** `sys.argv`

**Processing:**
1. `parse_args()` — declare all flags; return `argparse.Namespace`. Flags include `--config PATH` (optional; when provided, values from the file are used as defaults, overridden by any explicit CLI flags).
2. If `--config` provided: call `_load_config_file(path)` and merge returned dict into `args` (CLI flags take precedence over config file values).
3. `validate_args(args)` — enforce:
   - `--scope vm` requires `--vm-name`
   - `--scope vnet` requires `--vnet-id`
   - `--is-baseline` and `--compare-baseline` are mutually exclusive
   - `--compare-baseline` and `--is-baseline` cannot both be absent (one mode must be set)
   - `--session-id`, if provided, must match `^[a-zA-Z0-9_-]{1,64}$`
   - `--audit-dir` must exist and be writable (check at validation time, not at write time)

**Config file key map** (used by `_load_config_file` and Ghost Agent handler):

| Config key | `args` attribute | Type | Notes |
|---|---|---|---|
| `RESOURCE_GROUP` | `resource_group` | `str` | |
| `SUBSCRIPTION_ID` | `subscription_id` | `str \| None` | |
| `SCOPE` | `scope` | `str` | `vm` or `vnet` |
| `VM_NAME` | `vm_name` | `str \| None` | Used when `scope=vm` |
| `VNET_ID` | `vnet_id` | `str \| None` | Used when `scope=vnet` |
| `AUDIT_DIR` | `audit_dir` | `Path` | |
| `SESSION_ID` | `session_id` | `str \| None` | Overrides auto-generated ID |
| `IS_BASELINE` | `is_baseline` | `bool` | `true`/`1`/`yes` → `True`; `false`/`0`/`no` → `False` |
| `COMPARE_BASELINE` | `compare_baseline` | `str \| None` | Session ID of baseline to compare |

Inline comments (`# ...`) are stripped. Quoted values have quotes removed. Unrecognised keys print a warning to stderr and are ignored — tool does not abort.

**Output:** Validated `args` namespace. If `--session-id` not provided, set `args.session_id = generate_session_id()` (format: `eni_YYYYMMDD_HHMMSS_{4-char hex}`).

**Failure:** Any validation failure → print specific error message to stderr, `sys.exit(2)`.

---

### Stage 2 — Discover NICs

**Input:** `args.scope`, `args.vm_name` or `args.vnet_id`, `args.resource_group`, `provider`

**Processing:**
- `scope == "vm"`: call `provider.discover_nics_for_vm(args.vm_name)`
- `scope == "vnet"`: call `provider.discover_nics_for_vnet(args.vnet_id)`

**Output:** `list[str]` of NIC names. May be empty (valid for a newly-created VNet with no VMs yet).

**Failure modes:**

| Condition | Behavior | Exit |
|---|---|---|
| `RBACError` raised | Print RBAC error to stderr (see §4 for format) | `sys.exit(2)` |
| `ProviderError` raised | Print error to stderr | `sys.exit(2)` |
| Empty list returned | Print warning "No NICs found for {scope_target} — snapshot will have empty NIC list" to stderr; continue to Stage 3 with empty list | No exit; snapshot written with `"nics": []` |

---

### Stage 3 — Query State (concurrent)

**Input:** `list[str]` NIC names, `provider`, `max_workers` (default 4)

**Processing:**
1. Create a `threading.Lock` for progress counter. Initialize `counter = [0]` (mutable container). Total = `len(nic_names)`.
2. Use `executor.submit()` to submit one task per NIC in input order; store `Future` objects in a list preserving submission order.
3. Each task function:
   a. Acquire `lock`; increment `counter[0]`; print `Snapshotting NIC {counter[0]}/{total}: {nic_name}...` to stdout; release `lock`. The counter increment and print are a single atomic operation under the lock — no other thread can interleave between them.
   b. Call `provider.get_effective_routes(nic_name, resource_group=nic_rg)`.
   c. Call `provider.get_effective_nsg_rules(nic_name, resource_group=nic_rg)`.
   d. Return `{"nic_name": nic_name, "effective_routes": routes, "effective_nsg_rules": rules, "error": null}`.
   e. On any exception: return `{"nic_name": nic_name, "effective_routes": null, "effective_nsg_rules": null, "error": str(exception)}`.
4. After all futures are submitted, call `future.result()` on each in submission order to collect results. This preserves input NIC order in the snapshot artifact regardless of completion order.

**Output:** `list[dict]` — one entry per NIC. Every NIC appears in the output regardless of success or failure.

**Failure modes:** Exceptions are caught per-NIC and recorded in `"error"`. No exception from a single NIC propagates to the pool.

---

### Stage 4 — Assemble and Save Snapshot

**Input:** `list[dict]` from Stage 3, metadata from `args`

**Processing:**
1. Assemble the snapshot dict (schema §2.1):
   - `session_id`: `args.session_id`
   - `scope`, `scope_target`, `resource_group` from args
   - `timestamp`: UTC now in ISO 8601
   - `nics`: Stage 3 output
2. Serialise to `{audit_dir}/{session_id}_snapshot.json` with `json.dumps(indent=2)`.
3. Call `write_sha256(artifact_path)`.
4. Count NICs where `"error"` is non-null → `nic_error_count`.

**Output:** `SnapshotResult(snapshot=dict, artifact_path=Path, nic_error_count=int)`

**Failure modes:** File write failure (disk full, permissions) → print error to stderr, `sys.exit(2)`. This stage does not fail partially — the snapshot is atomic (written completely or not at all).

---

### Stage 5 — Diff (conditional — only when `--compare-baseline` is set)

**Input:** `SnapshotResult` from Stage 4, `args.compare_baseline` (session ID of baseline)

**Processing:**
1. Call `load_snapshot(args.compare_baseline, args.audit_dir)`:
   a. Locate `{audit_dir}/{compare_baseline}_snapshot.json`.
   b. Call `verify_sha256(path)` — raises `IntegrityError` if mismatch or sidecar missing.
   c. Parse and return dict.
2. Call `diff_snapshots(baseline=loaded, compare=new_snapshot.snapshot)` → diff dict.
3. Write diff to `{audit_dir}/{compare_baseline}_vs_{session_id}_diff.json`.
4. Call `print_diff_summary(diff)`.

**Output:** Diff artifact written to disk. Summary printed to stdout.

**Failure modes:**

| Condition | Behavior | Exit |
|---|---|---|
| Baseline file not found | Print "Baseline session '{id}' not found in {audit_dir}" to stderr | `sys.exit(2)` |
| SHA-256 sidecar missing | Print integrity error to stderr | `sys.exit(2)` |
| SHA-256 mismatch | Print integrity error with expected/actual digest to stderr | `sys.exit(2)` |
| Diff write fails | Print error to stderr | `sys.exit(2)` |

---

### Exit Code Policy (final)

After all stages complete:

| Condition | Exit code |
|---|---|
| All stages succeeded, zero NIC errors | `0` |
| Stages succeeded, one or more NIC errors recorded | `1` |
| Any stage triggered `sys.exit(2)` (fatal — no artifact produced) | `2` |

---

## 4. Error Handling Strategy

### 4.1 RBAC Error Format

When `RBACError` is raised, print to stderr:

```
ERROR: Authorization failed for NIC '{nic_name}'.
  Missing permission: {permission}
  Required for: {operation}
  Grant 'Network Contributor' or a custom role with this action on the resource group.
```

Permissions to detect and name:

| az CLI error substring | Permission | Operation |
|---|---|---|
| `effectiveNetworkSecurityGroups/action` | `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | `az network nic list-effective-nsg` |
| `effectiveRouteTable/action` | `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` | `az network nic show-effective-route-table` |
| *(fallback)* | *(full stderr)* | *(unknown operation)* |

For RBAC errors during NIC discovery (Stage 2): fatal, `sys.exit(2)`.
For RBAC errors during NIC query (Stage 3): recorded per-NIC in `"error"`, processing continues.

---

### 4.2 Full Error Table

| Error | Behavior | What caller receives |
|---|---|---|
| Invalid CLI args (missing required flag, mutual exclusion) | Print specific message to stderr | `sys.exit(2)` |
| `--session-id` format invalid | Print pattern requirement to stderr | `sys.exit(2)` |
| `--audit-dir` not writable | Print path and permission error to stderr | `sys.exit(2)` |
| NIC discovery returns empty list | Print warning to stderr; continue with `"nics": []` | exit `0` (no NIC errors) |
| `RBACError` during NIC discovery | Print RBAC error (§4.1) to stderr | `sys.exit(2)` |
| `ProviderError` during NIC discovery | Print error to stderr | `sys.exit(2)` |
| `RBACError` during NIC query | Recorded in `"error"` for that NIC | Processing continues; exit `1` at end |
| `ThrottleExhausted` during NIC query | Recorded in `"error"` for that NIC | Processing continues; exit `1` at end |
| `ProviderError` during NIC query | Recorded in `"error"` for that NIC | Processing continues; exit `1` at end |
| Non-JSON az CLI response | `ProviderError` raised with raw stdout | Recorded in `"error"` for that NIC |
| az CLI timeout | `ProviderError` raised with timeout message | Recorded in `"error"` for that NIC |
| Snapshot file write failure | Print path and OS error to stderr | `sys.exit(2)` |
| Baseline session ID not found | Print session ID and audit_dir to stderr | `sys.exit(2)` |
| SHA-256 sidecar missing | Print "Integrity file missing for {path}" to stderr | `sys.exit(2)` |
| SHA-256 mismatch | Print expected vs actual digest to stderr | `sys.exit(2)` |
| Diff artifact write failure | Print path and OS error to stderr | `sys.exit(2)` |

---

## 5. Edge Cases

### 5.1 Zero NICs discovered

`discover_nics_for_vm` or `discover_nics_for_vnet` returns an empty list. Stage 2 prints a warning to stderr and continues. The snapshot is written with `"nics": []`. A diff of two empty-NIC snapshots produces `drift_detected: false`, `changes_count: 0`. This is valid for a newly-created VNet with no VMs yet.

### 5.2 All NICs errored

Every NIC in Stage 3 returns with `"error"` set. The snapshot is written with all NICs having null data. Exit code is `1` (not `2`) — the snapshot artifact is valid and captures the error state. If `--compare-baseline` is set, all NICs are skipped in the diff; `skipped_nics` lists all of them; `drift_detected: false`, `changes_count: 0`.

### 5.3 NIC present in baseline but absent from compare snapshot

This happens when a NIC is detached between snapshots. `diff_snapshots` matches NICs by `nic_name`. A NIC in baseline with no counterpart in compare has all its routes reported as `removed` and all its NSG rules reported as `removed`. This is meaningful drift: routes that were effective are no longer present. The NIC appears in `nic_diffs`, not `skipped_nics`.

### 5.4 NIC present in compare snapshot but absent from baseline

New NIC attached between snapshots. All its routes are reported as `added` and all its NSG rules as `added`. The NIC appears in `nic_diffs`, not `skipped_nics`. An engineer baselining before a change window wants to see what effective state a new NIC brought in.

### 5.5 NIC healthy in baseline, errored in compare

Added to `skipped_nics`. Not reported as drift (per PRD acceptance criterion 6). The error is noted in the diff artifact's `skipped_nics` list.

### 5.6 Route with empty `addressPrefix` list

`_route_key` returns `((), source)`. Such a route is canonicalised and compared normally. An empty prefix list is a valid (if unusual) az CLI response for some system routes.

### 5.7 NSG rule with empty `expandedSourceAddressPrefix`

Canonicalisation falls back to `sourceAddressPrefixes` for comparison. Both baseline and compare go through the same canonicalisation, so the fallback is consistent.

### 5.8 `--is-baseline` and `--compare-baseline` both provided

Caught in Stage 1 validation. These flags are mutually exclusive. Exit 2 with message: `"--is-baseline and --compare-baseline cannot be used together"`.

### 5.9 Neither `--is-baseline` nor `--compare-baseline` provided

Caught in Stage 1 validation. The tool has no mode. Exit 2 with message: `"One of --is-baseline or --compare-baseline is required"`.

### 5.10 `--compare-baseline` references the current session ID

Session IDs are assigned before Stage 2 runs. If `args.compare_baseline == args.session_id`, the baseline and compare snapshots would be the same file. Caught in Stage 1 validation. Exit 2 with message: `"--compare-baseline session ID cannot match the current session ID"`.

### 5.11 Concurrent runs to the same `--audit-dir`

Artifact filenames are scoped by `session_id` (e.g. `eni_20260325_140000_a3f2_snapshot.json`). Auto-generated session IDs include a 4-character random hex suffix, so two simultaneous runs starting in the same second still produce distinct filenames. Two runs with the same explicit `--session-id` will overwrite each other's snapshot — this is a caller error, not handled defensively. The SHA-256 sidecar write follows the JSON write atomically enough for single-machine usage.

### 5.12 SHA-256 sidecar missing (snapshot written, sidecar not)

Partial write scenario (e.g. process killed between the two writes). `verify_sha256` raises `IntegrityError` with the message `"SHA-256 sidecar missing: {path}.sha256"`. The snapshot is treated as invalid. Exit 2.

### 5.13 VNet with subnets having no attached NICs

`discover_nics_for_vnet` iterates subnets and extracts NIC names from `ipConfigurations`. A subnet with no `ipConfigurations` contributes zero NIC names — it is silently skipped. If all subnets have no NICs, the result is an empty list → Stage 2 prints a warning and continues (§5.1 above).

### 5.14 Stopped VM (NIC query fails)

A stopped (deallocated) Azure VM causes `az network nic show-effective-route-table` to return an error because the NIC has no effective state while deallocated. This surfaces as `ProviderError` in Stage 3, recorded per-NIC in `"error"`. Processing continues for other NICs. Exit `1`.

### 5.15 Route `source` value not in known set

`_categorise_route` receives an unknown `source` string. Maps to `system_route_change` as a defensive fallback. The change is reported; the unknown source value is preserved verbatim in the change object so it is visible in the artifact.

---

## 6. `print_diff_summary` Output Format

Printed to stdout after the diff artifact is written. This is the human-readable dual output (D11).

```
Diff: eni_20260325_130000  →  eni_20260325_140000
────────────────────────────────────────────────
drift_detected: true   changes: 3   skipped_nics: 0

NIC: tf-dest-vm-nic
  REMOVED  bgp_route_change   10.2.0.0/24  (VirtualNetworkGateway)
  ADDED    security_rule_change  DenyAll-Inbound  priority=100  Deny

NIC: tf-src-vm-nic
  REMOVED  udr_route_change   0.0.0.0/0  next-hop: 10.1.0.4

Artifact: ./audit/eni_20260325_130000_vs_eni_20260325_140000_diff.json
────────────────────────────────────────────────
```

When `drift_detected: false`:
```
Diff: eni_20260325_130000  →  eni_20260325_140000
────────────────────────────────────────────────
drift_detected: false   changes: 0

No effective network state changes detected.

Artifact: ./audit/eni_20260325_130000_vs_eni_20260325_140000_diff.json
────────────────────────────────────────────────
```

When NICs were skipped:
```
Skipped NICs (errored in one or both snapshots): tf-other-vm-nic, tf-mgmt-nic
```

---

## 7. Intentional Omissions

| Capability | Excluded because |
|---|---|
| Retry logic in `LocalShell` | `LocalShell` is a thin execution layer. Retry is an Azure policy concern owned by `AzureNetworkProvider._run_az`. Embedding retry in `LocalShell` would make it a policy component, breaking the single-responsibility contract. |
| Token-bucket rate limiter in Stage 3 | A token-bucket requires time-based release logic and a background thread. For MVP fleet sizes (up to ~50 NICs) the `max_workers` thread count alone prevents burst spikes. Proper rate limiting is added when real-world throttle patterns on larger VNets are observed. |
| Intermediate artifact between Stage 3 and Stage 4 | Stage 3 output is an in-memory list of NIC dicts. Writing an intermediate JSON between Stage 3 and Stage 4 would duplicate the snapshot artifact with negligible benefit — Stage 4's output IS the canonical artifact for this pipeline. The intermediate disk write principle applies between logically separable processing stages; Stage 3 → Stage 4 is assembly, not a separate analytical stage. |
| Atomic file write (write-then-rename) | The snapshot is written to its final path directly. A partial write leaves a corrupt file that SHA-256 verification will reject on next load. Atomic rename (write to temp, rename) adds complexity; SHA-256 detection provides sufficient safety for a local forensics tool. |
| Diff of diff artifacts | No tool support for comparing two diff artifacts (e.g. "did drift get worse?"). This requires a higher-order analysis layer. Out of scope for the tool; Ghost Agent Brain can reason about a sequence of diffs. |
| `--explain` flag and AI prompt design | Post-MVP. Prompt specification is deferred to its own design document when the feature is scoped. |
