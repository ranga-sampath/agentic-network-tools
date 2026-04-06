# Test Plan — Effective Network Inspector

> Design references: `docs/product-requirements.md`, `docs/architecture.md`
> Implementation under test: `providers.py`, `diff.py`, `effective_network_inspector.py`
> Ghost Agent integration: `network-ghost-agent/ghost_agent.py` (`_run_effective_network_inspector_handler`)

---

## 1. Scope

### In scope

| Component | What is tested |
|---|---|
| `diff.py` | Normalisation, categorisation, added/removed/changed route and NSG rule detection, `drift_detected` field, `skipped_nics`, category counts |
| `providers.py` | Command vector construction (no `shell=True`), RBAC error detection, JSON parsing, per-method failure isolation, 429 retry backoff |
| `effective_network_inspector.py` | Config loading, `--config` file, session ID validation, pipeline orchestration, snapshot write + load + SHA-256 integrity, self-compare guard, exit codes, per-NIC error isolation, artifact naming |
| Ghost Agent handler | Config-file construction from `ghost_cfg`, deterministic artifact path construction, `compare_session_id` routing, result dict schema |
| Artifact lifecycle | Create, load, tamper detection, partial snapshot validity |
| Pipeline stage isolation | Each stage re-runnable from intermediate artifact without re-querying Azure |

### Explicitly out of scope

| Item | Reason |
|---|---|
| Azure live queries (most tests) | Replaced by mocked `LocalShell` or fixture JSON; unit tests must not require Azure credentials |
| `--explain` flag | Post-MVP; no implementation exists |
| Multi-subscription scope | Not in MVP |
| VNet BGP peer state | Not an effective-state API; out of MVP scope |
| `SafeExecShell` HITL classification | Covered by `agentic-safety-shell` test suite |

### Known architecture deviations (tests that will fail until implementation is updated)

These are gaps between `architecture.md` and the current code. They are marked **[ARCH-GAP]** throughout this document.

| Gap ID | Architecture says | Current code | Impact |
|---|---|---|---|
| AG-1 | Diff artifact: `{baseline}_vs_{compare}_diff.json` | `{session_id}_diff.json` | Ghost Agent handler glob pattern, audit clarity |
| AG-2 | `skipped_nics` field in diff artifact | Field absent | Brain cannot identify which NICs were excluded from the diff |
| AG-3 | SHA-256 file format: `{digest}  {filename}` (GNU sha256sum) | Just `{digest}\n` | External verification with `sha256sum -c` fails |
| AG-4 | Typed exceptions: `RBACError`, `ThrottleExhausted`, `ProviderError` | All use `RuntimeError` | Orchestrator cannot distinguish RBAC vs. throttle vs. parse error |
| AG-5 | Retry on HTTP 429 with exponential backoff | No retry implemented | Large VNet snapshots will fail at scale |
| AG-6 | `ThreadPoolExecutor` for concurrent NIC queries | Sequential loop | Slow for multi-NIC VMs; no rate-limiting semaphore |

---

## 2. Test Environment Requirements

### Unit and integration tests (no Azure)

- Python 3.12, `pytest`, `pytest-mock`
- No Azure credentials required
- Fixture directory: `tests/fixtures/` — static JSON files representing az CLI output
- Temp directory per test via `pytest`'s `tmp_path` fixture
- No network access

### E2E tests (Azure-connected)

- `az` CLI authenticated (`az login` or service principal)
- Role: Network Contributor on `nw-forensics-rg`
- VM: `tf-dest-vm` running and reachable via az CLI
- NSG: `tf-dest-vm-nsg` — test rule `test-deny-review-YYYYMMDD` created and deleted within the test
- Cleanup is mandatory: E2E tests must remove all injected NSG rules on teardown, including on failure (`pytest` fixture with `yield`)
- BGP E2E: only run when a VPN gateway is present (`pytest.mark.vpn_gateway`)

---

## 3. Fixture Inventory

All fixture files live in `tests/fixtures/`. They are static JSON strings representing az CLI `--output json` responses.

| File | Represents |
|---|---|
| `routes_value_envelope.json` | `az network nic show-effective-route-table` — `{"value": [...]}` envelope |
| `routes_list.json` | Same command — bare list `[...]` response (older API versions) |
| `routes_bgp.json` | Routes including `VirtualNetworkGateway`-sourced entries |
| `nsg_nsg_envelope.json` | `az network nic list-effective-nsg` — `{"networkSecurityGroups": [...]}` envelope |
| `nsg_value_envelope.json` | Same command — `{"value": [...]}` envelope |
| `nsg_list.json` | Same command — bare list |
| `nsg_with_deny.json` | NSG rules including a priority-100 inbound Deny |
| `vm_nic_ids.json` | `az vm nic list --query '[].id'` — resource ID list |
| `nic_list_vnet.json` | `az network nic list` — NICs with subnet IDs for VNet filtering |
| `az_rbac_error.json` | az CLI stderr containing `AuthorizationFailed` |
| `az_throttle_error.json` | az CLI stderr containing `429 Too Many Requests` |

---

## 4. Test Cases

### 4.1 `diff.py` — Normalisation and Diff Engine

These tests exercise the pure comparison engine. No I/O, no mocking.

---

**TC-DIFF-001: `get_effective_routes` — value envelope**
Input: `routes_value_envelope.json` — `{"value": [...]}`
Expected: List of normalised route dicts, sorted by `addressPrefix`. Every dict contains `addressPrefix`, `nextHopType`, `nextHopIpAddress`, `source`, `state`.

**TC-DIFF-002: `get_effective_routes` — bare list envelope**
Input: `routes_list.json` — bare `[...]`
Expected: Same normalisation as TC-DIFF-001. Azure API version differences must not cause a parse failure.

**TC-DIFF-003: `get_effective_routes` — list-valued `addressPrefix` preserved as list**
Input: Route object where `addressPrefix` is `["10.0.0.0/16"]` (list).
Expected: Stored as `["10.0.0.0/16"]` (list). Not coerced to a scalar string. `_canonicalise_route` sorts the list for comparison but does not flatten it.

**TC-DIFF-004: `get_effective_routes` — empty string input**
Input: `""`
Expected: Returns `[]`. No exception.

**TC-DIFF-005: `get_effective_routes` — malformed JSON**
Input: `"{not json"`
Expected: Returns `[]`. No exception.

**TC-DIFF-006: `get_effective_nsg_rules` — `networkSecurityGroups` envelope**
Input: `nsg_nsg_envelope.json`
Expected: Normalised rule list, sorted by `(direction, priority)`.

**TC-DIFF-007: `get_effective_nsg_rules` — `value` envelope**
Input: `nsg_value_envelope.json`
Expected: Same as TC-DIFF-006.

**TC-DIFF-008: `get_effective_nsg_rules` — bare list**
Input: `nsg_list.json`
Expected: Same as TC-DIFF-006.

**TC-DIFF-009: `_canonicalise_nsg_rule` — list fields sorted lexicographically**
Input: NSG rule where `destinationPortRanges` is `["443", "80", "22"]`.
Expected: Canonical form has `destinationPortRanges` sorted as `["22", "443", "80"]` (lexicographic string sort). Sorting eliminates false positives when Azure returns list items in different order across snapshots.

**TC-DIFF-010: `get_effective_nsg_rules` — empty**
Input: `""`
Expected: Returns `[]`. No exception.

---

**TC-DIFF-011: `diff_snapshots` — no drift (identical snapshots)**
Setup: Two snapshots built from the same NIC data.
Expected: `drift_detected: false`, `changes_count: 0`, `changes_by_category: {}`, `nic_diffs: []`.
Assert: `drift_detected` field is explicitly `False` — not absent.

**TC-DIFF-012: `diff_snapshots` — BGP route removed**
Setup: Baseline has a route `{source: "VirtualNetworkGateway", addressPrefix: "10.2.0.0/24"}`. Compare snapshot has no such route.
Expected: `drift_detected: true`, `changes_count: 1`, `changes_by_category: {"bgp_route_change": 1}`, one change entry with `change_type: "removed"`, `category: "bgp_route_change"`.

**TC-DIFF-013: `diff_snapshots` — BGP route added**
Setup: Baseline has no VirtualNetworkGateway routes. Compare has one.
Expected: `category: "bgp_route_change"`, `change_type: "added"`.

**TC-DIFF-014: `diff_snapshots` — UDR next-hop changed produces removed + added pair**
Setup: Baseline has `{source: "User", addressPrefix: ["0.0.0.0/0"], nextHopIpAddress: ["10.0.1.4"]}`. Compare has same prefix with `nextHopIpAddress: ["10.0.1.5"]`.
Expected: Two change objects in `changes`: one `{change_type: "removed", category: "udr_route_change"}` (old next-hop) and one `{change_type: "added", category: "udr_route_change"}` (new next-hop). `changes_count: 2`. No `"changed"` change type.

**TC-DIFF-015: `diff_snapshots` — system route changed**
Setup: Baseline has `{source: "Default", ...}`. Compare has same prefix with different `state`.
Expected: `category: "system_route_change"`.

**TC-DIFF-016: `diff_snapshots` — NSG rule added**
Setup: Baseline has no `deny-ssh` rule. Compare has `{name: "deny-ssh", direction: "Inbound", priority: 100, access: "Deny"}`.
Expected: `category: "security_rule_change"`, `change_type: "added"`.

**TC-DIFF-017: `diff_snapshots` — NSG rule removed**
Inverse of TC-DIFF-016.
Expected: `change_type: "removed"`, `category: "security_rule_change"`.

**TC-DIFF-018: `diff_snapshots` — NSG rule priority changed produces removed + added pair**
Setup: Baseline has rule `deny-ssh` at `direction: "Inbound"`, `priority: 200`. Compare has same rule name and direction at `priority: 100`.
Expected: Two change objects: one `{change_type: "removed", category: "security_rule_change"}` (priority 200) and one `{change_type: "added", category: "security_rule_change"}` (priority 100). `changes_count: 2`. No `"changed"` change type. The NSG rule identity key is `(name, direction)` — same name + direction, different priority = removed + added.

**TC-DIFF-019: `diff_snapshots` — mixed changes, multiple categories**
Setup: One BGP route removed, one UDR route next-hop changed (produces removed + added), one NSG rule added — on the same NIC.
Expected: `changes_count: 4` (1 bgp removed + 1 udr removed + 1 udr added + 1 nsg added), `changes_by_category: {"bgp_route_change": 1, "udr_route_change": 2, "security_rule_change": 1}`.

**TC-DIFF-020: `diff_snapshots` — multi-NIC snapshot, changes on one NIC only**
Setup: Two NICs in both snapshots. One NIC clean, one NIC has a UDR change.
Expected: `nic_diffs` contains exactly one entry (the changed NIC). The clean NIC does not appear in `nic_diffs`.

**TC-DIFF-021: `diff_snapshots` — NIC present in compare but absent in baseline (new NIC)**
Setup: Baseline has NIC A only. Compare has NIC A and NIC B (new NIC, two routes, one NSG rule).
Expected: All routes and NSG rules for NIC B appear as `change_type: "added"`, `category` per route source. NIC B appears in `nic_diffs`. `changes_count` includes NIC B's entries. NIC B is NOT in `skipped_nics`.

**TC-DIFF-021b: `diff_snapshots` — NIC present in baseline but absent in compare (detached NIC)**
Setup: Baseline has NIC A and NIC B. Compare has NIC A only (NIC B detached).
Expected: All routes and NSG rules for NIC B appear as `change_type: "removed"`. NIC B appears in `nic_diffs`. NIC B is NOT in `skipped_nics`.

**TC-DIFF-022: `diff_snapshots` — NIC errored in compare snapshot** [ARCH-GAP AG-2]
Setup: Baseline has NIC A clean. Compare has NIC A with `"error": "RBAC failure"`.
Expected: NIC A excluded from diff. NIC A's name appears in `skipped_nics`. No drift reported for NIC A. `drift_detected` reflects only non-errored NICs.

**TC-DIFF-023: `diff_snapshots` — NIC errored in baseline snapshot** [ARCH-GAP AG-2]
Setup: Baseline NIC A has `"error"`. Compare NIC A is clean.
Expected: NIC A excluded. Appears in `skipped_nics`. Not treated as drift (routes going from errored to present is not a valid diff).

**TC-DIFF-024: `diff_snapshots` — unknown route source categorised as `system_route_change`**
Setup: A route present in compare but absent in baseline has `source: "SomeUnknownSource"`.
Expected: `_categorise_route` maps unknown source to `system_route_change` (defensive fallback). Change is reported — not silently dropped. Unknown source value is preserved verbatim in the change object.

**TC-DIFF-025: `diff_snapshots` — NSG list fields with reordered items, no false positive**
Setup: Baseline NSG rule has `destinationPortRanges: ["80", "443"]`. Compare has same rule with `["443", "80"]` (same ports, different order).
Expected: `drift_detected: false`. Reordered lists in normalised rules must not produce a change entry.

**TC-DIFF-026: `diff_snapshots` — `drift_detected: false` field is always present** [requirement D9]
Setup: Two identical snapshots.
Expected: `"drift_detected"` key is present in the output dict with value `False`. Must not be absent.

**TC-DIFF-027: `_canonicalise_nsg_rule` — uses `expandedSourceAddressPrefix` when non-empty**
Setup: Two snapshots of the same NSG rule. Baseline has `sourceAddressPrefixes: ["VirtualNetwork"]`, `expandedSourceAddressPrefix: ["10.0.0.0/8", "10.1.0.0/16"]`. Compare has same tag `sourceAddressPrefixes: ["VirtualNetwork"]` but `expandedSourceAddressPrefix: ["10.0.0.0/8", "10.2.0.0/16"]` (one CIDR changed in the expanded set).
Expected: `drift_detected: true`, `security_rule_change` detected. The tag name (`VirtualNetwork`) did not change but the resolved CIDRs did — this is a real network posture change.

**TC-DIFF-028: `_canonicalise_nsg_rule` — falls back to `sourceAddressPrefixes` when expanded is empty**
Setup: NSG rule with `sourceAddressPrefixes: ["10.5.0.0/24"]`, `expandedSourceAddressPrefix: []`. Identical in baseline and compare.
Expected: `drift_detected: false`. Comparison uses `sourceAddressPrefixes` when expanded is empty — no false positive.

---

### 4.2 `providers.py` — Azure CLI Boundary

All tests mock `LocalShell` to avoid real az CLI calls. Verify the argument vectors, not just the return values.

---

**TC-PROV-001: `LocalShell.run()` — uses `shell=False`**
Setup: Capture the `subprocess.run` call via mock.
Expected: `shell=False` is passed. `command` argument is a `list[str]`, not a string.

**TC-PROV-002: `discover_nics_for_vm` — correct argument vector**
Setup: Mock `LocalShell.run()` to return stdout string for `vm_nic_ids.json`.
Expected: `subprocess.run` called with `["az", "vm", "nic", "list", "--resource-group", "rg-name", "--vm-name", "vm-name", "--query", "[].id", "--output", "json"]` (exact list, no shell string).

**TC-PROV-003: `discover_nics_for_vm` — subscription_id appended when present**
Setup: `AzureNetworkProvider(shell, "rg", subscription_id="sub-abc")`.
Expected: `["--subscription", "sub-abc"]` appended to the argument vector, not interpolated into a string.

**TC-PROV-004: `discover_nics_for_vm` — no subscription flag when omitted**
Setup: `AzureNetworkProvider(shell, "rg", subscription_id=None)`.
Expected: `"--subscription"` not present anywhere in the argument vector.

**TC-PROV-005: `discover_nics_for_vm` — NIC names extracted from resource IDs**
Setup: Mock returns `["/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/my-nic"]`.
Expected: `discover_nics_for_vm()` returns `["my-nic"]` (last path segment only).

**TC-PROV-006: `discover_nics_for_vm` — empty NIC list returns empty list**
Setup: Mock `LocalShell.run()` to return stdout string for `az vm nic list` returns `[]`.
Expected: `discover_nics_for_vm` returns `[]`. No exception. Stage 2 (orchestrator) handles the empty result by printing a warning and continuing.

**TC-PROV-007: `discover_nics_for_vm` — non-zero exit code raises ProviderError**
Setup: Mock `LocalShell.run()` to raise `ProviderError("Some az error")` (non-zero exit from az).
Expected: `ProviderError` propagates. The error message includes the stderr content from az.

**TC-PROV-008: `discover_nics_for_vnet` — NIC names extracted from subnet ipConfigurations**
Setup: Mock `LocalShell.run()` to return stdout string for `az network vnet subnet list` returns two subnets — one with two `ipConfigurations` entries, one with none.
Expected: `discover_nics_for_vnet` returns the two NIC names extracted from the first subnet's `ipConfigurations[].id` path segments. The second subnet (no ipConfigurations) contributes nothing. Returns `list[(nic_name, nic_rg)]` tuples, deduplicated.

**TC-PROV-008b: `discover_nics_for_vnet` — cross-resource-group NICs returned with correct RG**
Setup: Mock subnet response where `ipConfigurations[0].id` contains a NIC in `spoke-rg`, not `hub-rg` (the VNet's resource group).
Expected: Returned tuple contains `("nic-name", "spoke-rg")`. The NIC's own resource group is extracted from its resource ID — not the VNet's resource group.

**TC-PROV-009: `discover_nics_for_vnet` — empty result returns `[]`, not an error**
Setup: Mock returns subnet list where all subnets have empty `ipConfigurations`.
Expected: Returns `[]`. No exception.

**TC-PROV-010: `get_effective_routes` — correct argument vector**
Setup: Mock `LocalShell.run()`.
Expected: `["az", "network", "nic", "show-effective-route-table", "--resource-group", "rg", "--name", "nic-name", "--output", "json"]`.

**TC-PROV-011: `get_effective_nsg_rules` — correct argument vector**
Expected: `["az", "network", "nic", "list-effective-nsg", "--resource-group", "rg", "--name", "nic-name", "--output", "json"]`.

**TC-PROV-012: RBAC error — `AuthorizationFailed` in stderr raises RBACError**
Setup: Mock `LocalShell.run()` to raise `ProviderError` whose message contains `"AuthorizationFailed"`.
Expected: `_run_az` raises `RBACError`. Message contains `"Network Contributor"` and the missing permission name. Not a bare `ProviderError` or `RuntimeError`.

**TC-PROV-013: RBAC error — `does not have authorization` variant**
Setup: Mock `LocalShell.run()` to raise `ProviderError` whose message contains `"does not have authorization"`.
Expected: `RBACError` raised. Both known phrases trigger the RBAC path.

**TC-PROV-014: `get_effective_routes` returns parsed JSON, not raw string** [regression guard]
Setup: Mock `LocalShell.run()` to return stdout string `'{"value": [{"addressPrefix": ["10.0.0.0/8"], "source": "Default", "nextHopType": "VnetLocal", "nextHopIpAddress": [], "state": "Active"}]}'`.
Expected: `get_effective_routes()` returns a `list[dict]` unwrapped from the `"value"` key. Not a string. Not the full envelope dict.

**TC-PROV-015: Shell metacharacter in resource name — no injection possible** [security]
Setup: `AzureNetworkProvider(shell, resource_group="rg; rm -rf /")`.
Expected: The argument `"rg; rm -rf /"` is passed as a single element in the argument vector. `subprocess.run(shell=False)` means it is treated as a literal string argument, not a shell expression. No shell execution of the injected command.

**TC-PROV-016: `LocalShell.run()` — timeout raises ProviderError with timeout message**
Setup: Mock `subprocess.run` to raise `subprocess.TimeoutExpired(cmd=["az"], timeout=60)`.
Expected: `LocalShell.run()` raises `ProviderError` whose message contains `"timeout after 60s"`. Not a bare `TimeoutExpired`.

**TC-PROV-017: `_run_az` — 429 retry exhausted raises ThrottleExhausted**
Setup: Mock `LocalShell.run()` to always raise `ProviderError` whose message contains `"Too Many Requests"`.
Expected: After 5 retries, `_run_az` raises `ThrottleExhausted`. Total `LocalShell.run()` call count is 6 (1 initial + 5 retries). Each retry waits at least `initial_delay=2s` (mock `time.sleep` to assert call count and arguments).

**TC-PROV-018: `discover_nics_for_vnet` — cross-resource-group NIC uses NIC's own RG for queries**
Setup: Mock `az network vnet subnet list` returns one subnet with one `ipConfigurations` entry whose `id` is `/subscriptions/sub/resourceGroups/spoke-rg/providers/Microsoft.Network/networkInterfaces/nic-a/ipConfigurations/ipconfig1`. The provider's default `resource_group` is `hub-rg`.
Expected: `discover_nics_for_vnet` returns `[("nic-a", "spoke-rg")]`. When Stage 3 calls `get_effective_routes("nic-a", resource_group="spoke-rg")`, the az command uses `--resource-group spoke-rg`, not `hub-rg`.

**TC-PROV-019: `get_effective_nsg_rules` — unwraps from `networkSecurityGroups[].effectiveSecurityRules`**
Setup: Mock `LocalShell.run()` to return stdout with the full `az network nic list-effective-nsg` envelope containing two NSG groups, each with two `effectiveSecurityRules`.
Expected: `get_effective_nsg_rules` returns a flat list of 4 rule objects. The `networkSecurityGroups` wrapper and per-group structure are not present in the return value.

---

### 4.3 `effective_network_inspector.py` — Orchestrator

---

**TC-ORCH-001: `validate_session_id` — accepts valid formats**
Inputs: `"eni_20260401_120000"`, `"pre-test"`, `"a"`, `"A1-b_2"` (64 chars max).
Expected: No exception.

**TC-ORCH-002: `validate_session_id` — rejects path traversal**
Inputs: `"../evil"`, `"foo/../bar"`, `"foo/bar"`.
Expected: `ValueError` raised for each.

**TC-ORCH-003: `validate_session_id` — rejects empty string**
Input: `""`.
Expected: `ValueError`.

**TC-ORCH-004: `validate_session_id` — rejects special shell characters**
Inputs: `"foo;bar"`, `"foo bar"`, `"foo&bar"`.
Expected: `ValueError` for each.

**TC-ORCH-005: `validate_session_id` — rejects over 64 characters**
Input: `"a" * 65`.
Expected: `ValueError`.

---

**TC-ORCH-006: `save_snapshot` — creates both JSON and SHA-256 files**
Setup: Build a snapshot dict containing `"session_id": "test-session"`. Call `save_snapshot(snapshot_dict, tmp_path)`.
Expected: `test-session_snapshot.json` exists in `tmp_path`. `test-session_snapshot.json.sha256` exists. Both files non-empty. Session ID is read from the snapshot dict, not passed as a separate parameter.

**TC-ORCH-007: `save_snapshot` — SHA-256 file format** [ARCH-GAP AG-3]
Expected: SHA-256 file contains `{hex_digest}  {filename}` (two spaces, GNU sha256sum convention) so `sha256sum -c test-session_snapshot.json.sha256` passes from the audit directory.
*Currently failing: code writes just `{digest}\n`.*

**TC-ORCH-008: `load_snapshot` — verifies SHA-256 before returning data**
Setup: Write a valid snapshot. Tamper with a single byte in the JSON file. Call `load_snapshot`.
Expected: `IntegrityError` raised. The tampered snapshot is not returned.

**TC-ORCH-009: `load_snapshot` — missing SHA-256 companion raises IntegrityError**
Setup: Write snapshot JSON without the `.sha256` sidecar.
Expected: `IntegrityError`, not `FileNotFoundError`. The error message must mention the missing companion file.

**TC-ORCH-010: `load_snapshot` — missing snapshot JSON raises FileNotFoundError**
Setup: Request a session ID that does not exist.
Expected: `FileNotFoundError` with a message identifying the missing path.

**TC-ORCH-011: `load_snapshot` — valid snapshot returns correct dict**
Setup: Write a snapshot via `save_snapshot`, then load it via `load_snapshot`.
Expected: Returned dict equals the original. Round-trip is lossless.

---

**TC-ORCH-012: `_load_config_file` — KEY_MAP parsing**
Setup: Write a config file with all supported keys:
```
RESOURCE_GROUP=my-rg
SUBSCRIPTION_ID=sub-123
SCOPE=vm
VM_NAME=my-vm
VNET_ID=/subscriptions/sub/virtualNetworks/my-vnet
AUDIT_DIR=/tmp/audit
SESSION_ID=pre-test
IS_BASELINE=true
COMPARE_BASELINE=baseline-session
```
Expected: Returns dict with all keys mapped to their Python equivalents. `is_baseline` is `True` (bool). `subscription_id` is `"sub-123"`. No warnings printed.

**TC-ORCH-013: `_load_config_file` — `IS_BASELINE` variants**
Inputs: `true`, `True`, `1`, `yes` → all must return `True`. `false`, `0`, `no` → `False`.

**TC-ORCH-014: `_load_config_file` — unknown key is warned and ignored**
Setup: Config file contains `UNKNOWN_KEY=value`.
Expected: Warning printed to `stderr` (not stdout). Returned dict does not contain `unknown_key`. Tool does not abort.

**TC-ORCH-015: `_load_config_file` — inline comments stripped**
Input: `RESOURCE_GROUP=my-rg  # this is a comment`
Expected: `resource_group` is `"my-rg"`. `# this is a comment` is not included.

**TC-ORCH-016: `_load_config_file` — quoted values**
Input: `AUDIT_DIR="/path/with spaces/audit"`
Expected: `audit_dir` is `/path/with spaces/audit` (quotes stripped).

**TC-ORCH-017: `_load_config_file` — missing config file exits with code 1**
Setup: Pass a path that does not exist.
Expected: Tool exits with code 1. Error message on stderr identifies the file path.

---

**TC-ORCH-018: `InspectorConfig.__post_init__` — invalid scope rejected**
Input: `InspectorConfig(scope="invalid", ...)`
Expected: `ValueError` raised identifying the invalid scope.

**TC-ORCH-019: `InspectorConfig.__post_init__` — empty scope_target rejected**
Input: `InspectorConfig(scope="vm", scope_target="", ...)`
Expected: `ValueError` raised.

**TC-ORCH-020: `InspectorConfig.__post_init__` — empty resource_group rejected**
Input: `InspectorConfig(resource_group="", ...)`
Expected: `ValueError` raised.

---

**TC-ORCH-021: `run()` — per-NIC error isolation: routes fail, continue to next NIC**
Setup: Two NICs. Mock provider: NIC A routes query raises `ProviderError`. NIC B succeeds.
Expected:
- `snapshot["nics"]` has two entries.
- NIC A entry has `"error"` set (non-null string), `"effective_routes": null`, `"effective_nsg_rules": null`.
- NIC B entry has `"error": null` and populated `"effective_routes"` and `"effective_nsg_rules"`.
- Tool does not abort at NIC A failure.

**TC-ORCH-022: `run()` — NSG query skipped when routes fail for same NIC**
Setup: NIC A routes query raises `ProviderError`. Mock provider: NSG query for NIC A would succeed if called.
Expected: NSG query is never called for NIC A. NIC A has `"effective_nsg_rules": null`. NSG mock call count for NIC A is 0.

**TC-ORCH-023: `run()` — baseline mode writes snapshot and SHA-256**
Setup: Mock provider returns valid routes + NSG data. Run with `is_baseline=True`.
Expected:
- `{session_id}_snapshot.json` created in `audit_dir`.
- `{session_id}_snapshot.json.sha256` created in `audit_dir`.
- Result dict has `mode: "baseline"` and `session_id`.

**TC-ORCH-024: `run()` — compare mode produces diff artifact**
Setup: Write a valid baseline snapshot. Run with `compare_baseline` pointing to it. Mock provider returns different data (one new NSG rule).
Expected:
- Diff artifact written to `audit_dir`.
- Result dict has `mode: "compare"` and `diff_report` path.
- `diff["drift_detected"]` is `True`.
- `diff["changes_by_category"]["security_rule_change"]` is 1.

**TC-ORCH-025: `run()` — self-compare guard**
Setup: Write baseline with session ID `"test-session"`. Run compare with `compare_baseline="test-session"` and `session_id="test-session"` (same ID).
Expected: Tool exits with code 2 (Stage 1 validation failure). Error message on stderr identifies the self-compare. No diff artifact written.

**TC-ORCH-027: `run()` — per-NIC progress output format**
Setup: Capture stdout. Run with two NICs (`nic-a`, `nic-b`), `is_baseline=True`.
Expected: stdout contains `"Snapshotting NIC 1/2: nic-a..."` and `"Snapshotting NIC 2/2: nic-b..."`. Progress is per-NIC, not per-pipeline-stage.

**TC-ORCH-028: `run()` — progress counter is accurate under concurrent execution**
Setup: Run with 4 NICs, `max_workers=2`. Capture all progress lines.
Expected: Each NIC appears exactly once in progress output. Counter values are `1/4`, `2/4`, `3/4`, `4/4` (no duplicates, no gaps). Order of NICs in output may vary (concurrent), but counts are sequential.

---

**TC-ORCH-029: Diff artifact filename** [ARCH-GAP AG-1]
Setup: Baseline session ID is `"baseline-a"`. Compare session ID is `"compare-b"`.
Expected: Diff artifact file is named `baseline-a_vs_compare-b_diff.json` in `audit_dir`.
*Currently failing: code writes `compare-b_diff.json`.*

**TC-ORCH-030: Diff artifact — `skipped_nics` field present** [ARCH-GAP AG-2]
Setup: Baseline NIC A clean, NIC B errored. Compare NIC A clean, NIC B errored.
Expected: Diff artifact contains `"skipped_nics": ["NIC-B-name"]`. Field must be present even when empty (`[]`).
*Currently failing: `skipped_nics` field absent from `diff_snapshots` output.*

---

**TC-ORCH-031: CLI — `--scope vm` without `--vm-name` exits with error**
Setup: `main(["--scope", "vm", "--resource-group", "rg", "--is-baseline"])` (no `--vm-name`).
Expected: Exit code non-zero. Error message identifies the missing flag.

**TC-ORCH-032: CLI — `--scope vnet` without `--vnet-id` exits with error**
Expected: Same as TC-ORCH-031 for vnet.

**TC-ORCH-033: CLI — neither `--is-baseline` nor `--compare-baseline` exits with error**
Setup: All required flags present except the mode flag.
Expected: Exit code 2 (Stage 1 validation). Error message explains that one of the two mode flags is required.

**TC-ORCH-034: CLI — auto-generated session ID matches `eni_YYYYMMDD_HHMMSS_{hex}` format**
Setup: Run without `--session-id`.
Expected: Artifact filename uses a session ID matching `eni_\d{8}_\d{6}_[0-9a-f]{4}` (date, time, 4-char random hex suffix).

**TC-ORCH-035: CLI — `--config` values overridden by CLI flags**
Setup: Config file has `RESOURCE_GROUP=from-config`. CLI passes `--resource-group from-cli`.
Expected: `resource_group` used is `"from-cli"`. Config file value is ignored when CLI flag is present.

**TC-ORCH-036: Exit code policy — all NICs succeed → exit 0**
Setup: Mock provider returns success for all NICs.
Expected: Process exit code 0.

**TC-ORCH-037: Exit code policy — one NIC errors → exit non-zero**
Setup: Two NICs. One succeeds, one fails.
Expected: Process exit code non-zero (1 per architecture). Snapshot still written with the partial data.

**TC-ORCH-038: Exit code policy — baseline integrity check failure → exit 2**
Setup: Write a snapshot, tamper with it, attempt to compare.
Expected: Process exit code 2 (`IntegrityError` path). Error message on stderr identifies tampered session ID.

---

### 4.4 Pipeline Stage Isolation (Relational)

These tests verify that each stage's output is a self-contained intermediate artifact that the next stage can consume without re-running the prior stage.

---

**TC-PIPE-001: Stage isolation — diff.py re-runnable from snapshot pair**
Setup: Write two snapshot JSON files to disk (baseline and compare). Call `diff_snapshots` directly with the loaded dicts.
Expected: Diff dict produced correctly. `diff_snapshots` never reads files — it only takes dict arguments. The caller controls I/O.

**TC-PIPE-002: Stage isolation — snapshot round-trip**
Setup: Build a snapshot dict. Save via `save_snapshot`. Load via `load_snapshot`. Pass to `diff_snapshots`.
Expected: Loaded dict is bit-for-bit identical to the original (no field loss, no type coercion).

**TC-PIPE-003: Stage isolation — provider output consumed by normaliser without re-querying**
Setup: Take the JSON output of `get_effective_routes()` (a raw string). Pass directly to `get_effective_routes()`.
Expected: `get_effective_routes()` produces normalised route list. Provider is not called again.

**TC-PIPE-004: Relational — provider error recorded in snapshot, excluded from diff**
Setup: Three NICs. Two succeed. One raises `RuntimeError` (RBAC on NIC C).
Baseline: All three present, NIC C errored.
Compare: Same data, NIC C still errored.
Expected: `diff_snapshots` skips NIC C (in both). `drift_detected: false` (no real drift — the error is consistent). NIC C name in `skipped_nics`.

**TC-PIPE-005: Relational — new NIC in compare not in baseline reported as fully added**
Setup: Baseline has NIC A. Compare has NIC A and NIC B (new NIC, two routes, three NSG rules).
Expected: All routes and NSG rules of NIC B appear as `change_type: "added"`. `changes_count` includes all of them. NIC B appears in `nic_diffs`, NOT in `skipped_nics`.

---

### 4.5 Artifact Integrity

---

**TC-INT-001: SHA-256 sidecar — computed from actual file bytes**
Setup: Save a snapshot. Read the snapshot file bytes. Compute SHA-256 independently.
Expected: Value matches what is stored in the `.sha256` file (after stripping whitespace and optional filename suffix).

**TC-INT-002: Tamper detection — modified field in snapshot body**
Setup: Save snapshot. Read JSON, change `"resource_group"` to a different string. Re-write file without touching `.sha256`.
Expected: `load_snapshot` raises `IntegrityError`. The error message includes the session ID and distinguishes "hash mismatch" from "file missing".

**TC-INT-003: Tamper detection — appended byte**
Setup: Save snapshot. Append a single space byte to the JSON file.
Expected: `IntegrityError`.

**TC-INT-004: Tamper detection — `.sha256` deleted after write**
Setup: Save snapshot. Delete the `.sha256` file. Attempt `load_snapshot`.
Expected: `IntegrityError` (not `FileNotFoundError`) with message identifying the missing companion.

**TC-INT-005: Write failure — disk full emulation**
Setup: Mock `Path.write_bytes` to raise `OSError("No space left on device")`.
Expected: `save_snapshot` raises `OSError` with a message identifying the session ID and target directory. Not a bare Python traceback.

---

### 4.6 Boundary and Null Result Tests

---

**TC-BOUND-001: Empty NIC list — no NICs found for VM**
Setup: Mock `discover_nics_for_vm` returns `[]`.
Expected: Warning printed to stderr (not stdout). Snapshot written with `"nics": []`. Exit code 0. Diff of two empty-NIC snapshots produces `drift_detected: false`, `changes_count: 0`.

**TC-BOUND-002: NIC with zero effective routes**
Setup: Provider returns `{"value": []}` for routes.
Expected: NIC snapshot has `"effective_routes": []`. This is a valid state, not an error. No exception.

**TC-BOUND-003: NIC with zero effective NSG rules**
Setup: Provider returns `{"networkSecurityGroups": [{"effectiveSecurityRules": []}]}`.
Expected: NIC snapshot has `"effective_nsg_rules": []`. Valid state, not an error.

**TC-BOUND-004: Both snapshots empty — `drift_detected: false`, not an error**
Setup: `diff_snapshots` on two snapshots where both `"nics": []`.
Expected: `drift_detected: false`. `changes_count: 0`. No exception. Explicit confirmation that no drift occurred.

**TC-BOUND-005: Session ID at exactly 64 characters**
Input: `"a" * 64`
Expected: `validate_session_id` accepts it. No error.

**TC-BOUND-006: Session ID at 65 characters**
Input: `"a" * 65`
Expected: `ValueError`.

**TC-BOUND-007: `diff_snapshots` — route present in baseline, same route in compare with no field differences**
Setup: Identical route in both. `addressPrefix`, `nextHopType`, `source`, `state` all identical.
Expected: Route does not appear in diff. `drift_detected: false`.

**TC-BOUND-008: `diff_snapshots` — all four change categories in a single diff**
Setup: One NIC with: one BGP route removed, one UDR route added (no corresponding removal), one system route whose state changed (produces removed + added), one NSG rule removed.
Expected: `changes_by_category` has all four keys: `bgp_route_change`, `udr_route_change`, `system_route_change`, `security_rule_change`. `changes_count: 5` (1 bgp + 1 udr + 2 system + 1 nsg).

---

### 4.7 Ghost Agent Handler

---

**TC-GA-001: Handler writes correct config lines to temp file**
Setup: Capture temp file content. Call `_run_effective_network_inspector_handler` with a mock `ghost_cfg` containing `RESOURCE_GROUP`, `DEST_VM_NAME`, `AUDIT_DIR`, `SUBSCRIPTION_ID`.
Expected: Temp file contains `RESOURCE_GROUP=...`, `SCOPE=vm`, `VM_NAME=...`, `AUDIT_DIR=...`, `SUBSCRIPTION_ID=...`.

**TC-GA-002: Handler uses `ENI_VM_NAME` over `DEST_VM_NAME` when both present**
Setup: `ghost_cfg` has both `ENI_VM_NAME=vm-a` and `DEST_VM_NAME=vm-b`.
Expected: Temp config file contains `VM_NAME=vm-a`.

**TC-GA-003: Handler — `SUBSCRIPTION_ID` omitted when not in ghost_cfg**
Setup: `ghost_cfg` has no `SUBSCRIPTION_ID` key.
Expected: Temp config file does not contain `SUBSCRIPTION_ID=`.

**TC-GA-004: Handler — temp file deleted after subprocess regardless of exit code**
Setup: Mock subprocess to raise `TimeoutExpired`. Capture temp file path before exception.
Expected: Temp file no longer exists after the handler returns. Cleanup happens in the `finally` block.

**TC-GA-005: Handler — baseline mode reads artifact at deterministic path**
Setup: Handler generates session ID `"eni_test_a1b2"` before invoking subprocess. Mock subprocess returns exit 0. Write `eni_test_a1b2_snapshot.json` in `AUDIT_DIR`.
Expected: Handler constructs path `{AUDIT_DIR}/eni_test_a1b2_snapshot.json` directly (no mtime scan). Returns `{"status": "success", "mode": "baseline", "session_id": "eni_test_a1b2", "artifact": "..."}`.

**TC-GA-006: Handler — compare mode reads artifact at deterministic path**
Setup: Handler is given `compare_session_id="baseline-abc"` and generates current session ID `"eni_curr_1234"`. Mock subprocess returns exit 0. Write `baseline-abc_vs_eni_curr_1234_diff.json` in `AUDIT_DIR`.
Expected: Handler constructs path `{AUDIT_DIR}/baseline-abc_vs_eni_curr_1234_diff.json` directly. Returns `{"status": "success", "mode": "compare", "drift_detected": ..., "changes_count": ...}`.

**TC-GA-007: Handler — no artifact found returns error**
Setup: Mock subprocess returns exit 0 but writes no artifact.
Expected: Handler returns `{"status": "error", "error": "effective_network_inspector did not produce a ... artifact"}`.

**TC-GA-008: Handler — subprocess timeout returns structured error**
Setup: Mock subprocess to raise `TimeoutExpired`.
Expected: `{"status": "error", "error": "effective_network_inspector timed out after 300 seconds"}`.

**TC-GA-009: Handler — no `ghost_cfg` provided returns structured error**
Setup: Call `_dispatch_tool("detect_effective_network_drift", {}, shell, orchestrator, ghost_cfg=None)`.
Expected: `{"status": "error", "error": "detect_effective_network_drift requires --config to be set at startup"}`.

**TC-GA-010: Handler — neither `is_baseline` nor `compare_session_id` provided returns structured error**
Setup: Call handler with `tool_args = {"reasoning": "test"}` only.
Expected: `{"status": "error", "error": "Either is_baseline=true or compare_session_id must be provided"}`.

**TC-GA-011: Tool declaration schema — `compare_session_id` parameter name matches handler read**
Setup: Inspect the `detect_effective_network_drift` FunctionDeclaration in `_build_ghost_tools()`.
Expected: Parameter named `compare_session_id` exists. Handler reads `tool_args.get("compare_session_id")`. No `compare_baseline` parameter in the declaration.

---

## 5. Coverage Matrix

| Requirement | Test cases |
|---|---|
| Effective routes snapshot per NIC | TC-DIFF-001–005, TC-PROV-010, TC-ORCH-023 |
| Effective NSG rules snapshot per NIC | TC-DIFF-006–010, TC-PROV-011, TC-ORCH-023 |
| `bgp_route_change` category | TC-DIFF-012, TC-DIFF-013 |
| `udr_route_change` category | TC-DIFF-014 |
| `system_route_change` category | TC-DIFF-015 |
| `security_rule_change` category | TC-DIFF-016, TC-DIFF-017, TC-DIFF-018 |
| `drift_detected: false` explicit | TC-DIFF-011, TC-DIFF-026, TC-BOUND-004 |
| `drift_detected: true` when changed | TC-DIFF-012–019, TC-ORCH-024 |
| SHA-256 integrity — create | TC-ORCH-006, TC-INT-001 |
| SHA-256 integrity — verify on load | TC-ORCH-008, TC-INT-002, TC-INT-003 |
| SHA-256 companion missing | TC-ORCH-009, TC-INT-004 |
| SHA-256 file format (GNU sha256sum) [AG-3] | TC-ORCH-007 |
| Per-NIC error isolation | TC-ORCH-021, TC-ORCH-022, TC-PIPE-004 |
| Partial snapshot validity | TC-ORCH-021, TC-PIPE-004 |
| Self-compare guard | TC-ORCH-025 |
| RBAC error detection | TC-PROV-012, TC-PROV-013 |
| `AuthorizationFailed` + `does not have authorization` phrases | TC-PROV-012, TC-PROV-013 |
| Session ID validation | TC-ORCH-001–005 |
| Config file parsing | TC-ORCH-012–017 |
| CLI flag overrides config file | TC-ORCH-035 |
| Scope validation (vm/vnet) | TC-ORCH-018, TC-ORCH-031, TC-ORCH-032 |
| Mode validation (baseline/compare required) | TC-ORCH-033 |
| Auto-generated session ID format | TC-ORCH-034 |
| Exit code 0 (all NICs success) | TC-ORCH-036 |
| Exit code non-zero (NIC error) | TC-ORCH-037 |
| Exit code 2 (integrity failure) | TC-ORCH-038 |
| No `shell=True` | TC-PROV-001 |
| Argument vector (no string concatenation) | TC-PROV-002, TC-PROV-003, TC-PROV-010, TC-PROV-011 |
| Shell metacharacter injection | TC-PROV-015 |
| `stdout` used for az JSON (not `output`) | TC-PROV-014 |
| NIC added in compare only | TC-DIFF-021, TC-PIPE-005 |
| NIC errored in compare excluded from diff | TC-DIFF-022 |
| NIC errored in baseline excluded from diff | TC-DIFF-023 |
| `skipped_nics` field in diff [AG-2] | TC-DIFF-022, TC-DIFF-023, TC-ORCH-030, TC-PIPE-004 |
| Diff artifact filename format [AG-1] | TC-ORCH-029 |
| Ghost Agent handler — config construction | TC-GA-001, TC-GA-002, TC-GA-003 |
| Ghost Agent handler — temp file cleanup | TC-GA-004 |
| Ghost Agent handler — artifact discovery | TC-GA-005, TC-GA-006, TC-GA-007 |
| Ghost Agent handler — error paths | TC-GA-007, TC-GA-008, TC-GA-009, TC-GA-010 |
| Tool declaration schema consistency | TC-GA-011 |
| Null result — zero routes | TC-BOUND-002 |
| Null result — zero NSG rules | TC-BOUND-003 |
| Null result — zero NICs | TC-BOUND-001 |
| Null result — identical snapshots | TC-BOUND-004, TC-DIFF-011 |
| List field reorder — no false positive | TC-DIFF-009, TC-DIFF-025 |
| Unknown route source defaults to `system_route_change` | TC-DIFF-024 |
| Pipeline stage isolation | TC-PIPE-001–005 |
| Config warnings to stderr, not stdout | TC-ORCH-014 |
| `parse_warnings` — local to `run()`, not on config object | (code structure; verify no `config.parse_warnings` attribute) |
| NIC absent from baseline reported as fully added | TC-DIFF-021, TC-PIPE-005 |
| NIC absent from compare reported as fully removed | TC-DIFF-021b |
| Cross-resource-group NIC uses NIC's own RG for queries | TC-PROV-018 |
| `expandedSourceAddressPrefix` used when non-empty | TC-DIFF-027 |
| Falls back to `sourceAddressPrefixes` when expanded empty | TC-DIFF-028 |
| `get_effective_nsg_rules` unwraps nested envelope | TC-PROV-019 |
| 429 retry in `_run_az` (not `LocalShell`) | TC-PROV-017 |
| VNet scope E2E (snapshot + no-drift compare) | E2E Step 7 |
| BGP route withdrawal E2E | E2E Step 8 (requires VPN gateway) |
| `_load_config_file` — key map, bool parsing, comments, quotes | TC-ORCH-012–017 |

---

## 6. Pass / Fail Criteria

Every test case has an explicit expected outcome. A test passes only when all of the following hold:

- **Return value / dict schema**: every field named in "Expected" is present with the correct type and value.
- **File system state**: files that should exist do; files that should not exist (e.g., deleted temp file) do not.
- **Exit code**: process exits with the integer code stated.
- **Exception type**: when an exception is expected, it is the stated type (not a superclass like `Exception`).
- **Stderr / stdout routing**: warnings and errors go to stderr; progress output goes to stdout. Tests that assert "message on stderr" must fail if the message appears on stdout.
- **Mock call count**: for isolation tests (TC-ORCH-022, TC-PIPE-001), mock call counts are asserted — not just return values.
- **No side effects**: provider tests must not write files; diff tests must not call az CLI.

A test is **not** considered passing if it produces the right output but via the wrong mechanism (e.g., a test that passes because a mock was not called when it should have been, or passes despite `shell=True` because no injection occurred in that particular input).

---

## 7. E2E Verification Script

These steps require Azure connectivity to `nw-forensics-rg` with Network Contributor.
Run after all unit/integration tests pass.

```bash
# Step 1: Baseline snapshot
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --is-baseline --session-id e2e_pre_test

# Step 2: Inject deny rule
az network nsg rule create \
  --resource-group nw-forensics-rg \
  --nsg-name tf-dest-vm-nsg \
  --name test-deny-review-$(date +%Y%m%d) \
  --priority 100 --direction Inbound --access Deny \
  --protocol Tcp --source-address-prefixes '*' \
  --destination-address-prefixes '*' --destination-port-ranges 22

# Step 3: Compare — expect security_rule_change
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --compare-baseline e2e_pre_test
# Assert: drift_detected=true, changes_by_category.security_rule_change >= 1

# Step 4: Remove rule
az network nsg rule delete \
  --resource-group nw-forensics-rg \
  --nsg-name tf-dest-vm-nsg \
  --name test-deny-review-$(date +%Y%m%d)

# Step 5: Re-compare — expect no drift
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --compare-baseline e2e_pre_test
# Assert: drift_detected=false

# Step 6: RBAC error handling
# Run from a context without Network Contributor and assert a clear RBAC message
# appears (not a Python traceback) and exit code is non-zero.

# Step 7: VNet scope
python effective_network_inspector.py \
  --scope vnet --vnet-id /subscriptions/$SUBSCRIPTION_ID/resourceGroups/nw-forensics-rg/providers/Microsoft.Network/virtualNetworks/nw-forensics-vnet \
  --resource-group nw-forensics-rg \
  --is-baseline --session-id e2e_vnet_pre_test
# Assert: snapshot written, "nics" list non-empty, all NIC entries have effective_routes and effective_nsg_rules

python effective_network_inspector.py \
  --scope vnet --vnet-id /subscriptions/$SUBSCRIPTION_ID/resourceGroups/nw-forensics-rg/providers/Microsoft.Network/virtualNetworks/nw-forensics-vnet \
  --resource-group nw-forensics-rg \
  --compare-baseline e2e_vnet_pre_test
# Assert: drift_detected=false (no changes since baseline was just taken)

# Step 8: BGP route withdrawal (requires VPN gateway — skip if not present)
# @pytest.mark.vpn_gateway
# Precondition: nw-forensics-vnet subnet has a route table with "propagate gateway routes" enabled
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm --resource-group nw-forensics-rg \
  --is-baseline --session-id e2e_bgp_pre

# Disable propagate gateway routes on the subnet route table
az network route-table update \
  --resource-group nw-forensics-rg \
  --name tf-dest-vm-rt \
  --disable-bgp-route-propagation true

python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm --resource-group nw-forensics-rg \
  --compare-baseline e2e_bgp_pre
# Assert: drift_detected=true, changes_by_category.bgp_route_change >= 1
# (VirtualNetworkGateway-sourced routes disappeared from effective route table)

# Re-enable to clean up
az network route-table update \
  --resource-group nw-forensics-rg \
  --name tf-dest-vm-rt \
  --disable-bgp-route-propagation false
```

---

## 8. Architecture Gaps — Remediation Required Before Full Pass

The following tests are written against the design document. They will fail on the current implementation until these gaps are closed:

| Gap | Tests | Fix required |
|---|---|---|
| **AG-1**: Diff file named `{session}_diff.json` instead of `{baseline}_vs_{compare}_diff.json` | TC-ORCH-029, TC-GA-006 | Change `_write_artifact(..., "diff")` call in `run()` to use `{config.compare_baseline}_vs_{config.session_id}` as the filename stem |
| **AG-2**: `skipped_nics` field absent from diff artifact | TC-DIFF-022, TC-DIFF-023, TC-ORCH-030, TC-PIPE-004 | Add `skipped_nics` tracking in `diff_snapshots()`; always include the field (empty list when no skips) |
| **AG-3**: SHA-256 file format not GNU sha256sum-compatible | TC-ORCH-007 | Change `save_snapshot` to write `{digest}  {filename}\n`; update `load_snapshot` to parse the digest from the first whitespace-delimited token |
| **AG-4**: Typed exceptions not implemented | Affects RBAC/throttle/parse distinction in orchestrator tests | Add `RBACError`, `ThrottleExhausted`, `ProviderError`; update `providers.py` to raise them; update orchestrator catch clauses |
| **AG-5**: No 429 retry / backoff | TC-PROV-017 | Add retry loop in `AzureNetworkProvider._run_az` (not in `LocalShell` — retry is a policy concern of the provider, not the shell executor) |
| **AG-6**: Sequential NIC queries (no `ThreadPoolExecutor`) | TC-ORCH-028 | Add `ThreadPoolExecutor` in Stage 3 of `run_snapshot_pipeline`; per-NIC errors must not propagate to pool |
