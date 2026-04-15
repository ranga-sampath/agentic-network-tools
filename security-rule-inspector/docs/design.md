# Design — security-rule-inspector

> Document order: **Requirements → Architecture → Design (this document) → Code**
> Architecture source: `security-rule-inspector/docs/architecture.md`
> Requirements source: `security-rule-inspector/docs/product-requirements.md`

Sections in this document supersede architecture-level schema sketches. Where the
architecture names a schema or contract, this document is the authoritative specification.

---

## 1. Module and Function Inventory

### 1.1 `security_rule_inspector.py`

| Function | Signature | Single Responsibility |
|---|---|---|
| `main` | `() -> None` | Parse CLI args; drive pipeline stages; exit with correct code |
| `_enforce_session_prefix` | `(session_id: str) -> str` | Return session_id unchanged if it starts with `nsg_`; prepend `nsg_` otherwise |
| `_generate_session_id` | `() -> str` | Return `nsg_YYYYMMDD_HHMMSS` from `datetime.utcnow()` |
| `_ensure_audit_dir` | `(audit_dir: str) -> Path` | Create directory if absent (`exist_ok=True`); raise `SystemExit(2)` if creation fails |
| `_detect_mode` | `(args: Namespace) -> str` | Return `"verdict"` if all five traffic tuple fields are set; `"audit"` if none are set; raise `SystemExit(2)` for partial tuple |
| `_check_collision` | `(session_id: str, audit_dir: Path) -> None` | Exit 2 if any file matching `{session_id}_*.json` already exists in `audit_dir` |
| `_validate_traffic_tuple` | `(args: Namespace) -> TrafficTuple` | Parse and validate `src_ip`, `dst_ip`, `dst_port`, `proto`, `direction`; return a `TrafficTuple`; exit 2 on invalid values |
| `_run_pipeline` | `(args: Namespace, provider: NSGProvider \| None = None) -> int` | Orchestrate Stages 2–5; return exit code |
| `_render_verdict_table` | `(verdict: dict) -> str` | Return human-readable verdict output string from verdict artifact dict |
| `_render_audit_table` | `(audit: dict) -> str` | Return human-readable audit table string from audit artifact dict |

**`main()` call sequence:**
1. `parse_args()` → `args`
2. `_detect_mode(args)` → exit 2 on partial tuple
3. Verdict mode only: `args.traffic = _validate_traffic_tuple(args)`; audit mode: `args.traffic = None`
4. `args.session_id = _enforce_session_prefix(args.session_id or _generate_session_id())`
5. `audit_path = _ensure_audit_dir(args.audit_dir)` ← must precede collision check
6. `_check_collision(args.session_id, audit_path)`
7. `sys.exit(_run_pipeline(args))`

`main()` never catches exceptions from `_run_pipeline` — all error handling is inside
`_run_pipeline`, which returns `0` or `2`.

---

### 1.2 `providers.py`

#### Exception Hierarchy

```
ProviderError(RuntimeError)
  ├── RBACError(ProviderError)          # AuthorizationFailed in az CLI output
  ├── ThrottleExhausted(ProviderError)  # 429 persisted after max retries
  ├── VMNotFoundError(ProviderError)    # VM not found in the resource group
  └── NICResolutionError(ProviderError) # NIC resolution failed (no primary flag)
```

All exceptions carry a human-readable `message` attribute.
`ThrottleExhausted` also carries `attempts: int` and `last_wait_seconds: float`.
`RBACError.message` includes the missing permission name extracted from the az CLI error text.

#### `NSGProvider` (protocol / abstract base)

Defines the interface that any provider implementation must satisfy. `AzureNSGProvider`
implements this protocol. A `MockNSGProvider` can implement it for testing without real
az CLI calls.

| Method | Signature | Single Responsibility |
|---|---|---|
| `get_nic_name` | `(vm_name: str, resource_group: str) -> str` | Resolve primary NIC name |
| `get_effective_nsg` | `(nic_name: str, resource_group: str) -> dict` | Return raw effective NSG data as a parsed dict |

`_run_pipeline` accepts `provider: NSGProvider | None = None`. When `None`, it
instantiates `AzureNSGProvider(subscription_id=args.subscription_id)` internally.
When provided, it uses the supplied instance — this is the test seam.

#### `is_throttle` (module-level function)

| Function | Signature | Single Responsibility |
|---|---|---|
| `is_throttle` | `(stderr: str) -> bool` | Return `True` if stderr matches a known throttle pattern |

Patterns matched (case-insensitive, against `stderr.lower()`):
`"throttling"`, `"too many requests"`, `"rate limit"`, `"429"`

This function is module-level (not a method) so it can be patched in tests independently of
the provider instance. It is called only by `_call_with_retry`.

#### `LocalShell`

| Method | Signature | Single Responsibility |
|---|---|---|
| `run` | `(cmd: list[str], timeout: int = 60) -> str` | Execute `cmd` as an argument vector; return stdout on exit code 0; raise `ProviderError(stderr)` on non-zero exit |

`LocalShell.run()` uses `subprocess.run(cmd, capture_output=True, text=True)`. It never
uses `shell=True` or string interpolation. On non-zero exit code, it raises
`ProviderError` with the full stderr content. On timeout, it raises
`ProviderError("timeout after {timeout}s")`. `LocalShell` performs no error
classification and no retry — those are `AzureNSGProvider`'s responsibilities.

#### `AzureNSGProvider`

| Method | Signature | Single Responsibility |
|---|---|---|
| `__init__` | `(subscription_id: str \| None = None)` | Store subscription context; instantiate `LocalShell` |
| `get_nic_name` | `(vm_name: str, resource_group: str) -> str` | Resolve the primary NIC name for a VM |
| `get_effective_nsg` | `(nic_name: str, resource_group: str) -> dict` | Return raw effective NSG data as a parsed dict |
| `_call_with_retry` | `(cmd: list[str], context: str) -> str` | Run `LocalShell.run(cmd)` with throttle retry; raise `ThrottleExhausted` after max retries |
| `_classify_error` | `(stderr: str, context: str) -> None` | Inspect stderr; raise the most specific typed exception |

`_call_with_retry` and `_classify_error` are private helpers. No other component calls
them. Both `get_nic_name` and `get_effective_nsg` call `_call_with_retry`, then
`_classify_error` if `ProviderError` is caught.

**`get_nic_name` — primary NIC resolution:**

Runs `az vm show --resource-group {rg} --name {vm} --output json`. Parses the response to
extract the `networkProfile.networkInterfaces` array. Iterates the array looking for the
entry where `primary == true`. Returns the NIC name extracted from the `id` field (last
path segment). If no entry has `primary == true` (uncommon for single-NIC VMs) and the
array has exactly one entry, returns that entry. If neither condition is met, raises
`NICResolutionError`. If the VM itself is not found in the response, raises
`VMNotFoundError`.

**`_call_with_retry` retry policy:**
- Exit code 0: parse stdout JSON and return.
- `"AuthorizationFailed"` in stderr: raise `RBACError` immediately (do not retry).
- `"ResourceNotFound"` or `"NotFound"` in stderr during `az vm show`: raise `VMNotFoundError` immediately.
- `is_throttle(stderr)` returns `True`: wait with exponential backoff (`initial_delay=2s`, multiplier `2`, jitter `±0.5s`), retry up to `max_retries=5`. After exhausting retries, raise `ThrottleExhausted`.
- Any other non-zero exit: raise `ProviderError(stderr)` immediately.

**RBAC permissions required:**

| Operation | Azure permission |
|---|---|
| `az vm show` (NIC resolution) | `Microsoft.Compute/virtualMachines/read` |
| `az network nic list-effective-nsg` | `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` |

---

### 1.3 `nsg_preprocessor.py`

Copied unchanged from the `azure-security-rule-resolver` Claude Code skill.
Its interface is fixed. This design does not modify it.

| Function | Signature | Single Responsibility |
|---|---|---|
| `preprocess` | `(path: str) -> dict` | Read raw NSG JSON file; return normalised gates with sorted rule lists, or an error structure |

**Return structure on success:**

```
{
  "gate_count":     int,              -- number of NSG entries found (0, 1, or 2)
  "gates":          list[GateEntry], -- one entry per NSG (subnet or NIC)
  "parse_warnings": list[str]        -- always present; may be empty
}
```

**`GateEntry` structure:**

```
{
  "gate":             str,   -- "subnet-nsg" | "nic-nsg" | positional fallback ("nsg-1"...)
  "nsg_name":         str,   -- last path segment of the NSG resource ID
  "nsg_id":           str,   -- full ARM resource ID of the NSG
  "association_type": str,   -- "subnet" | "networkInterface" | "unknown"
  "association_id":   str,   -- ARM resource ID of the associated subnet or NIC
  "inbound_rules":    list[NsgRuleObject], -- Inbound rules sorted by priority ascending
  "outbound_rules":   list[NsgRuleObject]  -- Outbound rules sorted by priority ascending
}
```

**Return structure on error (file not found or invalid JSON only):**

```
{
  "error": str
}
```

No `parse_warnings` key when `"error"` is present. For all other cases (empty result,
unrecognised envelope, no entries) the preprocessor returns the success structure with
`gate_count=0` and a parse warning — it does not use the error structure.

**Orchestrator checks (Stage 3):**
- If `"error"` in result → print `result["error"]` to stderr, exit 2.
- If `result["gate_count"] == 0` → print parse warnings, exit 2 (`"No NSG entries found"`).
- Otherwise proceed with `result["gates"]` and forward `result["parse_warnings"]`.

**How the preprocessor identifies subnet vs. NIC NSG:**

Reads `entry["association"]` for each NSG entry. `"subnet"` key present → `gate = "subnet-nsg"`,
`association_type = "subnet"`. `"networkInterface"` key present → `gate = "nic-nsg"`,
`association_type = "networkInterface"`. Neither present → positional fallback label,
`association_type = "unknown"`, parse warning emitted.

**What the preprocessor does per gate:**

1. Extracts all `effectiveSecurityRules` from the entry.
2. Normalises each rule via `_normalize_rule()` → `NsgRuleObject` (see §2.4).
3. Separates rules into inbound and outbound lists by `direction` field.
4. Sorts each list by `priority` ascending (lower number = higher precedence).
5. Runs `_detect_shadows()` over each sorted list, setting `shadowed_by` on shadowed rules.

Because the preprocessor sorts and shadow-detects, the engine receives pre-sorted rule lists
and pre-populated `shadowed_by` fields. The engine does not re-sort (sorting is already done)
but does own gate-order assignment (which gate is evaluated first per direction — the
preprocessor does not encode evaluation order).

---

### 1.4 `nsg_engine.py`

A pure-function module. No I/O. No side effects. All functions are deterministic for
identical inputs.

| Function | Signature | Single Responsibility |
|---|---|---|
| `evaluate_verdict` | `(rule_sets: dict, traffic: TrafficTuple) -> dict` | Apply the Azure dual-gate model; return a complete verdict structure |
| `audit` | `(rule_sets: dict) -> dict` | Produce full rule inventory and findings across both gates and both directions |
| `_evaluate_gate` | `(rules: list[NsgRuleObject], traffic: TrafficTuple) -> GateResult` | Evaluate a single gate's rule set against traffic; return gate result |
| `_match_rule` | `(rule: NsgRuleObject, traffic: TrafficTuple) -> bool \| None` | Return `True` if rule matches; `False` if rule definitively does not match; `None` if match cannot be determined (UNRESOLVABLE) |
| `_is_unresolvable` | `(value: str) -> bool` | Return `True` if value cannot be matched against an IP address (not a valid IP CIDR and not `*`) |
| `_collect_shadows` | `(rules: list[NsgRuleObject], gate: str, direction: str) -> list[ShadowedRule]` | Convert preprocessor-populated `shadowed_by` fields into `ShadowedRule` objects; look up the shadowing rule by name in the same list |
| `_detect_permissive` | `(rules: list[NsgRuleObject], gate: str, direction: str) -> list[PermissiveRule]` | Return list of custom ALLOW rules with wildcard source, destination, or port |

**`evaluate_verdict` — dual-gate dispatch:**

Gate assignment by direction (architecture D5):
- Inbound: Gate 1 = subnet NSG; Gate 2 = NIC NSG
- Outbound: Gate 1 = NIC NSG; Gate 2 = subnet NSG

**Gate extraction from preprocessor output:** The `rule_sets["gates"]` list contains one
entry per NSG. Identify each gate by `gate_entry["association_type"]`: `"subnet"` is the
subnet gate; `"networkInterface"` is the NIC gate. If an expected gate is absent from the
list (no entry with the required `association_type`), treat it as an empty rule set.

Sequence:
1. Find the Gate 1 `GateEntry` from `rule_sets["gates"]` by `association_type`. Extract the
   relevant rule list (`inbound_rules` or `outbound_rules` per `traffic.direction`). The
   preprocessor has already sorted this list by priority ascending — the engine does not
   re-sort.
2. Call `_evaluate_gate(gate1_rules, traffic)` → `gate1_result`.
3. If `gate1_result.verdict == "DENY"`: set Gate 2 as not evaluated (`skip_reason = "PRIOR_GATE_DENY"`).
4. If `gate1_result.verdict == "INDETERMINATE"`: set Gate 2 as not evaluated (`skip_reason = "PRIOR_GATE_INDETERMINATE"`).
5. If `gate1_result.verdict == "ALLOW"`: find Gate 2 `GateEntry` by `association_type`;
   extract the relevant rule list; call `_evaluate_gate(gate2_rules, traffic)` → `gate2_result`.
6. Apply INDETERMINATE propagation table (architecture D15) to determine `final_verdict`.
7. Compute `shadowed_rules` by calling `_collect_shadows` on Gate 1's rule list and Gate 2's
   rule list; concatenate the results.
8. Collect all UNRESOLVABLE rules encountered across both gates into `unresolvable_rules`.

**`audit` — full rule inventory and findings:**

**Gate extraction:** Same as `evaluate_verdict` — find each `GateEntry` in `rule_sets["gates"]`
by `association_type`. If a gate is absent, treat as empty with `nsg_absent = True`.

Sequence:
1. Locate the subnet `GateEntry` and NIC `GateEntry` from `rule_sets["gates"]`. The preprocessor
   has already sorted `inbound_rules` and `outbound_rules` within each entry.
2. For each of the four rule sets (subnet inbound, subnet outbound, NIC inbound, NIC outbound):
   call `_collect_shadows(rule_list, gate, direction)` → append to `shadowed_rules`.
3. For each of the four rule sets: call `_detect_permissive(rule_list, gate, direction)` →
   append to `permissive_rules`.
4. For each of the four rule sets: determine if default-only. A rule set is default-only if
   it is empty (no NSG associated, `nsg_absent = True`) or every rule has `is_default == True`
   (`nsg_absent = False`). Record in `default_only_gates`.
5. Assemble the full rule inventory keyed by gate and direction (§2.10 schema).

The `audit` function returns the full structure without identity fields (`session_id`, `vm_name`,
`resource_group`, `nic_name`). The orchestrator adds these before writing the artifact.

**`_evaluate_gate` — single gate evaluation:**

Iterates rules in the order received (caller must have sorted by priority ascending). For each rule:
1. Call `_match_rule(rule, traffic)`.
2. If `True`: gate verdict = rule's `access` field (`"Allow"` → `"ALLOW"`, `"Deny"` → `"DENY"`). Decisive rule = this rule. Stop.
3. If `None` (UNRESOLVABLE): gate verdict = `"INDETERMINATE"`. Unresolvable rule = this rule. Stop.
4. If `False`: continue to next rule.

If the rule list is empty (no NSG associated with this gate): return `GateResult` with `verdict = "ALLOW"`, `decisive_rule = null`. An empty rule list means no NSG is associated — Azure passes traffic with no restriction. This is distinct from an NSG that evaluated and produced ALLOW: `decisive_rule` is null in this case. The caller emits a parse warning for empty rule sets.

If all rules evaluate to `False` and the list is non-empty: this should not occur in practice because Azure always includes a `DenyAllInBound` / `DenyAllOutBound` default rule at priority 65500 with `source_address = "*"`, `destination_address = "*"`, and `destination_ports = ["0-65535"]` — which matches every packet. If it occurs (malformed preprocessor output), return `verdict = "DENY"` with a parse warning and `decisive_rule = null`.

**`_match_rule` — rule matching logic:**

Returns `True` (match), `False` (definitive no-match), or `None` (UNRESOLVABLE).

Protocol check:
- Rule protocol `"*"` or `"All"` (case-insensitive): matches any protocol; continue.
- Rule protocol matches `traffic.protocol` exactly (case-insensitive): continue.
- Otherwise: return `False`.

Source address check:
- Split `rule.source_address` on `", "` to get individual values (a single address produces a
  one-element list). Apply OR semantics — any value matching means the source dimension matches.
- For each value:
  - If `_is_wildcard_address(value)` (see below): source dimension matches; continue to destination check.
  - If `_is_unresolvable(value)`: return `None`.
  - If `ipaddress.ip_address(traffic.src_ip)` is contained in `ipaddress.ip_network(value, strict=False)`: source dimension matches; continue to destination check.
- If no value matched and none was unresolvable: return `False`.

Destination address check: same logic as source, applied to `traffic.dst_ip` against `rule.destination_address` (split on `", "`).

Source port: not checked. The tool does not accept a source port as an investigation input — source ports are ephemeral and outside the traffic description. Regardless of the rule's `source_ports` value, the source port dimension is always treated as matching. Source port restrictions in NSG rules are rare and not part of the evaluation contract for this tool.

Destination port check:
- For each range in `rule.destination_ports` (OR semantics):
  - If `"*"` or `"0-65535"`: all remaining dimensions matched; return `True`.
  - If range contains `"-"`: parse `low, high = range.split("-")`; if `int(low) <= traffic.dst_port <= int(high)`: return `True`.
  - If range is a single number: if `int(range) == traffic.dst_port`: return `True`.
- If no range matched: return `False`.

**`_is_wildcard_address` — wildcard detection:**

```
def _is_wildcard_address(value: str) -> bool:
    return value.strip().lower() in ("*", "any", "0.0.0.0/0", "::/0")
```

Called before `_is_unresolvable`. Matches the same wildcard set the preprocessor's
`_address_is_wildcard()` uses. `"Any"` appears in some Azure API output variants.
`"0.0.0.0/0"` and `"::/0"` are valid CIDRs that also mean wildcard and must be treated as
matching before attempting IP containment.

**`_is_unresolvable` — value classification:**

```
def _is_unresolvable(value: str) -> bool:
    if _is_wildcard_address(value):
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return False   # valid IP CIDR
    except ValueError:
        return True    # service tag, ASG name, or other non-CIDR string
```

Called after `_is_wildcard_address` returns `False`. Standard service tags
(`VirtualNetwork`, `Internet`, `AzureLoadBalancer`) should already have been expanded to
CIDRs by the preprocessor using `expandedSourceAddressPrefix`. If they appear unexpanded
(the preprocessor fell back to the tag name), they fail the `ip_network` parse and are
correctly classified as UNRESOLVABLE — fail-closed behavior.

**`_collect_shadows` — shadow result assembly:**

The preprocessor already ran shadow detection during normalisation and set `shadowed_by`
on each rule that it determined to be unreachable. `_collect_shadows` converts those
populated fields into `ShadowedRule` objects for inclusion in the artifact.

Sequence: iterate the rule list. For each rule R where `R.shadowed_by is not None`:
- Find the rule S in the same list where `S.name == R.shadowed_by`.
- If S is found: emit `ShadowedRule(rule=R, shadowed_by=S, gate=gate, direction=direction)`.
- If S is not found (name mismatch or removed rule): emit a parse warning; skip.

**Preprocessor shadow detection semantics:** The preprocessor marks a rule as shadowed only
when the higher-priority rule satisfies all of: wildcard protocol (`"*"` or `"All"`),
wildcard destination ports (`"*"` or `"0-65535"`), wildcard source address, and wildcard
destination address. Partial-overlap cases (e.g., same protocol but narrower port range) are
not marked. This conservative definition prevents false positives but may miss shadows where
a sequence of specific rules together covers another rule's traffic space — that is a known
limitation of the preprocessor's algorithm and is acceptable given it is copied unchanged.

**`_detect_permissive` — permissive rule detection:**

A rule is permissive if all of:
1. `rule.access == "Allow"`
2. `rule.is_default == False` (custom rule, not an Azure default)
3. At least one of:
   - `_is_wildcard_address(rule.source_address)` — wildcard source
   - `_is_wildcard_address(rule.destination_address)` — wildcard destination
   - `"*" in rule.destination_ports or "0-65535" in rule.destination_ports` — wildcard port

Returns a `PermissiveRule` per matching rule, recording which dimensions are wildcarded.

---

## 2. Data Schemas

### 2.1 CLI Arguments

| Flag | Type | Required | Default | Notes |
|---|---|---|---|---|
| `--vm-name` | `str` | Yes | — | Azure VM name |
| `--resource-group` | `str` | Yes | — | Resource group containing the VM |
| `--src-ip` | `str` | Verdict only | `None` | Source IP address |
| `--dst-ip` | `str` | Verdict only | `None` | Destination IP address |
| `--dst-port` | `int` | Verdict only | `None` | Destination port (1–65535) |
| `--proto` | `str` | Verdict only | `None` | `tcp`, `udp`, `icmp`, or `*` |
| `--direction` | `str` | Verdict only | `None` | `inbound` or `outbound` |
| `--nic-name` | `str` | No | `None` | Override primary NIC resolution; skips `get_nic_name` call |
| `--subscription-id` | `str` | No | `None` | Defaults to active az CLI subscription |
| `--session-id` | `str` | No | auto-generated | `nsg_` prefix enforced; auto-generated if absent |
| `--audit-dir` | `str` | No | `./audit` | Directory for artifact writes |

**Mode detection** (in `_detect_mode`): The five traffic flags (`--src-ip`, `--dst-ip`,
`--dst-port`, `--proto`, `--direction`) must all be provided together (verdict mode) or all
omitted (audit mode). A partial set — any nonzero count fewer than five — is a fatal input
error (exit 2).

**Validation applied in `_validate_traffic_tuple`:**
- `--src-ip`, `--dst-ip`: pass through `ipaddress.ip_address()`. Invalid → exit 2.
- `--dst-port`: `1 <= value <= 65535`. Out of range → exit 2.
- `--proto`: case-insensitive; normalised to `"Tcp"`, `"Udp"`, `"Icmp"`, or `"*"`. Other values → exit 2.
- `--direction`: case-insensitive; normalised to `"Inbound"` or `"Outbound"`. Other values → exit 2.

---

### 2.2 Session ID Format

Auto-generated format: `nsg_YYYYMMDD_HHMMSS` (UTC, zero-padded).

Artifact files use `{session_id}` directly as the filename prefix. Because `_enforce_session_prefix`
guarantees the session ID starts with `nsg_`, artifact files always start with `nsg_`. This is how
D8 is satisfied — the prefix comes from the session ID itself, not from an additional naming
step. Artifact file patterns:

```
{session_id}_raw.json       e.g.  nsg_20260413_142000_raw.json
{session_id}_verdict.json   e.g.  nsg_20260413_142000_verdict.json
{session_id}_audit.json     e.g.  nsg_20260413_142000_audit.json
```

Rationale over UUID: timestamp IDs are human-readable and self-documenting in the audit
directory listing. Two invocations in the same second will produce the same ID — collision
detection in `_check_collision` will cause the second invocation to exit 2. See §6 Edge Cases.

Prefix enforcement: `_enforce_session_prefix` prepends `nsg_` if the supplied ID does not
start with it. If the user passes `nsg_myrun`, it is used unchanged. If the user passes
`myrun`, it becomes `nsg_myrun`.

Collision check glob: `_check_collision` checks for `{session_id}_*.json` in `audit_dir`. Because
`session_id` already starts with `nsg_`, this glob is scoped to this tool's artifacts only.

---

### 2.3 `TrafficTuple` (internal named tuple)

| Field | Type | Meaning |
|---|---|---|
| `src_ip` | `str` | Source IP address (validated by `ipaddress.ip_address`) |
| `dst_ip` | `str` | Destination IP address |
| `dst_port` | `int` | Destination port number |
| `protocol` | `str` | `"Tcp"`, `"Udp"`, `"Icmp"`, or `"*"` |
| `direction` | `str` | `"Inbound"` or `"Outbound"` |

Source port is not included. Source ports are ephemeral and are not part of the connectivity
investigation contract. The `_match_rule` function always treats the source port dimension as
matching, regardless of the rule's configured `source_ports`.

---

### 2.4 `NsgRuleObject` — normalised rule (produced by `nsg_preprocessor.py`)

| Field | Type | Source | Notes |
|---|---|---|---|
| `name` | `str` | `name` | Rule name as returned by Azure |
| `priority` | `int` | `priority` | Azure priority; lower number = higher precedence |
| `direction` | `str` | `direction` | `"Inbound"` or `"Outbound"` |
| `access` | `str` | `access` | `"Allow"` or `"Deny"` |
| `protocol` | `str` | `protocol` | `"Tcp"`, `"Udp"`, `"Icmp"`, `"All"`, or `"*"` — `"All"` is preserved as-is (not converted to `"*"`) |
| `source_address` | `str` | `expandedSourceAddressPrefix` if non-empty, else `sourceAddressPrefixes`, else `sourceAddressPrefix` | Single string; multiple values are comma-space-joined e.g. `"10.0.0.0/16, 10.1.0.0/24"`; `"*"` for wildcard |
| `source_ports` | `list[str]` | `sourcePortRanges` if present, else `sourcePortRange` | Port strings or ranges e.g. `["22"]`, `["1024-65535"]`, `["*"]`, `["0-65535"]` |
| `destination_address` | `str` | `expandedDestinationAddressPrefix` if non-empty, else `destinationAddressPrefixes`, else `destinationAddressPrefix` | Same format as `source_address` |
| `destination_ports` | `list[str]` | `destinationPortRanges` if present, else `destinationPortRange` | Port strings or ranges |
| `is_default` | `bool` | derived from `priority` | `True` if `priority >= 65000` (Azure default rule range) |
| `shadowed_by` | `str \| None` | set by preprocessor's `_detect_shadows()` | Name of the higher-priority rule that shadows this one; `None` if not shadowed |

**Address field canonicalisation:** The preprocessor's `_address()` function prefers
`expandedSourceAddressPrefix` (resolved CIDRs) over `sourceAddressPrefixes` over
`sourceAddressPrefix`. Multiple values are comma-space-joined into a single string. The
engine must split `source_address` and `destination_address` on `", "` to get individual
prefix values for matching.

**Protocol handling:** Azure returns `"All"` for wildcard protocol in effective NSG JSON.
The preprocessor preserves it as `"All"` — it does not convert to `"*"`. The engine's
`_match_rule` must treat both `"All"` and `"*"` as wildcards.

**Port range `"0-65535"`:** This is how Azure expresses wildcard ports in some versions.
The preprocessor preserves it as-is. The engine's port matching must treat `"0-65535"` as
equivalent to `"*"` (covers all ports 0–65535).

**Shadow detection:** `shadowed_by` is populated by the preprocessor's conservative shadow
algorithm. A rule is only marked shadowed if a higher-priority rule has wildcard protocol,
wildcard ports, and wildcard source and destination addresses. Rules with partial overlaps
(e.g., same protocol but different ports) are not marked shadowed by the preprocessor.
The engine uses `shadowed_by` directly — it does not re-run shadow detection.

---

### 2.5 `GateResult` (internal, used within verdict structure)

| Field | Type | Notes |
|---|---|---|
| `gate` | `str` | `"subnet"` or `"nic"` |
| `verdict` | `str \| None` | `"ALLOW"`, `"DENY"`, `"INDETERMINATE"`, or `null` if gate was not evaluated |
| `decisive_rule` | `NsgRuleObject \| None` | The rule that produced the verdict; `null` when INDETERMINATE, not evaluated, or ALLOW from empty rule set (no NSG) |
| `unresolvable_rule` | `NsgRuleObject \| None` | The rule that halted evaluation; `null` unless `verdict == "INDETERMINATE"` |
| `evaluated` | `bool` | `False` when the gate was skipped due to a prior gate result |
| `skip_reason` | `str \| None` | `"PRIOR_GATE_DENY"` or `"PRIOR_GATE_INDETERMINATE"` when `evaluated == False`; `null` otherwise |

**`decisive_rule` null cases:** `decisive_rule` is `null` in three situations: (a) the gate was
not evaluated (`evaluated == False`); (b) the verdict is `"INDETERMINATE"` (an unresolvable rule
stopped evaluation — the rule is in `unresolvable_rule` instead); (c) the verdict is `"ALLOW"`
from an empty rule set (no NSG associated). Consumers must not assume ALLOW means `decisive_rule`
is populated.

---

### 2.6 `ShadowedRule` (internal, included in artifacts)

| Field | Type | Notes |
|---|---|---|
| `rule` | `NsgRuleObject` | The shadowed (unreachable) rule |
| `shadowed_by` | `NsgRuleObject` | The higher-priority rule whose traffic space is a superset |
| `gate` | `str` | `"subnet"` or `"nic"` |
| `direction` | `str` | `"Inbound"` or `"Outbound"` |

---

### 2.7 `PermissiveRule` (internal, included in audit artifact)

| Field | Type | Notes |
|---|---|---|
| `rule` | `NsgRuleObject` | The permissive custom ALLOW rule |
| `gate` | `str` | `"subnet"` or `"nic"` |
| `direction` | `str` | `"Inbound"` or `"Outbound"` |
| `wildcard_dimensions` | `list[str]` | Subset of `["source", "destination", "port"]` indicating which dimensions are wildcarded |

---

### 2.8 Raw Artifact — `{session_id}_raw.json`

**Owner:** `security_rule_inspector.py` (Stage 2 write)

The raw file is the exact parsed JSON returned by `az network nic list-effective-nsg`.
No field is filtered or modified before writing. The nsg_preprocessor reads this file path
directly.

**Envelope formats:** The preprocessor handles four formats (in priority order):

| Format | Top-level structure | Notes |
|---|---|---|
| 1 | `{"value": [...]}` | Primary format from `az network nic list-effective-nsg` |
| 2 | `{"networkSecurityGroups": [...]}` | Alternative format seen in some API versions |
| 3 | `[{...}, ...]` | Raw list from `az --query` flattening |
| 4 | `{"effectiveSecurityRules": [...]}` | Single NSG, no wrapper |

The raw file written by Stage 2 will be Format 1 (the az CLI default output). The
preprocessor's format tolerance ensures the fixture files and other ad-hoc inputs are also
accepted.

**Primary format (Format 1) structure:**
```
{
  "value": [
    {
      "networkSecurityGroup": {
        "id": str                              -- ARM resource ID of the NSG
      },
      "association": {
        "subnet": { "id": str, ... }           -- present for subnet NSG entry
        -- OR --
        "networkInterface": { "id": str, ... } -- present for NIC NSG entry
      },
      "effectiveSecurityRules": [
        {
          "name":                              str,
          "protocol":                          str,  -- "Tcp", "Udp", "Icmp", "All"
          "sourceAddressPrefix":               str,
          "sourceAddressPrefixes":             list[str],  -- may be absent
          "expandedSourceAddressPrefix":       list[str],  -- may be absent or empty
          "destinationAddressPrefix":          str,
          "destinationAddressPrefixes":        list[str],
          "expandedDestinationAddressPrefix":  list[str],
          "sourcePortRange":                   str,
          "sourcePortRanges":                  list[str],  -- may be absent
          "destinationPortRange":              str,
          "destinationPortRanges":             list[str],
          "access":                            str,  -- "Allow" or "Deny"
          "priority":                          int,
          "direction":                         str   -- "Inbound" or "Outbound"
        }
      ]
    }
  ]
}
```

Not all fields are present in every rule. The fixtures demonstrate that simpler rules
(no expanded prefixes, no plural port arrays) are valid inputs — the preprocessor handles
absent fields gracefully.

---

### 2.9 Verdict Artifact — `{session_id}_verdict.json`

**Owner:** `security_rule_inspector.py` (Stage 4 write, verdict mode)

```
{
  "session_id":      str,               -- e.g. "nsg_20260413_142000"
  "mode":            "verdict",
  "vm_name":         str,
  "resource_group":  str,
  "nic_name":        str,
  "traffic": {
    "src_ip":        str,
    "dst_ip":        str,
    "dst_port":      int,
    "protocol":      str,               -- normalised: "Tcp", "Udp", "Icmp", or "*"
    "direction":     str                -- "Inbound" or "Outbound"
  },
  "gate_order":      list[str],         -- e.g. ["nic", "subnet"] for outbound
  "gate1": {
    "gate":              str,           -- "nic" or "subnet"
    "verdict":           str | null,    -- "ALLOW", "DENY", "INDETERMINATE"; null if not evaluated
    "decisive_rule":     NsgRuleObject | null,
    "unresolvable_rule": NsgRuleObject | null,
    "evaluated":         bool,
    "skip_reason":       str | null
  },
  "gate2": {
    "gate":              str,
    "verdict":           str | null,
    "decisive_rule":     NsgRuleObject | null,
    "unresolvable_rule": NsgRuleObject | null,
    "evaluated":         bool,
    "skip_reason":       str | null
  },
  "final_verdict":      str,            -- "ALLOW", "DENY", or "INDETERMINATE"
  "shadowed_rules":     list[ShadowedRule],
  "unresolvable_rules": list[NsgRuleObject],
  "parse_warnings":     list[str]
}
```

**Invariants:**
- `gate_order` always contains two elements.
- `gate1.evaluated` is always `true`. Gate 1 is always evaluated.
- When `gate2.evaluated == false`, `gate2.verdict` is `null` and `gate2.skip_reason` is set.
- `shadowed_rules` is computed across both gates regardless of whether Gate 2 was evaluated.
- `unresolvable_rules` contains at most two rules — one per gate — since evaluation stops at the first UNRESOLVABLE rule per gate, and Gate 2 is skipped when Gate 1 is INDETERMINATE.
- `parse_warnings` is always present; may be empty.

---

### 2.10 Audit Artifact — `{session_id}_audit.json`

**Owner:** `security_rule_inspector.py` (Stage 4 write, audit mode)

```
{
  "session_id":      str,
  "mode":            "audit",
  "vm_name":         str,
  "resource_group":  str,
  "nic_name":        str,
  "rule_sets": {
    "inbound": {
      "gate1": {
        "gate":  "subnet",
        "rules": list[NsgRuleObject]    -- sorted by priority ascending
      },
      "gate2": {
        "gate":  "nic",
        "rules": list[NsgRuleObject]
      }
    },
    "outbound": {
      "gate1": {
        "gate":  "nic",
        "rules": list[NsgRuleObject]
      },
      "gate2": {
        "gate":  "subnet",
        "rules": list[NsgRuleObject]
      }
    }
  },
  "findings": {
    "shadowed_rules":      list[ShadowedRule],
    "permissive_rules":    list[PermissiveRule],
    "default_only_gates":  list[DefaultOnlyGate]
  },
  "parse_warnings":  list[str]
}
```

**`DefaultOnlyGate`:**

```
{
  "gate":       str,   -- "subnet" or "nic"
  "direction":  str,   -- "Inbound" or "Outbound"
  "nsg_absent": bool   -- true: no NSG associated with this gate
                       -- false: NSG present but contains only Azure default rules
}
```

A gate is default-only when: its rule list is empty (`nsg_absent == true`), or every rule in
the sorted rule set has `is_default == True` (`nsg_absent == false`). Both are reported as
`DefaultOnlyGate` entries — the `nsg_absent` field distinguishes them. Ghost Agent must treat
these differently: `nsg_absent` means traffic passes without NSG evaluation; `nsg_absent == false`
means traffic passes through Azure's standard defaults (deny-all at 65500).

---

## 3. Pipeline Stage Detail

### Stage 1 — Validate

**Input:** `sys.argv`

**Processing:**
1. `parse_args()` — declare all flags; return `argparse.Namespace`.
2. `_detect_mode(args)` — determine `"verdict"` or `"audit"` based on traffic flag presence; exit 2 on partial tuple.
3. Verdict mode only: `args.traffic = _validate_traffic_tuple(args)` → `TrafficTuple`; exit 2 on invalid values. Audit mode: `args.traffic = None`.
4. `args.session_id = _enforce_session_prefix(args.session_id or _generate_session_id())`.
5. `audit_path = _ensure_audit_dir(args.audit_dir)`.
6. `_check_collision(args.session_id, audit_path)` — exit 2 if conflict found. Glob: `{args.session_id}_*.json`.

**Output:** Validated `args` namespace with `args.traffic` set; `audit_path: Path`

**Failure modes:**

| Condition | Stderr message | Exit |
|---|---|---|
| Required flag missing (`--vm-name`, `--resource-group`) | argparse default usage | 2 |
| Partial traffic tuple (1–4 of 5 fields provided) | `"Verdict mode requires all five: --src-ip, --dst-ip, --dst-port, --proto, --direction"` | 2 |
| `--src-ip` or `--dst-ip` not a valid IP | `"Invalid IP address: {value}"` | 2 |
| `--dst-port` out of range | `"Invalid port: {value} — must be 1–65535"` | 2 |
| `--proto` unrecognised | `"Invalid protocol: {value} — must be tcp, udp, icmp, or *"` | 2 |
| `--direction` unrecognised | `"Invalid direction: {value} — must be inbound or outbound"` | 2 |
| `audit_dir` not creatable | `"Cannot create audit directory: {path}: {reason}"` | 2 |
| Session ID collision | `"Session ID {id} already has artifacts in {audit_dir} — supply a new --session-id"` | 2 |

No Azure calls in Stage 1.

---

### Stage 2 — Collect

**Input:** `args`, `audit_path: Path`, `provider: NSGProvider`

**Processing:**
1. Resolve provider: use supplied `provider` argument if present (test seam); otherwise instantiate `AzureNSGProvider(subscription_id=args.subscription_id)`.
2. Resolve NIC name:
   - If `args.nic_name` is set: use directly; print `"Using NIC override: {nic_name}"` to stdout.
   - Else: print `"Resolving primary NIC for {vm_name}..."` to stdout; call `provider.get_nic_name(args.vm_name, args.resource_group)`.
3. Print `"Querying effective NSG for {nic_name}..."` to stdout.
4. Call `provider.get_effective_nsg(nic_name, args.resource_group)` → `raw_dict`.
5. Write `raw_dict` as JSON to `audit_path / f"{args.session_id}_raw.json"`.

**Output:** `raw_file_path: Path`, `nic_name: str`

**Failure modes:** Any `ProviderError` subtype → print specific message to stderr (see §4 Error Handling), exit 2. The raw file is written only after a successful query — no partial write on failure.

---

### Stage 3 — Preprocess

**Input:** `raw_file_path: Path`

**Processing:**
1. Call `nsg_preprocessor.preprocess(str(raw_file_path))`.
2. If `"error"` in result: print `result["error"]` to stderr, exit 2. (Only for file-not-found and invalid JSON.)
3. If `result["gate_count"] == 0`: print `"No NSG entries found in {raw_file_path}"` and any `parse_warnings` to stderr, exit 2.
4. Extract: `rule_sets = result` (full dict); `parse_warnings = result["parse_warnings"]`.

**Output:** `rule_sets: dict`, `parse_warnings: list[str]`

**Failure modes:**

| Condition | Stderr message | Exit |
|---|---|---|
| Raw file not found | `result["error"]` from preprocessor | 2 |
| Raw file not valid JSON | `result["error"]` from preprocessor | 2 |
| No NSG entries parsed (`gate_count == 0`) | `"No NSG entries found in {path}"` + parse warnings | 2 |

---

### Stage 4 — Evaluate

**Input:** `rule_sets: dict`, `parse_warnings: list[str]`, `args` (carries `args.traffic`), `nic_name: str`, `audit_path: Path`

**Processing:**
1. Dispatch by mode:
   - Verdict mode: `result = nsg_engine.evaluate_verdict(rule_sets, args.traffic)`
   - Audit mode: `result = nsg_engine.audit(rule_sets)`
2. Enrich result with identity fields: set `result["session_id"]`, `result["vm_name"]`, `result["resource_group"]`, `result["nic_name"]`. The engine returns these fields absent — the orchestrator adds them before serialisation.
3. Merge `parse_warnings` into `result["parse_warnings"]` (engine may have added its own from empty rule sets).
4. Write artifact:
   - Verdict mode: `audit_path / f"{args.session_id}_verdict.json"` (JSON, `indent=2`)
   - Audit mode: `audit_path / f"{args.session_id}_audit.json"` (JSON, `indent=2`)

**Output:** `result: dict`, `artifact_path: Path`

**Failure modes:** `nsg_engine` functions are pure and do not raise. The only failure path is the file write. If write fails: print path and OS error to stderr, exit 2.

---

### Stage 5 — Output

**Input:** `result: dict`, mode string, `artifact_path: Path`

**Processing:**
1. Print `_render_verdict_table(result)` or `_render_audit_table(result)` to stdout.
2. Print `"Artifact: {artifact_path}"` to stdout.
3. If `result["parse_warnings"]` is non-empty, print each warning to stdout prefixed with `"Warning: "`.

The console output is always derived from the artifact dict — never computed separately.
The artifact is written before Stage 5 runs; Stage 5 is display only.

`_render_audit_table` generates a posture summary section deterministically from the
findings: it identifies whether any direction is effectively blocked (high-priority deny rule
at gate 1 that covers all traffic), names the blocking rule and gate, and states whether the
result holds regardless of gate 2. This is template-driven; the data is in the findings.

**Output:** Human-readable table and optional warnings printed to stdout. Return exit code `0`.

---

### Exit Code Policy

| Condition | Exit code |
|---|---|
| Artifact written successfully; result is valid | `0` |
| Any fatal error — no artifact written | `2` |

Exit code `1` is not used by this tool. A single-NIC, single-invocation tool either fully
succeeds or fatally fails — there is no partial-result scenario. If multi-NIC scope is added
in future, exit code `1` semantics must be defined at that time.

---

## 4. Error Handling Strategy

### 4.1 RBAC Error Format

When `RBACError` is raised, print to stderr:

```
ERROR: Authorization failed.
  Missing permission: {permission}
  Required for:       {operation}
  Grant 'Network Contributor' or a custom role with this action on the resource group.
```

Permissions to detect and name:

| az CLI error substring | Permission | Operation |
|---|---|---|
| `effectiveNetworkSecurityGroups/action` | `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | `az network nic list-effective-nsg` |
| `virtualMachines/read` | `Microsoft.Compute/virtualMachines/read` | `az vm show` (NIC resolution) |
| *(fallback)* | *(full stderr excerpt)* | *(unknown operation)* |

---

### 4.2 Full Error Table

| Error | Behavior | Exit |
|---|---|---|
| Partial traffic tuple | Print message to stderr | 2 |
| Invalid IP address (src or dst) | Print message to stderr | 2 |
| Invalid port number | Print message to stderr | 2 |
| Invalid protocol value | Print message to stderr | 2 |
| Invalid direction value | Print message to stderr | 2 |
| `audit_dir` not creatable | Print path and OS error to stderr | 2 |
| Session ID collision | Print session ID and audit_dir to stderr | 2 |
| `RBACError` during NIC resolution | Print RBAC error (§4.1) to stderr | 2 |
| `VMNotFoundError` | Print VM name and resource group to stderr | 2 |
| `NICResolutionError` (no primary flag) | Print VM name and error message to stderr | 2 |
| `ThrottleExhausted` | Print attempts count and final wait duration to stderr | 2 |
| `ProviderError` (generic) | Print stderr excerpt to stderr | 2 |
| Non-JSON az CLI response | `ProviderError` raised with raw stdout excerpt | 2 |
| az CLI timeout | `ProviderError` raised with timeout message | 2 |
| Preprocessor returns error | Print error string to stderr | 2 |
| Artifact write failure | Print path and OS error to stderr | 2 |

---

## 5. Human-Readable Output Formats

### 5.1 Verdict Mode — `_render_verdict_table`

Printed to stdout in Stage 5, after the artifact is written.

```
Traffic:        10.1.0.5 → 10.2.0.10:1433 TCP outbound

Gate 1 (NIC NSG — evaluated first for outbound):
  Rule matched:   deny-all-outbound (priority 1000)
  Decision:       DENY
  Gate 2:         Not evaluated (prior gate DENY)

Final verdict:  DENY

Shadowed rules: allow-sql-outbound (priority 2000) — matches same traffic,
                unreachable because deny-all-outbound at 1000 takes precedence

Unresolvable:   (none)

Artifact:       ./audit/nsg_20260413_142000_verdict.json
────────────────────────────────────────────────────────
```

When Gate 2 is evaluated:
```
Gate 1 (Subnet NSG — evaluated first for inbound):
  Rule matched:   AllowHttpsInbound (priority 200)
  Decision:       ALLOW

Gate 2 (NIC NSG — evaluated second for inbound):
  Rule matched:   DenyAllInBound (priority 65500)
  Decision:       DENY

Final verdict:  DENY
```

When the verdict is INDETERMINATE:
```
Gate 1 (NIC NSG — evaluated first for outbound):
  Rule halted:    allow-storage-outbound (priority 300) — source references ASG "app-servers"
  Decision:       INDETERMINATE
  Gate 2:         Not evaluated (prior gate INDETERMINATE)

Final verdict:  INDETERMINATE

Unresolvable:   allow-storage-outbound (priority 300)
                  source: ASG "app-servers" — membership not available in effective NSG JSON
                  Provide ASG member IP addresses to resolve.
```

When the gate has no NSG (ALLOW from empty rule set):
```
Gate 1 (Subnet NSG — evaluated first for inbound):
  No NSG associated — gate imposes no restriction
  Decision:       ALLOW
```

When no shadowed rules: `Shadowed rules: (none)`

---

### 5.2 Audit Mode — `_render_audit_table`

Printed to stdout in Stage 5.

```
VM:   app-vm  (rg-networking)
NIC:  app-vm-nic

─── INBOUND ─────────────────────────────────────────────────────────────────

Subnet NSG (evaluated first for inbound):
  Priority  Name                      Action  Protocol  Source               Destination    Port
  100       DenyAllInbound            DENY    *         *                    *              *
  65000     AllowVnetInBound          ALLOW   *         VirtualNetwork       VirtualNetwork *        [default]
  65001     AllowAzureLoadBalancer    ALLOW   *         AzureLoadBalancer    *              *        [default]
  65500     DenyAllInBound            DENY    *         *                    *              *        [default]

NIC NSG (evaluated second for inbound):
  Priority  Name                      Action  Protocol  Source               Destination    Port
  200       allow-https               ALLOW   Tcp       *                    10.1.0.4       443
  65500     DenyAllInBound            DENY    *         *                    *              *        [default]

─── OUTBOUND ────────────────────────────────────────────────────────────────

NIC NSG (evaluated first for outbound):
  Priority  Name                      Action  Protocol  Source               Destination    Port
  65000     AllowVnetOutBound         ALLOW   *         VirtualNetwork       VirtualNetwork *        [default]
  65001     AllowInternetOutBound     ALLOW   *         *                    Internet       *        [default]
  65500     DenyAllOutBound           DENY    *         *                    *              *        [default]

Subnet NSG (evaluated second for outbound):
  (No NSG associated)

─── FINDINGS ────────────────────────────────────────────────────────────────

Shadowed rules:
  (none)

Overly permissive rules:
  (none)

Default-only gates:
  Subnet NSG / Outbound — no NSG associated

Posture summary:
  Inbound traffic is blocked by DenyAllInbound at priority 100 in the subnet NSG.
  No inbound traffic can reach this VM regardless of NIC NSG rules.

Artifact:   ./audit/nsg_20260413_142000_audit.json
────────────────────────────────────────────────────
```

When shadowed rules exist:
```
Shadowed rules:
  [Subnet NSG / Inbound] allow-ssh (priority 500)
    shadowed by: DenyAllInbound (priority 100) — superset on all dimensions
```

When permissive rules exist:
```
Overly permissive rules:
  [NIC NSG / Outbound] allow-all-outbound (priority 200)
    wildcard dimensions: source, destination, port
```

When a default-only gate has an NSG with only default rules:
```
Default-only gates:
  NIC NSG / Inbound — NSG present, no custom rules
```

---

## 6. Edge Cases

### 6.1 Same-second session ID collision

Two invocations in the same second generate the same auto-session ID. The second
invocation hits `_check_collision` (glob `{session_id}_*.json`) and exits 2 with a message
naming the session ID. The first invocation's artifacts are preserved intact.

### 6.2 VM has no NSG on subnet (subnet gate empty)

`az network nic list-effective-nsg` returns a `"value"` array with no entry where
`association.subnet` is present. The preprocessor's `gate_count` reflects only the NIC
gate; no `GateEntry` with `association_type == "subnet"` is produced. A parse warning is
emitted by the preprocessor: `"No NSG entries found"` or the gate is simply absent from
`gates`.

The engine finds no subnet `GateEntry` and treats both subnet rule sets (inbound and
outbound) as empty. Empty rule sets evaluate to ALLOW with `decisive_rule = null` (no NSG
— no restriction). The audit artifact reports the subnet gates as `DefaultOnlyGate` with
`nsg_absent = true`.

### 6.3 VM has no NIC NSG

Same as §6.2 with no `GateEntry` where `association_type == "networkInterface"`. The NIC
gates are treated as empty → ALLOW. The audit artifact reports NIC gates as `DefaultOnlyGate`
with `nsg_absent = true`. Fixture `fx-06-no-nic-nsg.json` exercises this scenario.

### 6.4 Both subnet and NIC NSGs absent

Parse warning emitted for each. All four gates return ALLOW. Final verdict is `"ALLOW"` for
any traffic in verdict mode. All four gates are reported as `default_only` with
`nsg_absent = true` in audit mode.

### 6.5 Stopped (deallocated) VM

`az network nic list-effective-nsg` may return an error for a deallocated VM — Azure
cannot compute effective state for a stopped VM's NIC in all configurations. This surfaces
as `ProviderError` in Stage 2. Tool exits 2 with the provider error message.

### 6.6 INDETERMINATE at Gate 1 — Gate 2 not evaluated

Gate 1 encounters an UNRESOLVABLE rule. Evaluation stops at that rule. Gate 2 is not
evaluated (`skip_reason = "PRIOR_GATE_INDETERMINATE"`). Final verdict is
`"INDETERMINATE"`. The unresolvable rule appears in both `gate1.unresolvable_rule` and
the top-level `unresolvable_rules` list.

### 6.7 INDETERMINATE at Gate 2 only

Gate 1 returns `"ALLOW"`. Gate 2 encounters an UNRESOLVABLE rule. Final verdict is
`"INDETERMINATE"`. The unresolvable rule appears in `gate2.unresolvable_rule`.

### 6.8 Rule with multiple source prefixes, one matching before an unresolvable one

`_match_rule` iterates source prefixes in list order. If a resolvable prefix definitively
matches (IP containment succeeds) before an unresolvable prefix is encountered, the source
dimension matches and evaluation continues to the destination check. The unresolvable prefix
is never reached.

Example: `source_address = "10.1.0.0/16, my-asg"` (split yields `["10.1.0.0/16", "my-asg"]`). Traffic source `10.1.0.5`:
- `10.1.0.0/16` → contained → source matches → proceed to destination check.
- `my-asg` never reached.

This is correct: a rule that already covers the traffic source via a resolvable CIDR can
still produce a verdict.

### 6.9 Rule with `*` protocol and specific destination port

Protocol `*` matches any protocol. The port check is still applied. The rule matches only
if the destination port also matches. Standard NSG evaluation semantics.

### 6.10 NIC with multiple IP configurations

NSG association is at the NIC level, not the IP configuration level. A NIC with multiple IP
configurations has the same effective NSG regardless of which IP is being addressed. The
tool queries at NIC scope. No per-IP-configuration special handling.

### 6.11 `--nic-name` override with wrong NIC

If the caller supplies a NIC name that is not attached to the specified VM,
`az network nic list-effective-nsg` will return the NSG for the wrong NIC (or an error).
The tool has no way to validate NIC ownership when the override is active. This is a caller
responsibility.

### 6.12 Non-empty rule set where all rules evaluate to `False`

Azure always includes a `DenyAllInBound` default rule at priority 65500 with `source_address = "*"`,
`destination_address = "*"`, and `destination_ports = ["0-65535"]`. A non-empty rule set where
no rule matches should not occur. If it does (malformed preprocessor output), `_evaluate_gate`
returns `"DENY"` with `decisive_rule = null` and a parse warning. Failing closed is the
correct behaviour for a non-empty but unexpectedly exhausted rule set.

---

## 7. Intentional Omissions

| Capability | Excluded because |
|---|---|
| Retry logic in `LocalShell` | `LocalShell` is a thin execution layer. Retry is an Azure policy concern owned by `AzureNSGProvider._call_with_retry`. Embedding retry in `LocalShell` would make it a policy component, breaking single-responsibility. Mirrors `effective-network-inspector` and `effective-route-inspector`. |
| SHA-256 sidecar for artifacts | The raw and verdict artifacts are produced and consumed within the same invocation or by the Ghost Agent handler immediately after. No long-lived NSG baseline needs tamper detection between sessions. Architecture D17 (collision detection) provides write safety; integrity checking beyond that is not warranted for this tool. |
| ASG membership resolution | Requires a separate Azure query per ASG. The effective NSG JSON does not contain membership data. Resolving ASG membership would widen the RBAC requirement and could still fail for ASGs in peered VNets. UNRESOLVABLE is the correct behaviour — surfacing the gap is more honest than silently skipping the rule. Architecture D9. |
| Non-standard service tag resolution | Service tag membership (e.g., `Storage.EastUS`) is published by Azure as a weekly-updated JSON file. Embedding or fetching it introduces a freshness dependency. These tags are flagged UNRESOLVABLE. Architecture intentional omissions. |
| Source port in `TrafficTuple` | Source ports are ephemeral and outside the scope of a connectivity investigation. NSG rules with specific source port ranges are rare in practice. Not including source port keeps the investigation model clean and the traffic description unambiguous. |
| `_match_rule` returning per-dimension match detail | `_match_rule` returns a ternary: `True`, `False`, or `None`. The calling code (`_evaluate_gate`) only needs to know whether the rule matched, did not match, or is indeterminate. Per-dimension detail has no caller and would change the return type. |
| AI-generated root cause or remediation text | The verdict and audit structures contain structured data only. The human-readable render functions are template-driven with deterministic logic. Ghost Agent Brain produces narrative RCA from the structured facts. Architecture D4. |
| Atomic-rename write (write-to-temp then rename) | The collision check (D17) prevents accidental overwrites of prior sessions. A concurrent invocation with the same explicit session ID is a caller error not handled defensively. Atomic rename adds complexity without solving the concurrent-caller problem. |
