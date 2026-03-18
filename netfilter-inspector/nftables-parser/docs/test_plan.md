# nftables-parser — Test Plan

*Modules: `nftables_parser.py`, `nftables_diff.py`*
*Requirements reference: `nftables-parser/docs/product-requirements.md`*
*Design reference: `nftables-parser/docs/design.md`*
*Status: Design complete — 2026-03-16*

---

## How to Run

```bash
cd netfilter-inspector/nftables-parser
python3 -m pytest

# With verbose output
python3 -m pytest -v --tb=short

# All Netfilter Inspector tests
cd netfilter-inspector
python3 -m pytest -v --tb=short
```

**Priority notation:**
- **MUST** — blocking; the module fails acceptance if this criterion fails
- **SHOULD** — important; failure warrants a documented exception before shipping

---

## Test Fixtures

Each fixture is a JSON file under `nftables-parser/nftables-samples/` containing valid `nft --json list ruleset` output. The fixture descriptions below specify the nftables objects they contain; the actual JSON must be valid nft output (all objects in a `{"nftables": [...]}` top-level array).

| Fixture | Description |
|---------|-------------|
| `fx-01-empty.json` | Metainfo only. No tables, no chains, no rules. |
| `fx-02-ip-clean.json` | ip family, `ip/filter` table. 3 base chains (input/forward/output), all `policy: accept`. 3 rules on output chain targeting Azure wire server (168.63.129.16): tcp/53 accept, uid-0 tcp accept, ct_state [invalid,new] tcp drop. All counters absent from rules. |
| `fx-03-inet-drop-policy.json` | inet family (dual-stack), `inet/filter` table. input and forward base chains with `policy: drop`. output with `policy: accept`. Rules: ct_state [established,related] accept, icmp accept, tcp dport 22 new accept. |
| `fx-04-regular-chains.json` | ip family. `ip/filter` table with base chain `input` jumping to regular chain `allowed-ports`. `allowed-ports` has tcp/22, tcp/443, tcp/80 accept rules. Also a jump to undefined chain `ghost_chain` in input (to test unresolved_chain_jumps). |
| `fx-05-sets.json` | ip family. Named set `blocklist` with interval flag and 3 CIDR elements. Named map `port-map`. Rule referencing `@blocklist` → drop. Rule referencing `@allowlist` → accept (set `allowlist` is NOT defined in the fixture — tests `found: false`). |
| `fx-06-multi-family.json` | Both `ip/filter` and `ip6/filter` tables. Each has identical base chain structures with 2 rules. Tests family key isolation in the tables dict. |
| `fx-07-inet-ip-mixed.json` | `inet/filter` table (dual-stack) coexisting with `ip/nat` table. Tests `inet_tables` diagnostic and correct family handling when families are mixed in one ruleset. |
| `fx-08-counters.json` | ip family. Same chain structure as `fx-02-ip-clean.json` but all rules include `counter` expressions with non-zero packet/byte counts. The drop rule has `packets: 42`. Also includes a named counter object. |
| `fx-09-nat.json` | ip family, `ip/nat` table. Two nat base chains: `prerouting` (type nat, hook prerouting, priority dstnat/-100) and `postrouting` (type nat, hook postrouting, priority srcnat/100). Two rules: DNAT redirect of tcp/80 → 192.168.1.10:8080 (prerouting), and masquerade for 192.168.1.0/24 (postrouting). Both non-terminal expressions land in `opaque_expressions` with parse warnings. |
| `fx-10-negation-ports-interfaces.json` | ip family, `ip/filter` table. Five rules on the `input` chain exercising: `src_addr_negated` (!= 10.0.0.0/8), `dst_port_negated` (!= tcp/22), `src_port` as a port range (1024-65535), `in_interface_negated` (!= eth0), and `out_interface` without negation (== eth1). All rules have `comment` fields. |
| `fx-11-log-return-reject-goto.json` | ip family, `ip/filter` table with three chains: `input` (base), `check-flags` (regular), `allowed` (regular, no rules). Five rules: log+accept SSH on tcp/22, reject telnet on tcp/23, return if established, goto `allowed` (defined), goto `missing_chain` (undefined — triggers `unresolved_chain_jumps`). |
| `fx-12-icmp-ct.json` | inet family, `inet/filter` table. Input base chain with `policy: drop`. Seven rules exercising ICMP/ICMPv6 type matching (echo-request, nd-neighbor-solicit, redirect with negation), extended ct fields (ct mark == 1, ct direction == original, ct zone == 1), and comments on all rules. |

---

## Part 1 — Parser (`nftables_parser.py`)

### 1. Fixture-Level Criteria

#### AC-F01 — Empty ruleset (`fx-01-empty.json`) — MUST

- `tables: {}` (empty dict, not null, not absent)
- `parse_warnings: []`
- `input_format: "nft-json"`
- `nft_version: "1.0.9"` (from metainfo)
- `json_schema_version: 1` (from metainfo)
- `diagnostics.drop_policy_chains: []`
- `diagnostics.accept_policy_chains: []`
- `diagnostics.active_drop_rules: []`
- `diagnostics.unresolved_chain_jumps: []`
- `diagnostics.inet_tables: []`
- `diagnostics.sets_referenced_in_rules: {}`
- `parsed_at` present and is a valid ISO-8601 timestamp

#### AC-F02 — Azure-style clean (`fx-02-ip-clean.json`) — MUST

- Exactly 1 table key: `"ip/filter"`
- `ip/filter` table has `family: "ip"`, `name: "filter"`
- Exactly 3 chains: `input`, `forward`, `output` — all `is_base_chain: true`, all `policy: "accept"`
- `input` and `forward` chains have `rules: []`
- `output` chain has exactly 3 rules:
  - Rule 1: `dst_addr: "168.63.129.16"`, `protocol: "tcp"`, `dst_port: "53"`, `verdict: "accept"`
  - Rule 2: `dst_addr: "168.63.129.16"`, `protocol: "tcp"`, `verdict: "accept"` (ct_state or owner match present)
  - Rule 3: `dst_addr: "168.63.129.16"`, `protocol: "tcp"`, `ct_state: ["invalid", "new"]`, `verdict: "drop"`, `verdict_stops_chain: true`
- All rules: `expression_hash` is a 64-character hex string
- All rules: `raw_expressions` present and non-empty
- All rules: `opaque_expressions: null` (all expressions recognized)
- `diagnostics.drop_policy_chains: []` (all policies are accept)
- `diagnostics.accept_policy_chains` contains `"ip/filter/input"`, `"ip/filter/forward"`, `"ip/filter/output"`

#### AC-F03 — inet drop-policy (`fx-03-inet-drop-policy.json`) — MUST

- Exactly 1 table key: `"inet/filter"`
- Table has `family: "inet"`
- input chain: `policy: "drop"`, `is_base_chain: true`, `type: "filter"`, `hook: "input"`
- forward chain: `policy: "drop"`, `is_base_chain: true`
- output chain: `policy: "accept"`, `is_base_chain: true`
- At least one rule with `ct_state: ["established", "related"]`, `verdict: "accept"`
- SSH rule: `protocol: "tcp"`, `dst_port: "22"`, `verdict: "accept"`
- `diagnostics.drop_policy_chains` contains `"inet/filter/input"` and `"inet/filter/forward"`
- `"inet/filter/output"` absent from `drop_policy_chains`
- `diagnostics.inet_tables` contains `"inet/filter"`

#### AC-F04 — Regular chains and jumps (`fx-04-regular-chains.json`) — MUST

- `ip/filter` table contains exactly 2 chains: `input` (base chain) and `allowed-ports` (regular chain)
- `input` chain: `is_base_chain: true`, `type: "filter"`, `hook: "input"`
- `allowed-ports` chain: `is_base_chain: false`, `type: null`, `hook: null`, `priority: null`, `policy: null`
- Jump rules in `input`: `jump_target: "allowed-ports"`, `verdict: null`, `verdict_stops_chain: false`
- Jump rule to undefined chain: `jump_target: "ghost_chain"`
- `allowed-ports` rules have `verdict: "accept"`, `verdict_stops_chain: true`
- `diagnostics.unresolved_chain_jumps` contains 1 entry for `jump_target: "ghost_chain"` with `table: "ip/filter"`, `chain: "input"`

#### AC-F05 — Sets (`fx-05-sets.json`) — MUST

- `ip/filter` table has `sets` key with `blocklist` and `port-map` entries
- `blocklist` set record: `type: "ipv4_addr"`, `flags: ["interval"]`, `elements` non-empty list, `is_map: false`
- `port-map` set record: `is_map: true`
- Rule referencing `@blocklist`: `set_references: ["blocklist"]`, `verdict: "drop"`
- Rule referencing `@allowlist`: `set_references: ["allowlist"]`, `verdict: "accept"`
- `diagnostics.sets_referenced_in_rules`:
  - `"blocklist"`: `found: true`
  - `"allowlist"`: `found: false` (set not defined in fixture)

#### AC-F06 — Multi-family (`fx-06-multi-family.json`) — MUST

- Exactly 2 table keys: `"ip/filter"` and `"ip6/filter"`
- `ip/filter` has `family: "ip"`; `ip6/filter` has `family: "ip6"`
- Chains and rules of each table are independent and correctly isolated
- IPv6 address in rules (e.g., `::1/128`) preserved verbatim in `src_addr` or `dst_addr`
- `diagnostics.inet_tables: []` (no inet family tables in this fixture)

#### AC-F07 — inet+ip mixed families (`fx-07-inet-ip-mixed.json`) — MUST

- Exactly 2 table keys: `"inet/filter"` and `"ip/nat"`
- `inet/filter` has `family: "inet"`; `ip/nat` has `family: "ip"`
- `diagnostics.inet_tables` contains `"inet/filter"` only; `"ip/nat"` absent
- Both tables independently parsed; neither affects the other's chain or rule records

#### AC-F08 — Counter-bearing rules (`fx-08-counters.json`) — MUST

- Same chain structure and rule match/verdict fields as AC-F02
- Every rule has a `counter` expression in `raw_expressions`
- `diagnostics.active_drop_rules` contains the drop rule (rule with `verdict: "drop"` and `packets: 42` in its counter expression)
- Rules with `packets: 0` absent from `diagnostics.active_drop_rules`
- Named counter object (top-level nftables object with key `"counter"`) captured without error; parse warning emitted noting it is treated as metadata only

#### AC-F09 — NAT table (`fx-09-nat.json`) — MUST

- Exactly 1 table key: `"ip/nat"`
- `prerouting` chain: `is_base_chain: true`, `type: "nat"`, `hook: "prerouting"`, `priority: -100` (from `"dstnat"` named priority)
- `postrouting` chain: `is_base_chain: true`, `type: "nat"`, `hook: "postrouting"`, `priority: 100` (from `"srcnat"` named priority)
- DNAT rule (handle 4): `protocol: "tcp"`, `dst_port: "80"`, `verdict: null`; `opaque_expressions` non-null and contains a `"dnat"` key entry; parse warning emitted
- Masquerade rule (handle 5): `src_addr: "192.168.1.0/24"`, `verdict: null`; `opaque_expressions` non-null and contains a `"masquerade"` key entry; parse warning emitted

#### AC-F10 — Negation, port ranges, interfaces (`fx-10-negation-ports-interfaces.json`) — MUST

- `ip/filter` table, `input` chain with exactly 5 rules
- Handle 3: `src_addr: "10.0.0.0/8"`, `src_addr_negated: true`, `verdict: "drop"`
- Handle 4: `dst_port: "22"`, `dst_port_negated: true`, `verdict: "drop"`
- Handle 5: `src_port: "1024-65535"`, `src_port_negated: false`, `verdict: "accept"` (port range format)
- Handle 6: `in_interface: "eth0"`, `in_interface_negated: true`, `verdict: "drop"`
- Handle 7: `out_interface: "eth1"`, `out_interface_negated: false`, `verdict: "accept"`
- `parse_warnings: []` (all expressions recognized)

#### AC-F11 — log, return, reject, goto (`fx-11-log-return-reject-goto.json`) — MUST

- `ip/filter` table with 3 chains: `input` (base), `check-flags` (regular), `allowed` (regular)
- `check-flags` and `allowed` chains: `is_base_chain: false`, `type: null`, `hook: null`
- Handle 5 (input): `is_log: true`, `log_prefix: "SSH-IN: "`, `verdict: "accept"`, `verdict_stops_chain: true`, `dst_port: "22"`, `opaque_expressions: null`
- Handle 6 (input): `verdict: "reject"`, `verdict_stops_chain: true`, `dst_port: "23"`
- Handle 7 (check-flags): `verdict: "return"`, `verdict_stops_chain: false`
- Handle 8 (check-flags): `goto_target: "allowed"`, `jump_target: null`, `verdict: null`, `verdict_stops_chain: false`
- Handle 9 (check-flags): `goto_target: "missing_chain"` — entry in `diagnostics.unresolved_chain_jumps` with `table: "ip/filter"`, `chain: "check-flags"`, `goto_target: "missing_chain"`
- `goto_target: "allowed"` absent from `diagnostics.unresolved_chain_jumps` (chain exists)
- `parse_warnings: []`

#### AC-F12 — ICMP/ICMPv6, extended ct fields, comments (`fx-12-icmp-ct.json`) — MUST

- Exactly 1 table key: `"inet/filter"`
- `input` chain: `policy: "drop"`, `is_base_chain: true`; exactly 7 rules
- All 7 rules: `comment` field is a non-null, non-empty string
- Handle 3: `icmp_type: "echo-request"`, `icmp_type_negated: false`, `protocol: "icmp"`, `verdict: "accept"`, `comment: "allow IPv4 ping"`
- Handle 4: `icmp_type: "echo-request"`, `icmp_type_negated: false`, `protocol: "icmpv6"`, `verdict: "accept"`
- Handle 5: `icmp_type: "nd-neighbor-solicit"`, `icmp_type_negated: false`, `protocol: "icmpv6"`, `verdict: "accept"`
- Handle 6: `icmp_type: "redirect"`, `icmp_type_negated: true`, `verdict: "accept"`
- Handle 7: `ct_mark: "1"`, `ct_mark_negated: false`, `verdict: "accept"`
- Handle 8: `ct_direction: "original"`, `verdict: "accept"`, `protocol: "tcp"`, `dst_port: "22"`
- Handle 9: `ct_zone: "1"`, `verdict: "drop"`, `verdict_stops_chain: true`
- All rules: `icmp_code: null`, `icmp_code_negated: false`
- ct-based rules (handles 7-9): `icmp_type: null`, `icmp_type_negated: false`
- ICMP rules (handles 3-6): `ct_mark: null`, `ct_mark_negated: false`, `ct_direction: null`, `ct_zone: null`
- `parse_warnings: []`

---

### 2. Field Accuracy Criteria

#### AC-FA01 — Table key format is `"family/name"` — MUST

- `ip` table named `filter` → key `"ip/filter"` not `"filter"` or `"ip:filter"`
- `inet` table named `main` → key `"inet/main"`
- Two tables of different families with the same name (e.g., `ip/filter` and `ip6/filter`) both present with distinct keys; neither overwrites the other

#### AC-FA02 — Chain type and hook values — MUST

- Base chain: `type` in `{"filter", "nat", "route"}`; `hook` in `{"input", "output", "forward", "prerouting", "postrouting", "ingress", "egress"}`
- Regular chain (no hook in nft JSON): `is_base_chain: false`, `type: null`, `hook: null`, `priority: null`, `policy: null`
- `is_base_chain` is always an explicit boolean, never absent

#### AC-FA03 — Named priority strings converted to integers — MUST

- nft JSON `"prio": "filter"` → `priority: 0`
- nft JSON `"prio": "srcnat"` → `priority: 100`
- nft JSON `"prio": "dstnat"` → `priority: -100`
- nft JSON `"prio": 0` (already integer) → `priority: 0`
- nft JSON `"prio": "unknown_priority_name"` → `priority: "unknown_priority_name"` (string preserved) + parse warning

#### AC-FA04 — Port values as strings — MUST

- `dport: 22` (integer in nft JSON) → `dst_port: "22"` (string in output)
- `sport: 1024` → `src_port: "1024"`
- Port range `{"range": [1024, 65535]}` in nft JSON → `dst_port: "1024-65535"` (string)

#### AC-FA05 — Address values preserved verbatim — MUST

- `"10.0.0.0/8"` in nft JSON → `src_addr: "10.0.0.0/8"` (not expanded to dotted-decimal mask)
- Single host `"192.168.1.1"` → `src_addr: "192.168.1.1"` (no `/32` appended)
- IPv6 prefix `"2001:db8::/32"` preserved as-is

#### AC-FA06 — Per-field negation booleans — MUST

- Match with `"op": "!="` → corresponding `_negated` field is `true`
- Match with `"op": "=="` → corresponding `_negated` field is `false`
- **When the corresponding match field is absent from the rule, the `_negated` field is `false` — never absent from the record.** Applies to all seven fields: a rule with no `src_addr` match has `src_addr_negated: false`; a rule with no `dst_port` match has `dst_port_negated: false`; and so on for all seven negation booleans.
- Mixed negation in one rule (e.g., `src_addr != 10.0.0.0/8` and `dst_port == 22`): `src_addr_negated: true`, `dst_port_negated: false` — both explicitly set
- Negation fields covered: `protocol_negated`, `src_addr_negated`, `dst_addr_negated`, `src_port_negated`, `dst_port_negated`, `in_interface_negated`, `out_interface_negated`

#### AC-FA07 — `verdict` and `verdict_stops_chain` contract — MUST

| Terminal expression | `verdict` | `verdict_stops_chain` |
|---------------------|-----------|----------------------|
| `{"accept": null}` | `"accept"` | `true` |
| `{"drop": null}` | `"drop"` | `true` |
| `{"reject": {...}}` | `"reject"` | `true` |
| `{"return": null}` | `"return"` | `false` |
| `{"jump": {"target": "chain"}}` | `null` | `false` |
| `{"goto": {"target": "chain"}}` | `null` | `false` |
| No terminal expression | `null` | `false` |
| `{"log": {...}}` only | `null` | `false` |
| `{"counter": {...}}` only | `null` | `false` |

#### AC-FA08 — `ct_state` list preserves source order — MUST

- nft JSON `{"set": ["established", "related"]}` → `ct_state: ["established", "related"]` (not alphabetically sorted)
- nft JSON `{"set": ["new", "invalid"]}` → `ct_state: ["new", "invalid"]`

#### AC-FA09 — `raw_expressions` always present and complete — MUST

- Every rule record has `raw_expressions` containing the full expression list from the source JSON
- `raw_expressions` is never null, never empty unless the nft JSON rule's `expr` field is absent (in which case `raw_expressions: []` and parse warning emitted)
- `raw_expressions` is the source of truth — no expressions are silently discarded from it

#### AC-FA10 — `expression_hash` is stable and format-correct — MUST

- Every rule record has `expression_hash` as a 64-character lowercase hex string (SHA-256 digest)
- Parsing the same nft JSON twice → identical `expression_hash` values for identical rules
- Two rules with identical `raw_expressions` but different `handle` values → identical `expression_hash`
- Two rules with different `raw_expressions` → different `expression_hash` values

#### AC-FA11 — `position` is 1-based and monotonically assigned — MUST

- First rule appended to a chain → `position: 1`
- Second rule → `position: 2`; nth rule → `position: n`
- Inserting a rule at a different position in nft does not change `position` assignment — the parser assigns position in parse order, not nft insertion order

#### AC-FA12 — Jump vs goto distinction preserved — MUST

- `{"jump": {"target": "chainname"}}` → `jump_target: "chainname"`, `goto_target: null`
- `{"goto": {"target": "chainname"}}` → `goto_target: "chainname"`, `jump_target: null`
- A rule cannot have both `jump_target` and `goto_target` non-null simultaneously

#### AC-FA13 — `expression_hash` canonical JSON key-sorting — MUST

The design specifies `json.dumps(exprs, sort_keys=True, ...)`. Without `sort_keys=True`, Python dict insertion order produces different JSON strings for the same logical expression — breaking the hash stability guarantee across captures.

- Construct expression object A: `{"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}`
- Construct expression object B: identical logical content but keys in different insertion order: `{"right": 22, "op": "==", "left": {"field": "dport", "protocol": "tcp"}}`
- Call `_expression_hash([A])` and `_expression_hash([B])` — assert both return the same 64-character hex digest
- Separately: `_expression_hash([A])` and `_expression_hash([A, {"accept": null}])` must return **different** digests (different expression lists)

#### AC-FA14 — `comment` field captured and defaulted — MUST

- Rule with a `comment` key in the nft JSON object → `comment` field in the rule record contains the string value
- Rule without a `comment` key → `comment: null` in the rule record
- `comment` field is always present in every rule record (never absent)

#### AC-FA15 — ICMP type parsing and negation — MUST

- `payload {protocol: "icmp", field: "type"}` match with `op: "=="` and `right: "echo-request"` → `icmp_type: "echo-request"`, `icmp_type_negated: false`, `protocol: "icmp"`
- Same match with `op: "!="` → `icmp_type_negated: true`
- `payload {protocol: "icmpv6", field: "type"}` → `protocol: "icmpv6"`, `icmp_type` set accordingly
- Rules without any ICMP type match: `icmp_type: null`, `icmp_type_negated: false` (always present)

#### AC-FA16 — Extended ct fields (`ct_mark`, `ct_direction`, `ct_zone`) — MUST

- `ct {key: mark}` match with `op: "=="` and `right: 1` → `ct_mark: "1"`, `ct_mark_negated: false`
- `ct {key: mark}` match with `op: "!="` → `ct_mark_negated: true`
- `ct {key: direction}` match → `ct_direction` set to the right-hand value string
- `ct {key: zone}` match → `ct_zone` set to the right-hand value string
- Rules without these matches: all four fields present with `null` / `false` defaults

#### AC-FA17 — ICMP code parsing — MUST

- `payload {protocol: "icmp", field: "code"}` match → `icmp_code` set to the right-hand value string; `icmp_code_negated: false`
- Same with `op: "!="` → `icmp_code_negated: true`
- `payload {protocol: "icmpv6", field: "code"}` → same extraction with `protocol: "icmpv6"`
- Rules without any ICMP code match: `icmp_code: null`, `icmp_code_negated: false` (always present)

---

### 3. Edge Case Criteria

#### AC-EC01 — Empty nftables array — MUST

Input: `{"nftables": []}` (valid JSON, valid top-level key, zero objects).

- `tables: {}`, `parse_warnings` contains one warning: `"nftables list is empty — no tables configured"`
- `nft_version: null`, `json_schema_version: null`
- No crash; exit code 0 from CLI

#### AC-EC02 — `inet` family table never split — MUST

Input: inet family table with rules matching both IPv4 and IPv6 addresses.

- Table stored under single key `"inet/filter"`, not split into `"ip/filter"` and `"ip6/filter"`
- `family: "inet"` preserved in table record
- `diagnostics.inet_tables` includes `"inet/filter"`
- No parse warnings about inet family

#### AC-EC03 — log + accept in one rule — MUST

Input: rule with expression list `[{"log": {"prefix": "SSH-IN: "}}, {"accept": null}]`.

- `is_log: true`, `log_prefix: "SSH-IN: "` (trailing space preserved)
- `verdict: "accept"`, `verdict_stops_chain: true`
- `opaque_expressions: null` (both expressions recognized)

#### AC-EC04 — counter-only rule (no verdict) — MUST

Input: rule with only `[{"counter": {"packets": 0, "bytes": 0}}]` and no verdict expression.

- `verdict: null`, `verdict_stops_chain: false`
- `opaque_expressions: null` (counter expression is recognized)
- Rule included in output; no parse warning (counter-only rules are valid nft constructs)

#### AC-EC05 — Set reference extraction from match RHS — MUST

Input: rule with match expression `{"match": {"op": "==", "left": {"payload": {...}}, "right": {"set": "@blocklist"}}}`.

- `set_references: ["blocklist"]` (the `@` prefix stripped)
- `src_addr` (or `dst_addr`) normalized to `null` (set reference is not a literal address)
- `opaque_expressions: null` — the match is recognized; only the RHS value is unusual

#### AC-EC06 — Named priority string for unknown name — MUST

Input: chain with `"prio": "custom_priority"` not in the nft standard priority map.

- `priority: "custom_priority"` (stored as-is)
- Parse warning: `"Unrecognised priority string 'custom_priority' in chain '...' — stored verbatim"`
- Chain otherwise fully parsed; no crash

#### AC-EC07 — Multiple terminal verdicts in one rule (malformed) — MUST

Input: rule with expression list `[{"accept": null}, {"drop": null}]`.

- First verdict wins: `verdict: "accept"`, `verdict_stops_chain: true`
- Second verdict expression moved to `opaque_expressions`
- Parse warning emitted: `"Multiple terminal verdicts in rule handle N — first verdict retained"`
- Rule included in output

#### AC-EC08 — Rule referencing undeclared chain — MUST

Input: `_parse_rule()` processes a rule for chain `"mychain"` in table `"ip/filter"`, but no chain object for `"mychain"` appeared earlier in the dispatch loop.

- Chain `"mychain"` created implicitly under `"ip/filter"` with `is_base_chain: false`, `rules: [<this rule>]`
- Parse warning: `"Rule handle N references undeclared chain 'mychain' in table 'ip/filter' — chain created implicitly"`
- All other chains unaffected

#### AC-EC09 — `flowtable` object — MUST

Input: nftables array contains a `{"flowtable": {"family": "ip", "table": "filter", "name": "ft0", "hook": "ingress", "prio": 10, "devices": ["eth0"]}}`.

- No parse warning emitted
- `flowtable` captured structurally under the table's `flowtables` dict
- Table record has `"flowtables": {"ft0": {"name": "ft0", "hook": "ingress", ...}}`
- Member details (devices) stored as-is (opaque)

#### AC-EC10 — `map` object — MUST

Input: nftables array contains a `{"map": {"family": "ip", "table": "filter", "name": "port-map", "handle": 5, "type": "inet_proto . inet_service", "elem": [...]}}`.

- Map record: `is_map: true`, `name: "port-map"`, `handle: 5`
- `elements` contains raw JSON string representation of `elem` entries
- No parse warning

#### AC-EC11 — Rule missing `handle` — MUST

Input: rule object with no `handle` key.

- Rule skipped entirely; not appended to any chain
- Parse warning: `"Rule in table/chain missing 'handle' field — skipped (handle required for diff identity)"`
- All other rules in the chain unaffected; parser continues

#### AC-EC12 — Duplicate rules (same content) — MUST

Input: two rule objects with identical `expr` but different `handle` values in the same chain.

- Two separate rule records at sequential positions
- Each has its own `handle`; both included in output
- Both have identical `expression_hash` values (same content)
- No deduplication; no parse warning

#### AC-EC13 — Dynamic set with no inline elements (`elements: null`) — MUST

Input: set object with no `elem` key: `{"set": {"family": "ip", "table": "filter", "name": "dynamic-blocklist", "handle": 7, "type": "ipv4_addr", "flags": ["dynamic"]}}`.

- Set record: `name: "dynamic-blocklist"`, `elements: null` (not `[]`, not `{}`)
- `is_map: false`, `flags: ["dynamic"]`
- No parse warning
- `null` signals elements are managed at runtime; an empty list `[]` would mean explicitly empty — the distinction must be preserved

#### AC-EC14 — Named `quota` and `limit` objects — MUST

F1 specifies: counter, quota, limit named objects must be captured (name and handle; values as metadata).

Synthetic input: nftables array containing:
- `{"quota": {"family": "ip", "table": "filter", "name": "data-limit", "handle": 8, "bytes": 1073741824, "used": 512000}}`
- `{"limit": {"family": "ip", "table": "filter", "name": "rate-limit", "handle": 9, "rate": 100, "rate_unit": "packets", "per": "second"}}`

- Both objects parsed without error
- Each captured under the table record with name and handle preserved
- Parse warning emitted for each noting they are treated as metadata
- No crash; all other objects in the array parsed normally

---

### 4. Diagnostics Criteria

#### AC-DI01 — `drop_policy_chains` populated correctly — MUST

Fixture: `fx-03-inet-drop-policy.json`
- `diagnostics.drop_policy_chains` contains `"inet/filter/input"` and `"inet/filter/forward"`
- `"inet/filter/output"` absent (policy is accept)

Fixture: `fx-02-ip-clean.json`
- `diagnostics.drop_policy_chains: []` (all policies are accept)

#### AC-DI02 — `accept_policy_chains` populated correctly — MUST

Fixture: `fx-03-inet-drop-policy.json`
- `diagnostics.accept_policy_chains` contains `"inet/filter/output"` only
- `"inet/filter/input"` and `"inet/filter/forward"` absent (policy is drop)

#### AC-DI03 — `active_drop_rules` populated only when counter data present — MUST

Fixture: `fx-08-counters.json` (drop rule with `packets: 42` in counter expression)
- `diagnostics.active_drop_rules` contains exactly 1 entry: the drop rule
- Entry is the full rule record, not just a reference

Fixture: `fx-02-ip-clean.json` (no counter expressions in rules)
- `diagnostics.active_drop_rules: []` — no counter data, no entries regardless of verdict

Synthetic: drop rule with counter expression present but `packets: 0`
- Rule absent from `diagnostics.active_drop_rules` (packet_count must be > 0)

#### AC-DI04 — `unresolved_chain_jumps` populated correctly — MUST

Fixture: `fx-04-regular-chains.json` (jump to `ghost_chain` with no corresponding chain object)
- `diagnostics.unresolved_chain_jumps` contains exactly 1 entry:
  - `table: "ip/filter"`, `chain: "input"`, `jump_target: "ghost_chain"`
  - `handle` and `position` of the offending rule present

Fixture: `fx-04-regular-chains.json` (jump to `allowed-ports` which IS defined)
- `"allowed-ports"` absent from `unresolved_chain_jumps`

Fixture: `fx-01-empty.json`
- `diagnostics.unresolved_chain_jumps: []`

Synthetic — `goto_target` variant (F3 requires jump_target OR goto_target to be checked):

Input: rule with `{"goto": {"target": "missing_goto_chain"}}` expression; no chain named `missing_goto_chain` in the same table.

- `diagnostics.unresolved_chain_jumps` contains 1 entry:
  - `table`, `chain`, `handle`, `position` of the offending rule present
  - `goto_target: "missing_goto_chain"` in the entry (not `jump_target`)
- A resolved `goto` to a chain that IS defined: absent from `unresolved_chain_jumps`

#### AC-DI05 — `inet_tables` populated correctly — MUST

Fixture: `fx-07-inet-ip-mixed.json`
- `diagnostics.inet_tables` contains `"inet/filter"` only
- `"ip/nat"` absent (ip family, not inet)

Fixture: `fx-06-multi-family.json`
- `diagnostics.inet_tables: []` (no inet family tables)

#### AC-DI06 — `sets_referenced_in_rules` reflects found/not-found — MUST

Fixture: `fx-05-sets.json`
- `diagnostics.sets_referenced_in_rules["blocklist"]`: `found: true`, `table: "ip/filter"`
- `diagnostics.sets_referenced_in_rules["allowlist"]`: `found: false`, `table: "ip/filter"`
- No entry for `port-map` (referenced from rules only via `@setname`; if not referenced in rules, absent)

#### AC-DI07 — `diagnostics` always fully present — MUST

For every input — including empty, malformed, and warning-only inputs:
- `diagnostics` key always present in output
- All sub-keys always present: `drop_policy_chains`, `accept_policy_chains`, `active_drop_rules`, `unresolved_chain_jumps`, `inet_tables`, `sets_referenced_in_rules`
- Sub-arrays: `[]` when empty; sub-dict: `{}` when empty
- No sub-key is ever absent or null

---

### 5. Error Handling Criteria

#### AC-EH01 — Non-JSON input raises `ValueError` — MUST

Input: `"*filter\n:INPUT DROP [0:0]\nCOMMIT\n"` (iptables-save text).

- `ValueError` raised with message beginning `"Input is not valid JSON: "`
- No partial output produced
- CLI: exits with code 1; clean error message on stderr; no traceback

#### AC-EH02 — Missing `nftables` key raises `ValueError` — MUST

Input: `'{"rules": []}'` (valid JSON, wrong top-level key).

- `ValueError("Input is not nft --json list ruleset output: missing 'nftables' key")`
- CLI: exits with code 1

#### AC-EH03 — `nftables` value not a list raises `ValueError` — MUST

Input: `'{"nftables": {"table": "filter"}}'` (nftables is a dict, not list).

- `ValueError("'nftables' must be a list")`
- CLI: exits with code 1

#### AC-EH04 — Unknown nftables object type produces warning, continues — MUST

Input: nftables array containing `{"unknown_type": {"family": "ip", "name": "x"}}`.

- Parse warning: `"Unknown nftables object type at index N: keys={'unknown_type'}"`
- Object skipped; all other objects in the array parsed normally
- Exit code 0 from CLI

#### AC-EH05 — Unrecognised expression type goes to `opaque_expressions` — MUST

Input: rule containing `{"nftrace": {"set": 1}}` (valid nft expression, not in known patterns).

- Expression appended to rule's `opaque_expressions` list
- Parse warning: `"Unrecognised expression type 'nftrace' in rule handle N — moved to opaque_expressions"`
- Rule included in output with all other expressions normalized normally
- `expression_hash` computed over the full `raw_expressions` including the opaque entry

#### AC-EH06 — `KeyError` / `TypeError` during expression extraction — MUST

Input: malformed match expression where `left` or `right` is an unexpected type (e.g., `{"match": {"op": "==", "left": null}}`).

- Expression moved to `opaque_expressions`
- Parse warning with context (rule handle, expression index, exception type)
- Rule included; other expressions in the same rule processed normally
- No Python exception propagates to caller

#### AC-EH07 — File not found (CLI) — MUST

CLI invocation: `python3 nftables_parser.py /nonexistent/path.json`

- Exit code 1
- Error message on stderr: `"File not found: /nonexistent/path.json"`
- No traceback (user-facing error message only)

#### AC-EH08 — Metainfo absent — MUST

Input: nftables array with table/chain/rule objects but no metainfo object.

- `nft_version: null`, `json_schema_version: null`
- Parse warning: `"metainfo object absent — nft_version and json_schema_version unavailable"`
- All table/chain/rule objects parsed normally; no crash

---

### 6. Non-Functional Criteria

#### AC-NF01 — Determinism — MUST

- Parsing the same JSON file 10 consecutive times produces byte-identical output in all fields except `parsed_at`
- `parsed_at` reflects actual parse time and differs between invocations

#### AC-NF02 — `parsed_at` excluded from expression_hash computation — MUST

- `parsed_at` is not part of any rule's `raw_expressions` or `expression_hash`
- Parsing the same file twice with different wall-clock times → identical `expression_hash` values for all rules

#### AC-NF03 — Output is always valid JSON — MUST

- `json.loads(output)` succeeds for every input, including non-JSON, malformed, and empty inputs
- `parse_warnings` always a list — never null, never absent
- When a `ValueError` is raised (AC-EH01/02/03), no JSON is emitted — the exception propagates

#### AC-NF04 — Input accepted from file path and stdin — MUST

- File path argument: `python3 nftables_parser.py fx-02-ip-clean.json` → JSON to stdout, exit 0
- Stdin: `cat fx-02-ip-clean.json | python3 nftables_parser.py` → identical JSON to stdout, exit 0
- Both paths produce byte-identical output for identical content (modulo `parsed_at`)

#### AC-NF05 — `--indent` argument controls output formatting — MUST

- `--indent 2` (default): pretty-printed with 2-space indent
- `--indent 0`: compact JSON, no newlines between fields
- `--indent 4`: 4-space indent
- Argument error produces exit code 2

#### AC-NF06 — No third-party imports — MUST

- `import sys; import importlib; importlib.import_module('nftables_parser')` succeeds on a fresh Python 3.8+ installation with no packages installed
- Module source contains no `import` statements outside Python standard library
- Verified by static scan: `grep -E "^import|^from" nftables_parser.py` returns only stdlib module names

#### AC-NF07 — Importable as a Python module — MUST

- `from nftables_parser import parse_nft_ruleset` succeeds without executing `main()`
- `parse_nft_ruleset(text)` callable directly from another Python module
- No side effects at import time (no file I/O, no network calls, no `argparse` execution)

---

### 7. Requirements Coverage Map

| Requirement | Criteria |
|-------------|----------|
| F1 — Parse metainfo | AC-F01, AC-EH08 |
| F1 — Parse table | AC-F02, AC-F03, AC-FA01 |
| F1 — Parse chain (base + regular) | AC-F04, AC-FA02, AC-FA03 |
| F1 — Parse rule | AC-F02, AC-F03, AC-FA09, AC-FA10 |
| F1 — Parse set | AC-F05, AC-EC10 |
| F1 — Parse map | AC-EC10 |
| F1 — Parse counter/quota/limit (named objects) | AC-F08, AC-EC14 |
| F1 — Parse flowtable | AC-EC09 |
| F2 — protocol | AC-FA04 (port string), AC-FA07 |
| F2 — dst_port / src_port | AC-FA04 |
| F2 — src_addr / dst_addr | AC-FA05 |
| F2 — in_interface / out_interface | AC-FA06 |
| F2 — ct_state | AC-FA08, AC-F03 |
| F2 — verdict / verdict_stops_chain | AC-FA07 |
| F2 — jump_target / goto_target | AC-FA12, AC-F04 |
| F2 — log_prefix / is_log | AC-EC03 |
| F2 — per-field negation | AC-FA06, AC-FA13 |
| F2 — icmp_type, icmp_code | AC-FA15, AC-FA17, AC-F12 |
| F2 — ct_mark, ct_direction, ct_zone | AC-FA16, AC-F12 |
| F2 — comment | AC-FA14, AC-F12 |
| F2 — opaque_expressions | AC-EH05, AC-EC06 |
| F3 — drop_policy_chains | AC-DI01 |
| F3 — accept_policy_chains | AC-DI02 |
| F3 — active_drop_rules | AC-DI03 |
| F3 — unresolved_chain_jumps | AC-DI04 (jump_target and goto_target) |
| F3 — inet_tables | AC-DI05 |
| F3 — sets_referenced_in_rules | AC-DI06 |
| F3 — diagnostics always present | AC-DI07 |
| F4 — Warnings without aborting | AC-EH04, AC-EH05, AC-EH06, AC-EC07, AC-EC11 |
| F5 — expression_hash stable | AC-FA10, AC-FA13, AC-NF02 |
| F5 — counter canonicalization | AC-D33, AC-FA10 |
| F6 — Standalone CLI (parser) | AC-NF04, AC-NF05, AC-EH07 |
| F6 — Standalone CLI (diff, JSON) | AC-DC01 through AC-DC06 |
| F6 — Standalone CLI (diff, --summary) | AC-DC07 through AC-DC10 |
| F6 — summary_diff() | AC-EX01 through AC-EX14 |
| C1 — nft-json only | AC-EH01, AC-EH02, AC-EH03 |
| C2 — No shell execution | AC-NF06 (verified by import + static scan) |
| C3 — No cloud dependency | AC-NF06 |
| C4 — inet as first-class family | AC-EC02, AC-F03, AC-F07, AC-DI05 |
| C5 — expression_hash frozen | AC-FA10 |
| C6 — Python 3.8+, importable | AC-NF07 |
| C7 — No third-party dependencies | AC-NF06 |

---

## Part 2 — Diff Engine (`nftables_diff.py`)

---

#### AC-D01 — Identical inputs produce no drift — MUST

Input: same `parse_nft_ruleset()` output as both baseline and current.

- `drift_detected: false`, `has_critical_changes: false`
- All change lists empty; all summary counts zero
- `baseline_parse_warnings` and `current_parse_warnings` passed through from inputs

#### AC-D02 — Rule added to existing chain — MUST

Input: baseline has N rules in a chain; current has the same chain with N+1 rules (new handle, not in baseline).

- New rule in `changes.rules_added` with full rule record from current
- Absent from `rules_removed` and `rules_recreated`
- `drift_detected: true`
- `summary.rules_added: 1`

#### AC-D03 — Rule removed from existing chain — MUST

Input: baseline has N rules; current has N-1 rules (one handle absent).

- Removed rule in `changes.rules_removed` with full rule record from baseline
- Absent from `rules_added` and `rules_recreated`
- `drift_detected: true`

#### AC-D04 — Rule repositioned within chain — MUST

Input: baseline has a rule at `position: 3`; current has the same handle at `position: 5`, same `expression_hash`.

- Rule in `changes.rules_repositioned` with `baseline_position: 3`, `current_position: 5`
- The `rule` sub-object contains **exactly** the fields from `_RULE_IDENTITY_FIELDS` (design §7) and no others. v1 fields: `table`, `chain`, `protocol`, `protocol_negated`, `src_addr`, `src_addr_negated`, `dst_addr`, `dst_addr_negated`, `src_port`, `src_port_negated`, `dst_port`, `dst_port_negated`, `in_interface`, `in_interface_negated`, `out_interface`, `out_interface_negated`, `ct_state`, `verdict`, `jump_target`, `goto_target`, `expression_hash`. v2 fields added: `icmp_type`, `icmp_type_negated`, `icmp_code`, `icmp_code_negated`, `ct_mark`, `ct_mark_negated`, `ct_direction`, `ct_zone`, `comment`.
- The following fields are explicitly absent from the `rule` sub-object: `handle`, `position`, `raw_expressions`, `opaque_expressions`, `is_log`, `log_prefix`, `set_references`, `verdict_stops_chain`
- Absent from `rules_added` and `rules_removed`
- `drift_detected: true`

#### AC-D05 — Rule recreated: same hash, new handle — MUST

Input: baseline has a rule with handle 7, `expression_hash: "abc123"`. Current has no handle 7, but has a new rule with handle 12 and `expression_hash: "abc123"`.

- Entry in `changes.rules_recreated`:
  - `baseline_rule`: full rule record with handle 7
  - `current_rule`: full rule record with handle 12
  - `note` field present describing the recreation
- Rule absent from `rules_added` and `rules_removed`
- `summary.rules_recreated: 1`; `summary.rules_added: 0`; `summary.rules_removed: 0`
- `drift_detected: true`

#### AC-D06 — Rule recreated: DROP verdict is always critical — MUST

Input: baseline has a DROP rule with handle 3. Current has no handle 3, but a new DROP rule with the same `expression_hash` (handle 8).

- Entry in `changes.rules_recreated`
- `has_critical_changes: true` (conservative: DROP recreation always flagged even if semantically identical)
- `drift_detected: true`

#### AC-D07 — Rule recreated: ACCEPT verdict is not critical — MUST

Input: baseline has an ACCEPT rule with handle 5. Current has a new ACCEPT rule with same `expression_hash` (handle 9). No other changes.

- Entry in `changes.rules_recreated`
- `has_critical_changes: false`
- `drift_detected: true`

#### AC-D08 — Chain added — MUST

Input: baseline has ip/filter with 3 chains; current adds user-defined chain `new-chain` with 2 rules.

- `new-chain` in `changes.chains_added` with `table: "ip/filter"`, `chain: "new-chain"`, `is_base_chain: false`, `rule_count: 2`
- The 2 rules of `new-chain` absent from `rules_added` (no double-counting)
- `drift_detected: true`

#### AC-D09 — Chain removed — MUST

Input: baseline has a user-defined chain with rules; current does not.

- Chain in `changes.chains_removed`
- Chain's rules absent from `rules_removed`
- `drift_detected: true`

#### AC-D10 — Table added — MUST

Input: baseline has only `ip/filter`; current has `ip/filter` and `ip/nat`.

- `"ip/nat"` in `changes.tables_added`
- All nat chains in `changes.chains_added`
- No nat rules in `changes.rules_added`
- `drift_detected: true`

#### AC-D11 — Table removed — MUST

Input: baseline has `ip/filter` and `ip/nat`; current has only `ip/filter`.

- `"ip/nat"` in `changes.tables_removed`
- All nat chains in `changes.chains_removed`
- No nat rules in `changes.rules_removed`
- `drift_detected: true`

#### AC-D12 — Chain policy changed — MUST

Input: `ip/filter/input` policy `"accept"` → `"drop"`.

- Entry in `changes.policy_changes`: `table: "ip/filter"`, `chain: "input"`, `baseline_policy: "accept"`, `current_policy: "drop"`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D13 — Policy change to accept is not critical — MUST

Input: `ip/filter/input` policy `"drop"` → `"accept"`.

- Entry in `changes.policy_changes`
- `has_critical_changes: false` (relaxation, not tightening)
- `drift_detected: true`

#### AC-D14 — DROP rule added — MUST

Input: current has a new rule with `verdict: "drop"` not in baseline.

- Rule in `rules_added`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D15 — REJECT rule removed — MUST

Input: baseline has a rule with `verdict: "reject"`; current does not.

- Rule in `rules_removed`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D16 — LOG-only rule repositioned — MUST

Input: a rule with `verdict: null`, `is_log: true` moves position; no other changes.

- Rule in `rules_repositioned`
- `has_critical_changes: false`, `drift_detected: true`

#### AC-D17 — Cross-format comparison rejected — MUST

Input: baseline has `input_format: "iptables-save"`; current has `input_format: "nft-json"`.

- `ValueError` raised naming both formats: `"Cannot diff iptables-save baseline against nft-json current"`
- No partial diff output produced
- CLI: exits with code 1

#### AC-D18 — Both inputs must be nft-json — MUST

Input: baseline has `input_format: "nft-json"`; current has `input_format: "ip6tables-save"`.

- `ValueError` raised
- Symmetric case also tested: iptables baseline, nft-json current

#### AC-D19 — Invalid input rejected — MUST

Input: dict missing `tables` key.

- `ValueError("baseline missing required field: 'tables'")` or equivalent for `"current"` label
- Input that is not a dict at all → `ValueError("baseline must be a dict")`

#### AC-D20 — Both inputs empty — MUST

Input: both baseline and current are `parse_nft_ruleset('{"nftables": []}')` output.

- `drift_detected: false`, `has_critical_changes: false`
- All change lists empty; all summary counts zero

#### AC-D21 — Empty baseline, non-empty current — MUST

Input: baseline is empty ruleset output; current is `fx-02-ip-clean.json` output.

- All current tables in `tables_added`; all their chains in `chains_added`
- `rules_added: []` (rules of added tables not double-counted)
- `drift_detected: true`

#### AC-D22 — `json_schema_version` mismatch emits warning, diff continues — MUST

Input: baseline has `json_schema_version: 1`; current has `json_schema_version: 2`. Same tables and rules otherwise.

- `drift_detected: false` (no rule/chain/policy changes)
- `current_parse_warnings` contains a warning about `json_schema_version` change
- `baseline_parse_warnings` unchanged
- No crash; `has_critical_changes: false`

#### AC-D23 — Summary counts always match change list lengths — MUST

For any valid input pair (tested across all AC-D test inputs):

- `summary["tables_added"] == len(changes["tables_added"])`
- `summary["tables_removed"] == len(changes["tables_removed"])`
- `summary["chains_added"] == len(changes["chains_added"])`
- `summary["chains_removed"] == len(changes["chains_removed"])`
- `summary["policy_changes"] == len(changes["policy_changes"])`
- `summary["rules_added"] == len(changes["rules_added"])`
- `summary["rules_removed"] == len(changes["rules_removed"])`
- `summary["rules_repositioned"] == len(changes["rules_repositioned"])`
- `summary["rules_recreated"] == len(changes["rules_recreated"])`

#### AC-D24 — `parse_warnings` passed through without affecting drift — MUST

Input: baseline has `parse_warnings: []`; current has `parse_warnings: ["Unknown object at index 3"]`.

- `current_parse_warnings` contains the warning
- `baseline_parse_warnings: []`
- `drift_detected` reflects only rule/chain/policy changes — the warning alone does not set it to true

#### AC-D25 — Output is always valid JSON with all top-level keys — MUST

For any valid input pair:

- `json.dumps(result)` succeeds without error
- All top-level keys always present: `diff_at`, `input_format`, `baseline_parsed_at`, `current_parsed_at`, `baseline_parse_warnings`, `current_parse_warnings`, `drift_detected`, `has_critical_changes`, `summary`, `changes`
- `changes` sub-keys all present: `tables_added`, `tables_removed`, `chains_added`, `chains_removed`, `policy_changes`, `rules_added`, `rules_removed`, `rules_repositioned`, `rules_recreated`
- `diff_at` is a valid ISO-8601 timestamp (parseable by `datetime.fromisoformat`) and falls at or after `current_parsed_at`
- `input_format: "nft-json"` (explicit value check, not just key presence)

#### AC-D26 — inet table drift — MUST

Input: baseline has `inet/filter` with policy `accept` on input chain; current changes policy to `drop`.

- `input_format: "nft-json"` in diff output
- `changes.policy_changes` contains entry with `table: "inet/filter"`
- `has_critical_changes: true`
- inet family is not treated differently from ip or ip6 for diff purposes

#### AC-D27 — Duplicate handles within same chain are a hard error — MUST

Input: a parsed ruleset where two rules in the same chain have the same handle value (indicates parser bug or malformed JSON).

- `ValueError` naming the table, chain, and duplicate handle value
- No partial diff output

#### AC-D28 — Same handle, different expression_hash: parser-bug detection path — MUST

Input: baseline and current both contain handle 5 in the same chain, but with different `expression_hash` values (nftables does not allow a rule's content to change under the same handle — this indicates malformed input or a parser bug).

- Handle 5 baseline record appears in `changes.rules_removed`
- Handle 5 current record appears in `changes.rules_added`
- A parse warning is emitted noting the same-handle content change: e.g., `"Rule handle 5 in ip/filter/input has different expression_hash in baseline vs current — nftables handles are immutable; this indicates malformed input"`
- Rule is absent from `changes.rules_recreated` (recreation requires a new handle, not same-handle content change)
- `drift_detected: true`

#### AC-D29 — Chain priority change recorded in `policy_changes` — MUST

Input: `ip/filter/input` base chain: `priority: 0` in baseline → `priority: -100` in current; policy unchanged.

- Entry in `changes.policy_changes`: `table: "ip/filter"`, `chain: "input"`, a `note` field present describing the priority change, old and new priority values present
- `drift_detected: true`
- `has_critical_changes` reflects policy value (not priority) — priority change alone does not set `has_critical_changes: true`

#### AC-D30 — Chain type change recorded in `policy_changes` — MUST

Input: `ip/filter/input` base chain: `type: "filter"` in baseline → `type: "nat"` in current; policy and priority unchanged.

- Entry in `changes.policy_changes`: `table: "ip/filter"`, `chain: "input"`, a `note` field present describing the type change, old and new type values present
- `drift_detected: true`

#### AC-D31 — Relational test: parser output → diff input end-to-end — MUST

This test verifies the schema coupling between `nftables_parser.py` and `nftables_diff.py` (architecture §4 coupling rule). **Inputs must be produced by `parse_nft_ruleset()`, not manually constructed.**

1. Parse `fx-02-ip-clean.json` with `parse_nft_ruleset()` → `baseline`
2. Construct a modified version of `fx-02-ip-clean.json` that adds one DROP rule to the output chain (different handle from existing rules)
3. Parse the modified fixture with `parse_nft_ruleset()` → `current`
4. Pass both directly to `diff_rulesets(baseline, current)` without any intermediate dict manipulation

Expected:
- `drift_detected: true`
- `has_critical_changes: true`
- `changes.rules_added` contains exactly 1 entry: the new DROP rule with correct `table`, `chain`, `handle`, `verdict: "drop"`, and `expression_hash`
- All other change lists empty

#### AC-D32 — Change lists are sorted deterministically — MUST

Input: two rulesets with changes spanning two tables (`ip/filter` and `ip/nat`) and two chains (`input` and `forward`) with multiple rules added in each chain.

- `changes.rules_added` is sorted ascending by `(table, chain, handle)`:
  - All `ip/filter/forward` entries before `ip/filter/input` entries
  - Within the same table/chain, entries sorted by `handle` ascending
- `changes.policy_changes` sorted by `(table, chain)` ascending
- `changes.chains_added` sorted by `(table, chain)` ascending
- Sorting is verified by asserting the exact sequence of `table`, `chain`, `handle` values across the list

#### AC-D33 — Counter canonicalization enables recreation detection — MUST

Counter expressions in rule `raw_expressions` vary between captures as traffic increments packet/byte counts. The `expression_hash` must strip counters before hashing so that two captures of the same rule with different counter values produce the same hash — enabling recreation detection.

Input: two rules with identical non-counter expressions but different inline `counter` values (e.g., `{"counter": {"packets": 0, "bytes": 0}}` vs `{"counter": {"packets": 5000, "bytes": 320000}}`), both present in baseline with different handles, both absent from current with new handles swapped.

- Both rules classified as `rules_recreated` (same hash after counter stripping, different handles)
- `rules_added: []`, `rules_removed: []`
- `drift_detected: true`

#### AC-D34 — `comment` field appears in repositioned rule identity — MUST

A rule with a `comment` field that moves position (same handle, same `expression_hash`, different `position`) must include the `comment` field in the `rules_repositioned` entry's `rule` identity sub-dict.

Input: a rule with `comment: "allow SSH"` repositioned from position 2 to position 4.

- Entry in `changes.rules_repositioned`: `rule` sub-dict contains `"comment": "allow SSH"`
- `rule` sub-dict also contains all other `_RULE_IDENTITY_FIELDS`

---

## Part 3 — Diff CLI (`nftables_diff.py`)

---

#### AC-DC01 — Successful diff from file paths — MUST

CLI: `python3 nftables_diff.py baseline.json current.json`

- Exit code 0
- Valid JSON on stdout; `json.loads(stdout)` succeeds
- `drift_detected` value matches expected (verified against known fixtures)
- No output on stderr

#### AC-DC02 — Drift exit code is still 0 — MUST

CLI: `python3 nftables_diff.py baseline.json current_with_changes.json` where current has a new DROP rule.

- Exit code **0** (not 1 — drift does not indicate a tool error; callers must read `drift_detected`)
- `drift_detected: true` and `has_critical_changes: true` in stdout JSON

#### AC-DC03 — Current from stdin (`-` argument) — MUST

CLI: `cat current.json | python3 nftables_diff.py baseline.json -`

- Exit code 0
- JSON output byte-identical to the file-path invocation with the same content (modulo `diff_at`)

#### AC-DC04 — File not found → exit code 1 — MUST

CLI: `python3 nftables_diff.py /nonexistent/baseline.json current.json`

- Exit code 1
- Error message on stderr naming the missing file
- No traceback

#### AC-DC05 — Cross-format input → exit code 1 — MUST

CLI: invoke with a baseline JSON whose `input_format` is `"iptables-save"` and a current JSON whose `input_format` is `"nft-json"`.

- Exit code 1
- Error message on stderr describing the format mismatch

#### AC-DC06 — Missing arguments → exit code 2 — MUST

CLI: `python3 nftables_diff.py` (no arguments)

- Exit code 2 (argparse error)
- Usage message on stderr

#### AC-DC07 — `--summary` flag produces Markdown output — MUST

CLI: `python3 nftables_diff.py baseline.json current.json --summary` where both are identical (no drift)

- Exit code 0
- `"nftables Ruleset Diff"` present in stdout
- `"No drift detected."` present in stdout
- Output is not valid JSON: `json.loads(stdout)` raises `json.JSONDecodeError`

#### AC-DC08 — `--summary` on differing inputs shows drift — MUST

CLI: `python3 nftables_diff.py baseline.json current.json --summary` where current differs from baseline

- Exit code 0
- `"nftables Ruleset Diff"` present in stdout
- `"Drift detected"` present in stdout (drift section header)
- Output is not valid JSON

#### AC-DC09 — `--summary --verbose` produces Markdown — MUST

CLI: `python3 nftables_diff.py baseline.json current.json --summary --verbose` on differing inputs

- Exit code 0
- `"nftables Ruleset Diff"` present in stdout
- Output is not valid JSON (Markdown format)

#### AC-DC10 — `--verbose` without `--summary` is silently tolerated — MUST

CLI: `python3 nftables_diff.py baseline.json current.json --verbose` (no `--summary`)

- Exit code 0
- Stdout is valid JSON (`json.loads(stdout)` succeeds); `drift_detected` field present
- Warning message on stderr noting `--verbose` has no effect without `--summary`

---

## Part 4 — Human-readable Summary (`summary_diff()`)

---

#### AC-EX01 — No-drift output — MUST

`summary_diff(diff)` where `drift_detected: false`.

- Return value is a string containing `"No drift detected."` (case-sensitive)
- `"nftables Ruleset Diff"` present in return value (header)
- Return value is not valid JSON (`json.loads()` raises)

#### AC-EX02 — Drift header present — MUST

`summary_diff(diff)` where `drift_detected: true`.

- `"Drift detected"` present in return value (case-sensitive)
- `"nftables Ruleset Diff"` present

#### AC-EX03 — Critical policy change labelled — MUST

`summary_diff(diff)` where `policy_changes` contains an entry with `current_policy: "drop"`.

- Return value contains `"⚠ CRITICAL"` in the policy changes section
- Text `"chain now drops by default"` or equivalent description present

#### AC-EX04 — DROP rule added labelled critical — MUST

`summary_diff(diff)` where `rules_added` contains a rule with `verdict: "drop"`.

- Return value contains `"⚠ CRITICAL"` in the rules added section

#### AC-EX05 — ACCEPT rule added is not labelled critical — MUST

`summary_diff(diff)` where `rules_added` contains only rules with `verdict: "accept"`.

- Return value does not contain `"⚠ CRITICAL"` for that section

#### AC-EX06 — Removed DROP rule labelled critical — MUST

`summary_diff(diff)` where `rules_removed` contains a rule with `verdict: "drop"`.

- Return value contains `"⚠ CRITICAL"` in the rules removed section

#### AC-EX07 — Recreated section present — MUST

`summary_diff(diff)` where `rules_recreated` is non-empty.

- Return value contains `"Rules Recreated"` (section header)
- Entry shows baseline and current handle numbers

#### AC-EX08 — Verbose mode includes full dict — MUST

`summary_diff(diff, verbose=True)` where `rules_added` is non-empty.

- Return value contains a raw JSON dict representation of the added rule (from `json.dumps`)
- Output is not valid JSON

#### AC-EX09 — Parse warnings appended — MUST

`summary_diff(diff)` where `current_parse_warnings` is non-empty.

- Return value contains `"Current Parse Warnings"` section
- Each warning string present in return value

#### AC-EX10 — Output contains no bare dict repr — MUST

`summary_diff(diff, verbose=False)` where all change lists are non-empty.

- Return value does not contain raw Python dict representation (`{' ` or `{"` patterns without being inside a code span)
- All rule information rendered as Markdown bullet lines, not raw Python objects

#### AC-EX11 — Summary table omits zero-count rows — MUST

`summary_diff(diff)` where only `rules_added: 1` and all other counts are 0.

- Summary table contains exactly one data row (for "Rules added")
- Rows for zero-count categories absent

#### AC-EX12 — Priority change rendered in policy section — MUST

`summary_diff(diff)` where `policy_changes` contains a priority-change entry (has `current_priority` key, no `current_policy` key).

- Return value contains `"priority"` and the old/new priority values in the policy changes section
- `"enforcement order"` or equivalent phrase present

#### AC-EX13 — Type change rendered in policy section — MUST

`summary_diff(diff)` where `policy_changes` contains a type-change entry (has `current_type` key).

- Return value contains `"type"` and the old/new type values in the policy changes section

#### AC-EX14 — No-drift with warnings shows warning section — MUST

`summary_diff(diff)` where `drift_detected: false` but `current_parse_warnings` is non-empty.

- Return value contains `"No drift detected."` (no drift section)
- Return value also contains `"Current Parse Warnings"` section with the warning strings

---

## Known Limitations

**`has_critical_changes` and repositioned DROP rules:** A DROP rule moving from position 5 to position 2 (gaining priority over other rules) produces `has_critical_changes: false`. The field classifies rule additions, removals, policy changes, and critical-verdict recreations — not repositioning. Engineers using the diff for security analysis must inspect `rules_repositioned` entries manually. See AC-D16 for the analogous case.

**`rules_recreated` conservative flag:** Recreation of a DROP or REJECT rule always sets `has_critical_changes: true` even when the recreated rule is semantically identical to the original. This is intentional: the deletion window is the reportable event. See AC-D06.
