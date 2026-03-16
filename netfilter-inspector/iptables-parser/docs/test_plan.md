# iptables-parser — Test Plan

*Modules: `iptables_parser.py`, `iptables_diff.py`*
*Status: MVP shipped — 2026-03-15*

---

## How to Run

```bash
# Parser tests (iptables-parser/)
cd netfilter-inspector/iptables-parser
python3 -m pytest

# Diff engine tests — currently at firewall-inspector/tests/test_diff.py
# (historical location; iptables_diff.py was moved to iptables-parser/ after tests were written)
cd netfilter-inspector/firewall-inspector
python3 -m pytest tests/test_diff.py

# All tests
cd netfilter-inspector
python3 -m pytest -v --tb=short
```

**Priority notation:**
- **MUST** — blocking; the module fails acceptance if this criterion fails
- **SHOULD** — important; failure warrants a documented exception before shipping

---

## Part 1 — Parser (`iptables_parser.py`)

### 1. Fixture-Level Criteria

#### AC-F01 — Azure baseline (`ubuntu2404-clean.txt`) — MUST

- Exactly 1 table key in output: `security`
- `filter`, `nat`, `mangle`, `raw` are absent from the output
- `security` table contains exactly 3 chains: `INPUT`, `FORWARD`, `OUTPUT`
- All 3 chains have `default_policy: "ACCEPT"`
- `INPUT` and `FORWARD` chains have `rules: []`
- `OUTPUT` chain has exactly 3 rules:
  - Rule 1: `target: "ACCEPT"`, destination `168.63.129.16/32`, protocol `"tcp"`, `dst_port: "53"`
  - Rule 2: `target: "ACCEPT"`, destination `168.63.129.16/32`, protocol `"tcp"`, `match_extensions.owner.uid_owner: "0"`
  - Rule 3: `target: "DROP"`, destination `168.63.129.16/32`, protocol `"tcp"`, `match_extensions.conntrack.ctstates: ["INVALID", "NEW"]`
- All rule-level `packet_count` and `byte_count` fields are `null`
- All chains have `policy_packet_count` and `policy_byte_count` present as integers
- `parsed_at` present and is a valid ISO-8601 timestamp
- `input_format: "iptables-save"`

#### AC-F02 — Azure baseline with counters (`ubuntu2404-clean-counters.txt`) — MUST

- Table structure, chain structure, and all rule match/target fields identical to AC-F01
- Every rule has `packet_count` (integer ≥ 0) and `byte_count` (integer ≥ 0)
- `input_format: "iptables-save-counters"`
- Chain `policy_packet_count` and `policy_byte_count` present in both AC-F01 and AC-F02

#### AC-F03 — Docker v26 (`ubuntu2404-docker.txt`) — MUST

- Exactly 3 tables parsed: `raw`, `filter`, `nat`
- `filter` table contains exactly 9 chains: 3 built-in and 6 user-defined (`DOCKER`, `DOCKER-BRIDGE`, `DOCKER-CT`, `DOCKER-FORWARD`, `DOCKER-INTERNAL`, `DOCKER-USER`)
- `DOCKER-USER` and `DOCKER-INTERNAL` are empty: `rules: []`
- `FORWARD` chain has `default_policy: "DROP"`
- `INPUT` and `OUTPUT` chains have `rules: []`
- `-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP` in `raw`:
  - `in_interface: "docker0"`, `in_interface_negated: true`
  - `destination: "172.17.0.2/32"`, `destination_negated: false`
  - `target: "DROP"`, `target_stops_chain_traversal: true`
- `-A DOCKER ! -i docker0 -o docker0 -j DROP`:
  - `in_interface: "docker0"`, `in_interface_negated: true`
  - `out_interface: "docker0"`, `out_interface_negated: false`
  - `target: "DROP"`, `target_stops_chain_traversal: true`
- `-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`:
  - `match_extensions.conntrack.ctstates: ["RELATED", "ESTABLISHED"]`
  - `target: "ACCEPT"`, `target_stops_chain_traversal: true`
- DNAT rule in nat: `target: "DNAT"`, `target_params.to_destination: "172.17.0.2:80"`, `in_interface_negated: true`, `dst_port: "8080"`
- MASQUERADE in nat POSTROUTING: `target_params: null`, `source: "172.17.0.0/16"`, `out_interface: "docker0"`, `out_interface_negated: true`
- FORWARD rules jumping to user-defined chains: `target_stops_chain_traversal: "conditional"`

#### AC-F04 — Docker + fail2ban (`ubuntu2404-docker-fail2ban.txt`) — MUST

- `f2b-sshd` present as user-defined chain in `filter`
- `-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd`:
  - `target: "f2b-sshd"`, `target_stops_chain_traversal: "conditional"`
  - `dst_port: null`
  - `match_extensions.multiport.destination_ports: ["22"]`
- REJECT rule: `target: "REJECT"`, `target_stops_chain_traversal: true`, `target_params.reject_with: "icmp-port-unreachable"`
- RETURN rule at end of `f2b-sshd`: `target: "RETURN"`, `target_stops_chain_traversal: true`

#### AC-F05 — Docker + fail2ban + WireGuard (`ubuntu2404-docker-fail2ban-wireguard.txt`) — MUST

- nat `POSTROUTING` has exactly 2 MASQUERADE rules:
  - Rule 1: `source: "172.17.0.0/16"`, `out_interface: "docker0"`, `out_interface_negated: true`
  - Rule 2: `out_interface: "eth0"`, `out_interface_negated: false`, `source: null`
- `filter` FORWARD: rule with `in_interface: "wg0"` and rule with `out_interface: "wg0"`, both `target: "ACCEPT"`

#### AC-F06 — CIS-hardened (`ubuntu2404-cis-hardened.txt`) — MUST

- Exactly 1 table: `filter`
- `INPUT` chain: `default_policy: "DROP"`, `type: "builtin"`
- `FORWARD` chain: `default_policy: "DROP"`, `type: "builtin"`
- `OUTPUT` chain: `default_policy: "ACCEPT"`, `type: "builtin"`
- State module rule: `match_extensions.state.states: ["RELATED", "ESTABLISHED"]` (not `conntrack`)
- icmp rule: `protocol: "icmp"`, `match_extensions.icmp.icmp_type: "8"` (not `"echo-request"`)
- SSH rule: `dst_port: "22"` and `match_extensions.state.states: ["NEW"]` on same rule object

#### AC-F07 — LOG + MARK + SNAT (`ubuntu2404-log-mark-snat.txt`) — MUST

- Exactly 3 tables: `mangle`, `filter`, `nat`
- Both mangle rules use `--set-xmark`:
  - `target_params.set_xmark_value: "0x1"`, `target_params.set_xmark_mask: "0xffffffff"`
  - `target_params.set_xmark_value: "0x2"`, `target_params.set_xmark_mask: "0xffffffff"`
  - Both: `target_stops_chain_traversal: false`
- LOG rule with `--log-level 6`: `target_params.log_prefix: "HTTP-ACCESS: "` (trailing space preserved), `target_params.log_level: "6"`
- LOG rule without `--log-level`: `target_params.log_level` absent (not null)
- SNAT rule: `target_params.to_source: "10.0.0.1"`, `source: "192.168.100.0/24"`, `out_interface: "eth0"`

#### AC-F08 — Docker with counters (`ubuntu2404-docker-counters.txt`) — MUST

- All rules have `packet_count` (integer ≥ 0) and `byte_count` (integer ≥ 0)
- `input_format: "iptables-save-counters"`
- All rule match/target fields identical to AC-F03

---

### 2. Field Accuracy Criteria

#### AC-FA01 — Protocol field preserved verbatim — MUST

- `protocol: "tcp"` not `"6"`, `protocol: "icmp"` not `"1"`, `protocol: "udp"` not `"17"`
- Whatever string appears after `-p` is the output value
- `protocol: null` when `-p` absent

#### AC-FA02 — CIDR notation preserved verbatim — MUST

- `192.168.100.0/24` not expanded to `192.168.100.0/255.255.255.0`
- `/32` suffix preserved when present
- Host addresses without CIDR preserved as-is

#### AC-FA03 — Port values preserved as strings — MUST

- `dst_port: "22"` not `22`
- `match_extensions.multiport.destination_ports: ["22"]` not `[22]`
- Port ranges as strings: `"1024:65535"` not split into `{from: 1024, to: 65535}`

#### AC-FA04 — State/ctstate lists preserve source order — MUST

- `RELATED,ESTABLISHED` → `["RELATED", "ESTABLISHED"]` (not alphabetically sorted)
- `INVALID,NEW` → `["INVALID", "NEW"]`
- `ESTABLISHED,RELATED` → `["ESTABLISHED", "RELATED"]`

#### AC-FA05 — Negation flags are explicit booleans — MUST

- Every match field that supports negation has a `_negated` boolean field
- `!` present → `_negated: true`; `!` absent → `_negated: false` (not omitted)
- Applies to: `source`, `destination`, `in_interface`, `out_interface`, `protocol`, `dst_port`, `src_port`
- Both negation syntaxes handled: `! -s 192.168.0.0/24` and `-s ! 192.168.0.0/24` both → `source_negated: true`

#### AC-FA06 — `target_stops_chain_traversal` three-value contract — MUST

| Target | Expected value |
|--------|---------------|
| `ACCEPT`, `DROP`, `REJECT`, `RETURN`, `NFQUEUE`, `MASQUERADE`, `SNAT`, `DNAT` | `true` |
| `LOG`, `NFLOG`, `MARK`, `CONNMARK` | `false` |
| Jump to user-defined chain | `"conditional"` |

No other values are valid. RETURN always produces `true` regardless of chain type.

#### AC-FA07 — Empty chains always have `rules: []` — MUST

- A chain with no appended rules always has `rules: []`, never an absent key
- Built-in and user-defined empty chains both have `rules: []`

#### AC-FA08 — `raw_rule` always present — MUST

- Every rule record has `raw_rule` containing the original unmodified rule line
- Counter prefix (`[packets:bytes]`) included in `raw_rule` when present in input

#### AC-FA09 — `parsed_at` excluded from determinism — MUST

- Parsing the same file twice: identical output in all fields except `parsed_at`
- `parsed_at` reflects actual parse time and differs between invocations

---

### 3. Edge Case Criteria

#### AC-EC01 — RETURN in user-defined chain — MUST

- RETURN in a user-defined chain: `target_stops_chain_traversal: true` (same as built-in chain)
- Chain `type` field distinguishes user-defined from built-in

#### AC-EC02 — Multiple modules on one rule — MUST

- `-p tcp -m tcp --dport 22 -m state --state NEW` → single rule object with both `dst_port: "22"` and `match_extensions.state.states: ["NEW"]`

#### AC-EC03 — `--set-xmark` with mask — MUST

- `--set-xmark 0x1/0xffffffff` → `target_params.set_xmark_value: "0x1"`, `target_params.set_xmark_mask: "0xffffffff"` (both hex strings verbatim)

#### AC-EC04 — Optional target parameters absent when not specified — MUST

- LOG without `--log-level`: `target_params.log_level` absent (not null)
- LOG without `--log-prefix`: `target_params.log_prefix` absent
- MASQUERADE without `--to-ports`: `target_params: null`

#### AC-EC05 — icmp-type as numeric string — MUST

- `--icmp-type 8` → `match_extensions.icmp.icmp_type: "8"` (not `"echo-request"`)

#### AC-EC06 — Duplicate rules — MUST

- Two identical rule lines in the same chain → two rule objects at sequential positions; no deduplication

#### AC-EC07 — Chain position is 1-based — MUST

- First appended rule: `position: 1`; increments by 1 per subsequent rule

#### AC-EC08 — All-empty input — MUST

- Comments and whitespace only → `tables: {}`, `parse_warnings: []`, all `diagnostics` sub-arrays empty, `input_format: "iptables-save"`

#### AC-EC09 — REJECT without `--reject-with` defaults to icmp-port-unreachable — MUST

- `-j REJECT` with no `--reject-with` → `target_params.reject_with: "icmp-port-unreachable"` (not absent)

---

### 4. Diagnostics Criteria

#### AC-DI01 — `drop_policy_chains` populated correctly — MUST

Fixture: `ubuntu2404-cis-hardened.txt`
- `diagnostics.drop_policy_chains` contains `"filter/INPUT"` and `"filter/FORWARD"`
- `"filter/OUTPUT"` absent (its policy is ACCEPT)

Fixture: `ubuntu2404-docker.txt`
- `diagnostics.drop_policy_chains` contains `"filter/FORWARD"`

#### AC-DI02 — `nat_summary` populated from nat table rules — MUST

Fixture: `ubuntu2404-docker.txt`
- `diagnostics.nat_summary.masquerade_rules`: exactly 1 entry (POSTROUTING MASQUERADE)
- `diagnostics.nat_summary.dnat_rules`: exactly 1 entry (DOCKER chain DNAT)
- Each entry is a full rule record

#### AC-DI03 — `user_defined_chains` entry includes `referenced_from` — MUST

Fixture: `ubuntu2404-docker-fail2ban.txt`
- `diagnostics.user_defined_chains` has entry for `"f2b-sshd"`
- `referenced_from` contains at least one entry with `table`, `chain`, and `position` fields

#### AC-DI04 — `conntrack_position_warnings` — MUST

Requires synthetic input (no real fixture contains this pattern):

```
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
```

- `diagnostics.conntrack_position_warnings` contains 1 entry
- Entry records: `chain: "INPUT"`, `conntrack_rule_position: 2`, `preceding_drop_rules` listing the DROP rule at position 1
- Warning does not assert a fault exists — records the condition for engineer review

#### AC-DI05 — `diagnostics` always fully present — MUST

- `diagnostics` key always present, even when all sub-arrays empty
- All sub-keys always present: `drop_policy_chains`, `accept_policy_chains`, `conntrack_position_warnings`, `active_drop_rules`, `nat_summary.masquerade_rules`, `nat_summary.dnat_rules`, `nat_summary.snat_rules`, `user_defined_chains`, `unresolved_chain_references`

---

### 5. Error Handling Criteria

#### AC-EH01 — Missing COMMIT — MUST

- Table block with no `COMMIT` → `parse_warnings` entry identifying the table
- Other valid tables still parsed; no crash

#### AC-EH02 — Unknown target — SHOULD

- Unrecognised target (e.g., `-j CUSTOM_TARGET`) → `target: "CUSTOM_TARGET"`, `target_stops_chain_traversal: "conditional"`
- Parse warning recorded; rule included with `raw_rule` preserved

#### AC-EH03 — Invalid chain policy — MUST

- Chain with `REJECT` as policy → parse warning; other chains in same table still parsed; no crash

#### AC-EH04 — Unresolved chain reference — SHOULD

- Jump to undefined chain → `diagnostics.unresolved_chain_references` entry with `target_chain` and referring location
- Parse warning recorded; rule included with `target_stops_chain_traversal: "conditional"`

#### AC-EH05 — Malformed rule line — MUST

- Rule missing `-j` or truncated → parse warning with line number and `raw_rule`
- Remaining lines parsed; no crash

#### AC-EH06 — Inconsistent counter prefixes — MUST

- Some rule lines have `[packets:bytes]`, others do not → parse warning
- Rules without counter prefix: `packet_count: null`, `byte_count: null`
- Rules with counter prefix parsed normally

---

### 6. Non-Functional Criteria

#### AC-NF01 — Determinism — MUST

- Same file parsed 10 consecutive times → byte-identical output (excluding `parsed_at`)

#### AC-NF02 — Performance — SHOULD

- All 8 fixture files parsed sequentially in under 2 seconds on a laptop-class machine

#### AC-NF03 — No external dependencies — MUST

- Parser imports only Python standard library modules; no `pip install` required

#### AC-NF04 — Output is always valid JSON — MUST

- `json.loads(parser_output)` succeeds for every input, including malformed input
- `parse_warnings` always a list — never null, never absent

#### AC-NF05 — Input accepted from file path or stdin — MUST

- File path argument and stdin both accepted; both produce identical output for identical content

---

### 7. Fixture-to-Criterion Coverage Map

| Pattern | F01 | F02 | F03 | F04 | F05 | F06 | F07 | F08 |
|---------|-----|-----|-----|-----|-----|-----|-----|-----|
| Chain policy counters always present | ✓ | ✓ | | | | | | |
| Rule counters null (no --counters) | ✓ | | | | | | | |
| Rule counters present (--counters) | | ✓ | | | | | | ✓ |
| INPUT/FORWARD DROP policy | | | ✓ | | | ✓ | ✓ | |
| Negated interface | | | ✓ | ✓ | ✓ | | | |
| conntrack module + ctstates | ✓ | | ✓ | ✓ | ✓ | | | |
| state module + states | | | | | | ✓ | ✓ | |
| icmp with numeric type | | | | | | ✓ | ✓ | |
| owner module | ✓ | ✓ | | | | | | |
| addrtype module | | | ✓ | | | | | |
| REJECT + reject_with | | | | ✓ | | | | |
| RETURN in user-defined chain | | | | ✓ | | | | |
| multiport destination_ports | | | | ✓ | | | | |
| DNAT + to_destination | | | ✓ | | | | | |
| MASQUERADE, no to_ports | | | ✓ | ✓ | ✓ | | | |
| Dual MASQUERADE in one chain | | | | | ✓ | | | |
| LOG + log_prefix/log_level | | | | | | | ✓ | |
| LOG without log_level | | | | | | | ✓ | |
| MARK + set_xmark_value/mask | | | | | | | ✓ | |
| SNAT + to_source | | | | | | | ✓ | |
| mangle table | | | | | | | ✓ | |
| security table only | ✓ | ✓ | | | | | | |
| Empty user-defined chains | | | ✓ | | | | | |
| Multiple modules on one rule | | | | | | ✓ | ✓ | |
| Duplicate rules | | | | | | | ✓ | |
| WireGuard FORWARD rules | | | | | ✓ | | | |

---

## Part 2 — Diff Engine (`iptables_diff.py`)

**Note:** Tests are at `firewall-inspector/tests/test_diff.py` (historical location — `iptables_diff.py` moved to `iptables-parser/` after the tests were written). The `firewall-inspector/tests/conftest.py` adds `../iptables-parser/` to `sys.path` so imports resolve correctly.

---

#### AC-D01 — Identical inputs produce no drift — MUST

Input: same parsed ruleset as both baseline and current.

- `drift_detected: false`, `has_critical_changes: false`
- All change lists empty; all summary counts zero

#### AC-D02 — Rule added to existing chain — MUST

Input: baseline has N rules; current has same chain with N+1 rules.

- New rule in `rules_added` with full rule record
- Absent from `rules_removed` and `rules_repositioned`
- `drift_detected: true`

#### AC-D03 — Rule removed from existing chain — MUST

Input: baseline has N rules; current has N-1 rules.

- Removed rule in `rules_removed` with full rule record from baseline
- Absent from `rules_added` and `rules_repositioned`
- `drift_detected: true`

#### AC-D04 — Rule repositioned within chain — MUST

Input: baseline has rule at position 3; current has identical rule at position 5.

- Rule in `rules_repositioned` with `baseline_position: 3`, `current_position: 5`
- Absent from `rules_added` and `rules_removed`
- `drift_detected: true`

#### AC-D05 — Chain added to existing table — MUST

Input: baseline has filter with 3 built-in chains; current adds one user-defined chain with 2 rules.

- New chain in `chains_added` with `table`, `chain`, `type`, `rule_count` fields
- The chain's 2 rules absent from `rules_added` (no double-counting)
- `drift_detected: true`

#### AC-D06 — Chain removed from existing table — MUST

Input: baseline has a user-defined chain; current does not.

- Chain in `chains_removed`
- Chain's rules absent from `rules_removed`
- `drift_detected: true`

#### AC-D07 — Entire table added — MUST

Input: baseline has only filter; current has filter and nat.

- `"nat"` in `tables_added`
- All nat chains in `chains_added`
- No nat rules in `rules_added`
- `drift_detected: true`

#### AC-D08 — Entire table removed — MUST

Input: baseline has filter and nat; current has only filter.

- `"nat"` in `tables_removed`
- All nat chains in `chains_removed`
- No nat rules in `rules_removed`
- `drift_detected: true`

#### AC-D09 — Chain default policy changed — MUST

Input: `filter/INPUT` policy ACCEPT → DROP.

- Entry in `policy_changes`: `table: "filter"`, `chain: "INPUT"`, `baseline_policy: "ACCEPT"`, `current_policy: "DROP"`
- `drift_detected: true`

#### AC-D10 — Counter-only changes produce no drift — MUST

Input: identical rules; only `packet_count` and `byte_count` differ.

- `drift_detected: false`; all change lists empty

#### AC-D11 — Counters file vs non-counters file, same rules — MUST

Input: baseline from `iptables-save` (`packet_count: null`); current from `iptables-save --counters` (non-null). Rule definitions identical.

- `drift_detected: false`; all change lists empty

#### AC-D12 — DROP rule added — MUST

Input: current has a new `-j DROP` rule not in baseline.

- Rule in `rules_added`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D13 — REJECT rule removed — MUST

Input: baseline has a `-j REJECT` rule; current does not.

- Rule in `rules_removed`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D14 — Policy changed ACCEPT → DROP — MUST

Input: `filter/INPUT` policy ACCEPT → DROP.

- Entry in `policy_changes`
- `has_critical_changes: true`, `drift_detected: true`

#### AC-D15 — Only a LOG rule repositioned — MUST

Input: a `-j LOG` rule moves position; no other changes.

- Rule in `rules_repositioned`
- `has_critical_changes: false`, `drift_detected: true`

#### AC-D16 — Duplicate rules: one copy removed — MUST

Input: baseline has 2 identical LOG rules; current has 1.

- Exactly 1 entry in `rules_removed`
- Remaining identical rule not flagged in any change list
- `drift_detected: true`

#### AC-D17 — Duplicate rules: both repositioned — MUST

Input: baseline has 2 identical LOG rules at positions 5 and 7; current has same rules at positions 6 and 8.

- Exactly 2 entries in `rules_repositioned`: `(5→6)` and `(7→8)`
- Absent from `rules_added` and `rules_removed`
- `drift_detected: true`

#### AC-D18 — Cross-family inputs rejected — MUST

Input: baseline `family: "ipv4"`, current `family: "ipv6"`.

- `ValueError` raised; error message names both families

#### AC-D19 — Invalid input rejected — MUST

Input: dict missing `tables` key or `family` key.

- `ValueError` raised with message identifying which input is invalid

#### AC-D20 — Summary counts always match change list lengths — MUST

For any valid input pair:

- `summary["tables_added"] == len(changes["tables_added"])`
- `summary["tables_removed"] == len(changes["tables_removed"])`
- `summary["chains_added"] == len(changes["chains_added"])`
- `summary["chains_removed"] == len(changes["chains_removed"])`
- `summary["policy_changes"] == len(changes["policy_changes"])`
- `summary["rules_added"] == len(changes["rules_added"])`
- `summary["rules_removed"] == len(changes["rules_removed"])`
- `summary["rules_repositioned"] == len(changes["rules_repositioned"])`

#### AC-D21 — `parse_warnings` passed through; does not affect drift — MUST

Input: baseline has empty `parse_warnings`; current has one warning.

- `current_parse_warnings` contains the warning; `baseline_parse_warnings` empty
- `drift_detected` reflects only rule/chain/policy changes, not warnings

#### AC-D22 — Empty baseline, non-empty current — MUST

Input: baseline is `parse_iptables_save("")`; current is a real fixture.

- All current tables in `tables_added`; all current chains in `chains_added`
- `rules_added: []` (no double-counting)
- `drift_detected: true`

#### AC-D23 — IPv6 diff — MUST

Input: two IPv6 parsed outputs (`family: "ipv6"`) with one rule difference.

- Output `family: "ipv6"`
- `::1/128` in rule identity fields preserved verbatim
- Diff logic behaves identically to IPv4

#### AC-D24 — `rules_repositioned` rule sub-object contains only identity fields — MUST

For any repositioned rule entry:

- `rule` sub-object contains exactly the fields in `_RULE_IDENTITY_FIELDS`
- `position`, `packet_count`, `byte_count`, `raw_rule`, `target_stops_chain_traversal` absent from the `rule` sub-object
- Full rule records (all fields) appear only in `rules_added` and `rules_removed`

#### AC-D25 — Output is always valid JSON — MUST

For any valid input pair:

- `json.dumps(result)` succeeds without error
- All top-level keys always present: `diff_at`, `family`, `baseline_parsed_at`, `current_parsed_at`, `baseline_parse_warnings`, `current_parse_warnings`, `drift_detected`, `has_critical_changes`, `summary`, `changes`

---

## Known Limitations

**`has_critical_changes` and repositioned DROP rules:** A DROP rule moving from position 5 to position 2 (gaining priority) produces `has_critical_changes: false`. The field classifies rule additions/removals and policy changes, not repositioning. Engineers using the diff for security-sensitive analysis should inspect `rules_repositioned` manually. See AC-D15 for the analogous LOG case.
