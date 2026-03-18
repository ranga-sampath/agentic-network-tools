# nftables-parser Module — Design

*Architecture reference: `netfilter-inspector/docs/architecture.md`*
*Requirements reference: `nftables-parser/docs/product-requirements.md`*
*Status: Design complete — 2026-03-16*

This document covers `nftables_parser.py` and `nftables_diff.py`. Both are standalone tools in `nftables-parser/` and together form the parsing and diff foundation for nftables firewall state in the Netfilter Inspector.

---

## 1. Component and Function Inventory

### `nftables_parser.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `parse_nft_ruleset` | `(text: str) → dict` | Parse complete `nft --json list ruleset` text into structured dict. Entry point for all consumers. |
| `_parse_table` | `(obj: dict, state: _ParseState) → None` | Register a table entry. Mutates `state.tables`. |
| `_parse_chain` | `(obj: dict, state: _ParseState) → None` | Register a chain under its table. Adds base-chain metadata (type, hook, priority, policy) or marks as regular chain. |
| `_parse_rule` | `(obj: dict, state: _ParseState) → None` | Parse a rule entry. Calls `_normalize_expressions()`. Appends rule record to its chain. |
| `_parse_set` | `(obj: dict, state: _ParseState) → None` | Register a named set (or map) under its table. Extracts type, elements list. |
| `_normalize_expressions` | `(exprs: list, warnings: list) → dict` | Walk the expression list and extract normalized fields (protocol, ports, addresses, verdict, etc.). Returns a dict of extracted fields + `opaque_expressions` for unrecognised entries. |
| `_extract_verdict` | `(expr: dict) → tuple[str \| None, bool]` | Extract `(verdict_str, verdict_stops_chain)` from a single expression object. Returns `(None, False)` if the expression is not a terminal verdict. |
| `_extract_match_fields` | `(match: dict, record: dict, warnings: list) → None` | Extract normalized fields from a `match` expression. Mutates `record` in-place. |
| `_expression_hash` | `(exprs: list) → str` | Compute SHA-256 of canonical JSON of the expression list (sorted keys, no whitespace). Inline `counter` expressions are stripped before hashing so packet/byte count changes do not produce false-positive diffs. Returns hex digest string. |
| `_run_diagnostics` | `(tables: dict) → dict` | Compute the diagnostics section from the fully populated tables dict. No warnings emitted here. |
| `main` | `() → None` | CLI entry point. Reads file or stdin, calls `parse_nft_ruleset`, prints JSON. |

### `nftables_diff.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `diff_rulesets` | `(baseline: dict, current: dict) → dict` | Compare two `parse_nft_ruleset()` outputs and return a structured diff. |
| `_validate` | `(d: Any, label: str) → None` | Validate that a dict has `input_format` and `tables` fields. Raises `ValueError` on failure. |
| `_rules_by_handle` | `(rules: list[dict]) → dict[int, dict]` | Index rules by handle. Raises `ValueError` on duplicate handles within a chain (indicates malformed parser output). |
| `_rules_by_hash` | `(rules: list[dict]) → dict[str, list[dict]]` | Index rules by `expression_hash`. Used as secondary key to detect semantically equivalent rules with new handles. |
| `_is_critical_verdict` | `(rule: dict) → bool` | Returns `True` if rule has `verdict` in `{"drop", "reject"}`. |
| `_policy_is_critical` | `(policy: str \| None) → bool` | Returns `True` if `policy == "drop"`. |
| `summary_diff` | `(diff: dict, *, verbose: bool = False) → str` | Produce a human-readable Markdown summary of a `diff_rulesets()` result. Returns a Markdown string. Non-JSON output. |
| `_rule_summary_lines` | `(rule: dict, *, verbose: bool, indent: str) → list[str]` | Return bullet lines describing a single rule record. In verbose mode emits the full JSON dict; in default mode emits the most discriminating fields only. |
| `_critical_label` | `(rule: dict) → str` | Returns `"  ⚠ CRITICAL"` if the rule has a drop or reject verdict; otherwise returns `""`. |
| `_append_warnings` | `(lines: list[str], diff: dict) → None` | Append parse warning sections to the Markdown line list if either `baseline_parse_warnings` or `current_parse_warnings` is non-empty. Mutates `lines` in-place. |
| `main` | `() → None` | CLI entry point. Reads two JSON files, calls `diff_rulesets`, prints JSON or Markdown depending on `--summary` flag. |

---

## 2. Data Schemas

### `parse_nft_ruleset()` output

```json
{
  "parsed_at":       "2026-03-16T09:00:00Z",
  "input_format":    "nft-json",
  "nft_version":     "1.0.9",
  "json_schema_version": 1,
  "tables": {
    "ip/filter": {
      "family":  "ip",
      "name":    "filter",
      "handle":  1,
      "chains": {
        "input": { "<chain_record>" },
        "mychain": { "<chain_record>" }
      },
      "sets": {
        "blocklist": { "<set_record>" }
      }
    },
    "inet/main": { "..." }
  },
  "diagnostics":    { "<diagnostics_record>" },
  "parse_warnings": [ "string", ... ]
}
```

**Table key format:** `"<family>/<name>"` — e.g. `"ip/filter"`, `"inet/main"`, `"ip6/output"`. The compound key is required because nftables allows tables of different families to share the same name.

**`input_format`** is always `"nft-json"`. This value is used by the diff engine and the firewall-inspector orchestrator to route to the correct parser/diff module.

### Chain record

```json
{
  "name":         "input",
  "handle":       1,
  "is_base_chain": true,
  "type":         "filter",
  "hook":         "input",
  "priority":     0,
  "policy":       "accept",
  "rules":        [ "<rule_record>", ... ]
}
```

**Regular chain** (no hook — reachable only via jump/goto from rules):
```json
{
  "name":         "mychain",
  "handle":       2,
  "is_base_chain": false,
  "type":         null,
  "hook":         null,
  "priority":     null,
  "policy":       null,
  "rules":        []
}
```

**`type`** values: `"filter"`, `"nat"`, `"route"`. `null` for regular chains.
**`hook`** values: `"input"`, `"output"`, `"forward"`, `"prerouting"`, `"postrouting"`, `"ingress"`, `"egress"`. `null` for regular chains.
**`priority`** values: integer (e.g. `0`, `100`, `-100`) or nft named priority string converted to integer (`"filter"` → `0`, `"srcnat"` → `100`, `"dstnat"` → `-100`). `null` for regular chains.

### Rule record

```json
{
  "table":                 "ip/filter",
  "chain":                 "input",
  "handle":                5,
  "position":              2,
  "verdict":               "accept",
  "verdict_stops_chain":   true,
  "protocol":              "tcp",
  "dst_port":              "22",
  "src_port":              null,
  "src_addr":              null,
  "dst_addr":              null,
  "in_interface":          null,
  "out_interface":         null,
  "ct_state":              null,
  "comment":               "allow SSH from management range",
  "icmp_type":             null,
  "icmp_type_negated":     false,
  "icmp_code":             null,
  "icmp_code_negated":     false,
  "ct_mark":               null,
  "ct_mark_negated":       false,
  "ct_direction":          null,
  "ct_zone":               null,
  "protocol_negated":      false,
  "src_addr_negated":      false,
  "dst_addr_negated":      false,
  "src_port_negated":      false,
  "dst_port_negated":      false,
  "in_interface_negated":  false,
  "out_interface_negated": false,
  "is_log":                false,
  "log_prefix":            null,
  "jump_target":           null,
  "goto_target":           null,
  "set_references":        [],
  "opaque_expressions":    null,
  "expression_hash":       "a3f9c2...",
  "raw_expressions":       [ { "match": {...} }, { "accept": null } ]
}
```

**Field semantics:**

| Field | Semantics |
|-------|-----------|
| `handle` | nftables-assigned stable integer identifier. Unique within a chain. Primary diff key. |
| `position` | 1-based monotonic position within the chain, assigned by the parser in parse order. Changes when rules are inserted before this rule. Secondary diff signal. |
| `verdict` | Terminal verdict string: `"accept"`, `"drop"`, `"return"`, `"reject"`, or `null` if no terminal verdict found (non-terminal rule — log-only, counter-only, etc.) |
| `verdict_stops_chain` | `true` for `accept`, `drop`, `reject`. `false` for `return` (returns to caller), and for rules with no terminal verdict (log-only, counter-only). |
| `protocol` | Extracted L4 protocol: `"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"`, `"esp"`, `"ah"`, or `null` if no protocol match in rule. |
| `ct_state` | List of conntrack state strings: e.g. `["established", "related"]`. `null` if no ct state match. |
| `comment` | The top-level `comment` string from the nft rule object (sibling of `family`, `chain`, `expr`). `null` if no comment is present. |
| `icmp_type` | ICMP/ICMPv6 type name from a `payload {protocol: icmp|icmpv6, field: type}` match (e.g. `"echo-request"`, `"nd-neighbor-solicit"`). `null` if no ICMP type match. |
| `icmp_type_negated` | `true` if the ICMP type match uses op `"!="`. `false` if absent or non-negated. |
| `icmp_code` | ICMP/ICMPv6 code name from a `payload {protocol: icmp|icmpv6, field: code}` match. `null` if no ICMP code match. |
| `icmp_code_negated` | `true` if the ICMP code match uses op `"!="`. `false` if absent or non-negated. |
| `ct_mark` | Conntrack mark value (as string) from a `ct {key: mark}` match. `null` if no ct mark match. |
| `ct_mark_negated` | `true` if the ct mark match uses op `"!="`. `false` if absent or non-negated. |
| `ct_direction` | Conntrack direction string from a `ct {key: direction}` match (e.g. `"original"`, `"reply"`). `null` if no ct direction match. Negation is not meaningful for direction and is not captured. |
| `ct_zone` | Conntrack zone value (as string) from a `ct {key: zone}` match. `null` if no ct zone match. Negation is not meaningful for zone and is not captured. |
| `protocol_negated` | `true` if the protocol match uses op `"!="`. Independent of other negation fields. `false` if no protocol match is present. |
| `src_addr_negated` | `true` if the source address match uses op `"!="`. |
| `dst_addr_negated` | `true` if the destination address match uses op `"!="`. |
| `src_port_negated` | `true` if the source port match uses op `"!="`. |
| `dst_port_negated` | `true` if the destination port match uses op `"!="`. |
| `in_interface_negated` | `true` if the ingress interface match uses op `"!="`. |
| `out_interface_negated` | `true` if the egress interface match uses op `"!="`. |
| `set_references` | List of set names referenced via `@setname` patterns in the expressions. Empty list if none. |
| `opaque_expressions` | Serialized JSON list of expression objects that could not be normalised to known fields. `null` if all expressions were recognised. A parse warning is emitted for each opaque expression. |
| `expression_hash` | SHA-256 hex digest of canonical JSON of `raw_expressions` (sorted keys, no whitespace). Used as secondary diff key. |
| `raw_expressions` | Full expression list from the source JSON. Always present — this is the source of truth when normalized fields are insufficient. |

**`verdict` for jump/goto rules:** A rule that jumps to a chain has `verdict: null` and `jump_target: "chainname"` (or `goto_target`). Chain traversal via jump is not a terminal verdict — the chain may RETURN or fall through. This is distinct from iptables where a user-chain jump was represented as `target: "CHAINNAME"` in the target field.

### Set record

```json
{
  "name":     "blocklist",
  "handle":   10,
  "type":     "ipv4_addr",
  "is_map":   false,
  "elements": ["10.0.0.1", "10.0.0.2", "192.168.0.0/24"],
  "flags":    ["interval"],
  "timeout":  null
}
```

**`is_map`** is `true` when the nft object type is `"map"` (key→value). Map values are stored opaquely in `elements` as raw JSON strings.
**`elements`** is `null` when the set has no inline elements defined (elements added dynamically at runtime).

### `_ParseState` (internal parse accumulator)

`_ParseState` is an internal type created at the start of `parse_nft_ruleset()` and passed to all `_parse_*` helper functions. It is not part of any public output schema.

```python
@dataclass
class _ParseState:
    tables:   dict[str, dict]  # "family/name" → partially assembled table record
    warnings: list[str]        # parse warnings accumulated during this run
```

**Lifecycle:** Created by `parse_nft_ruleset()` with `tables={}`, `warnings=[]`. Mutated in-place by `_parse_table()`, `_parse_chain()`, `_parse_rule()`, and `_parse_set()`. Read (not mutated) by `_run_diagnostics()` and the final output assembly step in `parse_nft_ruleset()`.

**`tables` structure while in-flight:** Keys are `"family/name"` compound strings (e.g. `"ip/filter"`). Values are partially assembled table dicts whose `"chains"` sub-dict grows as `_parse_chain()` and `_parse_rule()` are called. The table dict is complete only after the full dispatch loop finishes.

---

### Diagnostics record

```json
{
  "drop_policy_chains":      ["ip/filter/input", "inet/main/forward"],
  "accept_policy_chains":    ["ip/filter/output", "ip/filter/forward"],
  "active_drop_rules":       [ "<rule_record>", ... ],
  "unresolved_chain_jumps": [
    {
      "table":        "ip/filter",
      "chain":        "input",
      "handle":       7,
      "position":     3,
      "jump_target":  "ghost_chain"
    }
  ],
  "inet_tables":             ["inet/main"],
  "sets_referenced_in_rules": {
    "blocklist": { "table": "ip/filter", "found": true },
    "allowlist": { "table": "ip/filter", "found": false }
  }
}
```

**`active_drop_rules`** is always an empty list unless the input includes counter data (nft counters attached to rules). Counter extraction is best-effort: the `counter` expression in a rule's expression list may contain `packets` and `bytes` fields; if present and `packets > 0`, the rule is included in `active_drop_rules` if it also has `verdict = "drop"`.

**`inet_tables`** lists tables in the `"inet"` family. These tables enforce policy on both IPv4 and IPv6 traffic. The operator must be aware that a drop rule in an `inet/filter/input` chain blocks both address families simultaneously.

### `diff_rulesets()` output

```json
{
  "diff_at":                 "2026-03-16T10:00:00Z",
  "input_format":            "nft-json",
  "baseline_parsed_at":      "2026-03-16T08:00:00Z",
  "current_parsed_at":       "2026-03-16T10:00:00Z",
  "baseline_parse_warnings": [],
  "current_parse_warnings":  [],
  "drift_detected":          true,
  "has_critical_changes":    true,
  "summary": {
    "tables_added":       0,
    "tables_removed":     0,
    "chains_added":       0,
    "chains_removed":     0,
    "policy_changes":     0,
    "rules_added":        1,
    "rules_removed":      0,
    "rules_repositioned": 0,
    "rules_recreated":    0
  },
  "changes": {
    "tables_added":       [],
    "tables_removed":     [],
    "chains_added":       [],
    "chains_removed":     [],
    "policy_changes":     [],
    "rules_added":        [ "<full rule_record from current>" ],
    "rules_removed":      [ "<full rule_record from baseline>" ],
    "rules_repositioned": [
      {
        "table":              "ip/filter",
        "chain":              "input",
        "handle":             5,
        "baseline_position":  3,
        "current_position":   5,
        "rule":               { "<identity fields only>" }
      }
    ],
    "rules_recreated": [
      {
        "baseline_rule": "<full rule_record — old handle>",
        "current_rule":  "<full rule_record — new handle>",
        "note":          "Semantically equivalent rule: same expression_hash, different handle. Rule was deleted and re-added."
      }
    ]
  }
}
```

**`rules_recreated`**: A rule is classified as recreated when a rule in `rules_removed` (baseline handle absent from current) has the same `expression_hash` as a rule in `rules_added` (current handle absent from baseline). The old and new rule records are cross-referenced. The summary counts `rules_recreated` separately from `rules_added` / `rules_removed` — it does not double-count: a recreated rule is removed from both `rules_added` and `rules_removed` and placed in `rules_recreated`.

**`has_critical_changes` is `true` when any of:**
- `policy_changes` is non-empty and the new policy is `"drop"`
- Any `rules_added` entry has `verdict` in `{"drop", "reject"}`
- Any `rules_removed` entry has `verdict` in `{"drop", "reject"}`
- Any rule in the rules of a `chains_added` entry has `verdict` in `{"drop", "reject"}`
- Any rule in the rules of a `chains_removed` entry has `verdict` in `{"drop", "reject"}`
- Any `rules_recreated` entry has `verdict` in `{"drop", "reject"}` (conservative: recreation of a critical rule is always flagged even if semantically identical — the act of deleting and re-adding a blocking rule creates a window, however brief, during which the rule was not enforced; the recreation itself is the reportable event)

**`has_critical_changes` is `false` despite `drift_detected: true` when:** only non-verdict rules changed (log-only, counter-only), rules were repositioned only, or non-critical chains were added/removed.

**`chains_added` / `chains_removed` entry schema:**
```json
{"table": "ip/filter", "chain": "newchain", "handle": 15, "is_base_chain": false, "rule_count": 3}
```

**`policy_changes` entry schema:**
```json
{
  "table":           "ip/filter",
  "chain":           "input",
  "baseline_policy": "accept",
  "current_policy":  "drop"
}
```

---

## 3. Pipeline Stage Detail — `parse_nft_ruleset()`

The parser processes the JSON object list in a single sequential pass over the `nftables` array.

**Stage: JSON decode**
- Input: raw text string
- Processing: `json.loads(text)` — must be valid JSON; must have a top-level `"nftables"` key containing a list
- Failure: `json.JSONDecodeError` → `ValueError("Input is not valid JSON: ...")`
- Failure: `"nftables"` key missing → `ValueError("Input is not nft --json list ruleset output: missing 'nftables' key")`

**Stage: metainfo extraction**
- Input: first object in `nftables` list with key `"metainfo"`
- Processing: extract `version` and `json_schema_version`; store in output
- Failure: metainfo absent → `nft_version: null`, `json_schema_version: null`; parse warning emitted

**Stage: object dispatch loop**
- Input: each remaining object in `nftables` list
- Processing: determine object type by first key (`"table"`, `"chain"`, `"rule"`, `"set"`, `"map"`, `"counter"`, `"quota"`, `"limit"`, `"flowtable"`)
- Dispatch: call `_parse_table()`, `_parse_chain()`, `_parse_rule()`, `_parse_set()` for the four primary types; for all others, emit parse warning and continue
- Failure: no recognised key → parse warning: `"Unknown nftables object type at index N: keys={...}"`; object skipped

**Stage: `_parse_rule()` / `_normalize_expressions()`**
- Input: rule object dict from JSON
- Processing:
  1. Validate required fields: `family`, `table`, `chain`, `handle`, `expr` present
  2. Look up parent chain; emit warning and create implicit chain if not found
  3. Call `_normalize_expressions(expr_list, warnings)` → returns normalised field dict
  4. Compute `expression_hash` from raw `expr` list
  5. Assign `position` = current length of chain's rules list + 1
  6. Assemble full rule record; append to chain
- Failure: `handle` missing → `parse_warning` emitted; rule skipped (handle is required for diff identity)
- Failure: `expr` missing → `parse_warning` emitted; rule included with `verdict: null`, `raw_expressions: []`

**Stage: `_normalize_expressions()`**
- Input: nft JSON expression list
- Processing: iterate over expressions; for each, attempt extraction:
  - `{"match": {...}}` → call `_extract_match_fields()`
  - `{"accept": null}` → `verdict = "accept"`, `verdict_stops_chain = true`
  - `{"drop": null}` → `verdict = "drop"`, `verdict_stops_chain = true`
  - `{"return": null}` → `verdict = "return"`, `verdict_stops_chain = false`
  - `{"reject": {...}}` → `verdict = "reject"`, `verdict_stops_chain = true`; extract reject type if present
  - `{"jump": {"target": "chain"}}` → `jump_target = "chain"`
  - `{"goto": {"target": "chain"}}` → `goto_target = "chain"`
  - `{"log": {...}}` → `is_log = true`; extract `log_prefix` if present
  - `{"counter": {...}}` → extract packet/byte counts if present; not a verdict
  - `{"limit": {...}}`, `{"quota": {...}}` → non-terminal; do not add to opaque
  - Unrecognised top-level key → append to `opaque_expressions`; emit parse warning
- Failure handling: any `KeyError` or `TypeError` during extraction → expression moved to `opaque_expressions`; parse warning with context

**Stage: diagnostics pass (post-parse)**
- Runs once after all objects are processed
- Computes: `drop_policy_chains`, `accept_policy_chains`, `active_drop_rules`, `unresolved_chain_jumps`, `inet_tables`, `sets_referenced_in_rules`
- No parse warnings emitted here

---

## 4. Pipeline Stage Detail — `diff_rulesets()`

**Stage: Input validation**
- Each input validated: must be dict with `input_format` (str) and `tables` (dict) keys
- `input_format` compatibility: both must be `"nft-json"`. Cross-format diff (e.g. nft-json vs iptables-save) → `ValueError` naming both formats.
- Failure: `ValueError` with specific label (`"baseline"` or `"current"`) and missing field

**Stage: Table-level diff**
- `tables_added` = table keys in current not in baseline
- `tables_removed` = table keys in baseline not in current
- All chains in added tables → `chains_added`; all chains in removed tables → `chains_removed` (no double-count into `rules_added` / `rules_removed`)

**Stage: Chain-level diff (tables present in both)**
- For each table present in both: chains only in current → `chains_added`; chains only in baseline → `chains_removed`

**Stage: Policy diff (chains present in both)**
- Compare `policy` only. `null` → `"drop"` or `"accept"` → `null` are both recorded.
- `priority` and `type` changes are recorded in `policy_changes` with a `"note"` field (these affect enforcement order, not just policy)

**Stage: Rule diff — handle-based primary pass**
- Build `_rules_by_handle(baseline_chain_rules)` and `_rules_by_handle(current_chain_rules)` for each chain
- Handles only in current → candidate `rules_added`
- Handles only in baseline → candidate `rules_removed`
- Handles in both: compare `expression_hash`; if same → check position; if different → record as remove + add (rule content changed under same handle, which nftables does not allow — this would indicate a parser bug or malformed input; emit parse warning)

**Stage: Rule diff — expression hash secondary pass (recreated rule detection)**
- Build `_rules_by_hash(candidate_rules_removed)` and `_rules_by_hash(candidate_rules_added)`
- For each hash that appears in both: pair as `rules_recreated`; remove from `rules_added` and `rules_removed`
- Remaining unpaired entries remain in `rules_added` / `rules_removed`

**Stage: Position diff (handles present in both, same hash)**
- Compare `position` field; if different → add to `rules_repositioned`

**Stage: Sort and assemble**
- All change lists sorted: `(table, chain)` for table/chain/policy; `(table, chain, handle)` for rules
- `drift_detected` and `has_critical_changes` computed per §2 spec

---

## 5. Error Handling Strategy

### `parse_nft_ruleset()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Input is not valid JSON | `ValueError("Input is not valid JSON: ...")` | Exception; no output |
| `"nftables"` key absent | `ValueError("Input is not nft --json list ruleset output: missing 'nftables' key")` | Exception; no output |
| `"nftables"` value is not a list | `ValueError("'nftables' must be a list")` | Exception; no output |
| Rule missing `handle` | parse_warning; rule skipped | Partial parse with warning |
| Rule references undeclared chain | Chain created implicitly; parse_warning | Rule included; implicit chain in output |
| Rule expression unrecognised | Expression moved to `opaque_expressions`; parse_warning | Rule included with partial normalisation |
| Unknown object type in nftables list | parse_warning; object skipped | Partial parse with warning |
| Empty `nftables` list (zero objects) | No tables; no warnings | `{"tables": {}, "parse_warnings": [], ...}` |
| File read error (CLI) | `IOError` propagates | Exit code 1, traceback on stderr |
| `json.JSONDecodeError` for invalid JSON | Wrapped in `ValueError` | Exit code 1, clean error message on stderr |

### `diff_rulesets()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Input not a dict | `ValueError("baseline must be a dict")` or `"current must be a dict"` | Exception |
| Input missing `input_format` or `tables` | `ValueError` naming the label and missing field | Exception |
| Cross-format comparison (nft-json vs iptables-save) | `ValueError("Cannot diff nft-json baseline against iptables-save current")` | Exception |
| Duplicate handles in same chain (parser bug) | `ValueError` naming table, chain, and duplicate handle | Exception — indicates corrupted parser output |
| Both inputs identical | Completes normally | `{"drift_detected": false, "has_critical_changes": false, all_counts: 0, ...}` |
| Both inputs empty tables | Completes normally | `{"drift_detected": false, ...}` |
| File not found (CLI) | `FileNotFoundError` propagates | Exit code 1, traceback on stderr |

---

## 6. Edge Cases

### Parser edge cases

| Case | Handling |
|------|----------|
| Empty `nftables` array (nft outputs `{"nftables": []}` on a system with no tables) | Returns `{"tables": {}, ...}`. No error. Parse warning: `"nftables list is empty — no tables configured"`. |
| `inet` family table (dual-stack) | Stored under key `"inet/<name>"`. `inet` is a first-class family. The table covers both IPv4 and IPv6 simultaneously; this is recorded in `diagnostics.inet_tables`. |
| Rule with only a `counter` expression and no verdict | `verdict: null`, `verdict_stops_chain: false`. These rules exist solely to count traffic. Included in output; parse warning only if counter extraction fails. |
| Rule with `log` then `accept` (two expressions) | Both normalised: `is_log: true`, `log_prefix: "..."`, `verdict: "accept"`, `verdict_stops_chain: true`. Not opaque. |
| Set reference `@setname` in match right-hand side | Set name extracted and added to `set_references`. If the set is not found in the parsed output, an entry in `diagnostics.sets_referenced_in_rules` records `found: false`. |
| Named priority strings (`"filter"`, `"srcnat"`, `"dstnat"`) | Converted to integer at parse time using the nftables standard priority map. Stored as integer. If unrecognised, stored as-is (string) with a parse warning. |
| Chain with `priority` of type string in JSON (nft sometimes emits `"filter"` not `0`) | Normalised to integer via priority map during `_parse_chain()`. |
| Multiple terminal verdicts in one rule (malformed input) | First verdict wins; subsequent verdicts moved to `opaque_expressions`; parse warning. |
| Rule referencing a chain in a different table (cross-table jump) | Not valid in nftables; emit parse warning. `jump_target` is recorded as-is. `diagnostics.unresolved_chain_jumps` includes it. |
| `flowtable` object in nftables list | Structural capture only: name and hook recorded under table as `flowtables` dict. Member interfaces stored opaquely. No parse warning. |

### Diff engine edge cases

| Case | Handling |
|------|----------|
| Baseline has empty tables, current has rules | All current tables → `tables_added`; all their chains → `chains_added`. No `rules_added` entries (rules of added tables are not counted as individual rule additions). |
| Rule repositioned: handle present in both, same hash, different position | `rules_repositioned` entry. Not counted in `rules_added` or `rules_removed`. |
| Rule recreated: same hash, different handle | `rules_recreated` entry. Removed from `rules_added` and `rules_removed` counts. |
| Policy change `null → "accept"` | Recorded in `policy_changes`. Not a critical change (policy going to accept is a relaxation, not a tightening). |
| Policy change `"accept" → "drop"` | Recorded in `policy_changes`. `has_critical_changes = true`. |
| Policy change `"accept" → null` | Recorded in `policy_changes`. Not critical (null policy on a regular chain means no default policy — chain must RETURN or fall through to calling chain). |
| `inet` table drift | Treated identically to `ip` or `ip6` table drift. The `family` field in the table key (`"inet/filter"`) is passed through. Callers are expected to note that `inet` changes affect both IPv4 and IPv6. |
| Cross-format baseline comparison | Hard error (see §5). A nft-json baseline cannot be compared against an iptables-save current — the orchestrator is responsible for routing correctly. |
| `json_schema_version` differs between baseline and current | Emit a warning in `diff_output.current_parse_warnings`: `"json_schema_version changed (baseline: N, current: M) — expression structure may differ across nft versions"`. Continue diff. Individual expression differences surface as normal rule changes via `expression_hash`. |

---

## 7. Rule Identity — Field List and Expression Hash

### Primary key: `handle`

nftables assigns a unique integer handle to each rule within a chain at creation time. The handle persists as long as the rule exists. It is the only stable per-rule identifier in nftables — position is not stable (inserting a rule shifts positions of subsequent rules; handles do not change).

The diff engine uses `handle` as primary key:
- Handle present in both sides → same rule (check position for repositioning, hash for content change)
- Handle only in baseline → rule removed
- Handle only in current → rule added (candidate for recreation cross-reference)

### Secondary key: `expression_hash`

SHA-256 of canonical JSON of the `raw_expressions` list, with inline `counter` expressions stripped before hashing:

```python
canonical_exprs = [e for e in exprs if not (isinstance(e, dict) and "counter" in e)]
json.dumps(canonical_exprs, sort_keys=True, separators=(',', ':'))
```

Stripping counters means that packet/byte count changes between captures do not produce false-positive diffs. The full expression list (including counters) is preserved in `raw_expressions`.

Used only for recreation detection: if a baseline-only handle and a current-only handle have the same hash, the rule was deleted and re-added. This is the only use of the hash in the diff algorithm.

### `_RULE_IDENTITY_FIELDS` (for drift reporting)

When reporting `rules_repositioned` entries, the diff engine includes an `identity` sub-dict of these fields from the rule record:

```python
_RULE_IDENTITY_FIELDS = (
    # ── v1 fields (original) ─────────────────────────────────────────────
    "table", "chain",
    "protocol", "protocol_negated",
    "src_addr", "src_addr_negated",
    "dst_addr", "dst_addr_negated",
    "src_port", "src_port_negated",
    "dst_port", "dst_port_negated",
    "in_interface", "in_interface_negated",
    "out_interface", "out_interface_negated",
    "ct_state",
    "verdict",
    "jump_target", "goto_target",
    "expression_hash",
    # ── v2 fields (added: ICMP, extended ct, comment) ────────────────────
    # NOTE: adding fields here invalidates stored baselines taken with an
    # earlier parser version — new fields will be absent (None) in old
    # baselines and populated in current captures.
    "icmp_type", "icmp_type_negated",
    "icmp_code", "icmp_code_negated",
    "ct_mark", "ct_mark_negated",
    "ct_direction",
    "ct_zone",
    "comment",
)
```

These fields are for human-readable identification of the repositioned rule. They are **not** used for hash computation or for primary diff keying.

**Stability guarantee:** `expression_hash` computation algorithm is frozen. Any change to the serialisation (e.g., adding/removing fields from `raw_expressions` at parse time) invalidates all stored baselines and must be versioned.

---

## 8. CLI Contracts

### `nftables_parser.py` CLI

```
Usage: python3 nftables_parser.py [file] [--indent N]

Arguments:
  file          Path to nft --json list ruleset JSON file. Reads stdin if omitted.
  --indent N    JSON indentation for output. Default: 2.

Exit codes:
  0   Success (including parse_warnings present)
  1   File not found, unreadable, invalid JSON, or missing 'nftables' key
  2   Argument error (argparse)
```

### `nftables_diff.py` CLI

```
Usage: python3 nftables_diff.py baseline.json current.json [--indent N]
       python3 nftables_diff.py baseline.json current.json --summary [--verbose]
       cat current.json | python3 nftables_diff.py baseline.json -

Arguments:
  baseline      Path to baseline JSON file (nftables_parser.py output).
  current       Path to current JSON file, or '-' to read from stdin.
  --indent N    JSON indentation for JSON output mode. Default: 2. Ignored with --summary.
  --summary     Print a human-readable Markdown summary instead of raw JSON.
  --verbose     With --summary: include full rule dicts for each change entry.
                Without --summary: warning printed to stderr; flag silently ignored.

Exit codes:
  0   Success (including drift_detected: true)
  1   File not found, invalid JSON, ValueError from diff_rulesets(), or cross-format error
  2   Argument error (argparse)
```

**Note:** Exit code 0 does not mean no drift — it means the tool ran successfully. Callers must check `drift_detected` in the JSON output (or look for `"No drift detected."` in the Markdown output).

---

## 9. Intentional Omissions

| Omission | Rationale |
|----------|-----------|
| nftables text DSL parsing | `nft list ruleset` text is a context-sensitive recursive grammar — correct parsing requires a full recursive descent parser. `nft --json list ruleset` provides identical information in a well-specified format. Both are outputs of the same `nft` binary. |
| Named priority map completeness | The standard nftables priority names (`filter`, `raw`, `mangle`, `srcnat`, `dstnat`, `conntrack`, `security`) are mapped. Kernel-internal priority names for specific subsystems (bridge, netdev) are normalised only if they appear in the samples and can be verified. Unknown names produce a parse warning and are stored as-is. |
| Full `map` value parsing | Map values (e.g., verdict maps, interface maps) are complex and use-case specific. Structural capture of map type, name, and key type is sufficient for drift detection. Value parsing is deferred. |
| Expression evaluation ("is port 443 blocked?") | Requires chain traversal simulation, set resolution, and default policy propagation. This is the `--explain` feature, designed separately. The parser produces structure; explanation is a separate concern. |
| nftables `nft monitor trace` integration | Real-time rule tracing is a separate operational concern. The parser is a point-in-time snapshot tool. |
| Windows / macOS firewall parsing | Out of scope. This module is Linux nftables only. |
| nft versions before 0.9.1 | `--json` flag introduced in 0.9.1. Ubuntu 20.04 ships 0.9.3. Older systems use iptables-legacy, handled by iptables-parser. |
| Automatic set element resolution in rules | When a rule references `@setname`, expanding the set into all matched values would change the rule's meaning from "match set" to "match expanded list." The set reference is preserved as-is; expansion is the caller's responsibility. |
| `diff_engine_version` in diff output | Useful for long-term baseline compatibility tracking. Deferred until a second version of the expression hash algorithm exists. |
| Set element diffing | The diff engine compares table/chain/rule structure. Changes to the elements of a named set (e.g. entries added to `@blocklist`) are not diffed — the set record is captured at parse time but element-level diffing is not implemented. An empty diff output does not imply set elements are unchanged. Callers that need set element drift must compare the `sets` sub-dict of each table manually. |
