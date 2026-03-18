# iptables-parser Module — Design

*Architecture reference: `netfilter-inspector/architecture.md`*
*Status: Shipped — 2026-03-15*

This document covers `iptables_parser.py` and `iptables_diff.py`. Both are standalone tools in `iptables-parser/` and together form the parsing and diff foundation for the Netfilter Inspector.

---

## 1. Component and Function Inventory

### `iptables_parser.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `parse_iptables_save` | `(text: str, family: str = "ipv4") → dict` | Parse complete `iptables-save` text into structured dict. Entry point for all consumers. |
| `parse_rule_line` | `(line: str, table: str, chain_positions: dict, all_chains: set, warnings: list, family: str) → dict \| None` | Parse a single `-A` rule line into a rule record. Returns `None` if unparseable. |
| `_parse_match_ext` | `(module: str, tokens: list, i: int, record: dict, ext: dict, warnings: list) → int` | Parse a known `-m module` clause. Mutates `ext` (and sometimes `record`) in-place with parsed match data. Returns new token index. The return value is the primary output contract; mutation of `ext` is the side-effect contract. |
| `_parse_target_params` | `(target: str, tokens: list, i: int, record: dict, warnings: list, family: str) → int` | Parse target-specific parameters (REJECT --reject-with, SNAT --to-source, etc.). Returns new token index. |
| `strip_quotes` | `(s: str) → str` | Remove surrounding single or double quotes from a token value. |
| `main` | `() → None` | CLI entry point. Reads file or stdin, calls `parse_iptables_save`, prints JSON. |

### `iptables_diff.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `diff_rulesets` | `(baseline: dict, current: dict) → dict` | Compare two `parse_iptables_save()` outputs and return a structured diff. |
| `_identity_hash` | `(rule: dict) → str` | Compute SHA-256 of a rule's identity fields. Raises `KeyError` on missing fields. |
| `_identity_fields` | `(rule: dict) → dict` | Return a dict of identity fields only. Raises `KeyError` on missing fields. |
| `_chain_rules` | `(entry: dict, tables: dict) → list[dict]` | Return the rule list for a chains_added / chains_removed entry. |
| `_rules_by_hash` | `(rules: list[dict]) → dict[str, list[dict]]` | Group rules by identity hash; each group sorted ascending by position. |
| `_validate` | `(d: Any, label: str) → None` | Validate that a dict has `family` and `tables` fields. Raises `ValueError`. |
| `main` | `() → None` | CLI entry point. Reads two JSON files (or stdin for second arg `-`), calls `diff_rulesets`, prints JSON. |

---

## 2. Data Schemas

### `parse_iptables_save()` output

```json
{
  "parsed_at":      "2026-03-15T09:00:00Z",
  "family":         "ipv4",
  "input_format":   "iptables-save",
  "tables": {
    "<table_name>": {
      "chains": {
        "<chain_name>": {
          "type":                 "builtin | user-defined",
          "default_policy":       "ACCEPT | DROP | RETURN | null",
          "policy_packet_count":  0,
          "policy_byte_count":    0,
          "rules": [ <rule_record>, ... ]
        }
      }
    }
  },
  "diagnostics":     { ... },
  "parse_warnings":  [ "string", ... ]
}
```

**Notes:**
- `default_policy: null` — chain is user-defined (policy `-`), or an invalid policy was parsed (warning emitted)
- `input_format` values: `"iptables-save"`, `"iptables-save-counters"`, `"ip6tables-save"`, `"ip6tables-save-counters"`
- `tables` is an empty dict `{}` for an empty input (zero tables parsed)

### Rule record

```json
{
  "table":                        "filter",
  "chain":                        "INPUT",
  "position":                     1,
  "protocol":                     "tcp | udp | icmp | all | null",
  "protocol_negated":             false,
  "source":                       "0.0.0.0/0 | null",
  "source_negated":               false,
  "destination":                  "0.0.0.0/0 | null",
  "destination_negated":          false,
  "in_interface":                 "eth0 | null",
  "in_interface_negated":         false,
  "out_interface":                "null",
  "out_interface_negated":        false,
  "dst_port":                     "22 | null",
  "dst_port_negated":             false,
  "src_port":                     "null",
  "src_port_negated":             false,
  "target":                       "ACCEPT",
  "target_params":                null,
  "target_stops_chain_traversal": true,
  "match_extensions":             {},
  "opaque_extensions":            null,
  "packet_count":                 null,
  "byte_count":                   null,
  "raw_rule":                     "-A INPUT -p tcp --dport 22 -j ACCEPT"
}
```

**Field semantics:**
- `position`: 1-based, monotonically increasing within each chain
- `target_stops_chain_traversal`: `true` for ACCEPT, DROP, REJECT, RETURN, MASQUERADE, SNAT, DNAT, NFQUEUE; `false` for LOG, NFLOG, MARK, CONNMARK; `false` for user-defined chain jumps (chain traversal is conditional on RETURN)
- `packet_count` / `byte_count`: `null` when input is standard `iptables-save` (no `--counters` flag); integer when input is counters format
- `match_extensions`: keyed by module name (`"conntrack"`, `"state"`, `"tcp"`, `"udp"`, `"multiport"`, etc.). Empty dict when no `-m` clauses present.
- `opaque_extensions`: string of unparsed `-m module ...` fragments for unrecognised modules; `null` if none

### `target_params` by target

| Target | Params schema |
|--------|--------------|
| `REJECT` | `{"reject_with": "icmp-port-unreachable"}` |
| `SNAT` | `{"to_source": "10.0.0.1"}` |
| `DNAT` | `{"to_destination": "10.0.0.5:8080"}` |
| `MASQUERADE` | `{"to_ports": "1024-65535"}` or `null` |
| `NFQUEUE` | `{"queue_num": "0"}` or `null` |
| `LOG` | `{"log_prefix": "FW_DROP ", "log_level": "warning"}` or `null` |
| `MARK` | `{"set_xmark_value": "0x1", "set_xmark_mask": "0xffffffff"}` |
| `CONNMARK` | `{"save_mark": true}` or `{"restore_mark": true}` |
| All others | `null` |

### `diagnostics` schema

```json
{
  "drop_policy_chains":            ["filter/INPUT", "filter/FORWARD"],
  "accept_policy_chains":          ["filter/OUTPUT"],
  "conntrack_position_warnings": [
    {
      "table": "filter",
      "chain": "INPUT",
      "conntrack_rule_position": 5,
      "conntrack_raw_rule": "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
      "preceding_drop_rules": [
        {"position": 2, "raw_rule": "-A INPUT -s 10.0.0.0/8 -j DROP"}
      ]
    }
  ],
  "active_drop_rules": [ <rule_record> ],
  "nat_summary": {
    "masquerade_rules": [ <rule_record> ],
    "dnat_rules":       [ <rule_record> ],
    "snat_rules":       [ <rule_record> ]
  },
  "user_defined_chains": {
    "DOCKER": {"referenced_from": [{"table": "filter", "chain": "FORWARD", "position": 1}]}
  },
  "unresolved_chain_references": [
    {"target_chain": "GHOST", "referenced_from": {"table": "filter", "chain": "INPUT", "position": 3}}
  ]
}
```

**Notes:**
- `active_drop_rules`: always empty when input has no counters (`packet_count` is null). Only populated for counters-format input where `packet_count > 0`.
- `conntrack_position_warnings`: fires when a conntrack ACCEPT rule appears after a DROP/REJECT rule in the same chain. The conntrack rule may never be reached for established traffic.

### `diff_rulesets()` output

```json
{
  "diff_at":                 "2026-03-15T10:00:00Z",
  "family":                  "ipv4",
  "baseline_parsed_at":      "2026-03-15T08:00:00Z",
  "current_parsed_at":       "2026-03-15T10:00:00Z",
  "baseline_parse_warnings": [],
  "current_parse_warnings":  [],
  "drift_detected":          true,
  "has_critical_changes":    false,
  "summary": {
    "tables_added":       0,
    "tables_removed":     0,
    "chains_added":       0,
    "chains_removed":     0,
    "policy_changes":     0,
    "rules_added":        1,
    "rules_removed":      0,
    "rules_repositioned": 0
  },
  "changes": {
    "tables_added":       [],
    "tables_removed":     [],
    "chains_added":       [],
    "chains_removed":     [],
    "policy_changes":     [],
    "rules_added":        [ <full rule_record from current> ],
    "rules_removed":      [ <full rule_record from baseline> ],
    "rules_repositioned": [
      {
        "table":             "filter",
        "chain":             "INPUT",
        "baseline_position": 3,
        "current_position":  5,
        "rule":              { <identity fields only> }
      }
    ]
  }
}
```

**`chains_added` / `chains_removed` entry schema:**

```json
{"table": "filter", "chain": "f2b-sshd", "type": "user-defined", "rule_count": 2}
```

**`policy_changes` entry schema:**

```json
{
  "table":           "filter",
  "chain":           "INPUT",
  "baseline_policy": "ACCEPT",
  "current_policy":  "DROP"
}
```

**`has_critical_changes` is `true` when any of:**
- `policy_changes` is non-empty
- Any `rules_added` entry has `target` in `{"DROP", "REJECT"}`
- Any `rules_removed` entry has `target` in `{"DROP", "REJECT"}`
- Any rule in the rules of a `chains_added` entry has `target` in `{"DROP", "REJECT"}`
- Any rule in the rules of a `chains_removed` entry has `target` in `{"DROP", "REJECT"}`

**`has_critical_changes` is `false` despite `drift_detected: true` when:** rules were added/removed with targets outside `{"DROP", "REJECT"}`, or rules were repositioned only, or chains with no critical-target rules were added/removed.

**Known limitation — repositioned DROP/REJECT rules:** `has_critical_changes` is always `false` for `rules_repositioned` entries, regardless of the rule's target. A DROP rule moving from position 5 to position 2 (ahead of an ACCEPT rule for the same traffic class) is a security-relevant enforcement order change, but it does not set `has_critical_changes`. Operators must inspect `rules_repositioned` entries for DROP/REJECT targets whenever `drift_detected: true` and `has_critical_changes: false` appears together. This limitation is a consequence of the `has_critical_changes` definition covering rule existence changes, not rule ordering changes.

---

## 3. Pipeline Stage Detail — `parse_iptables_save()`

The parser processes input as a single sequential pass, maintaining a state machine across lines.

**Stage: Tokenise input**
- Input: raw `iptables-save` text string
- Processing: split on newlines; strip each line; skip blank lines and lines starting with `#`
- Failure: no failure path — blank and comment lines are silently skipped

**Stage: Table block detection**
- Input: line starting with `*`
- Processing: `flush_table()` closes any open table; sets `current_table = line[1:].strip()`
- Failure: if `current_table` is already set and no COMMIT has been seen, `flush_table()` emits a `parse_warning` for the incomplete block before opening the new one

**Stage: Chain definition parsing**
- Input: line starting with `:`
- Pattern: `:CHAIN POLICY [pkts:bytes]`
- Processing: regex match; policy `"-"` → `default_policy: null`; policy `"REJECT"` → `default_policy: null` + warning; chain type determined from `BUILTIN_CHAINS` lookup
- Failure: no regex match → `parse_warning` emitted, line skipped

**Stage: Rule line parsing**
- Input: line starting with `-A` or `[` (counters prefix)
- Processing: delegates to `parse_rule_line()`; on `None` return → `parse_warning` emitted, line skipped
- Position tracking: `chain_positions[chain_name]` incremented atomically; 1-based within each chain

**Stage: COMMIT handling**
- Input: line `"COMMIT"`
- Processing: sets `commit_seen = True`; calls `flush_table()`
- If input ends without COMMIT: `flush_table()` called at end of input; warning emitted for the incomplete table

**Stage: Diagnostics pass (post-parse)**
- Runs once after all tables are populated
- Computes: `drop_policy_chains`, `accept_policy_chains`, `conntrack_position_warnings`, `active_drop_rules`, `nat_summary`, `user_defined_chains`, `unresolved_chain_references`
- No warnings emitted here (warnings are emitted during parse pass only)

---

## 4. Pipeline Stage Detail — `diff_rulesets()`

**Stage: Input validation**
- Each input validated: must be dict with `family` (str) and `tables` (dict) keys
- Failure: `ValueError` with specific label (`"baseline"` or `"current"`) identifying which input is invalid
- Cross-family check: `baseline["family"] != current["family"]` → `ValueError` naming both families

**Stage: Table-level diff**
- `tables_added` = names in `current["tables"]` not in `baseline["tables"]`
- `tables_removed` = names in `baseline["tables"]` not in `current["tables"]`
- All chains in added tables → `chains_added` (no double-count into `rules_added`)
- All chains in removed tables → `chains_removed` (no double-count into `rules_removed`)

**Stage: Chain-level diff (tables present in both)**
- For each table present in both: chains only in current → `chains_added`; chains only in baseline → `chains_removed`

**Stage: Policy diff (chains present in both)**
- Compare `default_policy` only
- `policy_packet_count`, `policy_byte_count` changes are not drift

**Stage: Rule diff (chains present in both)**
- `_rules_by_hash()` groups baseline and current rules by identity hash
- `Counter` comparison: `b_count` vs `c_count` per hash
  - `c_count > b_count`: `(c_count - b_count)` excess rules appended to `rules_added` from current
  - `b_count > c_count`: `(b_count - c_count)` excess rules appended to `rules_removed` from baseline
  - `min(b_count, c_count) > 0`: paired rules checked for position change → `rules_repositioned`

**Stage: Sort and assemble**
- All change lists sorted deterministically: `(table, chain)` for table/chain/policy; `(table, chain, position)` for rules; `(table, chain, baseline_position)` for repositioned
- `drift_detected` = `any(tables_added, tables_removed, chains_added, chains_removed, policy_changes, rules_added, rules_removed, rules_repositioned)`
- `has_critical_changes` computed per spec in §2

---

## 5. Error Handling Strategy

### `parse_iptables_save()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| `family` not `"ipv4"` or `"ipv6"` | Raises `ValueError` immediately | Exception; no output |
| Rule line unparseable | `parse_warning` appended; line skipped | Partial parse with warning in `parse_warnings` |
| Chain definition unparseable | `parse_warning` appended; line skipped | Partial parse with warning |
| Rule references undeclared chain | Chain created implicitly; `parse_warning` appended | Rule included; chain present in output |
| Table block ends without COMMIT | `parse_warning` appended; partial results included | Partial table with warning |
| Empty input (zero characters) | No tables; no warnings | `{"tables": {}, "parse_warnings": [], ...}` |
| File read error (CLI) | `IOError` propagates; Python prints traceback to stderr | Exit code 1, traceback on stderr |

### `diff_rulesets()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Input not a dict | `ValueError("baseline must be a dict")` or `"current must be a dict"` | Exception |
| Input missing `family` or `tables` | `ValueError` naming the label and missing field | Exception |
| `tables` not a dict | `ValueError` naming the label | Exception |
| Cross-family comparison | `ValueError` naming both families | Exception |
| Rule missing identity field | `KeyError` with table/chain/position context | Exception — indicates corrupted or non-parser-generated input |
| Both inputs are identical | Completes normally | `{"drift_detected": false, "has_critical_changes": false, all_counts: 0, ...}` |
| Both inputs have empty `tables` | Completes normally | `{"drift_detected": false, ...}` |
| File not found (CLI) | `FileNotFoundError` propagates; Python prints traceback to stderr | Exit code 1, traceback on stderr |

**Design intent:** The parser degrades gracefully on malformed input (warnings, not exceptions). The diff engine does not — it requires valid parser output. Any `ValueError` or `KeyError` from `diff_rulesets()` indicates the inputs were not produced by the parser.

---

## 6. Edge Cases

### Parser edge cases

| Case | Handling |
|------|----------|
| Empty input string | Returns `{tables: {}, parse_warnings: []}`. No error. |
| Input with counters format (`[pkts:bytes] -A ...`) | Detected per-rule; `input_format` set to `"iptables-save-counters"`. Rules with counters have integer `packet_count`/`byte_count`; rules without have `null`. Mixed-counter chains emit a warning. |
| Duplicate rules (two identical `-A` lines) | Both parsed; each gets a unique position. Identity hash collision is intentional — handled in diff via `Counter`. |
| User-defined chain referenced before declaration | Chain created implicitly; warning emitted. Subsequent `-A` rules for that chain are appended normally. |
| COMMIT appears with no preceding `*table` line | Ignored — `current_table` is `None`; `flush_table()` is a no-op. |
| Multiple tables with the same name | Second `*table` line calls `flush_table()` on the first, then reopens. The second occurrence replaces the first in output. Warning emitted for the unclosed block. |
| `ip6tables-save` input passed with `family="ipv4"` | Parsed as ipv4. The parser has no out-of-band way to detect this. Callers should ensure the family argument matches the input source. |
| Rule with `!` negation before `-p`, `-s`, `-d`, `-i`, `-o` | Negation captured in `*_negated` bool for that field; token consumed before field token. |
| Rule line with quoted `--comment "my comment"` | `strip_quotes()` removes surrounding quotes before storing in `match_extensions.comment.comment_text`. |
| Unknown `-m module` | Consumed opaquely into `opaque_extensions`; warning emitted. The rule is still included in output. |

### Diff engine edge cases

| Case | Handling |
|------|----------|
| Baseline has empty `tables`, current has rules | All current tables → `tables_added`; all their chains → `chains_added`. No `rules_added` entries. |
| One chain gains one rule that shifts all subsequent positions | Produces 1 `rules_added` + up to N `rules_repositioned` for the N rules that shifted. Both are correct; the operator must interpret whether the repositioning is significant. |
| Duplicate rules: baseline has 2 identical LOG rules, current has 1 | 1 entry in `rules_removed`. The remaining matching rule is not flagged. |
| Duplicate rules: both sides have 2, positions differ | Both pairs compared; produces 0 or up to 2 `rules_repositioned` entries depending on position changes. |
| Policy change from `null` to `"DROP"` | Recorded in `policy_changes`. Both `baseline_policy: null` and `current_policy: "DROP"` included. |
| `input_format` differs between baseline and current | No error; counters are excluded from identity fields. A counters-format baseline diffed against a non-counters current produces a clean diff if rules are otherwise identical. |
| Same timestamp in `parsed_at` for both inputs | No error; timestamps are pass-through metadata, not used for comparison logic. |
| Cross-family diff attempted (e.g., baseline `"ipv4"`, current `"ipv6"`) | `ValueError` raised before any diff computation. |

---

## 7. Rule Identity — Field List Stability Guarantee

`_RULE_IDENTITY_FIELDS` is the contract between stored baselines and future comparison runs. Any change to this tuple invalidates all previously stored baselines.

**Fields included:**

```python
_RULE_IDENTITY_FIELDS = (
    "table", "chain",
    "protocol", "protocol_negated",
    "source", "source_negated",
    "destination", "destination_negated",
    "in_interface", "in_interface_negated",
    "out_interface", "out_interface_negated",
    "dst_port", "dst_port_negated",
    "src_port", "src_port_negated",
    "target", "target_params",
    "match_extensions", "opaque_extensions",
)
```

**Fields explicitly excluded from identity:**

| Field | Reason |
|-------|--------|
| `position` | What the diff tracks — not part of what makes two rules "the same rule" |
| `packet_count`, `byte_count` | Traffic counters; change on every packet |
| `raw_rule` | Formatting artifact; semantically equivalent rules may have different raw text |
| `target_stops_chain_traversal` | Derived field; recalculated on every parse |
| `parsed_at`, `input_format`, `family` | Top-level metadata; not per-rule |

---

## 8. CLI Contracts

### `iptables_parser.py` CLI

```
Usage: python3 iptables_parser.py [file] [--family ipv4|ipv6] [--indent N]

Arguments:
  file          Path to iptables-save file. Reads stdin if omitted.
  --family      Address family of input. Default: ipv4.
  --indent N    JSON indentation. Default: 2.

Exit codes:
  0   Success
  1   File not found or unreadable (Python default IOError)
  2   Argument error (argparse)
```

### `iptables_diff.py` CLI

```
Usage: python3 iptables_diff.py baseline.json current.json [--indent N]
       cat current.json | python3 iptables_diff.py baseline.json -

Arguments:
  baseline      Path to baseline JSON file (iptables_parser.py output).
  current       Path to current JSON file, or '-' to read from stdin.
  --indent N    JSON indentation. Default: 2.

Exit codes:
  0   Success (including drift_detected: false)
  1   File not found, invalid JSON, or ValueError from diff_rulesets()
  2   Argument error (argparse)
```

**Note:** Exit code 0 does not mean no drift — it means the tool ran successfully. Check `drift_detected` in the output to determine whether drift was found.

---

## 9. `iptables_explain.py` — Explain Engine

### Component and function inventory

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `explain_snapshot` | `(snapshot: dict, model: str \| None) → str` | Call Claude API with state system prompt; return markdown explanation of the firewall ruleset. |
| `explain_diff` | `(diff: dict, model: str \| None) → str` | Call Claude API with diff system prompt; return markdown explanation of what changed between two rulesets. |
| `_build_state_system_prompt` | `() → str` | Return the iptables expert system prompt for state explanation. Encodes: table eval order, first-match semantics, chain traversal mechanics, ESTABLISHED/RELATED patterns, counter semantics, scope limitations, zero-tables guard, output format directive, analytical guidance. |
| `_build_diff_system_prompt` | `() → str` | Return the system prompt for diff explanation. Encodes: change category semantics, position-change significance, security posture framing, `has_critical_changes` limitations, scope limitations, output format directive. |
| `_get_client` | `() → genai.Client` | Construct and return a Gemini client. Raises `ImportError` if `google-genai` not installed; raises `EnvironmentError` if `GEMINI_API_KEY` not set. |
| `_get_model` | `() → str` | Return model name from `IPTABLES_EXPLAIN_MODEL` env var, defaulting to `gemini-2.0-flash`. |
| `_write_output` | `(text: str, output_path: str \| None) → None` | Write explanation to file (printing path to stderr) or to stdout. |
| `main` | `() → None` | CLI entry point. Three modes: snapshot JSON file, `--diff-json` file, `--diff` two text files. |

### Data flow

**State explanation mode:**
```
iptables-save text
    → parse_iptables_save()  [in iptables_parser.py]
    → snapshot dict
    → json.dumps(snapshot)   [as user message]
    → Claude API (system: _build_state_system_prompt())
    → markdown explanation string
    → stdout or --output file
```
Side effect: snapshot dict written to `{input_stem}_snapshot.json`.

**Diff explanation mode:**
```
before.txt + after.txt
    → parse_iptables_save() × 2
    → baseline dict + current dict
    → diff_rulesets()        [in iptables_diff.py]
    → diff dict
    → json.dumps(diff)       [as user message]
    → Claude API (system: _build_diff_system_prompt())
    → markdown explanation string
    → stdout or --output file
```
Side effects: two snapshot JSONs + diff JSON written to disk.

### Configuration model

| Variable | Required | Default | Source |
|----------|----------|---------|--------|
| `GEMINI_API_KEY` | Yes (for explain modes) | — | Environment variable only. Never in any config file. |
| `IPTABLES_EXPLAIN_MODEL` | No | `gemini-2.0-flash` | Environment variable. |

### CLI contracts

#### `iptables_explain.py` standalone CLI

```
Usage:
  python3 iptables_explain.py SNAPSHOT_JSON
  python3 iptables_explain.py --diff-json DIFF_JSON
  python3 iptables_explain.py --diff BEFORE.txt AFTER.txt [--family ipv4|ipv6]
  python3 iptables_explain.py ... [--output PATH] [--indent N]

Exit codes:
  0   Success
  1   File not found, API error, or missing API key
  2   Argument error (argparse)
```

#### `iptables_parser.py` with explain flags

```
Usage:
  python3 iptables_parser.py FILE --explain [--output PATH]
  python3 iptables_parser.py FILE --explain-diff FILE2 [--output PATH]

  --explain         After parsing FILE, write snapshot JSON to {FILE_stem}_snapshot.json
                    (path printed to stderr), then call Claude API and output explanation
                    to stdout (or --output). JSON is NOT printed to stdout in this mode.

  --explain-diff FILE2
                    Parse FILE (baseline) and FILE2 (current). Write both snapshot JSONs
                    and the diff JSON ({baseline_stem}_vs_{current_stem}_diff.json) to
                    disk (paths printed to stderr). Call Claude API and output diff
                    explanation to stdout (or --output). JSON is NOT printed to stdout.

  --output PATH     Write explanation to PATH instead of stdout. Only valid with
                    --explain or --explain-diff.

Exit codes:
  0   Success
  1   File not found, API error, or missing API key (from iptables_explain)
  2   Argument error (argparse)
```

**Backward compatibility:** All existing `iptables_parser.py` CLI invocations without `--explain` or `--explain-diff` are unchanged. Normal mode (JSON to stdout) is unaffected.

### System prompt design rationale

The system prompt is the primary quality lever for the explain feature. A generic LLM asked to explain iptables rules makes category errors: it conflates table traversal order, misreads RETURN targets, and misinterprets the default policy semantics. The system prompt eliminates these errors by encoding the evaluation model explicitly.

**Key encoding decisions:**

| Concept | Why explicitly encoded |
|---------|----------------------|
| First-match semantics | The most common iptables misinterpretation; a DROP at position 5 is meaningless if an ACCEPT at position 1 covers the same traffic |
| RETURN does not mean accept | Engineers unfamiliar with iptables frequently misread RETURN as an acceptance verdict |
| Default policy is not a catch-all rule | Misread as an implicit rule at the end of the chain; it fires only when the chain is exhausted |
| ESTABLISHED/RELATED permits return traffic | Without this knowledge, stateful firewall patterns (the most common pattern) are misread |
| LOG is non-terminal | LOG rules pass the packet to the next rule; they are not blocking rules |
| Zero-tables guard | On iptables-nft hosts, `iptables-save` returns empty output even when nftables is enforcing traffic |
| Scope limitations (Azure NSG, nftables, routing) | The most important honesty constraint — the LLM must not assert operational facts it cannot derive from the JSON |

**Analytical guidance directives** (in both prompts):
- Frame findings as observations ("the rules permit") not authoritative verdicts ("traffic is allowed")
- Trace chain traversal explicitly for user-defined chains — do not assume the outcome
- Flag complexity or ambiguity explicitly rather than guessing
- For the diff prompt: address change categories in priority order (policy > DROP/REJECT > ACCEPT > reposition > infrastructure)

### Dependency model

`iptables_explain.py` imports:
- `google.genai` (external, required for explain modes, imported lazily inside `_get_client`)
- `iptables_parser.parse_iptables_save` (sibling module, imported inside `main()` for `--diff` text mode only)
- `iptables_diff.diff_rulesets` (sibling module, imported inside `main()` for `--diff` text mode only)

`iptables_parser.py` imports `iptables_explain` (inside `main()` only, when `--explain` or `--explain-diff` is passed). This is not a circular import because `iptables_explain` imports `iptables_parser` only inside its own `main()`, not at module level.

**Zero-dependency guarantee preserved:** `iptables_parser.py` and `iptables_diff.py` retain zero external dependencies when used as library modules (imported by other code). The `google-genai` dependency is only triggered by the CLI explain path.

### Error handling

| Error | Behavior |
|-------|----------|
| `google-genai` not installed | `ImportError` with install instructions |
| `GEMINI_API_KEY` not set | `EnvironmentError` with clear message before any API call |
| API call fails | Exception propagates; Python prints traceback to stderr; exit code 1 |
| Input file not found | `FileNotFoundError` propagates; exit code 1 |
| `--output` with no `--explain`/`--explain-diff` | `argparse.error()` with explanation; exit code 2 |
| `--explain` without a file argument | `argparse.error()`; exit code 2 |

---

## 10. Intentional Omissions

| Omission | Rationale |
|----------|-----------|
| `ip6tables-save` combined output in a single parse call | `iptables-save` and `ip6tables-save` are separate commands with separate outputs. `parse_iptables_save()` takes one text input and one family argument. Combined family parsing is the orchestrator's responsibility (two calls). |
| Semantic rule evaluation (e.g., "is port 443 blocked?") | Requires evaluating chain traversal, negated matches, and default policy in combination. This is the `--explain` feature, designed separately in `explain-feature-design.md`. It is not part of the parser or diff engine. |
| `nftables` input format | `nft list ruleset` output is a completely different format. A separate parser module is required. |
| Streaming or incremental parse | Input is always complete. The diagnostics pass requires the full table structure. |
| Diff engine importing `iptables_parser.py` | Schema coupling only — not a code import. The diff engine validates the minimum required fields (`family`, `tables`) but does not call the parser. |
| `diff_engine_version` in diff output | Useful for long-term baseline compatibility if `_RULE_IDENTITY_FIELDS` changes. Deferred. Add when a second version of the identity field list exists. |
