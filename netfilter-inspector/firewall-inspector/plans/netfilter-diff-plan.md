# Netfilter Diff Engine — Design Plan

*Module 5 of the Netfilter Inspector*
*Status: Approved for build — 2026-03-13*

---

## Module Structure

Single file `iptables_diff.py`. Pure stdlib (`json`, `hashlib`, `datetime`, `argparse`, `sys`). Same pattern as `iptables_parser.py` — one public function, one CLI.

---

## Public API

```python
def diff_rulesets(baseline: dict, current: dict) -> dict:
```

Input: two dicts from `parse_iptables_save()`. Output: structured diff dict.

---

## Rule Identity — Frozen Field List

Defined once at the top of the file as a module-level constant. Never inferred dynamically from the record.

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

Identity hash: `sha256(json.dumps({f: rule[f] for f in _RULE_IDENTITY_FIELDS}, sort_keys=True))`.

### Fields excluded from identity

| Field | Reason |
|-------|--------|
| `position` | What we're tracking, not part of identity |
| `packet_count`, `byte_count` | Counter traffic, not rule definition |
| `raw_rule` | Formatting artifact |
| `target_stops_chain_traversal` | Derived field, not parsed from the rule line |
| `parsed_at`, `input_format`, `family` | Top-level metadata |

---

## Output Schema

```json
{
  "diff_at": "2026-03-13T12:00:00Z",
  "family": "ipv4",
  "baseline_parsed_at": "2026-03-12T08:00:00Z",
  "current_parsed_at":  "2026-03-13T08:00:00Z",
  "baseline_parse_warnings": [],
  "current_parse_warnings":  ["Table 'filter' block ended without COMMIT"],
  "drift_detected": true,
  "has_critical_changes": true,
  "summary": {
    "tables_added": 1,
    "tables_removed": 0,
    "chains_added": 2,
    "chains_removed": 0,
    "policy_changes": 1,
    "rules_added": 3,
    "rules_removed": 1,
    "rules_repositioned": 2
  },
  "changes": {
    "tables_added":   ["nat"],
    "tables_removed": [],
    "chains_added": [
      {"table": "filter", "chain": "f2b-sshd", "type": "user-defined", "rule_count": 2}
    ],
    "chains_removed": [],
    "policy_changes": [
      {
        "table": "filter", "chain": "INPUT",
        "baseline_policy": "ACCEPT", "current_policy": "DROP"
      }
    ],
    "rules_added":   [{"table": "filter", "chain": "INPUT", "position": 1, "...": "full rule record from current"}],
    "rules_removed": [{"table": "filter", "chain": "INPUT", "position": 3, "...": "full rule record from baseline"}],
    "rules_repositioned": [
      {
        "table": "filter", "chain": "INPUT",
        "baseline_position": 3, "current_position": 5,
        "rule": {"target": "ACCEPT", "...": "identity fields only"}
      }
    ]
  }
}
```

---

## `drift_detected` and `has_critical_changes`

**`drift_detected`** — `true` if any change list is non-empty. `false` means the two rulesets are functionally identical (counters and timestamps excluded).

**`has_critical_changes`** — `true` if any of the following:
- Any entry in `policy_changes` (default policy change on any chain is network-breaking)
- Any rule in `rules_added` or `rules_removed` where `target` is `DROP` or `REJECT`

A `drift_detected: true` / `has_critical_changes: false` result means the changes are positional or structural noise (LOG rules moving, user-defined chains appearing) rather than a security-relevant change.

---

## Algorithm

### Step 1 — Table diff

```
tables_added   = tables in current but not in baseline
tables_removed = tables in baseline but not in current
```

- Tables only in current: all their chains go into `chains_added`. No double-counting — their rules do NOT also appear in `rules_added`.
- Tables only in baseline: all their chains go into `chains_removed`. Their rules do NOT appear in `rules_removed`.
- Tables present in both: proceed to Step 2.

### Step 2 — Chain diff (for tables present in both)

```
chains_added   = chains in current table but not in baseline table
chains_removed = chains in baseline table but not in current table
```

Same no-double-counting rule as Step 1.

### Step 3 — Policy diff (for chains present in both)

```
if baseline_chain["default_policy"] != current_chain["default_policy"]:
    → policy_changes entry with before/after values
```

`policy_packet_count` / `policy_byte_count` changes are **ignored** — counters only.

### Step 4 — Rule diff (for chains present in both)

```python
from collections import Counter

baseline_hashes = Counter(identity_hash(r) for r in baseline_rules)
current_hashes  = Counter(identity_hash(r) for r in current_rules)

for h in set(baseline_hashes) | set(current_hashes):
    b_count = baseline_hashes[h]
    c_count = current_hashes[h]

    if c_count > b_count:
        # excess rules in current → rules_added
        # take (c_count - b_count) rule records from current_rules matching h
    elif b_count > c_count:
        # excess rules in baseline → rules_removed
        # take (b_count - c_count) rule records from baseline_rules matching h
    else:
        # equal count — rule exists in both, check positions
        b_positions = sorted(r["position"] for r in baseline_rules if identity_hash(r) == h)
        c_positions = sorted(r["position"] for r in current_rules  if identity_hash(r) == h)
        for bp, cp in zip(b_positions, c_positions):
            if bp != cp:
                → rules_repositioned entry with baseline_position, current_position, identity fields
```

Duplicate rules are handled correctly by Counter. If baseline has 2 identical LOG rules and current has 1, one entry goes to `rules_removed`. If both change position, both appear in `rules_repositioned`.

---

## Input Validation

```python
if "family" not in baseline or "tables" not in baseline:
    raise ValueError("baseline is not a valid parse_iptables_save() output")
if "family" not in current or "tables" not in current:
    raise ValueError("current is not a valid parse_iptables_save() output")
if baseline["family"] != current["family"]:
    raise ValueError(
        f"Cannot diff across address families: "
        f"baseline is {baseline['family']!r}, current is {current['family']!r}"
    )
```

`input_format` mismatch (e.g., `iptables-save` vs `iptables-save-counters`) is **allowed**. Counters are excluded from identity so this produces a clean diff.

---

## CLI

```bash
python3 iptables_diff.py baseline.json current.json
python3 iptables_diff.py baseline.json current.json --indent 2
cat current.json | python3 iptables_diff.py baseline.json -
```

Second argument is either a file path or `-` for stdin — useful for piping live `iptables-save` output through the parser and directly into the diff.

---

## What Does NOT Count as Drift

| Field | Reason excluded |
|-------|----------------|
| `packet_count`, `byte_count` | Counter traffic, changes on every packet |
| `policy_packet_count`, `policy_byte_count` | Same |
| `parsed_at` | Timestamp |
| `input_format` | Capture metadata, not firewall state |
| `parse_warnings` | Parsing artifacts — passed through as reference, do not affect `drift_detected` |
| `diagnostics` | Derived from rules, not independent firewall state |

---

## Known Limitations (Post-MVP)

| Limitation | Detail |
|-----------|--------|
| Bulk-insert reposition noise | Inserting one rule at position 1 of a 20-rule chain reports 1 added + up to 20 repositioned. Positionally accurate but operationally noisy. Not solved in MVP. |
| Reposition significance relative to DROP rules | The diff reports positions but not whether a reposition changes effective packet processing order relative to DROP/REJECT rules. This is the VM Firewall Inspector's diagnostic responsibility using `conntrack_position_warnings` from the parser. |
| Call-chain context for user-defined chain changes | A rule change in `DOCKER-CT` does not surface which chains call `DOCKER-CT`. Requires graph traversal — out of scope for a structural diff. |
| `diff_engine_version` in output | Useful for long-term baseline compatibility if identity field list changes. Deferred. |

---

*Acceptance criteria: `netfilter-diff-acceptance-criteria.md`*
