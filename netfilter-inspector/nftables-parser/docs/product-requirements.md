# nftables Parser — Product Requirements Document

*Module 2 of the Netfilter Inspector*
*Architecture reference: `netfilter-inspector/docs/architecture.md`*

---

## 1. Overview

The nftables Parser is a standalone module that takes `nft --json list ruleset` output as its input and produces a structured, machine-readable representation of the complete nftables firewall ruleset. It answers the question a network engineer has always had to answer by hand: **what tables, chains, and rules are active, what is each rule doing, and what does the combined policy mean for inbound and outbound traffic?**

The module has no dependency on a running VM, a cloud provider, an SSH session, or any network connectivity. Its only input is text — specifically, the JSON output of `nft --json list ruleset`, which is the programmatic interface for capturing, inspecting, and auditing nftables state. It can parse that text from a file captured during a live incident, from an artifact stored in a change ticket, or from a compliance snapshot run six months ago.

This document covers requirements for the parser module alone. It does not cover iptables, the firewall-inspector orchestrator, Azure integration, drift comparison, or any other module in the Netfilter Inspector system.

---

## 2. The Problem This Module Solves

nftables is the native firewall framework on Linux 3.13+ and the default on Ubuntu 20.04+, Debian 10+, and all current Azure VM images. It replaces iptables/ip6tables/arptables/ebtables with a unified framework that handles all address families in a single tool. Any VM provisioned from a current Azure marketplace image runs nftables by default — either natively or with an iptables compatibility shim.

Despite being the dominant framework on modern Linux, nftables has no equivalent to iptables-save's simple, line-oriented, widely-supported text format. The `nft list ruleset` text output is a domain-specific language with nested blocks, inline expressions, and context-dependent syntax — not suitable for line-by-line parsing. The correct programmatic interface is `nft --json list ruleset`, which produces a flat list of typed objects (metainfo, tables, chains, rules, sets, maps) in well-specified JSON.

The consequence: engineers investigating a firewall state on a modern Linux VM must either read the nftables DSL by eye, write ad-hoc grep/sed scripts against the text output, or use `nft` itself interactively — none of which produce a stable, diffable, machine-readable artifact.

This module closes that gap. It produces:
- A normalized JSON representation of the full nftables policy
- A diagnostics section highlighting drop-policy chains, unresolved chain jumps, and dual-stack inet tables
- Parse warnings for any element that could not be fully normalized
- A stable per-rule identity definition that enables the diff engine to detect rule changes reliably across captures

---

## 3. Who Uses This

**Network engineers and SREs** running the tool standalone to audit or document the firewall state of a Linux VM — from any cloud, any on-premises environment, or any host accessible via SSH. No Azure dependency.

**The Netfilter Inspector firewall-inspector orchestrator** as Stage 4 of the investigation pipeline when the framework detector identifies a native nftables environment.

**The iptables-explain Claude skill** (planned) as the parse step before explanation — accepts `nft --json` output or a pre-parsed snapshot JSON, explains the policy in plain language.

**The Network Ghost Agent** via the firewall-inspector subprocess — reads the `_snapshot.json` and `_drift.json` artifacts produced by the pipeline to reason about OS-layer firewall state during an investigation.

---

## 4. Functional Requirements

### F1 — Parse all standard nftables object types
The parser must handle all object types produced by `nft --json list ruleset`:
- `metainfo` — nft version, JSON schema version
- `table` — family, name, handle
- `chain` — base chains (with type, hook, priority, policy) and regular chains (no hook)
- `rule` — handle, chain reference, expression list
- `set` — named IP/port/protocol sets, including inline elements
- `map` — key→value sets (parse structurally; treat values as opaque)
- `counter`, `quota`, `limit` — named objects (capture name and handle; treat values as metadata)
- `flowtable` — capture name and hook; treat member details as opaque

### F2 — Normalize rule expressions into standard fields where possible
For each rule, the parser must extract normalized fields from the expression list when the expression matches a known pattern:
- `protocol` — from `payload.protocol` (`tcp`, `udp`, `icmp`, `icmpv6`) or `meta l4proto`
- `dst_port` — from `payload {protocol: tcp|udp, field: dport}` match
- `src_port` — from `payload {protocol: tcp|udp, field: sport}` match
- `src_addr` — from `payload {protocol: ip|ip6, field: saddr}` match (CIDR or single address)
- `dst_addr` — from `payload {protocol: ip|ip6, field: daddr}` match
- `in_interface` — from `meta {key: iifname}` match
- `out_interface` — from `meta {key: oifname}` match
- `ct_state` — from `ct {key: state}` match (list of state names)
- `ct_mark` — from `ct {key: mark}` match (value as string)
- `ct_direction` — from `ct {key: direction}` match (e.g. `"original"`, `"reply"`)
- `ct_zone` — from `ct {key: zone}` match (value as string)
- `icmp_type` — from `payload {protocol: icmp|icmpv6, field: type}` match (e.g. `"echo-request"`, `"nd-neighbor-solicit"`)
- `icmp_code` — from `payload {protocol: icmp|icmpv6, field: code}` match
- `comment` — top-level comment string on the nft rule object (sibling of `expr`)
- `verdict` — from the terminal expression: `accept`, `drop`, `return`, `reject`
- `verdict_stops_chain` — `true` for `accept`, `drop`, `reject`; `false` for `return` (returns to caller), `log` (non-terminal), `counter` (non-terminal), `limit` (non-terminal)
- `jump_target` / `goto_target` — from `jump {target: chain}` / `goto {target: chain}` expressions
- `log_prefix` — from `log {prefix: "..."}` expression
- `is_log` — `true` if any expression in the rule is a `log` statement
- `src_addr_negated`, `dst_addr_negated` — `true` when the corresponding address match uses op `!=`
- `src_port_negated`, `dst_port_negated` — `true` when the corresponding port match uses op `!=`
- `in_interface_negated`, `out_interface_negated` — `true` when the corresponding interface match uses op `!=`
- `protocol_negated` — `true` when the protocol match uses op `!=`
- `ct_mark_negated` — `true` when the ct mark match uses op `!=`
- `icmp_type_negated`, `icmp_code_negated` — `true` when the corresponding ICMP match uses op `!=`

Fields that cannot be extracted from the known patterns are collected in `opaque_expressions` (the raw expression list from the JSON) with a parse warning. The rule is included in output regardless — opaque expressions are never discarded.

### F3 — Produce a diagnostics section
Post-parse diagnostics computed from the full parsed output:
- `drop_policy_chains` — list of `family/table/chain` paths where `policy = "drop"`
- `accept_policy_chains` — list of `family/table/chain` paths where `policy = "accept"`
- `active_drop_rules` — rules with `verdict = "drop"` and `packet_count > 0` (only when input includes counter data)
- `unresolved_chain_jumps` — rules whose `jump_target` or `goto_target` does not match any chain name in the same table
- `inet_tables` — names of tables with `family = "inet"` (dual-stack; applies to both IPv4 and IPv6)
- `sets_referenced_in_rules` — set names referenced by rules (`@setname` pattern) with a note for each whether the set definition was found in the parsed output

### F4 — Emit parse warnings without aborting
Unknown expression types, unrecognised match patterns, and malformed object entries must produce a `parse_warning` entry and continue. The parser must never abort on a single unrecognised element — it produces a partial result with all successfully parsed objects and the warnings list populated.

### F5 — Stable rule identity definition
The parser must produce a per-rule `expression_hash` field: a stable content hash of the expression list. This hash is the secondary identity key used by the diff engine to detect semantic equivalence when a rule is deleted and re-added (new handle, same content). The `handle` is the primary key. The hash algorithm and serialisation format are specified in the design document.

Inline `counter` expressions (which carry packet/byte counts that change with traffic) must be stripped from the expression list before hashing. This ensures that two captures of the same rule with different counter values produce the same `expression_hash`, preventing false-positive diffs. The full `raw_expressions` list (including counters) is preserved unchanged in the rule record.

### F6 — Standalone CLI
The module must be runnable as a standalone CLI tool:

- `nftables_parser.py`: reads nft JSON input from a file path or stdin; prints structured JSON to stdout; exits with a non-zero code on error.
- `nftables_diff.py`: accepts two parsed JSON files (or one file and stdin via `"-"`); prints a structured JSON diff by default; supports `--summary` for human-readable Markdown output and `--verbose` (with `--summary`) for full rule detail in each diff entry; exits with a non-zero code on error. Drift does not produce a non-zero exit code — callers must read `drift_detected`.

The exact CLI interface is specified in the design document.

---

## 5. Constraints

**C1 — Input format is `nft --json list ruleset` JSON only.** The nftables text DSL is not a supported input. If non-JSON text is provided, the parser raises a `ValueError` immediately.

**C2 — No shell execution.** The parser never runs `nft`, `ssh`, or any subprocess. Input must be provided by the caller.

**C3 — No cloud dependency.** The parser is cloud-agnostic. No Azure, AWS, or GCP SDK imports.

**C4 — `inet` family is a first-class family.** Do not split `inet` tables into separate `ip` and `ip6` outputs. The `inet` policy applies to both address families simultaneously; splitting would misrepresent the enforcement semantics.

**C5 — Baseline compatibility stability.** The `_RULE_IDENTITY_FIELDS` list and the `expression_hash` computation algorithm are frozen per version. Any change to either invalidates all previously stored baselines. Changes must be documented and versioned.

**C6 — Python 3.8+ only.** The module is part of the Netfilter Inspector Python codebase and must be importable as a Python module in addition to being runnable as a standalone CLI tool.

**C7 — No third-party Python dependencies.** The module must use Python standard library only. It must be deployable on any standard Python 3 installation without a package installation step.

---

## 6. Out of Scope

| Item | Reason |
|------|--------|
| nftables text DSL parsing | Complex recursive grammar; `nft --json` is the correct programmatic interface |
| iptables-save parsing | Handled by the sibling `iptables-parser` module |
| Semantic rule evaluation ("is port 443 blocked?") | Requires chain traversal simulation; this is the `--explain` feature, a separate concern |
| `nft monitor` / streaming rule change events | Point-in-time snapshot model; streaming is a separate architectural concern |
| Multi-VM fleet capture | The orchestrator (firewall-inspector) handles scope; the parser takes a single text input |
| nftables flowtable / netdev family full parsing | Uncommon in cloud VM environments; structural capture sufficient for MVP |
| Windows Firewall / netsh | Out of scope; different OS, different tool |
| nft versions older than 0.9.1 | JSON output flag introduced in 0.9.1 (Ubuntu 20.04 ships 0.9.3). Older systems use iptables-legacy, handled by the iptables-parser. |
