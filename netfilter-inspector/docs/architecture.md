# Netfilter Inspector — Architecture

*Status: Active development — 2026-03-16*
*Scope: iptables-parser module + nftables-parser module + firewall-inspector module*

---

## 1. Design Decision Table

| Decision | Choice | Rationale |
|----------|--------|-----------|
| iptables-parser input format | `iptables-save` / `ip6tables-save` text only | The de facto standard for Linux firewall state capture; produced by every backup script, change procedure, and incident response workflow. No other format reaches the same corpus breadth. |
| nftables-parser input format | `nft --json list ruleset` JSON output | The nftables DSL text format is a recursive context-sensitive grammar — not suitable for a stdlib-only parser. The `--json` flag produces a well-specified, machine-readable JSON structure available on nft 0.9.1+ (Ubuntu 20.04+, all current Azure VM images). JSON input also enables handle-based rule identity: nftables assigns a stable integer handle to each rule, which is a better primary key than a computed hash over flag fields. |
| nftables-parser rule identity | `handle` as primary key; expression SHA-256 hash as secondary | nftables assigns a unique integer handle to every rule within a chain. Drift detection uses handle presence/absence as primary: a missing handle = removed rule, a new handle = added rule. The expression hash enables semantic equivalence detection when a rule is deleted and re-added (new handle, same content) — those appear as remove+add with a cross-reference note rather than as two unrelated changes. |
| nftables `inet` family handling | Parsed as a single dual-stack table; no family split | `inet` tables apply to both IPv4 and IPv6 in a single ruleset. Splitting them by protocol would misrepresent the policy — an `inet` table with `policy drop` drops both IPv4 and IPv6 traffic. The parser preserves `inet` as a first-class family; the drift engine and firewall-inspector treat it as a third family alongside `ip` and `ip6`. |
| Parser output format | Structured JSON dict (`parse_iptables_save()`) | Every downstream consumer — diff engine, orchestrator, Ghost Agent — queries by key, not by line number. JSON is self-describing and directly serialisable. |
| Diff engine placement | `iptables-parser/` module (as `iptables_diff.py`) | The diff engine operates entirely on `parse_iptables_save()` output. Its only dependency is the parser output schema. Co-locating it with the parser makes the dependency explicit and prevents a layering inversion where `firewall-inspector` would own a component that `iptables-parser` depends on. |
| Rule identity definition | Frozen field list (`_RULE_IDENTITY_FIELDS`) | Identity must be stable across captures. Deriving identity fields dynamically would make the definition a runtime variable, breaking baseline comparisons when the derivation changes. Explicit enumeration makes schema changes deliberate and auditable. |
| Probe delivery mechanism | Shell script over SSH / `az vm run-command` | `iptables-save` must run as root on the target VM. SSH and Azure run-command are the two access patterns available. Encapsulating both in a `Provider` abstraction means the orchestrator never knows which one is in use. |
| Provider abstraction | `_BaseSSHProvider` base + `AzureProvider` / `SSHProvider` | Both providers share SSH key management, SCP output retrieval, and cleanup. The only difference is probe delivery (`az vm run-command invoke` vs `ssh user@host "sudo bash -s"`). Shared logic lives once in the base; divergence is isolated to `run_probe()`. |
| Two-hop SSH topology | `ProxyCommand` only (no `ProxyJump`) | `ProxyJump` is a convenience alias. `ProxyCommand` is the underlying mechanism and is universally supported. The distinction matters for `subprocess.run(shell=True)` invocations where multi-hop nesting must be explicit. |
| Session ID as artifact namespace | Caller-supplied, validated `^[a-zA-Z0-9_-]{1,64}$` | Every artifact produced by a pipeline run uses the session_id as a filename prefix. This makes all artifacts for a run discoverable by glob, enables cross-stage restartability, and prevents directory traversal via filename injection. Validation fires before any shell command is constructed. |
| Baseline integrity | SHA-256 of snapshot JSON bytes, stored in a `.sha256` companion file | A mutated snapshot must not silently pass as a valid baseline. The companion file records the hash at write time; the compare path verifies it at read time. Any modification — accidental or deliberate — raises `IntegrityError` before the diff runs. |
| Framework detection | Probe-based, not config-file-based | Config files describe intent; the probe observes what is actually enforced. A system with `nftables` installed but `iptables-legacy` active (via `update-alternatives`) would be misclassified by a config-file approach. |
| `--family` scope | `ipv4`, `ipv6`, or `both` (iptables only) | IPv6 tables are a separate kernel subsystem probed by `ip6tables-save`. Treating them as one combined ruleset would conflate address families. `both` runs two separate probes and produces two separate parsed outputs. For nftables VMs, `config.family` is ignored — nftables uses a single unified ruleset (`nft --json list ruleset`) covering all address families. The parse result is stored under the single key `"nft"` regardless of what `FAMILY` was set to in the config. |
| Audit directory | Local filesystem, caller-supplied path | No cloud storage dependency in the core pipeline. The directory is the only shared state between pipeline stages and between runs. Ghost Agent can supply a run-specific directory; a standalone operator supplies their own. |
| Safety classification for probe commands | Read-only `sudo iptables-save` / `sudo ip6tables-save` | These commands produce no side effects on the target VM. They are classified SAFE in the Ghost Agent tool decision rules — no HITL gate is required for baseline capture or comparison runs. |
| HITL gate for NSG port-open remediation | Gate exists in `SafeExecShell` (Ghost Agent mode); absent in `LocalShell` (standalone mode) | Opening a firewall rule is a mutative, network-affecting action. In Ghost Agent mode, `SafeExecShell` classifies `az network nsg rule create` as MUTATIVE and blocks until the operator approves. In standalone mode, `LocalShell` executes commands immediately — the operator is the gate by virtue of controlling the CLI invocation directly. |
| No third-party Python dependencies | stdlib only (`json`, `hashlib`, `re`, `argparse`, `subprocess`, `tempfile`) | A forensic tool deployed on an Azure bastion or a bare-metal jump host must not require a package installation step. Dependency on `requests`, `pydantic`, or any other non-stdlib library would block deployment in every restricted environment the tool is designed for. |

---

## 2. System Boundary Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│  OPERATOR BOUNDARY                                                     │
│                                                                        │
│  CLI: firewall_inspector.py --config config.env --is-baseline         │
│       firewall_inspector.py --config config.env --compare-baseline ID │
│  CLI: iptables_parser.py [file]    (iptables-save text input)         │
│  CLI: iptables_diff.py baseline.json current.json                     │
│  CLI: nftables_parser.py [file]    (nft --json list ruleset input)    │
│  CLI: nftables_diff.py baseline.json current.json                     │
└──────────────────────────┬─────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  firewall-inspector/                                                     │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  firewall_inspector.py  (orchestrator)                          │    │
│  │                                                                 │    │
│  │  InspectorConfig ──► validate_session_id()                      │    │
│  │        │                                                        │    │
│  │        ▼                                                        │    │
│  │  Stage 1: Probe delivery                                        │    │
│  │    provider.run_probe(vm_name, session_id, ssh_user, probe_script) │  │
│  │        │                                                        │    │
│  │        ▼                                                        │    │
│  │  Stage 2: Output retrieval                                      │    │
│  │    provider.retrieve_probe_output()                             │    │
│  │        │                                                        │    │
│  │  Stage 3: Framework detection  ◄── framework_detector.py       │    │
│  │        │                                                        │    │
│  │  Stage 4: Parse                                                 │    │
│  │    iptables* ──► iptables_parser.py                             │    │
│  │    nftables  ──► nftables_parser.py                             │    │
│  │        │                                                        │    │
│  │  Stage 5: Diff / baseline save                                  │    │
│  │    iptables* ──► iptables_diff.py                               │    │
│  │    nftables  ──► nftables_diff.py                               │    │
│  │    (routing: by baseline input_format)                          │    │
│  │        │                                                        │    │
│  │  Stage 6: Classify (iptables)  ◄── chain_classifier.py         │    │
│  │        │                                                        │    │
│  │  Stage 7: Report (stdout + JSON artifact)                      │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────┐       │
│  │  providers.py                                                │       │
│  │                                                              │       │
│  │  _BaseSSHProvider                                            │       │
│  │    ├── AzureProvider  (az vm run-command invoke)             │       │
│  │    └── SSHProvider    (ssh user@host "sudo bash -s")         │       │
│  │  LocalShell           (subprocess.run wrapper)               │       │
│  └──────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  Artifacts (audit_dir/):                                                 │
│    {session_id}_commands.log       ← one JSON line per shell command     │
│    {session_id}_snapshot.json      ← parsed baseline (is-baseline mode) │
│    {session_id}_snapshot.json.sha256 ← integrity companion file         │
│    {session_id}_drift.json         ← structured diff (compare mode)     │
│                                                                          │
│  Note: probe text (raw iptables-save output) is held in memory and is   │
│  never written to disk. The snapshot is the first disk artifact.         │
└──────────────────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────────────────────────┐
           │               │                                   │
           ▼               ▼                                   ▼
┌────────────────┐  ┌──────────────────┐           ┌──────────────────────┐
│ TARGET VM      │  │ iptables-parser/ │  ┌──────────────────┐  ┌──────────────────────┐
│                │  │                  │  │ nftables-parser/ │  │ Network Ghost Agent  │
│ probe.sh runs  │  │ iptables_parser  │  │                  │  │                      │
│ as root:       │  │  .py             │  │ nftables_parser  │  │ Calls                │
│ iptables-save  │  │   parse_         │  │  .py             │  │ firewall_inspector   │
│ ip6tables-save │  │   iptables_save()│  │   parse_nft_     │  │ as a tool            │
│ nft --json     │  │                  │  │   ruleset()      │  │                      │
│   list ruleset │  │ iptables_diff    │  │                  │  │ Reads diff artifact  │
│                │  │  .py             │  │ nftables_diff    │  │ for RCA chain        │
│ Access via:    │  │   diff_          │  │  .py             │  └──────────────────────┘
│ • Azure run-   │  │   rulesets()     │  │   diff_          │
│   command      │  └──────────────────┘  │   rulesets()     │
│ • Direct SSH   │                        └──────────────────┘
│ • SSH via      │
│   bastion      │
└────────────────┘
```

---

## 3. Component Inventory

### `iptables-parser/iptables_parser.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `parse_iptables_save(text: str, family: str) → dict` |
| **CLI** | `python3 iptables_parser.py [file] [--family ipv4\|ipv6] [--indent N]` |
| **Input** | Raw `iptables-save` or `ip6tables-save` text |
| **Output** | Structured dict: `{parsed_at, family, input_format, tables, diagnostics, parse_warnings}` |
| **May do** | Parse any syntactically valid iptables-save text; emit parse_warnings for anomalies; run diagnostics (policy audit, conntrack positioning, NAT summary) |
| **May not do** | Execute any shell command; read from a VM; perform network I/O; call the diff engine |
| **Dependencies** | None (stdlib only) |

### `iptables-parser/iptables_diff.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `diff_rulesets(baseline: dict, current: dict) → dict` |
| **CLI** | `python3 iptables_diff.py baseline.json current.json [--indent N]`; accepts `-` for stdin |
| **Input** | Two `parse_iptables_save()` output dicts |
| **Output** | Structured diff: `{diff_at, family, drift_detected, has_critical_changes, summary, changes}` |
| **May do** | Compare two same-family rulesets; classify drift by type (tables/chains/policy/rules/repositioned); determine criticality |
| **May not do** | Execute shell commands; query any external system; compare rulesets across address families; modify inputs |
| **Dependencies** | Consumes `iptables_parser.py` output schema (no import dependency) |

### `nftables-parser/nftables_parser.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `parse_nft_ruleset(text: str) → dict` |
| **CLI** | `python3 nftables_parser.py [file] [--indent N]` |
| **Input** | Raw JSON string from `nft --json list ruleset` |
| **Output** | Structured dict: `{parsed_at, input_format, nft_version, tables, diagnostics, parse_warnings}` |
| **May do** | Parse any syntactically valid `nft --json` output; extract rule expressions into normalized fields where possible; mark complex expressions as opaque; run diagnostics (drop-policy chains, unresolved chain jumps, inet dual-stack tables) |
| **May not do** | Execute any shell command; read from a VM; perform network I/O; call the diff engine; parse nftables text DSL format |
| **Dependencies** | None (stdlib only — `json`, `hashlib`, `re`, `argparse`) |

### `nftables-parser/nftables_diff.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `diff_rulesets(baseline: dict, current: dict) → dict` |
| **CLI** | `python3 nftables_diff.py baseline.json current.json [--indent N]`; accepts `-` for stdin |
| **Input** | Two `parse_nft_ruleset()` output dicts |
| **Output** | Structured diff: `{diff_at, drift_detected, has_critical_changes, summary, changes}` |
| **May do** | Compare two nft rulesets; classify drift by type (tables/chains/policy/rules/repositioned/recreated); determine criticality |
| **May not do** | Execute shell commands; compare rulesets of different input_format values; modify inputs |
| **Dependencies** | Consumes `nftables_parser.py` output schema (no import dependency) |

### `firewall-inspector/framework_detector.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `detect_framework(version_strings: dict[str, str]) → dict` — returns `{framework, confidence, parse_warnings}` where `framework` is one of `"iptables-legacy"`, `"iptables-nft"`, `"nftables"`, `"unknown"` |
| **Input** | Dict of per-tool version strings pre-extracted from the probe's `framework_detection` section: `{iptables, iptables_legacy, nft, update_alternatives}` |
| **May do** | Inspect version string evidence for framework signatures; emit parse_warnings |
| **May not do** | Execute shell commands; query VMs; return probabilistic results — detection is deterministic from version string content |
| **Dependencies** | None |

### `firewall-inspector/chain_classifier.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `classify_diff(diff: dict) → dict` — annotates diff changes with severity tiers |
| **Tiers** | `structural` (policy changes, chain adds/removes), `ephemeral` (repositioning only), `user-defined` |
| **May do** | Read diff output; attach classification metadata to each change entry |
| **May not do** | Modify `drift_detected` or `has_critical_changes`; access the filesystem; call external APIs |
| **Dependencies** | Consumes `iptables_diff.py` output schema only. `classify_diff()` is not called for nftables diffs — the chain name patterns it uses (KUBE-SEP-, DOCKER, f2b-, ufw-) are iptables-specific. |

### `firewall-inspector/providers.py`

| Attribute | Value |
|-----------|-------|
| **Exposes** | `AzureProvider`, `SSHProvider`, `LocalShell` |
| **`_BaseSSHProvider`** | Base for both cloud providers. Holds SSH key paths, target/bastion IPs, SSH user. Provides `_ssh_opts()`, `_proxy_command()`, `retrieve_probe_output()`, `cleanup_probe_output()` |
| **`AzureProvider`** | Delivers probe via `az vm run-command invoke`; retrieves output via SCP |
| **`SSHProvider`** | Delivers probe via `ssh user@host "sudo bash -s -- SESSION_ID SSH_USER" < probe.sh` |
| **`LocalShell`** | Wraps `subprocess.run` for all shell execution; the single shell execution boundary |
| **May do** | Execute shell commands through `LocalShell`; manage temporary probe files; handle HITL gate for port-open remediation |
| **May not do** | Parse iptables output; make diff decisions; store session state |
| **Access patterns** | Case 1: direct SSH (no bastion, `TARGET_VM_IP` is reachable); Case 2: two-hop via bastion (`BASTION_PUBLIC_IP` set, ProxyCommand used) |

### `firewall-inspector/firewall_inspector.py`

| Attribute | Value |
|-----------|-------|
| **Role** | Pipeline orchestrator. Owns the run lifecycle: config validation → probe → parse → diff → report |
| **Key types** | `InspectorConfig` (dataclass), `IntegrityError` (exception) |
| **Modes** | `--is-baseline`: capture, parse, write snapshot + SHA-256 companion; `--compare-baseline SESSION_ID`: capture, parse, verify baseline integrity, diff, classify, write drift report |
| **Artifact writes** | Commands log (append, throughout run) → snapshot + `.sha256` (baseline mode) → drift JSON (compare mode). Probe text is never written to disk — held in memory between retrieval and parse. |
| **May do** | Orchestrate all modules; write artifacts; produce console output; validate session_id before any shell use |
| **May not do** | Parse iptables text directly (delegates to `iptables_parser`); compute diffs (delegates to `iptables_diff`); classify changes (delegates to `chain_classifier`); detect framework (delegates to `framework_detector`) |

---

## 4. Integration Coupling Rules

### `firewall_inspector.py` ↔ `iptables_parser.py`

- Orchestrator calls `parse_iptables_save(text, family)` exactly once per probe family per run.
- Input: raw iptables-save text string from probe output.
- Output: the full `parse_iptables_save()` dict. The orchestrator stores this as `{session_id}_snapshot.json`.
- The orchestrator **must not** access `tables`, `diagnostics`, or any nested field directly — it passes the full dict to `iptables_diff.diff_rulesets()` without inspection.
- Schema change in parser output → review of orchestrator and diff engine required before baseline compatibility is assumed.

### `firewall_inspector.py` ↔ `iptables_diff.py`

- Orchestrator calls `diff_rulesets(baseline_dict, current_dict)` in compare mode.
- Inputs: two dicts previously written by the parser. The baseline is read from the snapshot JSON file; the current is freshly parsed in the same run.
- Output: the full diff dict. The orchestrator passes it to `chain_classifier.classify_diff()` and then writes it as `{session_id}_diff.json`.
- Integrity check **must complete** before the baseline dict is passed to `diff_rulesets`. An `IntegrityError` aborts the pipeline before the diff runs.
- The orchestrator **must not** inspect diff change lists to determine drift — it reads `diff["drift_detected"]` and `diff["has_critical_changes"]` only.

### `firewall_inspector.py` ↔ `providers.py`

- The orchestrator instantiates exactly one provider per run based on `config.provider`.
- Provider choice: `"azure"` → `AzureProvider`; `"ssh"` → `SSHProvider`. No other values are valid. Validation is a hard error (`SystemExit(2)`) before any provider is instantiated.
- The orchestrator calls three provider methods in order: `run_probe()`, `retrieve_probe_output()`, `cleanup_probe_output()`. All three are called regardless of probe success — cleanup is always attempted.
- The orchestrator **must not** construct shell commands directly — all shell execution is through the provider.

### `firewall_inspector.py` ↔ `framework_detector.py`

- The orchestrator calls `_extract_version_strings(fw_section)` to pre-split the raw probe section, then passes the resulting dict to `detect_framework(version_strings)`.
- Detection result **gates the parse branch**: `framework == "nftables"` routes to `parse_nft_ruleset()`; all other values route to `parse_iptables_save()`. The two paths are mutually exclusive per run. Detection result is also stored in the snapshot (`framework`, `framework_confidence`) for the operator.
- Parse warnings from `detect_framework()` are appended to `config.parse_warnings` and surfaced in the snapshot.
- The orchestrator **must not** make framework decisions outside `detect_framework()`.

### `firewall_inspector.py` ↔ `chain_classifier.py`

- The orchestrator calls `classify_diff(diff_dict)` after `diff_rulesets()` completes — for iptables diffs only.
- `classify_diff()` is **not** called for nftables diffs. The chain name patterns it contains (KUBE-SEP-, DOCKER, f2b-, ufw-) are iptables-specific and have no meaning in an nftables ruleset.
- The classifier receives the raw diff dict and returns an annotated version. The orchestrator replaces the diff dict with the annotated version before writing the artifact.
- The classifier **must not** modify `drift_detected` or `has_critical_changes`.

### `firewall_inspector.py` ↔ `nftables_parser.py` / `nftables_diff.py`

- The orchestrator calls `parse_nft_ruleset(text)` when `detect_framework()` returns `framework="nftables"`. It calls `parse_iptables_save(text, family)` for all other framework values. The two parse paths are mutually exclusive per run.
- **Parse routing:** determined by the current framework detection result. nftables parse populates `parsed["nft"]`; iptables parse populates `parsed["ipv4"]` / `parsed["ipv6"]`.
- **Diff routing:** determined by the presence of `"nft"` in the baseline snapshot's `rulesets` dict — not by `input_format` and not by the current framework detection result. If `baseline["rulesets"]["nft"]` exists (and is non-null), `nft_diff_rulesets()` is called; otherwise `iptables_diff.diff_rulesets()` is called.
- **Framework mismatch guard:** the orchestrator checks `"nft" in baseline["rulesets"]` against `"nft" in parsed` before invoking either diff engine. A mismatch raises `ValueError` with a message identifying both the baseline framework and the current framework. The diff engine is never called on mismatched input. This approach correctly treats `"iptables-legacy"` and `"iptables-nft"` as the same diff-engine family — both produce `ipv4`/`ipv6` keys, not a `"nft"` key — and will never false-fire on a legacy→nft migration.
- The probe script runs `nft --json list ruleset` in addition to `iptables-save` / `ip6tables-save`. The probe output section key for nftables output is `"nftables"` (accessed as `sections["nftables"]`). Both iptables and nftables sections are always collected by the probe — only the parse routing is gated on the framework detection result.
- An empty or whitespace-only `"nftables"` section is treated as unavailable (same as `###UNAVAILABLE###`). `parse_nft_ruleset()` is never called on an empty string.

### `iptables_diff.py` ↔ `iptables_parser.py` (schema coupling only)

- `iptables_diff.py` consumes the `parse_iptables_save()` output schema but does **not** import `iptables_parser.py`.
- The coupling is schema-level: `diff_rulesets()` expects `{"family": str, "tables": dict}` at minimum.
- Any change to the parser output schema that affects `family` or `tables` requires a corresponding review of `_RULE_IDENTITY_FIELDS` and the diff algorithm.

### Network Ghost Agent ↔ `firewall_inspector.py`

- Ghost Agent invokes `firewall_inspector.py` as a subprocess via `SafeExecShell`.
- All `--is-baseline` and `--compare-baseline` probe commands are SAFE-classified (read-only `iptables-save`). No HITL gate.
- Port-open remediation (`az network nsg rule create`) is MUTATIVE-classified. HITL gate fires before execution.
- Ghost Agent reads `{session_id}_diff.json` as a structured input to its investigation chain. It does not parse stdout.
- Ghost Agent supplies `AUDIT_DIR` pointing to its run-specific artifact directory. The inspector writes all artifacts there.

---

## 5. Audit Trail

The tool executes shell commands against live VM infrastructure. Every command execution is recorded.

**Record:** `{audit_dir}/{session_id}_commands.log`

**Format:** One JSON line per command, append-only:
```json
{"ts": "2026-03-15T09:00:01Z", "command": "az vm run-command invoke ...", "exit_code": 0, "output_bytes": 4096}
```

**Writer:** `LocalShell` exclusively. No other component writes to this file.

**What is recorded:** Timestamp, command string, exit code, output byte count.

**What is not recorded:** Command output content. The output is transient — relevant content is captured in the snapshot/drift JSON artifacts, not in the command log. This keeps the log compact and prevents the log from containing sensitive firewall state data.

**Scope:** The `_commands.log` is written when `LocalShell` is instantiated with `audit_dir` and `session_id`. In Ghost Agent mode, `SafeExecShell` maintains its own audit record (outside this tool's scope). The `_commands.log` is a standalone-mode audit artifact.

**Integrity:** The log is append-only by file open mode (`"a"`). It is not integrity-protected (no hash companion). It is an operational record, not a tamper-evident security artifact — the snapshot's `.sha256` companion serves the tamper-detection role for firewall state.

---

## 6. Intentional Omissions

| Omission | Principle violated if added | Detail |
|----------|----------------------------|--------|
| **nftables text DSL parsing** | Earn complexity | The `nft list ruleset` text format is a recursive context-sensitive grammar not suited to stdlib-only parsing. `nft --json list ruleset` produces equivalent structured output and is the correct programmatic interface. The nftables-parser module consumes JSON only; text DSL parsing is not in scope. |
| **nftables-parser in `iptables-parser/`** | Single responsibility | The two parsers have unrelated grammars, different identity models (handle vs field hash), and different diagnostics. Co-locating them would merge two independent modules. `nftables-parser/` is a sibling module to `iptables-parser/` under the same `netfilter-inspector/` umbrella. |
| **Real-time streaming / watch mode** | Earn complexity | The tool models point-in-time snapshots and diffs. Streaming would require a persistent connection and an event model. The operational use case (change window bracket, post-incident capture) is entirely satisfied by discrete runs. |
| **Rule interpretation / `--explain`** | Earn complexity | Explaining what a rule set means in natural language is a separate concern from parsing and diffing it. It requires different inputs (the parsed ruleset, possibly traffic context) and a different output contract. Designed separately in `explain-feature-design.md`; not part of the diff pipeline. |
| **Direct cloud API integration in the parser** | Single responsibility | `iptables_parser.py` takes text. Making it aware of Azure, SSH, or any retrieval mechanism would destroy its standalone value and reusability. |
| **Automatic baseline rotation** | YAGNI | Deciding when to rotate baselines is a policy decision, not a tooling decision. The tool writes and reads artifacts at caller direction. Automatic rotation would require policy configuration, expiry logic, and a storage management concern that the tool is not designed to own. |
| **Result storage in cloud (blob / S3)** | Earn complexity | Local filesystem is sufficient for the primary use cases (single operator, Ghost Agent run directory). Cloud storage is post-MVP. Adding it to the MVP would require credential handling, SDK dependencies, and error handling paths that dwarf the core logic. |
| **Multi-VM fleet scan** | Earn complexity | Running against one VM per invocation keeps the session ID, artifact namespace, and failure domain simple. Fleet scanning is a loop around the tool, not a concern inside it. |
| **Windows Firewall / netsh state** | Scope boundary | The tool is designed for Linux netfilter. Windows Firewall is a separate product with a separate query API. The scope boundary is OS-layer Linux firewall state. |
| **Probabilistic anomaly detection** | Safety gates are structural | Detecting "anomalous" rule changes using heuristics or ML introduces false positives and false negatives in a safety-relevant context. `drift_detected` and `has_critical_changes` are deterministic computations from structured data. |
| **Config file auto-generation** | YAGNI | The tool reads a caller-supplied config.env. Generating a template config from VM metadata would require additional API calls and a templating concern that adds no value to the core pipeline. |
