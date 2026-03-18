# Firewall Inspector — Design

*Architecture reference: `netfilter-inspector/architecture.md`*
*Status: MVP shipped — 2026-03-15*

This document covers `firewall_inspector.py`, `providers.py`, `framework_detector.py`, and `chain_classifier.py`.

---

## 1. Component and Function Inventory

### `firewall_inspector.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `validate_session_id` | `(session_id: str) → None` | Enforce `^[a-zA-Z0-9_-]{1,64}$` before any shell command or file path is constructed. Raises `ValueError` on invalid input. |
| `_snapshot_sha256` | `(json_bytes: bytes) → str` | Return SHA-256 hex digest of serialised snapshot bytes. |
| `save_snapshot` | `(snapshot: dict, audit_dir: str, session_id: str) → str` | Write snapshot JSON and `.sha256` companion to `audit_dir`. Returns snapshot file path. |
| `load_snapshot` | `(audit_dir: str, session_id: str) → dict` | Read and verify SHA-256 of a previously saved snapshot. Raises `FileNotFoundError` or `IntegrityError`. |
| `_parse_probe_sections` | `(text: str) → dict[str, str]` | Split probe output on `###SECTION:name###` markers. Returns `{section_name: content}`. |
| `_section_available` | `(content: str) → bool` | Return `False` if content is exactly `###UNAVAILABLE###`. |
| `_extract_version_strings` | `(fw_section: str) → dict[str, str]` | Split `framework_detection` section into per-tool version strings for framework detector. |
| `_write_artifact` | `(data: dict, audit_dir: str, session_id: str, suffix: str) → str` | Write JSON artifact to `{audit_dir}/{session_id}_{suffix}.json`. Returns file path. |
| `_print_drift_summary` | `(drift: dict) → None` | Print human-readable drift summary to stdout. |
| `run` | `(config: InspectorConfig, shell: Any, provider: Any) → dict` | Full pipeline: probe → retrieve → parse → baseline/diff → report. |
| `main` | `() → None` | CLI entry point: load config, validate provider, instantiate provider, call `run()`. |

### `providers.py`

| Class / Function | Signature | Responsibility |
|----------|-----------|----------------|
| `LocalShell.__init__` | `(audit_dir: str \| None, session_id: str \| None)` | Create command log path if both args supplied. |
| `LocalShell.execute` | `(cmd: dict) → dict` | Run command via `subprocess.run(shell=True, timeout=120)`. Return shell result dict. Append to `_commands.log`. |
| `_BaseSSHProvider.__init__` | `(shell, ssh_user, target_vm_ip, target_ssh_key_path, bastion_public_ip=None, bastion_ssh_key_path=None)` | Store SSH topology parameters. |
| `_BaseSSHProvider._ssh_opts` | `() → str` | Return `-o StrictHostKeyChecking=yes -o BatchMode=yes -i "{key}"`. Always applied; never overridden. |
| `_BaseSSHProvider._proxy_command` | `() → str` | Return ProxyCommand option string for Case 2 (two-hop). Empty string for Case 1 (direct). |
| `_BaseSSHProvider.retrieve_probe_output` | `(remote_path: str, local_path: str) → None` | SCP probe output file from target VM to local path. Raises `RuntimeError` on denied or non-zero exit. |
| `_BaseSSHProvider.cleanup_probe_output` | `(remote_path: str) → bool` | SSH `rm -f {remote_path}` on target VM. Returns `True` on success, `False` on failure. Never raises. |
| `AzureProvider.run_probe` | `(vm_name, session_id, ssh_user, probe_script) → dict` | Deliver and run probe via `az vm run-command invoke`. Returns `{probe_output_path, probe_output_bytes}`. |
| `SSHProvider.run_probe` | `(vm_name, session_id, ssh_user, probe_script) → dict` | Deliver and run probe via `ssh user@host "sudo bash -s -- SESSION_ID SSH_USER" < probe.sh`. Returns `{probe_output_path, probe_output_bytes}`. |
| `_parse_probe_response` | `(raw: str) → dict` | Parse `PROBE_OUTPUT_PATH=...` and `PROBE_OUTPUT_BYTES=...` lines from probe stdout. Raises `ValueError` if path absent. |

### `framework_detector.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `detect_framework` | `(version_strings: dict[str, str]) → dict` | Determine active iptables framework from version string evidence. Returns `{framework, confidence, parse_warnings}`. |

### `chain_classifier.py`

| Function | Signature | Responsibility |
|----------|-----------|----------------|
| `classify_diff` | `(diff: dict) → dict` | Annotate diff change entries with `severity_tier`. Returns modified diff dict. Does not change `drift_detected` or `has_critical_changes`. |

---

## 2. Data Schemas

### `InspectorConfig`

```python
@dataclass
class InspectorConfig:
    # Required
    ssh_user:             str          # SSH user on the target VM
    target_vm_ip:         str          # Public IP (Case 1) or private IP (Case 2)
    ssh_key_path:         str          # SSH key path for target VM
    session_id:           str          # Validated ^[a-zA-Z0-9_-]{1,64}$
    audit_dir:            str          # Local directory for all artifacts

    # Optional with defaults
    vm_name:              str = ""     # Azure VM name; display label for --provider azure
    resource_group:       str = ""     # Azure resource group; required for --provider azure
    provider:             str = "azure"        # "azure" | "ssh"
    subscription_id:      str | None = None    # Azure subscription; uses az default if omitted
    bastion_public_ip:    str | None = None    # Case 2 only
    bastion_ssh_key_path: str | None = None    # Case 2; defaults to ssh_key_path when unset
    is_baseline:          bool = False
    compare_baseline:     str | None = None    # session_id of baseline to compare against
    family:               str = "ipv4"         # "ipv4" | "ipv6" | "both"
    parse_warnings:       list[str] = field(default_factory=list)
    # WARNING: parse_warnings is a run-time accumulator, not a config input.
    # run() appends warnings to this field throughout the pipeline.
    # Do not reuse an InspectorConfig instance across multiple run() calls —
    # warnings from the first run will persist into the second.
```

### `ShellProtocol` — execute() return contract

```python
{
    "status":    "success" | "error" | "denied",
    "output":    str,           # stdout + stderr combined
    "exit_code": int,           # -1 for timeout or denial
    "audit_id":  str,           # "local" for LocalShell; SafeExecShell audit ID otherwise
}
```

### `run_probe()` return contract

Both `AzureProvider.run_probe()` and `SSHProvider.run_probe()` return:

```python
{
    "probe_output_path":  str,   # Absolute path to temp file on target VM
    "probe_output_bytes": int,   # File size in bytes
}
```

These are parsed from the probe script's stdout lines:
```
PROBE_OUTPUT_PATH=/tmp/fw_XXXXXX.txt
PROBE_OUTPUT_BYTES=4096
```

### Probe output sections

The probe script writes sections delimited by `###SECTION:name###` markers:

```
###SECTION:framework_detection###
iptables v1.8.7 (legacy)
...
###SECTION:iptables_ipv4###
# Generated by iptables-save v1.8.7
*filter
:INPUT ACCEPT [0:0]
...
COMMIT
###SECTION:iptables_ipv6###
###UNAVAILABLE###
```

Section names: `framework_detection`, `iptables_ipv4`, `iptables_ipv6`, `nftables`.

`###UNAVAILABLE###` is written when the corresponding command fails or the binary is absent.

The `nftables` section contains the output of `nft --json list ruleset`. It is always collected by the probe regardless of detected framework — the `nftables_parser` module is only invoked when the framework detector returns `"nftables"`.

### Snapshot artifact

Written to `{audit_dir}/{session_id}_snapshot.json`:

```json
{
  "snapshot_at":          "2026-03-15T09:00:00Z",
  "session_id":           "fw_20260315_090000",
  "vm_name":              "prod-vm-01",
  "resource_group":       "my-rg",
  "family":               "both",
  "framework":            "iptables-legacy",
  "framework_confidence": "high",
  "probe_script_sha256":  "abc123...",
  "parse_warnings":       [],
  "rulesets": {
    "ipv4": { <parse_iptables_save() output> },
    "ipv6": { <parse_iptables_save() output> }
  }
}
```

For a nftables VM (`framework = "nftables"`), `rulesets` has a single `"nft"` key instead of `"ipv4"`/`"ipv6"`. The `family` field is stored as `"nft"` — `config.family` is ignored for nftables runs because nftables uses a single unified ruleset covering all address families:

```json
{
  "snapshot_at":          "2026-03-15T09:00:00Z",
  "session_id":           "fw_20260315_090000",
  "vm_name":              "prod-vm-01",
  "resource_group":       "my-rg",
  "family":               "nft",
  "framework":            "nftables",
  "framework_confidence": "high",
  "probe_script_sha256":  "abc123...",
  "parse_warnings":       [],
  "rulesets": {
    "nft": { <parse_nft_ruleset() output> }
  }
}
```

Note: `snapshot["framework"]` (top-level, the detected firewall stack) is distinct from `snapshot["rulesets"]["nft"]["input_format"]` (inside the ruleset record, the parser's declared format `"nft-json"`). These are two different fields at two different nesting levels.

`rulesets[fam]` is `null` when the section was unavailable on the target VM.

Companion file `{session_id}_snapshot.json.sha256` holds one line: the SHA-256 hex digest of the snapshot JSON bytes (2-space indent).

### Drift report artifact

Written to `{audit_dir}/{session_id}_drift.json`:

```json
{
  "diff_at":            "2026-03-15T10:00:00Z",
  "session_id":         "fw_20260315_100000",
  "vm_name":            "prod-vm-01",
  "resource_group":     "my-rg",
  "baseline_session":   "fw_20260315_090000",
  "probe_script_sha256": "abc123...",
  "drift_by_family": {
    "ipv4": { <diff_rulesets() output, annotated by classify_diff()> },
    "ipv6": { <diff_rulesets() output, or {"error": "..."}> }
  }
}
```

For a nftables VM, `drift_by_family` has a single `"nft"` key:

```json
{
  "drift_by_family": {
    "nft": { <nft_diff_rulesets() output> }
  }
}
```

`classify_diff()` is **not** called for nftables diffs — it is iptables-specific (KUBE-SEP-, DOCKER, f2b- chain patterns).

When a family diff cannot run (one or both rulesets null): `{"error": "Cannot diff nft: one or both rulesets unavailable."}`.

### `detect_framework()` return

```python
{
    "framework":      "iptables-legacy" | "iptables-nft" | "nftables" | "unknown",
    "confidence":     "high" | "medium" | "low",
    "parse_warnings": [ "string", ... ]
}
```

### Config file format (`.env` / `config.env`)

Key-value pairs, one per line. Lines starting with `#` are comments. Blank lines ignored.

```ini
PROVIDER=azure              # azure | ssh
TARGET_VM_IP=10.0.0.5
TARGET_SSH_KEY_PATH=${HOME}/.ssh/id_rsa
SSH_USER=ubuntu
AUDIT_DIR=./audit
FAMILY=both

# Azure-only
VM_NAME=prod-vm-01
RESOURCE_GROUP=my-rg
SUBSCRIPTION_ID=

# Two-hop access (Case 2)
BASTION_PUBLIC_IP=
BASTION_SSH_KEY_PATH=

SESSION_ID=                 # Auto-generated as fw_{YYYYMMDD}_{HHMMSS} if empty
```

---

## 3. Pipeline Stage Detail — `run()`

### Stage 1: Session ID validation

- `validate_session_id(config.session_id)` called as the first operation
- Failure: `ValueError` → `main()` catches and exits with code 1
- This validation runs even when `run()` is called directly (e.g., Ghost Agent) — not only from `main()`

### Stage 2: Probe delivery — `provider.run_probe()`

**AzureProvider path:**
```bash
az vm run-command invoke \
  --resource-group {rg} \
  --name {vm_name} \
  --command-id RunShellScript \
  --scripts "{probe_script_content}" \
  --parameters SESSION_ID={session_id} SSH_USER={ssh_user} \
  [--subscription {subscription_id}]
```
- Response is JSON with `value[0].message` containing stdout
- `_parse_probe_response()` extracts `PROBE_OUTPUT_PATH` and `PROBE_OUTPUT_BYTES` from stdout

**SSHProvider path:**
```bash
ssh {ssh_opts} {proxy_command} {ssh_user}@{target_vm_ip} \
  "sudo bash -s -- {session_id} {ssh_user}" < {probe_tmp_file}
```
- Probe script written to a local temp file before the command is run
- `sudo bash -s -- SESSION_ID SSH_USER`: `-s` reads from stdin; positional args become `$1` and `$2` inside the script
- Probe script's stdout contains `PROBE_OUTPUT_PATH=...` and `PROBE_OUTPUT_BYTES=...`
- Local temp file deleted after command completes regardless of outcome

**Failure modes (both providers):**

| Failure | Behavior |
|---------|----------|
| `shell.execute()` returns `"denied"` | `RuntimeError("probe denied")` — pipeline aborts at Stage 2 |
| Non-zero exit code | `RuntimeError` with output excerpt — pipeline aborts |
| Missing `PROBE_OUTPUT_PATH` in stdout | `ValueError` from `_parse_probe_response()` — pipeline aborts |

### Stage 3: Output retrieval — `provider.retrieve_probe_output()`

```bash
scp {ssh_opts} {proxy_command} \
  {ssh_user}@{target_vm_ip}:{remote_path} {local_tmp_file}
```

- Local temp file created with `tempfile.mkstemp()`, permissions set to `0o600`
- `finally` block guarantees: local temp file deleted; remote temp file cleanup attempted
- Remote cleanup failure → warning appended to `config.parse_warnings`; pipeline continues
- Probe text read from local temp before local temp is deleted

### Stage 4: Section parsing

- `_parse_probe_sections(probe_text)` splits on `###SECTION:name###` markers
- Missing section key → treated as empty string in subsequent steps
- `###UNAVAILABLE###` content → `_section_available()` returns `False`; `parse_warnings` entry added; `parsed[fam] = None`

### Stage 5: Framework detection

- `_extract_version_strings(fw_section)` extracts per-tool version strings from raw section content
- `detect_framework(version_strings)` returns `{framework, confidence, parse_warnings}`
- `parse_warnings` from detector appended to `config.parse_warnings`
- Detection result stored in snapshot (`framework`, `framework_confidence`)
- **Framework detection gates the parse branch** — `framework == "nftables"` routes to the nftables parse path; all other values route to the iptables parse path.

### Stage 6: Parse

**nftables path** (`framework == "nftables"`):
- `parse_nft_ruleset(nft_content)` called with the `nftables` probe section
- Result stored as `parsed["nft"]`; `families = ["nft"]`
- Section unavailability (including empty/whitespace-only): `parsed["nft"] = None`; warning emitted
- `config.family` is ignored — nftables uses a unified ruleset covering all address families; the result is always stored under `"nft"` regardless of `FAMILY` setting

**iptables path** (all other frameworks):
- `parse_iptables_save(content, family=fam)` called for each requested family
- `config.family = "both"` → two calls (ipv4, ipv6)
- Unavailable sections skipped with warning; available sections parsed fully
- All `parse_warnings` from the parser are surfaced in the snapshot

### Stage 7: Snapshot assembly and save (`--is-baseline`)

- Snapshot dict assembled from config metadata + framework result + parsed rulesets
- `save_snapshot()` writes JSON with 2-space indent; writes `.sha256` companion
- Both files must be present for `load_snapshot()` to succeed
- Artifact directory created with `mkdir -p` if it does not exist

### Stage 8: Compare and diff (`--compare-baseline`)

- `load_snapshot(audit_dir, compare_baseline)` reads and verifies SHA-256 of baseline
- `IntegrityError` → pipeline aborts with message; no diff is run
- **Framework mismatch guard**: checks `"nft" in baseline["rulesets"]` against `"nft" in parsed`. If they differ → `ValueError` with message naming both the baseline framework and current framework; pipeline aborts before any diff engine is called. This approach treats `"iptables-legacy"` and `"iptables-nft"` as the same diff-engine family (both produce `ipv4`/`ipv6` keys, never a `"nft"` key) and will never false-fire on a legacy→nft migration.
- **Diff routing**: determined by `"nft" in parsed` (the current run's rulesets dict), not by the `framework` string and not by `input_format` inside the ruleset record. `"nft" in parsed` → `nft_diff_rulesets()` → stored in `drift_reports["nft"]`. `classify_diff()` is NOT called for nftables.
- **iptables diff path** (`"nft" not in parsed`): `diff_rulesets(b, c)` → `classify_diff()` → stored in `drift_reports[fam]`
- If either side is `None` → `{"error": "..."}` written for that family; other families still processed
- Drift artifact written to `{session_id}_drift.json`
- `_print_drift_summary()` outputs human-readable summary to stdout

### Stage 9: Report

`run()` returns:

```python
{
    "snapshot": <snapshot dict>,
    "baseline_saved": "<path>",      # --is-baseline mode only
    "drift_report": "<path>",        # --compare-baseline mode only
    "drift": <drift dict>,           # --compare-baseline mode only
    "probe_script_sha256": "<hash>", # --is-baseline mode only
}
```

---

## 4. SSH Topology Cases

### Case 1 — Direct access (no bastion)

Target VM has a public IP. `BASTION_PUBLIC_IP` is empty or absent.

```
Operator machine
       |
       | SSH / SCP (direct)
       |
  Target VM (public IP)
```

- `_proxy_command()` returns `""`
- SCP: `scp {ssh_opts} {user}@{target_ip}:{remote} {local}`
- SSH: `ssh {ssh_opts} {user}@{target_ip} "..."`

### Case 2 — Two-hop via bastion

Target VM has only a private IP. `BASTION_PUBLIC_IP` is set.

```
Operator machine
       |
       | SSH to bastion (public IP)
       |
    Bastion VM
       |
       | SSH to target (private IP, ProxyCommand tunnels through bastion)
       |
  Target VM (private IP)
```

- `_proxy_command()` returns:
  ```
  -o "ProxyCommand=ssh -W %h:%p -i '{bastion_key}' -o StrictHostKeyChecking=yes -o BatchMode=yes {user}@{bastion_ip}"
  ```
- SCP and SSH commands include this ProxyCommand option string
- `BASTION_SSH_KEY_PATH` defaults to `TARGET_SSH_KEY_PATH` when unset (shared key assumption)
- `known_hosts` must contain entries for both bastion and target before first run

---

## 5. Error Handling Strategy

### `validate_session_id()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Value does not match `^[a-zA-Z0-9_-]{1,64}$` | `ValueError` with specific message | Exception; no pipeline runs |

### `save_snapshot()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| `audit_dir` path not creatable | `OSError` propagates | Exception from `mkdir` |
| Write failure | `OSError` propagates | Exception; partial file may exist |

### `load_snapshot()`

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Snapshot JSON missing | `FileNotFoundError` with path | Exception |
| `.sha256` companion missing | `IntegrityError` with explanation | Exception; pipeline aborted |
| SHA-256 mismatch | `IntegrityError` with first 16 chars of both hashes | Exception; pipeline aborted |
| Malformed JSON | `json.JSONDecodeError` propagates | Exception |

### `run()` — probe delivery

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Probe denied by safety shell | `RuntimeError("probe denied by safety shell")` | Run aborts; caller receives exception |
| Probe non-zero exit | `RuntimeError` with exit code and output | Run aborts |
| Probe stdout missing `PROBE_OUTPUT_PATH` | `ValueError` from `_parse_probe_response()` | Run aborts |
| SCP denied | `RuntimeError` | Run aborts |
| SCP non-zero exit | `RuntimeError` with output excerpt | Run aborts |
| Remote cleanup failure | Warning appended; pipeline continues | `config.parse_warnings` entry; run succeeds |
| Local temp file deletion failure | Logged; pipeline continues | Non-fatal |

### `run()` — parse and diff

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Section unavailable (`###UNAVAILABLE###`) | Warning; `parsed[fam] = None` | Run continues; affected family skipped in diff |
| `parse_iptables_save()` raises | Exception propagates | Run aborts |
| `parse_nft_ruleset()` raises | Exception propagates | Run aborts |
| `diff_rulesets()` raises `ValueError` | Exception propagates | Run aborts |
| `nft_diff_rulesets()` raises `ValueError` | Exception propagates | Run aborts |
| One side of diff is `None` | `{"error": "..."}` stored for that family | Other families still diffed; run continues |
| Framework mismatch between baseline and current | `ValueError` with explanation | Run aborts; no diff written |
| `IntegrityError` on baseline load | Message printed; run aborts | `SystemExit(1)` in `main()`; caller receives exception from `run()` |
| `_write_artifact()` raises `OSError` | Exception propagates | Run aborts after diff completes; drift artifact not written |

### `main()` — config and provider validation

| Error | Behavior | What caller receives |
|-------|----------|---------------------|
| Config file not found | Error message + `SystemExit(2)` | CLI exits 2 |
| Required field missing | Error message + `SystemExit(2)` | CLI exits 2 |
| `PROVIDER` not `azure` or `ssh` | `parser.error()` + `SystemExit(2)` | CLI exits 2 |
| `--is-baseline` and `--compare-baseline` both set | `parser.error()` | CLI exits 2 |
| `validate_session_id()` raises | Error message + `SystemExit(1)` | CLI exits 1 |
| `run()` raises `RuntimeError` | Error message + `SystemExit(1)` | CLI exits 1 |
| `run()` raises `ValueError` from framework mismatch guard | Unhandled; Python traceback to stderr | CLI exits 1 with traceback. The traceback message is actionable ("Framework mismatch: ... Capture a new baseline.") — no clean-message wrapping is implemented; the raw traceback is the intended user-facing output for this error. |
| `run()` raises `IntegrityError` | Unhandled; Python traceback to stderr | CLI exits 1 with traceback |
| `run()` raises `ValueError` (from diff engine) | Unhandled; Python traceback to stderr | CLI exits 1 with traceback |
| `run()` raises `OSError` (from artifact write) | Unhandled; Python traceback to stderr | CLI exits 1 with traceback |

---

## 6. Probe Script Design

The probe script is a static string constant `_PROBE_SCRIPT` embedded in `firewall_inspector.py`. It is never generated at runtime with interpolated values — all runtime parameters are passed as positional arguments (`$1` = SESSION_ID, `$2` = SSH_USER).

**Script contract:**
- `set -euo pipefail` — exits on unguarded errors. Note: each `iptables-save` invocation is followed by `|| printf '###UNAVAILABLE###\n'`, so `set -e` does not cause exit on those command failures — the fallback runs instead. `set -e` catches unexpected failures in other parts of the script (e.g., `mktemp`, `chmod`).
- Writes all output to a temp file created by `mktemp /tmp/fw_XXXXXX.txt`
- `chmod 600` on temp file immediately after creation
- Collects four sections in order: `framework_detection`, `iptables_ipv4`, `iptables_ipv6`, `nftables`
- Each `iptables-save` invocation uses `-c` (with counters)
- The `nftables` section uses `nft --json list ruleset` — always collected; the parser only invokes `parse_nft_ruleset()` when the framework detector returns `"nftables"`
- Unavailability: each section wrapped in `|| printf '###UNAVAILABLE###\n'` — one section failure does not abort the rest
- `chown "$SSH_USER" "$OUT"`: transfers ownership so the SSH user can SCP the file. Non-fatal if it fails (target user may already be root).
- Final two lines print `PROBE_OUTPUT_PATH=` and `PROBE_OUTPUT_BYTES=` for the orchestrator to parse

**`PROBE_SCRIPT_SHA256`**: SHA-256 of the probe script string, computed at module import time. Stored in both the snapshot and the drift report as a chain-of-custody record. The operator can verify this hash against the HITL gate display when running under Ghost Agent.

**Why static, not generated:**
If the probe script were assembled from config values, a malicious or misconfigured `session_id` could inject shell commands. The static script with positional-argument delivery is the injection barrier.

---

## Shell Injection Surface

Shell commands are assembled as f-strings and executed via `subprocess.run(shell=True)`. The injection surface and the validation status of each config field used in shell commands:

| Field | Used in | Validation |
|-------|---------|-----------|
| `session_id` | Artifact filenames only (not in shell commands) | Validated: `^[a-zA-Z0-9_-]{1,64}$` before any use |
| `probe_script` | SSH stdin redirect (`< probe_tmp_file`) | Static constant; never assembled from user input |
| `ssh_user` | SSH/SCP user prefix (`{user}@{host}`); bash positional arg in probe | **Not validated.** Trusted as a legitimate Unix username. Values come from operator-controlled config file. |
| `target_vm_ip` | SSH/SCP host (`{user}@{host}`) | **Not validated.** Trusted as an IP address. Values come from operator-controlled config file. |
| `vm_name` | `az vm run-command invoke --name {vm_name}` | **Not validated.** Trusted as an Azure VM name. Values come from operator-controlled config file. |
| `resource_group` | `az vm run-command invoke --resource-group {rg}` | **Not validated.** Trusted as an Azure resource group name. Values come from operator-controlled config file. |
| `bastion_public_ip` | ProxyCommand SSH host | **Not validated.** Trusted as an IP address. Values come from operator-controlled config file. |
| `target_ssh_key_path` | `-i "{key}"` in SSH/SCP opts | **Not validated.** Path expanded via `os.path.expandvars`/`expanduser`. Values come from operator-controlled config file. |

**Threat model:** The config file is operator-supplied and operator-controlled. An attacker who can modify the config file already has operator-level access to the machine running the tool, which is a higher privilege level than anything the tool can access. Validation of `session_id` is a correctness control (prevent path traversal in artifact filenames), not a defence against a malicious operator.

**Consequence:** The tool does not defend against a malicious operator who controls the config file. It defends against an accidental misconfiguration in `session_id` that could corrupt artifact filenames or allow directory traversal. The distinction between correctness validation (`session_id`) and security validation (the rest) should be understood by any caller integrating this tool.

---

## 7. Edge Cases

| Case | Handling |
|------|----------|
| `--family both` and one family unavailable | Available family is parsed and saved normally. Missing family: `parsed[fam] = None`; warning emitted. Baseline stores `null` for that family. Diff for the null family returns `{"error": "..."}`. |
| Target VM has no iptables installed | Both iptables sections return `###UNAVAILABLE###`. Snapshot saved with `rulesets: {"ipv4": null, "ipv6": null}`. Useful as a "no firewall" baseline. |
| `--is-baseline` run overwrites existing snapshot | Overwrites silently. The `.sha256` companion is also overwritten. If the user wants multiple baselines, they use different `SESSION_ID` values. |
| `PROVIDER=ssh` with no `VM_NAME` set | `target_label = config.vm_name or config.target_vm_ip` — `target_vm_ip` used as display label. No error. |
| `PROVIDER=azure` with empty `RESOURCE_GROUP` | Caught at startup: `--provider azure` requires `resource_group`. `SystemExit(2)`. |
| Two runs with identical `SESSION_ID` produce conflicting snapshots | Second run overwrites first. Session ID naming convention (`fw_{YYYYMMDD}_{HHMMSS}`) prevents accidental collision. Custom session IDs are caller responsibility. |
| `audit_dir` path does not exist | `save_snapshot()` calls `mkdir(parents=True, exist_ok=True)`. Auto-created. |
| `bastion_ssh_key_path` not set | Defaults to `target_ssh_key_path`. If both VMs use different keys, the operator must set `BASTION_SSH_KEY_PATH` explicitly. |
| SCP retrieves partial file (interrupted connection) | `probe_text = Path(local_tmp).read_text(...)` reads whatever was written. `_parse_probe_sections()` will return incomplete sections or miss `PROBE_OUTPUT_PATH`. The latter causes `ValueError`. Probe re-run required. |
| `StrictHostKeyChecking=yes` and unknown host | SSH / SCP exit non-zero. Error message includes the host verification failure. Operator must run `ssh-keyscan` before first use. |
| `BatchMode=yes` prevents password prompts | SSH exits if prompted for a password. Error is visible in the RuntimeError output. Operator must use key-based auth. |
| `diff_rulesets()` compares different families | `ValueError` from diff engine — families are stored per-key in the snapshot; the orchestrator passes `baseline.rulesets[fam]` and `current.rulesets[fam]` — same family guaranteed. |
| VM migrated from iptables to nftables since baseline was taken | Mismatch guard fires: `"nft" in baseline["rulesets"]` is False, `"nft" in parsed` is True → `ValueError` with explanation; pipeline aborts. Operator must take a new nftables baseline. |
| `nftables` probe section absent or empty | `sections.get("nftables", "")` returns `""`. Empty string is treated as unavailable (same as `###UNAVAILABLE###`). `parsed["nft"] = None`; warning emitted. Snapshot saves with `rulesets: {"nft": null}`. |
| `nftables` probe section present but minimal (`{"nftables":[]}`) | Valid JSON with no rules. `parse_nft_ruleset()` returns an empty tables dict. Not an error — a freshly provisioned VM with no nftables rules is a legitimate state. |
| `nft --json` emits a warning line to stderr before the JSON body | The outer `collect > "$OUT" 2>&1` redirect will intermix the warning with the JSON output. `json.loads()` will fail with `JSONDecodeError` (not `###UNAVAILABLE###`). The exception propagates and aborts the pipeline. This is a known limitation of the shell redirection design shared with iptables-save sections; JSON format is more sensitive to prefix corruption than line-oriented text. |
| Entire new table+chain added between baseline and compare | `nft_diff_rulesets()` classifies the event as `chains_added`, not `rules_added`. `chains_added` entries contain only chain metadata — `table`, `chain`, `hook`, `type`, `policy`, `rule_count` — but **not** individual rule details (`verdict`, `dst_port`, `protocol`, etc.) for rules that were created inside that new chain. **Example:** baseline has no `fw_test` table; compare state has `table inet fw_test { chain input { tcp dport 4444 drop } }`. The diff reports `chains_added: [{"table": "inet/fw_test", "chain": "input", "rule_count": 1}]` with `rules_added: []`. The `rule_count` confirms a rule exists but neither the `verdict` nor the `dst_port` is visible. `has_critical_changes` is computed from `rules_added` entries only, so it remains `false` even though a DROP rule was added. Contrast: if the chain already exists in the baseline and a rule is added to it, the rule appears in `rules_added` with full fields and `has_critical_changes` is set correctly. **Workaround:** ensure the chain exists in the baseline snapshot before testing rule-level drift; use `--is-baseline` after chain creation and before rule injection. |
| `FAMILY=ipv4` or `FAMILY=both` on a nftables VM | `config.family` is ignored for nftables runs. The parse path unconditionally calls `parse_nft_ruleset()` and stores the result under `"nft"`. The snapshot records `"family": "nft"` regardless of the config value. |

---

## 8. Config File Loading

`_load_config_file(path)` reads a `.env`-style file and populates `argparse` defaults.

**Key map** (env variable → `InspectorConfig` field):

| Env key | Field | Type |
|---------|-------|------|
| `PROVIDER` | `provider` | str |
| `VM_NAME` | `vm_name` | str |
| `RESOURCE_GROUP` | `resource_group` | str |
| `SUBSCRIPTION_ID` | `subscription_id` | str |
| `TARGET_VM_IP` | `target_vm_ip` | str |
| `TARGET_SSH_KEY_PATH` | `ssh_key_path` | str (shell-expanded) |
| `BASTION_PUBLIC_IP` | `bastion_public_ip` | str |
| `BASTION_SSH_KEY_PATH` | `bastion_ssh_key_path` | str (shell-expanded) |
| `SSH_USER` | `ssh_user` | str |
| `AUDIT_DIR` | `audit_dir` | str |
| `FAMILY` | `family` | str |
| `SESSION_ID` | `session_id` | str |

**Shell expansion:** Values containing `${HOME}` or `~` in `TARGET_SSH_KEY_PATH` and `BASTION_SSH_KEY_PATH` are expanded via `os.path.expandvars` + `os.path.expanduser`.

**Empty values:** Empty string values in the config file are treated as "not set" — the CLI default is used.

**PROVIDER post-parse validation:** `argparse choices=` only validates argv values, not `set_defaults` values set by `_load_config_file()`. An explicit post-parse check enforces `provider in ("azure", "ssh")` for config-file-sourced values, with `parser.error()` on violation.

---

## 9. Intentional Omissions

| Omission | Rationale |
|----------|-----------|
| `--explain` flag | Designed separately in `explain-feature-design.md`. Requires a different output model and optionally an LLM invocation. Not part of the baseline/diff pipeline. |
| nftables chain classification | `classify_diff()` contains iptables-specific chain name patterns (KUBE-SEP-, DOCKER, f2b-, ufw-). These have no meaning for nftables. nftables diffs are returned as-is from `nft_diff_rulesets()` without severity annotation. Dedicated nftables chain classification is deferred. |
| Automatic `known_hosts` population | `StrictHostKeyChecking=yes` is a deliberate security control. Auto-accepting host keys would silently disable MITM protection. Operator must run `ssh-keyscan` before first use. |
| Windows Firewall / PowerShell | OS boundary. Different probe, different parser, different deployment model. |
| Direct `iptables` command execution on target | The probe reads state via `iptables-save`. The tool never executes iptables rule modification commands on a target VM — that would make it a configuration management tool, not an inspector. |
| REST-based probe delivery (Azure Custom Script Extension) | `az vm run-command invoke` is synchronous and returns output inline. Custom Script Extension requires polling, blob storage for output, and extension installation. More complex for identical capability at this scale. |
| `--dry-run` for baseline overwrite | The `SESSION_ID` naming convention (`fw_{YYYYMMDD}_{HHMMSS}`) is the protection against accidental overwrite. A `--dry-run` flag adds complexity without changing the naming convention's behaviour. |
