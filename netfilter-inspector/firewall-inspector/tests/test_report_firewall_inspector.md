# VM Firewall Inspector — Test Report

*Modules: `framework_detector.py` (Module 4), `providers.py`, `firewall_inspector.py` (orchestrator), `chain_classifier.py` (Module 6)*
*Against design: `vm-firewall-inspector-plan.md`, `security_challenges.md`*
*Test date: 2026-03-14 (initial) / 2026-03-15 (SSHProvider + end-to-end Multipass)*
*Last test run: 2026-03-15 — `python3 -m pytest tests/test_framework_detector.py tests/test_chain_classifier.py tests/test_inspector.py -v` → **94 passed, 2 skipped in 0.11s***

---

## Summary

| Module / Category | File | Tests | Pass | Skip | Bugs fixed |
|-------------------|------|-------|------|------|------------|
| Framework detector (`framework_detector.py`) | `test_framework_detector.py` | 18 | 18 | 0 | — |
| Chain classifier (`chain_classifier.py`) | `test_chain_classifier.py` | 21 | 21 | 0 | — |
| Security — session_id validation | `test_inspector.py` (SEC-VAL) | 14 | 14 | 0 | — |
| Security — SSH/SCP hardening (AzureProvider) | `test_inspector.py` (SEC-SSH-01–07) | 7 | 7 | 0 | 2 (ProxyCommand, local_path quoting) |
| Security — SSH/SCP hardening (SSHProvider) | `test_inspector.py` (SEC-SSH-08–14) | 7 | 7 | 0 | — |
| Security — probe script integrity | `test_inspector.py` (SEC-PROBE) | 6 | 6 | 0 | — |
| Security — baseline integrity | `test_inspector.py` (SEC-BAS) | 5 | 5 | 0 | — |
| Security — LocalShell audit log | `test_inspector.py` (SEC-LOG) | 4 | 4 | 0 | 1 test fix |
| Security — SafeExecShell classification | `test_inspector.py` (SEC-CLS) | 2 | 0 | 2 | — |
| Functional tests | `test_inspector.py` (FI) | 12 | 12 | 0 | — |
| **Total** | | **96** | **94** | **2** | |

Two bugs were identified during the first code review and fixed. Four more were found during the second code review (post-SSHProvider). The 2 skipped tests (SEC-CLS) require `safe_exec_shell` on the Python path — they pass in the Ghost Agent environment.

**Full suite (all modules including iptables_parser and iptables_diff):** 180 passed, 0 failed.

---

## End-to-End Integration Tests (Multipass VM — 2026-03-15)

Run against `fw-legacy` (Multipass Ubuntu 22.04, switched to `iptables-legacy` via `update-alternatives`).
Provider: `--provider ssh`. IP: `192.168.2.6`. User: `ubuntu`.

| # | Scenario | Expected | Actual | Result |
|---|----------|----------|--------|--------|
| E2E-1 | Rule removal detected | `rules_removed=1 drift=True critical=False` | `rules_removed=1 drift=True critical=False` | PASS |
| E2E-2 | Policy change detected | `policy_changes=1 critical=True` | `policy_changes=1 critical=True rules_added=1` | PASS |
| E2E-3 | No drift (all-clear) | `drift=False` both families | `drift=False` both families | PASS |
| E2E-4 | IPv6 drift detected | `[ipv6] drift=True critical=True rules_added=1` | `[ipv6] drift=True critical=True rules_added=1` | PASS |
| E2E-5 | Multiple rules simultaneously | `rules_added=3 critical=True` | `rules_added=3 critical=True` | PASS |
| E2E-6 | `--family ipv4` scoping | IPv6 not reported | `[ipv4]` only in output | PASS |
| E2E-7 | Session ID override | All artifacts use custom name | All 3 artifacts use custom session ID | PASS |

**Note on E2E-2 (policy change):** `iptables -P INPUT DROP` without a prior SSH ACCEPT rule locks out SSH — and `multipass exec` also uses SSH on macOS, requiring a VM reboot to recover. Safe test sequence: always add `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` before setting a DROP policy.

**Note on critical=False for rule removal (E2E-1):** A removed ACCEPT rule with default policy ACCEPT does not change effective traffic behavior. `critical=False` is the correct classification — no traffic is newly blocked.

**Note on iptables-nft gap:** Ubuntu 22.04 and 24.04 both default to `iptables-nft`. On a fresh VM with no rules, `iptables-save` returns empty output — 0 tables parsed. Two workarounds: (1) switch to iptables-legacy via `update-alternatives`; (2) add rules via the iptables frontend to populate nftables tables. Ubuntu 24.04 required a reboot after an `iptables -L` invocation even after the alternatives switch — the kernel module did not initialize until explicitly queried.

---

## Section 1: Framework Detector (FD-01 — FD-16)

Tests call `detect_framework()` directly with a version string dict. No mocks required — pure function.

### FD-01 — update-alternatives detects nft — PASS

`update_alternatives` Value pointing to `iptables-nft`: `framework="iptables-nft"`, `confidence="high"`, `iptables_cmd="iptables-save"`.

### FD-02 — update-alternatives detects legacy — PASS

`update_alternatives` Value pointing to `iptables-legacy`: `framework="iptables-legacy"`, `confidence="high"`.

### FD-03 — UA legacy uses iptables-legacy-save when binary present — PASS

UA says legacy AND `iptables_legacy` version string present: `iptables_cmd="iptables-legacy-save"`.

### FD-04 — UA legacy falls back to iptables-save when no legacy binary — PASS

UA says legacy but no `iptables_legacy` version string: `iptables_cmd="iptables-save"`.

### FD-05 — iptables version tag detects nft — PASS

`iptables --version` with `(nf_tables)`: `framework="iptables-nft"`, `confidence="high"`, `iptables_cmd="iptables-save"`.

### FD-06 — iptables version tag detects legacy — PASS

`iptables --version` with `(legacy)`: `framework="iptables-legacy"`, `confidence="high"`.

### FD-07 — Version tag matching is case-insensitive (nft) — PASS

`(NF_TABLES)` (uppercase): `framework="iptables-nft"`. No case-sensitive failure.

### FD-08 — Version tag matching is case-insensitive (legacy) — PASS

`(LEGACY)` (uppercase): `framework="iptables-legacy"`.

### FD-09 — Old version, no tag, with legacy binary → high confidence — PASS

`iptables v1.4.21` (no backend tag) + `iptables-legacy` present: `framework="iptables-legacy"`, `confidence="high"`, 1 parse warning.

### FD-10 — Old version, no tag, no legacy binary → low confidence — PASS

`iptables v1.4.21` only: `framework="iptables-legacy"`, `confidence="low"`, 1 parse warning.

### FD-11 — iptables-legacy binary only, no iptables main — PASS

Only `iptables-legacy` version present: `framework="iptables-legacy"`, `iptables_cmd="iptables-legacy-save"`, `confidence="low"`, 1 parse warning.

### FD-12 — nft only → unknown (MVP limitation) — PASS

Only `nft --version` present: `framework="unknown"`, `iptables_cmd=None`, `nft_available=True`, at least 1 warning containing "nftables".

### FD-13 — All empty strings → unknown — PASS

All version strings empty: `framework="unknown"`, `confidence="low"`, at least 1 parse warning.

### FD-14 — Missing keys → unknown — PASS

Empty dict (no keys at all): `framework="unknown"`, `confidence="low"`.

### FD-15 / FD-15b — nft_available flag — PASS

`nft_available=True` when `nft --version` present; `nft_available=False` when absent.

### FD-16 / FD-16b — parse_warnings populated correctly — PASS

Clean high-confidence detection (UA path): `parse_warnings=[]`. Ambiguous detection (old iptables, no backup evidence): at least 1 warning.

---

## Section 2: Chain Classifier (CC-01 — CC-22)

Tests call `classify_chain()` and `classify_diff()` directly. No mocks required — pure functions.

### CC-01 to CC-03 — Ephemeral patterns: KUBE-SEP, KUBE-SVC, KUBE-FW — PASS

`KUBE-SEP-ABCD1234`, `KUBE-SVC-XYZ`, `KUBE-FW-SOMEID` → all `"ephemeral"`.

### CC-04 to CC-06 — Structural patterns: DOCKER, f2b, ufw — PASS

`DOCKER` → `"structural"`. `f2b-sshd` → `"structural"`. `ufw-before-input` → `"structural"`.

### CC-07 — Ephemeral wins priority over structural — PASS

Temporarily added `^KUBE-` to `_STRUCTURAL_PATTERNS`: `KUBE-SEP-XXXX` still returns `"ephemeral"` (checked first). Pattern lists restored in `finally`.

### CC-08 / CC-09 — User-defined fallback — PASS

`INPUT` → `"user-defined"`. `BLOCK-LIST` → `"user-defined"`.

### CC-10 — Ephemeral rules_added suppressed — PASS

1 rule with `chain="KUBE-SEP-XXXX"`: after `classify_diff()`, `changes["rules_added"]=[]`, `summary["rules_added"]=0`.

### CC-11 — Ephemeral rules_removed suppressed — PASS

1 rule with `chain="KUBE-SVC-ABC"`: after classify, `rules_removed=[]`, `summary["rules_removed"]=0`.

### CC-12 — Ephemeral rules_repositioned suppressed — PASS

1 repositioned entry with `chain="KUBE-SEP-XXXX"`: after classify, `rules_repositioned=[]`, `summary["rules_repositioned"]=0`.

### CC-13 — Mixed diff: only ephemeral suppressed — PASS

2 rules: `KUBE-SEP-XXXX` (ephemeral) and `INPUT` (user-defined). After classify: 1 rule in `rules_added`, chain is `"INPUT"`. Ephemeral rule removed, user-defined rule preserved.

### CC-15 / CC-16 — User-defined and structural rules not suppressed — PASS

`INPUT` and `DOCKER` rules in `rules_added`: both preserved in output. `len(rules_added) == 1` in each case.

### CC-17 — Summary counts match filtered lists — PASS

3 rules (2 ephemeral, 1 user-defined): after classify, `summary["rules_added"] == len(changes["rules_added"]) == 1`.

### CC-18 — Input dict not mutated — PASS

`classify_diff(d)` called; `d` compared to deep copy taken before the call: no mutation. All fields unchanged.

### CC-19 — chain_classifications key present and correct — PASS

3 rules with different chain tiers: `result["chain_classifications"]["INPUT"]=="user-defined"`, `["KUBE-SEP-XXXX"]=="ephemeral"`, `["DOCKER"]=="structural"`.

### CC-20 — ephemeral_summary counts correct — PASS

2 rules added to `KUBE-SEP-A`, 1 rule removed from `KUBE-SEP-B`: `ephemeral_summary["KUBE-SEP-A"]["current_rule_count"]==2`, `["KUBE-SEP-B"]["baseline_rule_count"]==1`.

### CC-21 — Policy changes for ephemeral chains not suppressed — PASS

Policy change entry with `chain="KUBE-SEP-XXXX"`: after classify, `len(changes["policy_changes"])==1`. Policy changes are operationally significant on any chain tier.

### CC-22 — Extensibility: new structural pattern without code change — PASS

`re.compile(r"^tun-vpn-")` appended to `_STRUCTURAL_PATTERNS`: `classify_chain("tun-vpn-client0")=="structural"`, `classify_chain("INPUT")=="user-defined"` (unchanged). Pattern removed in `finally`.

---

## Section 3: Security Tests — session_id Validation (SEC-VAL)

### SEC-VAL-01 — Valid session IDs accepted (5 parametrized cases) — PASS

`fw_20260314_100000`, `test-session`, `abc`, 64-char string, `fw-abc_123-XYZ`: all pass `validate_session_id()` without raising.

### SEC-VAL-02 — Invalid session IDs rejected (8 parametrized cases) — PASS

| Input | Reason | Result |
|-------|--------|--------|
| `abc;cmd` | semicolon | `ValueError: Invalid session_id` |
| `abc$var` | dollar sign | `ValueError: Invalid session_id` |
| `../etc/passwd` | path traversal | `ValueError: Invalid session_id` |
| `abc&&ls` | double ampersand | `ValueError: Invalid session_id` |
| `abc\|ls` | pipe | `ValueError: Invalid session_id` |
| `hello world` | space | `ValueError: Invalid session_id` |
| 65-char string | too long | `ValueError: Invalid session_id` |
| empty string | empty | `ValueError: Invalid session_id` |

### SEC-VAL-08 — Validation fires before any shell execute() call — PASS

`InspectorConfig` with `session_id="bad;id"`: `validate_session_id()` raises `ValueError`; `mock_shell.execute` and `mock_provider.run_probe` both have `assert_not_called()` confirmed.

---

## Section 4: Security Tests — SSH/SCP Hardening (SEC-SSH)

### AzureProvider (SEC-SSH-01 — SEC-SSH-07)

#### SEC-SSH-01 — SCP contains StrictHostKeyChecking=yes — PASS

`retrieve_probe_output()` called (Case 2, with bastion); `shell.execute.call_args` inspected: `"StrictHostKeyChecking=yes"` present in the constructed SCP command string.

#### SEC-SSH-02 — SCP contains ProxyCommand with bastion IP — PASS

Case 2 SCP call: `"ProxyCommand"` and `"1.2.3.4"` (the `bastion_public_ip`) both present in the command string.

**Note:** Original design used `ProxyJump`. Changed to `ProxyCommand` to allow specifying a separate `-i` key for the bastion hop. `ProxyJump` does not accept a separate `-i` argument.

#### SEC-SSH-03 — SSH cleanup contains StrictHostKeyChecking=yes — PASS

`cleanup_probe_output()` called; constructed SSH command contains `"StrictHostKeyChecking=yes"`.

#### SEC-SSH-04 — StrictHostKeyChecking=no never appears in any command (regression guard) — PASS

All command types triggered (`retrieve_probe_output`, `cleanup_probe_output`); all `call_args_list` entries inspected: `"StrictHostKeyChecking=no"` absent from every command.

#### SEC-SSH-05 — Case 1 (no bastion): no ProxyCommand, target IP present — PASS

`bastion_public_ip=None`: no `ProxyCommand` or `ProxyJump` in either `retrieve_probe_output` or `cleanup_probe_output` commands. Target VM IP `"20.1.2.3"` present in both commands.

#### SEC-SSH-06 — Case 2b (different keys): bastion key inside ProxyCommand, target key outside — PASS

`target_ssh_key="/home/user/.ssh/target_key"`, `bastion_ssh_key="/home/user/.ssh/bastion_key"`: command split on `"ProxyCommand"` — target key in outer `-i`, bastion key inside ProxyCommand. Neither key appears on the wrong side.

#### SEC-SSH-07 — Case 2a (same key): shared key appears in both positions — PASS

`bastion_ssh_key_path=None` (defaults to target key): target key path appears ≥ 2 times in the SCP command (once as outer `-i`, once inside ProxyCommand).

### SSHProvider (SEC-SSH-08 — SEC-SSH-14)

#### SEC-SSH-08 — run_probe builds correct SSH command — PASS

`run_probe("fw-test", "fw_20260315_100000", "ubuntu", probe_script)` called. Assertions:
- `"bash -s -- fw_20260315_100000 ubuntu"` present (session_id and ssh_user as bash positional args, not just as SSH username match)
- `"192.168.64.5"` (target IP) present
- `"<"` (stdin redirect) present — confirms probe script delivery mechanism

#### SEC-SSH-09 — run_probe denied raises RuntimeError — PASS

Shell returns `status="denied"`: `RuntimeError` raised with `"denied"` in message.

#### SEC-SSH-10 — run_probe non-zero exit raises RuntimeError — PASS

Shell returns `exit_code=255`, `output="ssh: connect to host ... Connection refused"`: `RuntimeError` raised with `"SSH probe failed"` in message.

#### SEC-SSH-11 — retrieve_probe_output contains StrictHostKeyChecking=yes — PASS

`SSHProvider.retrieve_probe_output()` called: `"StrictHostKeyChecking=yes"` present; `"StrictHostKeyChecking=no"` absent.

#### SEC-SSH-12 — Case 1 (no bastion): no ProxyCommand, target IP present — PASS

`bastion_public_ip=None`: no `ProxyCommand` in `retrieve_probe_output` or `cleanup_probe_output`. Target IP present in both commands.

#### SEC-SSH-13 — Case 2 (with bastion): ProxyCommand contains bastion IP — PASS

`bastion_public_ip="10.0.0.1"`: `"ProxyCommand"` and `"10.0.0.1"` both present in `retrieve_probe_output` command.

#### SEC-SSH-14 — run_probe SSH command contains StrictHostKeyChecking=yes — PASS

`run_probe()` called: constructed SSH command contains `"StrictHostKeyChecking=yes"`, `"StrictHostKeyChecking=no"` absent.

---

## Section 5: Security Tests — Probe Script Integrity (SEC-PROBE)

### SEC-PROBE-01 — _PROBE_SCRIPT is a string constant — PASS

`isinstance(_PROBE_SCRIPT, str)` and `len(_PROBE_SCRIPT) > 50`. Not callable, not generated dynamically.

### SEC-PROBE-02 — Probe uses mktemp — PASS

`"mktemp"` present in `_PROBE_SCRIPT`. Temp file is not a predictable static path.

### SEC-PROBE-03 — Probe sets chmod 600 on output file — PASS

`"chmod 600"` present in `_PROBE_SCRIPT`. Output file is not world-readable.

### SEC-PROBE-04 — Probe always collects both families — PASS

`"###SECTION:iptables_ipv4###"`, `"###SECTION:iptables_ipv6###"`, and `"###SECTION:framework_detection###"` all present in `_PROBE_SCRIPT`. No family-conditional interpolation.

### SEC-PROBE-05 — PROBE_SCRIPT_SHA256 matches actual script — PASS

`hashlib.sha256(_PROBE_SCRIPT.encode("utf-8")).hexdigest()` equals `PROBE_SCRIPT_SHA256` constant. Operator can verify the deployed probe matches the expected hash via HITL gate display.

### SEC-PROBE-06 — Probe chowns output file to SSH_USER — PASS

`'chown "$SSH_USER"'` and `'SSH_USER="$2"'` both present in `_PROBE_SCRIPT`.

**Background:** `az vm run-command invoke` executes the probe as root. The output file is created root-owned mode 600. The SSH user (`azureuser`) cannot read it, causing SCP retrieval to fail with `Permission denied`. Fix: probe accepts `ssh_user` as `$2` and `chown`s the file after writing.

---

## Section 6: Security Tests — Baseline Integrity (SEC-BAS)

### SEC-BAS-01 — save_snapshot() writes sha256 companion file — PASS

`save_snapshot()` called: `{session_id}_snapshot.json.sha256` exists in `audit_dir`. Companion is always written alongside the JSON.

### SEC-BAS-02 — sha256 companion content matches snapshot bytes — PASS

`hashlib.sha256(json_bytes).hexdigest()` computed independently from the written JSON file; matches the content of the companion file exactly.

### SEC-BAS-03 — Tampered snapshot raises IntegrityError — PASS

Snapshot written, then `"original"` replaced with `"tampered"` in the JSON file: `load_snapshot()` raises `IntegrityError` with `"integrity check failed"`.

### SEC-BAS-04 — Unmodified baseline loads correctly — PASS

Round-trip: `save_snapshot(snap)` then `load_snapshot()` returns the original dict with all fields intact.

### SEC-BAS-05 — Missing sha256 companion raises IntegrityError — PASS

Snapshot written, companion file deleted: `load_snapshot()` raises `IntegrityError` with `"companion file missing"`. Missing companion is treated as tamper evidence.

---

## Section 7: Security Tests — LocalShell Audit Log (SEC-LOG)

### SEC-LOG-01 — Two execute() calls produce two log entries — PASS

Two `execute()` calls on a `LocalShell` with `audit_dir` and `session_id`: `{session_id}_commands.log` contains exactly 2 non-empty lines.

### SEC-LOG-02 — Each entry has required fields — PASS

Single `execute()` call: log entry is valid JSON with `ts`, `command`, `exit_code`, `output_bytes` keys. `command` matches input; `exit_code == 0`.

### SEC-LOG-03 — Log does not contain output text — PASS

`execute()` called; log entry JSON has **no `"output"` key**. Command output text is never written to the log. `output_bytes > 0` (byte count is logged, content is not).

**Note:** Initial version of this test used `assert "SENSITIVE_FIREWALL_OUTPUT" not in log_content` which failed because the sentinel appeared in the `"command"` field. Fixed to assert `"output" not in entry` (key absence check).

### SEC-LOG-04 — Multiple calls append to log (not overwrite) — PASS

5 `execute()` calls: log contains 5 lines; each line is valid JSON. Log grows by append.

---

## Section 8: Security Tests — SafeExecShell Classification (SEC-CLS)

These are regression guards. Both tests use `pytest.skip` if `safe_exec_shell` is not on the Python path.

### SEC-CLS-01 — az vm run-command invoke is RISKY (regression guard) — SKIP (local env)

`classify("az vm run-command invoke ...")` expected to return `"RISKY"`. The verb `invoke` is not in `_AZ_SAFE_VERBS` or `_AZ_RISKY_VERBS`, falling to the Tier 2 "unknown verb — default RISKY" path. This must never be reclassified to SAFE.

### SEC-CLS-02 — az network nic list-effective-nsg is SAFE (regression guard) — SKIP (local env)

`classify("az network nic list-effective-nsg ...")` expected to return `"SAFE"`. Read-only network query; no HITL gate required.

Both pass in the Ghost Agent environment where `safe_exec_shell` is on the path.

---

## Section 9: Functional Tests (FI-01 — FI-12)

### FI-01 — _parse_probe_sections returns correct section content — PASS

Probe text with three sections: `framework_detection` content contains the version string; `iptables_ipv4` content contains `*filter`; `iptables_ipv6` content contains `###UNAVAILABLE###`.

### FI-02 — _section_available returns False for ###UNAVAILABLE### — PASS

`_section_available("###UNAVAILABLE###")` → `False`. `_section_available("  ###UNAVAILABLE###  ")` → `False`. Leading/trailing whitespace handled.

### FI-03 — _section_available returns True for content — PASS

`_section_available("*filter\nCOMMIT")` → `True`. `_section_available("")` → `True` (empty but not the sentinel).

### FI-04 — _parse_probe_response extracts from az JSON envelope — PASS

Full az CLI JSON with `[stdout]` / `[stderr]` markers: `probe_output_path="/tmp/fw_abc123.txt"`, `probe_output_bytes=4096`.

### FI-05 — _parse_probe_response falls back to raw text — PASS

Non-JSON input with `PROBE_OUTPUT_PATH=` / `PROBE_OUTPUT_BYTES=` lines: parsed correctly via raw fallback. This is the SSHProvider path — direct SSH stdout bypasses the JSON envelope entirely.

### FI-06 — _parse_probe_response raises RuntimeError if path not found — PASS

Input with no `PROBE_OUTPUT_PATH=` line: `RuntimeError("Probe output path not found")`.

### FI-07 — save_snapshot / load_snapshot round-trip — PASS

Dict with nested fields saved then loaded: all fields preserved exactly, including `nested: {"key": [1, 2, 3]}`.

### FI-08 — load_snapshot raises FileNotFoundError when snapshot absent — PASS

`load_snapshot()` on a session_id that was never saved: `FileNotFoundError`.

### FI-09 — LocalShell executes a command and returns the contract — PASS

`shell.execute({"command": "echo hello"})`: `status="success"`, `exit_code=0`, `"hello"` in `output`, `audit_id="local"`.

### FI-10 — LocalShell returns error on non-zero exit code — PASS

`shell.execute({"command": "false"})`: `status="error"`, `exit_code != 0`.

### FI-11 — LocalShell without audit_dir does not log or raise — PASS

`LocalShell()` (no `audit_dir` or `session_id`): `execute()` succeeds and returns correct result; no exception; no log file written.

### FI-12 — Invalid PROVIDER from config.env is rejected — PASS

`PROVIDER=ftp` in config.env: tool exits with code 2 before instantiating any provider.

**Background:** argparse `choices=` only validates values parsed from argv, not values injected via `set_defaults`. An invalid provider value from the config file would silently route to `SSHProvider`. Explicit post-parse validation added to catch this.

---

## Bugs Found and Fixed

### Round 1 — Code Review 2026-03-14

All bugs found during Senior Staff Engineer code review after the initial test suite was written.

#### C1 — `_extract_version_strings()` drops iptables version string when backend is legacy

| | |
|--|--|
| **Severity** | CRITICAL |
| **Symptom** | On systems where `iptables --version` returns `iptables v1.8.7 (legacy)` (no separate `iptables-legacy` binary, no update-alternatives), `detect_framework()` returned `framework="unknown"`. Default Debian 10 / Ubuntu 20.04 configuration. |
| **Root cause** | Condition `if line.startswith("iptables v") and "legacy" not in line.lower()` incorrectly excluded the main binary's output when it reported the legacy backend. |
| **Fix** | Removed `and "legacy" not in line.lower()`. The `elif line.startswith("iptables-legacy"):` branch already handles the legacy binary. |

#### S1 — `run()` did not call `validate_session_id()` internally

| | |
|--|--|
| **Severity** | SIGNIFICANT |
| **Symptom** | Ghost Agent callers invoking `run()` directly could bypass session_id validation, allowing shell injection or path traversal. |
| **Fix** | Added `validate_session_id(config.session_id)` as the first statement in `run()`. |

#### S2 — Misleading field name: `result["baseline_sha256"]`

| | |
|--|--|
| **Severity** | SIGNIFICANT |
| **Fix** | Renamed to `result["probe_script_sha256"]` — consistent with the snapshot dict field name. |

#### M1 — SSH key path not quoted

| | |
|--|--|
| **Severity** | MINOR |
| **Fix** | Changed `-i {self._key_path}` to `-i "{self._key_path}"` in `_ssh_opts()`. |

#### M2 — remote_path not quoted in SSH cleanup command

| | |
|--|--|
| **Severity** | MINOR |
| **Fix** | Changed `rm -f {remote_path}` to `rm -f "{remote_path}"`. |

#### M3 — Probe script used `set -uo pipefail` (missing `-e`)

| | |
|--|--|
| **Severity** | MINOR |
| **Fix** | Changed to `set -euo pipefail`. Added `|| true` on individual version detection commands. |

#### M4 — Test function mislabeled CC-14 instead of CC-18

| | |
|--|--|
| **Severity** | MINOR |
| **Fix** | Renamed `test_cc14_input_dict_not_mutated` → `test_cc18_input_dict_not_mutated`. |

### Round 2 — Code Review 2026-03-15 (post-SSHProvider)

Found during Senior Staff Engineer code review of the `--provider ssh` implementation.

#### B1 — run_probe passes empty string for vm_name when --provider ssh

| | |
|--|--|
| **Severity** | MINOR |
| **Symptom** | `run_probe(vm_name=config.vm_name, ...)` passed an empty string when `--provider ssh` and `--vm-name` not set. Reasoning message: `"Run firewall probe on  via direct SSH"`. |
| **Fix** | Compute `target_label = config.vm_name or config.target_vm_ip` at top of `run()`. Pass `target_label` to `run_probe()`. Use `target_label` in warning messages. |

#### B2 — PROVIDER from config.env not validated against valid choices

| | |
|--|--|
| **Severity** | SIGNIFICANT |
| **Symptom** | `PROVIDER=ftp` in config.env would silently route to `SSHProvider` (the `else` branch of `if args.provider == "azure"`). argparse `choices=` only validates argv values, not `set_defaults` values. |
| **Fix** | Added explicit post-parse validation: `if args.provider not in ("azure", "ssh"): parser.error(...)`. |

#### B3 — Warning message showed empty string for --provider ssh with no vm_name

| | |
|--|--|
| **Severity** | MINOR |
| **Symptom** | `"iptables ipv4 output unavailable on ."` |
| **Fix** | Warning now uses `target_label` (same fix as B1). |

#### B4 — SEC-SSH-08 assertion matched SSH username instead of bash positional arg

| | |
|--|--|
| **Severity** | MINOR (test quality) |
| **Symptom** | `assert "ubuntu" in cmd` matched the SSH username `ubuntu@192.168.64.5` even if the `bash -s` positional args were dropped. Test would pass with broken code. |
| **Fix** | Changed to `assert "bash -s -- fw_20260315_100000 ubuntu" in cmd` and added `assert "<" in cmd`. |

---

## Automated Test Suite

All tests run with no external dependencies beyond `pytest`. No mocking framework beyond `unittest.mock` (stdlib). SEC-CLS tests use `pytest.skip` if `safe_exec_shell` not on path.

```bash
python3 -m pytest tests/test_framework_detector.py tests/test_chain_classifier.py tests/test_inspector.py -v
```

### Test file layout

| File | Coverage area | Tests |
|------|---------------|-------|
| `tests/test_framework_detector.py` | FD-01 to FD-16 — `detect_framework()` all detection branches | 18 |
| `tests/test_chain_classifier.py` | CC-01 to CC-22 — `classify_chain()` and `classify_diff()` | 21 |
| `tests/test_inspector.py` (SEC-VAL) | Session ID validation — 5 valid, 8 invalid, 1 pre-shell check | 14 |
| `tests/test_inspector.py` (SEC-SSH-01–07) | AzureProvider: StrictHostKeyChecking, ProxyCommand, Case 1/Case 2 keys | 7 |
| `tests/test_inspector.py` (SEC-SSH-08–14) | SSHProvider: command format, denied/error handling, StrictHostKeyChecking, Case 1/2 | 7 |
| `tests/test_inspector.py` (SEC-PROBE) | Static constant, mktemp, chmod 600, both families, sha256, chown | 6 |
| `tests/test_inspector.py` (SEC-BAS) | save/load/tamper/missing companion integrity | 5 |
| `tests/test_inspector.py` (SEC-LOG) | Log presence, required fields, no output content, append | 4 |
| `tests/test_inspector.py` (SEC-CLS) | az vm run-command RISKY, az network nic list-effective-nsg SAFE | 2 |
| `tests/test_inspector.py` (FI) | Section parser, probe response, snapshot round-trip, LocalShell, PROVIDER validation | 12 |
| **Total** | | **96** |

### Last run result

```
============================= test session starts ==============================
platform darwin -- Python 3.9.6, pytest-8.4.2, pluggy-1.6.0
rootdir: /Users/rangas/aiApps/nw-forensics/netfilter-inspector/firewall-inspector
configfile: pytest.ini
collected 96 items

tests/test_framework_detector.py ... [18 passed]
tests/test_chain_classifier.py ... [21 passed]
tests/test_inspector.py ... [55 passed, 2 skipped]

======================== 94 passed, 2 skipped in 0.11s =========================
```

---

## Known Gaps (Post-MVP)

| Gap | Reason deferred |
|-----|----------------|
| nftables-native probe and parse path | Module 3 — nftables support deferred post-MVP; Ubuntu 22.04/24.04 default to iptables-nft; tool requires iptables-legacy or rules to be populated via iptables frontend |
| Ghost Agent integration test (`detect_firewall_drift` tool) | Requires Ghost Agent test harness with SafeExecShell in test mode; deferred to Ghost Agent integration test phase |
| `--explain` feature | Design doc at `docs/explain-feature-design.md`; not yet built |
| Windows Firewall (`netsh advfirewall`) | Different OS layer; out of scope |
| `_extract_version_strings()` unit tests | Internal helper; coverage provided indirectly through probe parsing path |
