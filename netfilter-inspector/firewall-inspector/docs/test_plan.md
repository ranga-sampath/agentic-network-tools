# firewall-inspector — Test Plan

*Modules: `firewall_inspector.py`, `providers.py`, `framework_detector.py`, `chain_classifier.py`*
*Status: 94 passed, 2 skipped of 96 collected — MVP 2026-03-15*

---

## 1. Scope

**In scope:**

| Component | What is tested |
|-----------|---------------|
| `firewall_inspector.py` | Probe output parsing, snapshot save/load, baseline integrity, section splitting, Azure probe response envelope handling |
| `providers.py` — `LocalShell` | Command execution, audit log format, append-only behaviour, no-log-when-no-audit-dir |
| `providers.py` — `SSHProvider` | SSH command construction, Case 1/Case 2 topology, strict host key checking, HITL deny handling |
| `providers.py` — `AzureProvider` | Command classification (SAFE vs. RISKY) |
| `framework_detector.py` | Detection logic for all framework outcomes, confidence levels, `nft_available` flag, warnings |
| `chain_classifier.py` | Chain tier classification, drift suppression by tier, summary count invariant, immutability |

**Out of scope:**

| Area | Reason |
|------|--------|
| Ghost Agent / `SafeExecShell` end-to-end | HITL decision loop requires live Ghost Agent integration; not a unit test concern |
| `AzureProvider.run_probe()` live path | Requires live `az` CLI and a running VM — 2 tests currently skipped |
| `--family both` orchestrator flow | Covered by Multipass end-to-end validation; not by unit tests |
| `--explain` feature | Not yet built (post-MVP) |

---

## 2. Test Environment

- Python 3.9+
- `pytest` installed (`pip install pytest`)
- No network access required — all tests use mocks or string constants
- Fixture files not required — inspector tests generate all input inline
- Two tests require `az` CLI + live VM: skipped automatically when unavailable

```bash
cd netfilter-inspector/firewall-inspector
python3 -m pytest                        # 96 collected, 94 passed, 2 skipped
python3 -m pytest tests/test_inspector.py
python3 -m pytest tests/test_framework_detector.py
python3 -m pytest tests/test_chain_classifier.py
python3 -m pytest -v --tb=short          # verbose with short tracebacks
```

---

## 3. Test Categories and Coverage

### 3.1 Session ID Validation (`test_inspector.py` — SEC-VAL)

Session ID is the only field validated at startup; shell execution must not begin until it passes.

| Test ID | Test function | Input | Expected outcome |
|---------|--------------|-------|-----------------|
| SEC-VAL-01 | `test_sec_val_01_valid_ids_accepted` | `"fw_20260315"`, `"my-session"`, `"A1"` | Accepted without error |
| SEC-VAL-02 | `test_sec_val_02_invalid_ids_rejected` | Space, `/`, `;`, `>`, `<`, backtick, `$()`, >64 chars | `ValueError` raised |
| SEC-VAL-08 | `test_sec_val_08_validation_fires_before_shell_execute` | Invalid session ID supplied | Validation raises before any `shell.execute()` call; zero shell calls recorded |

**Key invariant:** An invalid session ID must never reach the shell execution layer. SEC-VAL-08 verifies this structurally.

---

### 3.2 SSH Security (`test_inspector.py` — SEC-SSH)

SSH command construction must enforce strict host key checking on every command, and must implement the correct two-hop topology when a bastion is configured.

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| SEC-SSH-01 | `test_sec_ssh_01_scp_contains_strict_host_key_checking` | SCP retrieve command | `-o StrictHostKeyChecking=yes` present |
| SEC-SSH-02 | `test_sec_ssh_02_scp_contains_proxy_command` | Case 2 (bastion configured) | `-o ProxyCommand=` present in SCP |
| SEC-SSH-03 | `test_sec_ssh_03_cleanup_contains_strict_host_key_checking` | Remote cleanup SSH command | `-o StrictHostKeyChecking=yes` present |
| SEC-SSH-04 | `test_sec_ssh_04_no_command_uses_strict_host_checking_no` | All generated commands | No command contains `StrictHostKeyChecking=no` |
| SEC-SSH-05 | `test_sec_ssh_05_case1_no_proxy_command` | Case 1: no `BASTION_PUBLIC_IP` | ProxyCommand absent from SSH command |
| SEC-SSH-06 | `test_sec_ssh_06_case2b_different_keys_in_proxy_command` | Case 2b: separate bastion and VM keys | Both key paths present in command |
| SEC-SSH-07 | `test_sec_ssh_07_case2a_same_key_defaults` | Case 2a: single key for both hops | Command uses that key for both hops |
| SEC-SSH-08 | `test_sec_ssh_08_ssh_provider_run_probe_command_format` | `SSHProvider.run_probe()` | Command structure matches expected SSH + probe invocation |
| SEC-SSH-09 | `test_sec_ssh_09_ssh_provider_run_probe_denied_raises` | Shell returns `status: "denied"` | `RuntimeError` raised; probe not executed |
| SEC-SSH-10 | `test_sec_ssh_10_ssh_provider_run_probe_nonzero_exit_raises` | Shell returns non-zero exit | `RuntimeError` raised |
| SEC-SSH-11 | `test_sec_ssh_11_ssh_provider_retrieve_uses_strict_host_key_checking` | `SSHProvider.retrieve_probe_output()` SCP | `StrictHostKeyChecking=yes` present |
| SEC-SSH-12 | `test_sec_ssh_12_ssh_provider_case1_no_proxy_command` | `SSHProvider` Case 1 | No ProxyCommand |
| SEC-SSH-13 | `test_sec_ssh_13_ssh_provider_case2_proxy_command_present` | `SSHProvider` Case 2 | ProxyCommand present |
| SEC-SSH-14 | `test_sec_ssh_14_ssh_provider_run_probe_strict_host_key_checking` | `SSHProvider.run_probe()` | `StrictHostKeyChecking=yes` present |

**Key invariants:**
- `StrictHostKeyChecking=no` must never appear in any command — SEC-SSH-04 is a negative test covering all commands.
- HITL denial must abort the probe, not silently continue — SEC-SSH-09.

---

### 3.3 Probe Script Integrity (`test_inspector.py` — SEC-PROBE)

The probe script is a static constant. Any runtime assembly from user-controlled inputs would be a shell injection surface.

| Test ID | Test function | What is verified | Expected outcome |
|---------|--------------|-----------------|-----------------|
| SEC-PROBE-01 | `test_sec_probe_01_probe_script_is_string_constant` | `_PROBE_SCRIPT` type | `isinstance(_PROBE_SCRIPT, str)` — not assembled at runtime |
| SEC-PROBE-02 | `test_sec_probe_02_probe_script_contains_mktemp` | Temp file creation | Script contains `mktemp` |
| SEC-PROBE-03 | `test_sec_probe_03_probe_script_contains_chmod_600` | Output file permissions | Script contains `chmod 600` |
| SEC-PROBE-04 | `test_sec_probe_04_probe_always_collects_both_families` | IPv4 and IPv6 iptables sections always captured | Script contains both `iptables-save` and `ip6tables-save` invocations regardless of `FAMILY` config. Note: this test covers iptables sections only — nftables section presence is verified by FW-NF08. |
| SEC-PROBE-05 | `test_sec_probe_05_probe_sha256_matches_script` | Script content stability | SHA-256 of `_PROBE_SCRIPT` matches expected hash — detects accidental modification. **Note:** The nftables section was added to the probe script; the expected hash constant in this test must be recalculated whenever the probe script is finalized. See Known Gaps — SEC-PROBE-05 hash update. |
| SEC-PROBE-06 | `test_sec_probe_06_probe_chowns_output_to_ssh_user` | Output file ownership | Script contains `chown $2` (SSH user passed as positional arg, not interpolated) |

**Key invariant:** SEC-PROBE-05 is a content-stability guard. If the probe script is modified, this test fails explicitly — preventing silent changes to a security-sensitive constant.

---

### 3.4 Baseline Integrity (`test_inspector.py` — SEC-BAS)

Snapshot lifecycle: save and load form a full cycle. Integrity is enforced via a SHA-256 companion file; tampering must be detected.

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| SEC-BAS-01 | `test_sec_bas_01_save_creates_sha256_companion` | `save_snapshot()` called | `{session_id}_snapshot.json.sha256` created alongside `_snapshot.json` |
| SEC-BAS-02 | `test_sec_bas_02_sha256_file_matches_snapshot` | After `save_snapshot()` | SHA-256 in companion file matches `hashlib.sha256(snapshot_bytes).hexdigest()` |
| SEC-BAS-03 | `test_sec_bas_03_tampered_snapshot_raises_integrity_error` | Snapshot file modified after save | `load_baseline()` raises `IntegrityError` |
| SEC-BAS-04 | `test_sec_bas_04_unmodified_baseline_loads_correctly` | Round-trip: save then load | Loaded dict equals saved dict |
| SEC-BAS-05 | `test_sec_bas_05_missing_sha256_companion_raises_integrity_error` | `.sha256` file deleted | `load_baseline()` raises `IntegrityError` |

**Lifecycle covered:** save → companion created → load (clean) → load (tampered) → load (companion missing). Non-create paths are fully tested.

---

### 3.5 Audit Logging (`test_inspector.py` — SEC-LOG)

`LocalShell` is the designated audit writer. The log must be append-only; output text must not be recorded.

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| SEC-LOG-01 | `test_sec_log_01_two_calls_produce_two_log_entries` | Two `LocalShell.execute()` calls | Log file contains exactly 2 lines |
| SEC-LOG-02 | `test_sec_log_02_each_entry_has_required_fields` | Log entry content | Each entry is valid JSON with `timestamp`, `command`, `exit_code` fields |
| SEC-LOG-03 | `test_sec_log_03_log_does_not_contain_output_text` | Command produces output | Command stdout/stderr absent from log file |
| SEC-LOG-04 | `test_sec_log_04_multiple_calls_append_to_log` | Sequential calls | Earlier entries remain intact; file grows by appending |

**Key invariant:** SEC-LOG-03 tests that the audit log is a command record, not an output capture. Storing output would log sensitive iptables rule content.

---

### 3.6 Command Classification (`test_inspector.py` — SEC-CLS)

Azure commands are classified as SAFE (read-only, no HITL gate) or RISKY (mutative, HITL gate fires). Misclassification in either direction is a defect.

| Test ID | Test function | Command | Expected classification |
|---------|--------------|---------|------------------------|
| SEC-CLS-01 | `test_sec_cls_01_az_vm_run_command_invoke_is_risky` | `az vm run-command invoke` | RISKY — executes arbitrary commands on the VM |
| SEC-CLS-02 | `test_sec_cls_02_az_nic_list_effective_nsg_is_safe` | `az network nic list-effective-nsg` | SAFE — read-only effective NSG query |

**Gap note:** Only 2 classification tests exist. A complete classification test suite would cover: all probe delivery commands, all SCP retrieval commands, NSG rule creation (RISKY), iptables-save invocations (SAFE). Expand post-MVP.

---

### 3.7 Functional Inspector Tests (`test_inspector.py` — FI)

Core inspector pipeline functions: probe output parsing, snapshot I/O, shell execution contract, provider configuration.

| Test ID | Test function | What is verified | Expected outcome |
|---------|--------------|-----------------|-----------------|
| FI-01 | `test_fi01_parse_sections_basic` | `_split_probe_output()` | Probe output split into named sections by `###SECTION###` markers |
| FI-02 | `test_fi02_section_available_returns_false_for_unavailable` | `section_available()` — UNAVAILABLE marker | `False` returned for `###UNAVAILABLE###` content |
| FI-03 | `test_fi03_section_available_returns_true_for_content` | `section_available()` — real content | `True` returned for non-empty, non-UNAVAILABLE section |
| FI-04 | `test_fi04_parse_probe_response_json_envelope` | `_parse_probe_response()` Azure JSON | JSON envelope unwrapped; inner text extracted at expected path |
| FI-05 | `test_fi05_parse_probe_response_raw_fallback` | `_parse_probe_response()` non-JSON | Response passed through as-is without modification |
| FI-06 | `test_fi06_parse_probe_response_missing_path_raises` | `_parse_probe_response()` missing key | `KeyError` raised with actionable message |
| FI-07 | `test_fi07_snapshot_round_trip` | `save_snapshot()` + `load_baseline()` | Dict survives round-trip: saved == loaded |
| FI-08 | `test_fi08_load_missing_snapshot_raises_file_not_found` | `load_baseline()` — no file | `FileNotFoundError` raised |
| FI-09 | `test_fi09_local_shell_executes_command` | `LocalShell.execute()` happy path | Returns `{"status": "success", "output": ..., "exit_code": 0}` |
| FI-10 | `test_fi10_local_shell_returns_error_on_nonzero` | `LocalShell.execute()` non-zero exit | Returns `{"status": "error", "exit_code": N}` |
| FI-11 | `test_fi11_local_shell_no_log_when_no_audit_dir` | `LocalShell` without `audit_dir` | No log file created; execution proceeds normally |
| FI-12 | `test_fi12_invalid_provider_from_config_is_rejected` | Unknown `PROVIDER` value in config | `ValueError` raised before any shell command |

---

### 3.8 Framework Detector (`test_framework_detector.py` — FD)

`detect_framework()` must correctly classify the active netfilter stack from version strings. The `confidence` field signals when detection fell back to a heuristic.

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| FD-01 | `test_fd01_ua_detects_nft` | `update-alternatives` → `iptables-nft` path | `framework: "iptables-nft"` |
| FD-02 | `test_fd02_ua_detects_legacy` | `update-alternatives` → `iptables-legacy` path | `framework: "iptables-legacy"` |
| FD-03 | `test_fd03_ua_legacy_cmd_uses_legacy_save_when_available` | UA=legacy + `iptables-legacy` binary present | `iptables_cmd: "iptables-legacy-save"` |
| FD-04 | `test_fd04_ua_legacy_cmd_falls_back_to_iptables_save_when_no_legacy_binary` | UA=legacy + no legacy binary | `iptables_cmd: "iptables-save"` |
| FD-05 | `test_fd05_version_tag_nft` | `iptables --version` contains `"nft"` | `framework: "iptables-nft"` |
| FD-06 | `test_fd06_version_tag_legacy` | `iptables --version` contains `"legacy"` | `framework: "iptables-legacy"` |
| FD-07 | `test_fd07_version_tag_nft_case_insensitive` | Version string `"NFT"` (uppercase) | `framework: "iptables-nft"` |
| FD-08 | `test_fd08_version_tag_legacy_case_insensitive` | Version string `"LEGACY"` | `framework: "iptables-legacy"` |
| FD-09 | `test_fd09_old_version_no_tag_with_legacy_binary` | Old iptables (no nft/legacy tag) + legacy binary present | `framework: "iptables-legacy"` |
| FD-10 | `test_fd10_old_version_no_tag_without_legacy_binary` | Old iptables + no legacy binary | `framework: "unknown"`, `confidence: "low"` |
| FD-11 | `test_fd11_legacy_binary_only` | Only `iptables-legacy --version` available | `framework: "iptables-legacy"` |
| FD-12 | `test_fd12_nft_only_returns_unknown` | Only `nft --version` present, no iptables | `framework: "unknown"` — nftables-native is detected but not parseable |
| FD-13 | `test_fd13_all_empty_strings` | All version strings empty | `framework: "unknown"`, `confidence: "low"` |
| FD-14 | `test_fd14_missing_keys` | Some keys absent from input dict | No `KeyError`; graceful degradation to `unknown` |
| FD-15 | `test_fd15_nft_available_true_when_nft_present` | `nft --version` present | `nft_available: true` |
| FD-15b | `test_fd15b_nft_available_false_when_no_nft` | No `nft --version` | `nft_available: false` |
| FD-16 | `test_fd16_no_warnings_for_clean_high_confidence` | Unambiguous detection | `warnings: []` |
| FD-16b | `test_fd16b_warnings_for_ambiguous_detection` | Ambiguous version strings | `warnings` non-empty |

**Default-deny behavior tested:** FD-10, FD-13, FD-14 all verify that unknown or missing inputs produce `"unknown"` with `confidence: "low"` — not a silent default to a potentially wrong framework.

---

### 3.9 Chain Classifier (`test_chain_classifier.py` — CC)

`classify_drift()` suppresses ephemeral chains (Kubernetes pod routes, short-lived service entries) from drift reports. Structural and user-defined chains must not be suppressed. The input dict must not be mutated.

#### Chain tier classification

| Test ID | Test function | Chain | Expected tier |
|---------|--------------|-------|---------------|
| CC-01 | `test_cc01_kube_sep_is_ephemeral` | `KUBE-SEP-*` | `ephemeral` |
| CC-02 | `test_cc02_kube_svc_is_ephemeral` | `KUBE-SVC-*` | `ephemeral` |
| CC-03 | `test_cc03_kube_fw_is_ephemeral` | `KUBE-FW-*` | `ephemeral` |
| CC-04 | `test_cc04_docker_is_structural` | `DOCKER*` | `structural` |
| CC-05 | `test_cc05_f2b_chain_is_structural` | `f2b-*` | `structural` |
| CC-06 | `test_cc06_ufw_chain_is_structural` | `ufw-*` | `structural` |
| CC-07 | `test_cc07_ephemeral_wins_over_structural_if_prefix_matches_both` | Chain matching both patterns | `ephemeral` wins |
| CC-08 | `test_cc08_input_is_user_defined` | Built-in chain `INPUT` | `user_defined` |
| CC-09 | `test_cc09_custom_chain_is_user_defined` | Unknown chain name | `user_defined` |

#### Suppression behavior

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| CC-10 | `test_cc10_ephemeral_rules_added_suppressed` | Rules added to ephemeral chain | Absent from output `rules_added` |
| CC-11 | `test_cc11_ephemeral_rules_removed_suppressed` | Rules removed from ephemeral chain | Absent from output `rules_removed` |
| CC-12 | `test_cc12_ephemeral_rules_repositioned_suppressed` | Rules repositioned in ephemeral chain | Absent from output `rules_repositioned` |
| CC-13 | `test_cc13_mixed_diff_only_ephemeral_suppressed` | Mixed ephemeral + structural changes | Only ephemeral entries suppressed; structural entries retained |
| CC-15 | `test_cc15_user_defined_rules_not_suppressed` | Rules changed in `user_defined` chain | Retained in output |
| CC-16 | `test_cc16_structural_rules_not_suppressed` | Rules changed in `structural` chain | Retained in output |
| CC-21 | `test_cc21_policy_changes_not_suppressed_for_ephemeral` | Default policy change on ephemeral chain | Retained — policy changes are never suppressed |

#### Invariants and output correctness

| Test ID | Test function | What is verified | Expected outcome |
|---------|--------------|-----------------|-----------------|
| CC-17 | `test_cc17_summary_counts_match_filtered_lists` | `summary[k] == len(changes[k])` after suppression | True for all 8 keys |
| CC-18 | `test_cc18_input_dict_not_mutated` | Input diff dict after `classify_drift()` | Input dict identical before and after call |
| CC-19 | `test_cc19_chain_classifications_key_present` | Output structure | `chain_classifications` key always present |
| CC-20 | `test_cc20_ephemeral_summary_counts` | Suppressed count tracking | Suppressed counts recorded in output for caller visibility |
| CC-22 | `test_cc22_new_pattern_added_without_code_change` | Pattern extensibility | New classification pattern can be added via data, not code |

**Key invariant — CC-18:** The input diff dict must not be mutated. The classifier receives a diff from `diff_rulesets()` and must not modify it in-place — callers downstream of both functions depend on the original dict being stable.

---

### 3.10 nftables Integration (`test_inspector.py` — FW-NF)

Verify that the parse and diff branches correctly route nftables input through `parse_nft_ruleset()` and `nft_diff_rulesets()`, and that framework mismatches are rejected before any diff is attempted.

**Mock boundary for all FW-NF tests:** `detect_framework()` is mocked to return a controlled `{framework, confidence, parse_warnings}` dict. It is not called live. This is required because `detect_framework()` returns `"unknown"` (not `"nftables"`) for a probe section containing only `nft --version` output (see FD-12); a live call would never produce `framework="nftables"` without a full real probe section. All other module boundaries (`parse_nft_ruleset`, `nft_diff_rulesets`, `diff_rulesets`, `classify_diff`) are also mocked to control call sequencing and avoid parser-level fixture requirements for integration boundary tests.

**Fixture strategy for FW-NF04/FW-NF05:** These tests verify call sequencing across `firewall_inspector.py`, `nftables_diff.py`, and `chain_classifier.py`. They use synthetic dicts conforming to the minimal snapshot schema (`{"rulesets": {"nft": {}}}` for nftables; `{"rulesets": {"ipv4": {}}}` for iptables) rather than real `parse_nft_ruleset()` output. The mocked diff functions return a minimal `{"drift_detected": False, "has_critical_changes": False, "summary": {}, "changes": {}}` dict. Test environment remains "no network access required."

| Test ID | Test function | Scenario | Expected outcome |
|---------|--------------|----------|-----------------|
| FW-NF01 | `test_fw_nf01_nftables_section_parsed_when_framework_nftables` | Probe output with `###SECTION:nftables###` containing valid JSON; `detect_framework()` mocked to return `framework="nftables"` | `parse_nft_ruleset()` called once; `parsed["nft"]` populated; `parsed["ipv4"]` and `parsed["ipv6"]` absent |
| FW-NF02 | `test_fw_nf02_nftables_snapshot_family_field_is_nft` | nftables parse branch + `--is-baseline`; `detect_framework()` mocked | Snapshot `rulesets` has `"nft"` key; `"ipv4"` and `"ipv6"` absent; `snapshot["family"] == "nft"` |
| FW-NF03 | `test_fw_nf03_iptables_framework_does_not_invoke_nft_parser` | Probe output with iptables sections; `detect_framework()` mocked to return `framework="iptables-legacy"` | `parse_nft_ruleset()` call count == 0; `parsed["ipv4"]` and/or `parsed["ipv6"]` populated |
| FW-NF04 | `test_fw_nf04_nftables_diff_uses_nft_diff_rulesets` | nftables baseline (synthetic: `rulesets={"nft":{}}`) + nftables current; `detect_framework()` mocked; `nft_diff_rulesets` and `classify_diff` both mocked | `nft_diff_rulesets()` call count == 1; `classify_diff()` call count == 0 |
| FW-NF05 | `test_fw_nf05_iptables_diff_uses_diff_rulesets_and_classify_diff` | iptables baseline (synthetic: `rulesets={"ipv4":{}}`) + iptables current; `detect_framework()` mocked; `diff_rulesets` and `classify_diff` both mocked | `diff_rulesets()` call count == 1; `classify_diff()` call count == 1; `nft_diff_rulesets()` call count == 0 |
| FW-NF06 | `test_fw_nf06_framework_mismatch_raises_value_error` | Baseline snapshot has `rulesets={"ipv4":{}}` (no `"nft"` key); current parsed has `"nft"` key; `detect_framework()` mocked to return `"nftables"` | `ValueError` raised with "Framework mismatch" in message; `nft_diff_rulesets()` call count == 0; no drift artifact written |
| FW-NF07 | `test_fw_nf07_nftables_unavailable_section_warns` | `nftables` probe section contains `###UNAVAILABLE###`; `detect_framework()` mocked to return `"nftables"` | `parsed["nft"] == None`; warning in `config.parse_warnings`; `parse_nft_ruleset()` call count == 0; no exception |
| FW-NF07b | `test_fw_nf07b_nftables_empty_section_treated_as_unavailable` | `nftables` probe section is empty string (section key absent); `detect_framework()` mocked to return `"nftables"` | Same as FW-NF07: `parsed["nft"] == None`; warning emitted; `parse_nft_ruleset()` call count == 0 |
| FW-NF08 | `test_fw_nf08_probe_script_contains_nftables_section` | `_PROBE_SCRIPT` string constant | Script contains `###SECTION:nftables###` and `nft --json list ruleset` |

**Key invariants:**
- **FW-NF04** explicitly asserts `classify_diff()` call count == 0. This is the critical separation invariant — `classify_diff()` on nftables output would corrupt the drift report with spurious iptables chain-pattern annotations.
- **FW-NF06** verifies the mismatch guard fires before any diff engine is called, not after — `nft_diff_rulesets()` call count == 0 is the assertion.
- **FW-NF04/FW-NF05** use mock.patch on all three diff/classify functions simultaneously so the call count of each can be independently asserted.
- Implementation location: `tests/test_inspector.py`, alongside existing inspector tests.

---

## 4. Coverage Matrix

| Requirement area | Tests |
|-----------------|-------|
| Session ID validation — valid inputs accepted | SEC-VAL-01 |
| Session ID validation — invalid inputs rejected | SEC-VAL-02 |
| Validation fires before shell execution | SEC-VAL-08 |
| SSH strict host key checking — all commands | SEC-SSH-01, 03, 04, 11, 14 |
| SSH Case 1 (direct) vs Case 2 (bastion) topology | SEC-SSH-05, 06, 07, 12, 13 |
| HITL denial aborts probe | SEC-SSH-09 |
| Non-zero probe exit raises error | SEC-SSH-10 |
| Probe script is a static constant | SEC-PROBE-01 |
| Probe script secure temp file handling | SEC-PROBE-02, 03 |
| Probe collects both IP families | SEC-PROBE-04 |
| Probe script content stability | SEC-PROBE-05 |
| Probe ownership via positional arg | SEC-PROBE-06 |
| Snapshot save creates SHA-256 companion | SEC-BAS-01, 02 |
| Tampered snapshot rejected | SEC-BAS-03 |
| Clean snapshot round-trip | SEC-BAS-04 |
| Missing companion file rejected | SEC-BAS-05 |
| Audit log format and fields | SEC-LOG-01, 02 |
| Audit log does not record output | SEC-LOG-03 |
| Audit log is append-only | SEC-LOG-04 |
| RISKY command classified correctly | SEC-CLS-01 |
| SAFE command classified correctly | SEC-CLS-02 |
| Probe output section splitting | FI-01, 02, 03 |
| Azure JSON envelope unwrapping | FI-04, 05, 06 |
| Snapshot lifecycle (save / load / missing) | FI-07, 08 |
| `LocalShell` execution contract | FI-09, 10, 11 |
| Invalid provider rejected | FI-12 |
| Framework detection — all outcomes | FD-01 through FD-14 |
| `nft_available` flag | FD-15, 15b |
| Detection confidence and warnings | FD-16, 16b |
| Chain tier classification | CC-01 through CC-09 |
| Ephemeral drift suppression | CC-10, 11, 12, 13 |
| Structural / user-defined not suppressed | CC-15, 16 |
| Policy changes never suppressed | CC-21 |
| Summary count invariant after suppression | CC-17 |
| Input immutability | CC-18 |
| Output schema completeness | CC-19, 20 |
| Pattern extensibility | CC-22 |
| nftables parse branch (nft key populated, iptables keys absent) | FW-NF01, FW-NF02 |
| iptables parse branch not affected by nftables addition | FW-NF03 |
| nftables diff uses nft_diff_rulesets; classify_diff not called | FW-NF04 |
| iptables diff path unchanged | FW-NF05 |
| Framework mismatch guard raises ValueError | FW-NF06 |
| nftables section unavailable handled gracefully | FW-NF07 |
| Probe script contains nftables section | FW-NF08 |

---

## 5. Known Gaps

| Gap | Impact | When to close |
|-----|--------|---------------|
| FW-NF01 through FW-NF08b not yet implemented | nftables integration path is documented but not unit-tested | Implement in `tests/test_inspector.py` alongside nftables Multipass E2E validation |
| SEC-PROBE-05 expected SHA-256 hash stale | The nftables section was added to `_PROBE_SCRIPT`; the expected hash constant in the test must be recalculated | Recalculate with `python3 -c "import hashlib; from firewall_inspector import _PROBE_SCRIPT; print(hashlib.sha256(_PROBE_SCRIPT.encode()).hexdigest())"` and update the test before running SEC-PROBE-05 |
| Command classification covers only 2 commands | Misclassification of additional Azure commands would be undetected | Add tests for all probe delivery, SCP retrieval, and NSG mutation commands |
| `AzureProvider.run_probe()` not unit-testable | Two tests skipped; live Azure path untested in CI | Add integration test environment with az CLI + test VM |
| `SafeExecShell` HITL gate full decision loop | HITL approval/deny/timeout behavior is not tested end-to-end | Integration test with Ghost Agent when SafeExecShell is available |
| `--family both` orchestrator path | Two-family parse flow is validated on Multipass only; not in pytest | Add unit test with dual parse mock after Multipass validation |
| nftables Multipass E2E | nftables baseline + drift scenarios not validated on a live VM | Create Multipass `fw-nftables` VM (Ubuntu 22.04 native nftables) and run E2E suite |
