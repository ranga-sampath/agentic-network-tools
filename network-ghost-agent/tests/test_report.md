# Test Report — Unified Ghost Agent CLI

## Run Metadata

| Field | Value |
|-------|-------|
| **Last run** | 2026-03-18 |
| **Command** | `uv run --python 3.12 python -m pytest tests/ -v --tb=short` |
| **Python** | 3.12.12 (system default 3.9.6 is incompatible — `X \| Y` union syntax requires 3.10+) |
| **Result** | **106 passed, 3 skipped, 2 xfailed** in 0.13s |

---

## Summary by Section

| Section | Total | Passed | Skipped | xFailed |
|---------|-------|--------|---------|---------|
| S — Session State | 12 | 12 | 0 | 0 |
| H — Startup / Handshake | 15 | 15 | 0 | 0 |
| D — Tool Dispatch | 13 | 13 | 0 | 0 |
| M — Denial State Machine | 11 | 11 | 0 | 0 |
| L — Loop Control | 8 | 7 | 0 | 1 |
| R — RCA Generation | 15 | 15 | 0 | 0 |
| E — Error Recovery | 9 | 8 | 0 | 1 |
| I — Integration / E2E | 7 | 4 | 3 | 0 |
| T — Static / Structural | 5 | 5 | 0 | 0 |
| FI — Firewall Inspector Handler | 13 | 13 | 0 | 0 |
| **Total** | **108** | **106** | **3** | **2** |

---

## Skipped Tests (3)

| ID | Test | Justification |
|----|------|--------------|
| I5 | `test_I5_real_azure_capture` | Requires live Azure credentials and Network Watcher resources; classified SKIP in test plan by design. |
| I6 | `test_I6_real_gemini_api` | Requires a live Gemini API key and active quota; classified SKIP in test plan by design. |
| I7 | `test_I7_concurrent_sessions` | Concurrent session safety requires multi-process infrastructure; out of scope for unit test suite. |

---

## xFailed Tests (2)

| ID | Test | Priority | Justification |
|----|------|----------|--------------|
| L8 | `test_L8_evidence_conflicts_recorded` | GOOD | `evidence_conflicts` conflict-detection block is specified in design §4 but not yet implemented in `_run_loop`. |
| E6 | `test_E6_timeout_result_injects_meta_timeout` | GOOD | `_dispatch_tool` does not yet inject `_meta.timeout = true` for shell timeout results; deferred as non-blocking GOOD priority item. |

---

## Netfilter Inspector Integration

This section covers all testing done to verify the `detect_config_drift` tool chain — from the low-level firewall parsing libraries up to the live Ghost Agent conversational session. Testing was structured in four layers, each building on the layer below it.

---

### Test Strategy — Layered Approach

**Layer 1 — Parse & Diff (unit, no infrastructure)**
Verified correctness of `iptables_parser.py` and `iptables_diff.py` in complete isolation. All inputs are text strings or synthetic dicts. No VMs, no SSH, no mocking infrastructure. This layer validates the core data contracts — field shapes, edge cases, critical-change detection — that every layer above depends on.

**Layer 2 — Inspector pipeline (unit + Multipass VM E2E)**
Verified `firewall_inspector.py`, `framework_detector.py`, and `chain_classifier.py` at two sub-levels. First, a pure unit suite covering security properties (session ID validation, SSH hardening, baseline integrity, probe script constants) and functional behaviour (section parsing, snapshot round-trip, provider routing). Second, real E2E runs against two Multipass VMs — `fw-legacy` (iptables-legacy) and `fw-nftables` (nftables-native) — executing the full probe → parse → diff → artifact pipeline over actual SSH. Also includes FW-NF unit tests that verify the nftables code path inside the inspector (framework detection, parser/diff routing, mismatch guard, empty-section guard) without requiring a live VM.

**Layer 3 — Handler integration (mock-based, no VM)**
Verified `_run_firewall_inspector_handler()` in the Ghost Agent — the function that bridges `detect_config_drift` tool calls to the firewall inspector subprocess and shapes the result for the Brain. `subprocess.run` is mocked with a side-effect that writes a synthetic drift JSON to `audit_dir`, allowing the handler's data-processing logic and Brain-facing result shape to be tested independently of VM infrastructure. Covers nftables result fields, iptables result fields, field-name asymmetry enforcement, error family handling, and mixed-family routing.

**Layer 4 — Live Brain E2E (real Gemini + real VM)**
Verified the complete conversational loop with no mocks on the critical path — real `gemini-2.0-flash` Brain, real `_run_firewall_inspector_handler`, real `fw-nftables` Multipass VM over SSH. The scenario runs two Ghost Agent turns: a baseline capture (empty chain) followed by a DROP rule injection and a compare turn. Checks that the Brain invokes the tool correctly in both modes, that the drift artifact shows `drift_detected=True` with rule-level detail, and that the Brain's analysis text uses nftables vocabulary and identifies the change as a security concern.

---

### Layer 1 — Results: Parse & Diff Engine

**Test files:** `netfilter-inspector/iptables-parser/tests/`
**Last run:** 2026-03-13 — `python3 -m pytest tests/ -v` → **86 passed in 0.11s**

| Category | Tests | Pass | Fail |
|----------|-------|------|------|
| Fixture-level (AC-F01–F10) | 10 | 10 | 0 |
| Field accuracy (AC-FA01–FA11) | 12 | 12 | 0 |
| Edge cases (AC-EC01–EC10) | 11 | 11 | 0 |
| Diagnostics (AC-DI01–DI05) | 8 | 8 | 0 |
| Error handling (AC-EH01–EH06) | 7 | 7 | 0 |
| Non-functional (AC-NF01–NF06) | 6 | 6 | 0 |
| Diff engine (AC-D01–D25 + post-review) | 29 | 29 | 0 |
| **Layer 1 Total** | **86** | **86** | **0** |

4 bugs found and fixed in `iptables_parser.py` during test development. 1 bug found and fixed in `iptables_diff.py` during code review (`has_critical_changes` blind spot for `chains_added`/`chains_removed`).

Full detail: `netfilter-inspector/iptables-parser/tests/test_report_iptables_parser.md`

---

### Layer 2 — Results: Inspector Pipeline

**Test files:** `netfilter-inspector/firewall-inspector/tests/`
**Last run (unit suite):** 2026-03-18 — `uv run --python 3.12 pytest firewall-inspector/ -v` → **141 passed, 2 skipped in 0.11s**

| Category | Tests | Pass | Skip |
|----------|-------|------|------|
| Framework detector (FD-01–FD-16) | 18 | 18 | 0 |
| Chain classifier (CC-01–CC-22) | 21 | 21 | 0 |
| Security — session_id validation (SEC-VAL-01–10) | 16 | 16 | 0 |
| Security — SSH/SCP hardening SSHProvider (SEC-SSH-01–07, 08–14) | 14 | 14 | 0 |
| Security — Azure control-plane hardening (SEC-AZ-01–07) | 7 | 7 | 0 |
| Security — probe script integrity (SEC-PROBE) | 6 | 6 | 0 |
| Security — baseline integrity (SEC-BAS) | 5 | 5 | 0 |
| Security — LocalShell audit log (SEC-LOG) | 4 | 4 | 0 |
| Security — SafeExecShell classification (SEC-CLS) | 2 | 0 | 2 |
| Functional (FI-01–FI-12) | 12 | 12 | 0 |
| nftables code path (FW-NF01–FW-NF08b) | 10 | 10 | 0 |
| Parse response + extract helpers | 26 | 26 | 0 |
| **Layer 2 unit total** | **141** | **141** | **2** |

The 2 skipped tests (SEC-CLS) require `safe_exec_shell` on the Python path; both pass in the Ghost Agent environment.

The 10 FW-NF tests cover: nftables framework detection routing, `parse_nft_ruleset` and `nft_diff_rulesets` called on the nft path, `classify_diff` never called on nftables data, framework mismatch guard, and empty nftables section guard.

**Multipass E2E — `fw-legacy` VM (iptables-legacy, 192.168.2.6)**

| # | Scenario | Result |
|---|----------|--------|
| E2E-1 | Rule removal detected | PASS |
| E2E-2 | Policy change detected | PASS |
| E2E-3 | No drift (all-clear) | PASS |
| E2E-4 | IPv6 drift detected | PASS |
| E2E-5 | Multiple rules simultaneously | PASS |
| E2E-6 | `--family ipv4` scoping | PASS |
| E2E-7 | Session ID override | PASS |

**Multipass E2E — `fw-nftables` VM (nftables-native, 192.168.2.7)**

| # | Scenario | Result |
|---|----------|--------|
| NF-E2E-1 | Baseline captured on nft-native VM | PASS |
| NF-E2E-2 | No-drift compare returns `drift_detected=False` | PASS |
| NF-E2E-3 | DROP rule addition detected, `has_critical_changes=True` | PASS |
| NF-E2E-4 | Rule removal detected | PASS |
| NF-E2E-5 | Policy change detected on base chain | PASS |
| NF-E2E-6 | Framework mismatch guard fires on iptables-vs-nft compare | PASS |
| NF-E2E-7 | Session ID override | PASS |

Full detail: `netfilter-inspector/firewall-inspector/tests/test_report_firewall_inspector.md`

---

### Layer 3 — Results: Ghost Agent Handler Integration

**Test file:** `network-ghost-agent/tests/test_firewall_inspector_handler.py`
**Last run:** 2026-03-16 — `python3 -m pytest tests/test_firewall_inspector_handler.py -v` → **13 passed in 0.05s**

| ID | What it verifies | Result |
|----|-----------------|--------|
| GA-NF01 | Baseline mode: `is_baseline=True` arg passed to inspector subprocess | PASS |
| GA-NF02 | nftables result: `verdict`/`src_addr` present; `target`/`source`/`raw_rule` absent | PASS |
| GA-NF03 | nftables result: top-level `drift_detected` and `has_critical_changes` flags correct | PASS |
| GA-NF04 | iptables result: `target`/`source`/`raw_rule` present; `verdict`/`src_addr` absent | PASS |
| GA-NF05 | iptables result: top-level flags correctly reflect iptables family | PASS |
| GA-NF06 | Compare mode: `compare_session_id` arg passed, baseline session ID forwarded | PASS |
| GA-NF07 | Subprocess non-zero exit raises `RuntimeError` with audit_dir context | PASS |
| GA-NF08 | Error family (malformed drift JSON) excluded from top-level flag computation | PASS |
| GA-NF09 | Mixed families (nft + ipv4) each routed independently; both result shapes present | PASS |
| GA-NF10 | No-drift compare: `drift_detected=False`, `has_critical_changes=False` | PASS |
| GA-NF11 | Audit dir created if absent before subprocess is invoked | PASS |
| GA-NF12 | `FW_SSH_USER` config override forwarded to subprocess correctly | PASS |
| GA-NF13 | Result dict contains `artifact` path pointing to drift file in audit_dir | PASS |

All 13 tests use a mocked `subprocess.run` whose side-effect writes a synthetic drift JSON to `audit_dir`. No SSH, no VM, no Gemini API required.

---

### Layer 4 — Results: Live Ghost Agent E2E

**Test file:** `network-ghost-agent/tests/test_layer4_live.py`
**Run:** 2026-03-16 — `.venv/bin/python3 tests/test_layer4_live.py`
**Infrastructure:** Real `gemini-2.0-flash` Brain, real `fw-nftables` Multipass VM (192.168.2.7)
**Result:** **7 / 7 checks passed**

**Setup:** Phase 1 creates an empty `fw_test` table and `input` chain on the VM before the baseline capture, so the chain exists in the baseline. Phase 2 adds `tcp dport 4444 drop` to the existing chain, making it appear as `rules_added=1` with full rule details (verdict, dst_port) visible to the Brain.

| ID | What it verifies | Result |
|----|-----------------|--------|
| L4-01 | Brain calls `detect_config_drift` with `is_baseline=True` for baseline intent | PASS |
| L4-02 | Baseline snapshot artifact (`*_snapshot.json`) created in audit dir | PASS |
| L4-03 | Brain calls `detect_config_drift` with `compare_session_id` for compare intent | PASS |
| L4-04 | Compare returns `drift_detected=True` in the `nft` family | PASS |
| L4-05 | Brain analysis uses nftables vocabulary (`drop`/`verdict`/`4444`) — not iptables-only terms | PASS |
| L4-06 | Brain flags the DROP rule as a security concern | PASS |
| L4-07 | Pre-completion checklist fired — RCA has substantive `root_cause_summary` | PASS |

**Known limitation surfaced during Layer 4 testing:** When a DROP rule is introduced as part of a brand-new table+chain (the chain did not exist in the baseline), the nftables diff engine classifies the event as `chains_added` rather than `rules_added`. The Brain receives `rule_count=1` but cannot see the specific `verdict` or `dst_port`. `has_critical_changes` remains `false` in this case. Documented in `network-ghost-agent/docs/design.md` (Tool 7 known limitation) and `netfilter-inspector/firewall-inspector/docs/design.md` (edge cases table). Workaround applied in the test: chain created before baseline capture so the rule injection registers as `rules_added`.
