# Test Report — Unified Ghost Agent CLI

## Run Metadata

| Field | Value |
|-------|-------|
| **Last run** | 2026-02-20 |
| **Command** | `uv run --python 3.12 --with pytest python -m pytest tests/ -v --tb=short` |
| **Python** | 3.12.12 (system default 3.9.6 is incompatible — `X \| Y` union syntax requires 3.10+) |
| **Result** | **90 passed, 3 skipped, 2 xfailed** in 0.12s |

---

## Summary by Section

| Section | Total | Passed | Skipped | xFailed |
|---------|-------|--------|---------|---------|
| S — Session State | 12 | 12 | 0 | 0 |
| H — Startup / Handshake | 15 | 15 | 0 | 0 |
| D — Tool Dispatch | 12 | 12 | 0 | 0 |
| M — Denial State Machine | 11 | 11 | 0 | 0 |
| L — Loop Control | 8 | 7 | 0 | 1 |
| R — RCA Generation | 15 | 15 | 0 | 0 |
| E — Error Recovery | 9 | 8 | 0 | 1 |
| I — Integration / E2E | 7 | 4 | 3 | 0 |
| T — Static / Structural | 5 | 5 | 0 | 0 |
| **Total** | **95** | **90** | **3** | **2** |

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
