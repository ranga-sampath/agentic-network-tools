# Run Metadata Schema

Every completed eval run writes a `metadata.json` sidecar into its run directory alongside `run_summary.json`. It is the stable identifier for behavioral comparison across model versions and system prompt versions.

---

## Fields

| Field | Type | Example |
|---|---|---|
| `run_id` | string | `use_case_f_claude-sonnet-4-6_20260501_091111` |
| `model_id` | string | `claude-sonnet-4-6` |
| `use_case_id` | string | `use_case_f` |
| `timestamp_utc` | ISO 8601 string | `2026-05-01T09:11:11.409838+00:00` |
| `system_prompt_hash` | string (SHA-256 hex) | `a3f2...` |
| `ghost_agent_commit` | string (git SHA) | `7f555a1...` |
| `silent_update_detectable` | boolean | `false` |

### Field notes

**`run_id`** — Format: `{use_case_id}_{model_id}_{yyyymmdd}_{hhmmss}`. Human-readable, sortable, and unique at second granularity. Used as the artifact store key in Phase 2.

**`model_id`** — The model identifier as sent in the API request. This records what was requested, not a guarantee of what internal backend version the provider served. Silent backend updates within the same model ID are not detectable from this field — that is Phase 3's responsibility.

**`system_prompt_hash`** — SHA-256 of `ghost_agent.py` at run time. The `SYSTEM_PROMPT` constant is embedded in that file; any change to the system prompt changes this hash. Changes to other parts of `ghost_agent.py` also change the hash — treat a changed hash as "prompt may have changed" not "prompt definitely changed."

**`ghost_agent_commit`** — Git commit hash of `network-ghost-agent/` at run time. Combined with `system_prompt_hash`, this fully pins the agent code version for the run.

**`silent_update_detectable`** — Always `false`. Included explicitly so the limitation is visible in the record, not buried in documentation.

---

## Backfilled runs

Runs created before Phase 1 was implemented carry an additional field:

| Field | Type | Value |
|---|---|---|
| `backfilled` | boolean | `true` |

For backfilled runs:
- `system_prompt_hash` is the SHA-256 of `ghost_agent.py` at backfill time. The system prompt did not change between the original test runs and the backfill, so this is the accurate baseline hash.
- `ghost_agent_commit` is reconstructed via `git log --before=<created_at>` — the nearest commit at or before the run timestamp. Accurate to the nearest commit boundary.

---

## Storage

One `metadata.json` file per run, co-located with `run_summary.json`:

```
eval/runs/
  phase1/anthropic/claude-sonnet-4-6/use_case_m/
    run_summary.json
    metadata.json        ← sidecar
    ghost_session.json
    audit/
```
