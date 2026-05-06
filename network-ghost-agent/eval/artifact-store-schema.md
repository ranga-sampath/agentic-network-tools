# Eval Artifact Store — Schema

The artifact store is an append-only archive of eval run outputs. Its purpose is to decouple scoring from execution: new rubrics, judge prompts, and system prompt variant experiments can be scored against stored outputs without re-running Azure infrastructure. The Azure environment, fault injection state, and model backend state at run time are ephemeral and cannot be reproduced on demand.

---

## Prerequisite verification findings

Before the store was designed, all existing run directories were inspected to confirm what artifact data is available.

**Final reports (`ghost_report_*.md`):** Present in all 33 runs. One canonical report per run.

**Intermediate tool call logs (`shell_audit_*.jsonl`):** Present in all 33 runs. Each record contains the full command string, agent reasoning, output summary, exit code, timing, classification, and action taken. Phase 4 (LLM-as-judge on tool call sequences) can be applied retroactively to all existing runs.

**Orphan files:** Two runs contain files from aborted prior session attempts — `phase1/gemini/gemini-2.5-flash/use_case_e` (4 shell_audit files, 2 ghost_report files) and `phase1/anthropic/claude-haiku-4-5-20251001/use_case_a` (7 shell_audit files). The canonical session is identified by the `session_id` field in `run_summary.json`. Only files matching that session_id are copied into the store; orphan files are left in the source run directory.

---

## Directory layout

```
eval/artifact-store/
  run_index.json                               ← root index (see schema below)
  use_case_f/
    claude-sonnet-4-6/
      use_case_f_claude-sonnet-4-6_20260501_091111/
        metadata.json
        run_summary.json
        PROMPT.txt
        ghost_report_ghost_20260501_091111.md
        ghost_audit_ghost_20260501_091111.md
        shell_audit_ghost_20260501_091111.jsonl
    gemini-2.5-flash/
      use_case_f_gemini-2.5-flash_20260501_090931/
        ...
```

Organized by use case then model — the natural query dimension is always "all models on a given use case."

---

## Artifact files per run

| File | Source | Notes |
|---|---|---|
| `metadata.json` | `run_dir/metadata.json` | Phase 1 sidecar: run_id, model_id, system_prompt_hash, ghost_agent_commit |
| `run_summary.json` | `run_dir/run_summary.json` | Structured extraction: hypothesis list, recommended actions, command counts |
| `PROMPT.txt` | `demo/use_case_X/PROMPT.txt` | Scenario description as given to the agent — provides fault context for Phase 4 judge |
| `ghost_report_{session_id}.md` | `run_dir/audit/` | Final RCA report as presented to the operator |
| `ghost_audit_{session_id}.md` | `run_dir/audit/` | Hypothesis log + command evidence table |
| `shell_audit_{session_id}.jsonl` | `run_dir/audit/` | Full tool call sequence: command, reasoning, output, timing, classification |

`ghost_session.json` and `runner_stdout.log` are excluded — their useful content is already captured in `run_summary.json` and the audit files.

---

## `run_index.json` schema

Root-level index at `eval/artifact-store/run_index.json`. Each entry maps an artifact key to its store path and records provenance.

```json
{
  "schema_version": "1",
  "runs": [
    {
      "run_id":             "use_case_f_claude-sonnet-4-6_20260501_091111",
      "use_case_id":        "use_case_f",
      "model_id":           "claude-sonnet-4-6",
      "system_prompt_hash": "0c7b534a...",
      "backfilled":         true,
      "artifact_coverage":  "full",
      "path":               "use_case_f/claude-sonnet-4-6/use_case_f_claude-sonnet-4-6_20260501_091111",
      "superseded_by":      null
    }
  ]
}
```

### Field notes

**`artifact_coverage`** — `"full"` when the store entry contains all five artifact files including the tool call sequence (shell_audit + ghost_audit). `"report_only"` when only the final report and metadata are available. All current runs are `"full"`. This field lets Phase 4 filter runs by available data depth without inspecting the filesystem.

**`superseded_by`** — `null` for canonical runs. If a known-bad run is re-executed, the original entry is never deleted; instead `superseded_by` is set to the replacement `run_id`. Scoring scripts check this field to skip superseded runs automatically. To mark a run as superseded, manually edit `run_index.json` — no script is provided for this operation. Note: the improvement plan proposed placing this field in `metadata.json`, but the index is the correct home — `metadata.json` records capture-time provenance and should not be modified after the fact; `superseded_by` is a store-level relationship between runs that belongs in the index.

**`path`** — Relative to `eval/artifact-store/`. The `run_id` is the leaf directory name, which makes entries unambiguous without inspecting the index.

---

## Append-only policy

- New runs are added to the store; existing entries are never deleted or overwritten.
- To mark a run as superseded: set `superseded_by` in the index entry to the replacement `run_id`. The original files remain untouched.
- Backfilled runs (created before Phase 1 was implemented) carry `"backfilled": true`. See `metadata-schema.md` for what this means for `system_prompt_hash` accuracy.

---

## Storage

The artifact store is local only (`eval/artifact-store/` is gitignored). Commit plan is deferred.
