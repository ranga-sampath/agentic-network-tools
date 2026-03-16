# Netfilter Inspector — Design

*Architecture reference: `netfilter-inspector/architecture.md`*
*Status: MVP shipped — 2026-03-15*

This document covers the end-to-end design of the Netfilter Inspector — how the two modules (`iptables-parser` and `firewall-inspector`) integrate, what the complete pipeline looks like, and how the tool is used in both standalone and Ghost Agent modes.

Sub-module design detail is in the respective `docs/design.md` files:
- `iptables-parser/docs/design.md` — parser and diff engine
- `firewall-inspector/docs/design.md` — orchestrator, providers, framework detector, chain classifier

---

## 1. Pipeline Overview

The Netfilter Inspector is a three-phase pipeline: **Capture → Store → Compare**.

```
Phase 1: Capture (both modes)
  ┌──────────────────────────────────────────────────┐
  │  1. Validate session_id                          │
  │  2. Deliver probe script to target VM            │
  │  3. Retrieve probe output via SCP                │
  │  4. Split probe output into sections             │
  │  5. Detect active firewall framework             │
  │  6. Parse iptables-save sections                 │
  └──────────────────────────────────────────────────┘

Phase 2: Store (--is-baseline)
  ┌──────────────────────────────────────────────────┐
  │  7a. Assemble snapshot dict                      │
  │  7b. Write {session_id}_snapshot.json            │
  │  7c. Write {session_id}_snapshot.json.sha256     │
  └──────────────────────────────────────────────────┘

Phase 2: Compare (--compare-baseline SESSION_ID)
  ┌──────────────────────────────────────────────────┐
  │  7a. Load baseline snapshot from audit_dir       │
  │  7b. Verify SHA-256 integrity                    │
  │  7c. Diff current against baseline               │
  │  7d. Classify drift entries                      │
  │  7e. Write {session_id}_drift.json               │
  │  7f. Print drift summary to stdout               │
  └──────────────────────────────────────────────────┘
```

---

## 2. Artifact Sequence and Naming

All artifacts share a `{session_id}` prefix and are written to `{audit_dir}/`.

| Artifact | Written by | Content | Notes |
|----------|-----------|---------|-------|
| `{session_id}_commands.log` | `LocalShell` | One JSON line per shell command executed | Append-only; written in standalone mode only. In Ghost Agent mode (`SafeExecShell`), the shell maintains its own audit log outside this tool's scope. |
| `{session_id}_snapshot.json` | `save_snapshot()` | Full snapshot: metadata + framework + parsed rulesets | Written in `--is-baseline` mode only |
| `{session_id}_snapshot.json.sha256` | `save_snapshot()` | SHA-256 of snapshot JSON bytes | Written alongside snapshot; both required for load |
| `{session_id}_drift.json` | `_write_artifact()` | Diff result: metadata + per-family drift reports | Written in `--compare-baseline` mode only |

There is no intermediate artifact between probe retrieval and snapshot — the probe text is held in memory and parsed without writing to disk. The snapshot is the first disk artifact.

**Session ID naming convention:** Auto-generated as `fw_{YYYYMMDD}_{HHMMSS}` in UTC when `SESSION_ID` is empty in config. Custom values must match `^[a-zA-Z0-9_-]{1,64}$`.

---

## 3. Module Dependency at Runtime

```
firewall_inspector.py (orchestrator)
    │
    ├── providers.py            # probe delivery + retrieval
    │       └── LocalShell      # shell execution
    │
    ├── framework_detector.py   # framework classification
    │
    ├── iptables_parser.py      # (imported from sibling iptables-parser/)
    │   parse_iptables_save()   # parse iptables-save text → dict
    │
    ├── iptables_diff.py        # (imported from sibling iptables-parser/)
    │   diff_rulesets()         # diff two parse_iptables_save() outputs
    │
    └── chain_classifier.py     # annotate diff with severity tiers
```

**Import path:** `firewall_inspector.py` inserts two paths into `sys.path` at startup:
1. Its own directory (`firewall-inspector/`) — for `providers`, `framework_detector`, `chain_classifier`
2. `../iptables-parser/` — for `iptables_parser` and `iptables_diff`

This means `iptables_parser` and `iptables_diff` are imported as top-level module names. No package structure or `__init__.py` is required.

---

## 4. Standalone Usage

### 4.1 Azure VM — baseline capture

```ini
# config.env
PROVIDER=azure
VM_NAME=prod-vm-01
RESOURCE_GROUP=my-rg
TARGET_VM_IP=10.0.0.5
TARGET_SSH_KEY_PATH=${HOME}/.ssh/id_rsa
BASTION_PUBLIC_IP=52.1.2.3
SSH_USER=azureuser
AUDIT_DIR=./audit
FAMILY=both
```

```bash
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --is-baseline \
    --session-id fw_pre_change_20260315
```

Output:
```
[1/5] Running probe on prod-vm-01 (session: fw_pre_change_20260315) ...
      Probe output: /tmp/fw_abc123.txt (4096 bytes)
[2/5] Retrieving probe output from 10.0.0.5 ...
[3/5] Parsing probe output ...
      Framework: iptables-legacy (confidence: high)
[4/5] Parsing iptables rules (family: both) ...
      [ipv4] 1 table(s) parsed
      [ipv6] 0 table(s) parsed
[5/5] Saving results ...
      Baseline saved: ./audit/fw_pre_change_20260315_snapshot.json
```

### 4.2 Azure VM — drift comparison

Apply changes. Then:

```bash
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --compare-baseline fw_pre_change_20260315 \
    --session-id fw_post_change_20260315
```

Output:
```
[1/5] Running probe on prod-vm-01 (session: fw_post_change_20260315) ...
...
[5/5] Saving results ...
      Comparing against baseline: fw_pre_change_20260315

── Drift Report ──────────────────────────────────────
  [ipv4] drift_detected: TRUE  has_critical_changes: TRUE
         rules_added: 1  rules_removed: 0  policy_changes: 0
  [ipv6] drift_detected: FALSE
──────────────────────────────────────────────────────
```

### 4.3 Multipass / SSH VM

```ini
# multipass-config.env
PROVIDER=ssh
TARGET_VM_IP=192.168.2.6
TARGET_SSH_KEY_PATH=${HOME}/.ssh/id_rsa
SSH_USER=ubuntu
AUDIT_DIR=./audit
FAMILY=both
```

```bash
python3 firewall-inspector/firewall_inspector.py \
    --config multipass-config.env \
    --is-baseline
```

No `BASTION_PUBLIC_IP` — Case 1 (direct SSH). The Multipass VM is on the local subnet.

---

## 5. Standalone Tool Usage — iptables-parser

The parser and diff engine are independently useful without the orchestrator.

### Parse a saved iptables-save file

```bash
python3 iptables-parser/iptables_parser.py /etc/iptables/rules.v4
python3 iptables-parser/iptables_parser.py /etc/iptables/rules.v4 --family ipv4
sudo iptables-save | python3 iptables-parser/iptables_parser.py
```

Output: JSON to stdout.

### Diff two snapshots

```bash
python3 iptables-parser/iptables_diff.py baseline.json current.json
python3 iptables-parser/iptables_diff.py baseline.json current.json --indent 4
sudo iptables-save | python3 iptables-parser/iptables_parser.py | \
    python3 iptables-parser/iptables_diff.py pre_change.json -
```

Output: JSON to stdout. Check `drift_detected` field.

---

## 6. Ghost Agent Integration

Ghost Agent invokes `firewall_inspector.py` as a direct subprocess from `_run_firewall_inspector_handler()` in `ghost_agent.py`. The inspector runs as a child process, not as an imported Python module, and not via `SafeExecShell`.

**Invocation pattern:**
```
ghost_agent.py
  └── _run_firewall_inspector_handler(ghost_cfg, tool_args)
        ├── Writes temp config.env with PROVIDER, AUDIT_DIR, VM_NAME/TARGET_VM_IP etc.
        ├── subprocess.run([python, "firewall_inspector.py", "--config", tmp_path, ...])
        ├── Deletes temp config.env in finally block
        └── Reads *_snapshot.json or *_drift.json from AUDIT_DIR
```

**Tool classification:**
- All `--is-baseline` and `--compare-baseline` invocations: SAFE (read-only `iptables-save`). No HITL gate required. Ghost Agent does not route these through SafeExecShell.
- The inspector itself does not run any mutative commands in its current scope. NSG port-open remediation is out of scope for the inspector (C-2 — read-only on target VM).

**Input:** Ghost Agent supplies `AUDIT_DIR` (shared with its own audit directory), `session_id` (optional), `is_baseline` or `compare_session_id`, and `provider` (`azure` or `ssh`).

**Output (baseline mode):** Handler returns `{"status": "success", "mode": "baseline", "session_id": str, "artifact": path_to_snapshot_json}`. The `session_id` value is what Ghost Agent stores and passes back as `compare_session_id` in a future compare call.

**Output (compare mode):** Handler returns `{"status": "success", "mode": "compare", "drift_detected": bool, "has_critical_changes": bool, "ipv4": {...}, "ipv6": {...}, "artifact": path_to_drift_json}`. Ghost Agent uses `drift_detected`, `has_critical_changes`, and the per-family `summary` dict as evidence in its investigation chain.

**Tool decision rules (Ghost Agent additions):**
- "Nothing changed but it broke" → call `detect_config_drift` before any other hypothesis
- Post-incident forensics → `detect_config_drift` before environment is restored
- Change window sign-off → `detect_config_drift --compare-baseline` immediately after window closes
- Environment parity failure → `detect_config_drift` on both environments, compare results

**Provider selection:**
- `provider=azure`: uses `az vm run-command invoke` to run `iptables-save` inside the VM. Requires `FW_VM_NAME` and `RESOURCE_GROUP` in Ghost Agent's `config.env`. No SSH key needed; requires VM Contributor role.
- `provider=ssh`: uses direct SSH to connect to the VM and run `iptables-save`. Requires `FW_TARGET_VM_IP` and `FW_SSH_KEY_PATH` in Ghost Agent's `config.env`. Supports bastion-hop if `FW_BASTION_PUBLIC_IP` is set. Use for Multipass or dev environments without Azure role assignments.

---

## 7. Running Tests

```bash
# All tests
cd /path/to/netfilter-inspector
python3 -m pytest

# Parser + diff engine only
cd iptables-parser && python3 -m pytest

# Firewall inspector only
cd firewall-inspector && python3 -m pytest

# Verbose with short tracebacks
python3 -m pytest -v --tb=short
```

**Test counts (MVP shipped 2026-03-15):**
- `iptables-parser/`: 86 tests
- `firewall-inspector/`: 94 passed, 2 skipped of 96 collected

---

## 8. Prerequisites

| Requirement | Details |
|-------------|---------|
| Python 3.9+ | No third-party packages required for library code |
| `pytest` | Tests only |
| `az` CLI | `--provider azure` only; requires `vm run-command invoke` permission |
| SSH key access | Target VM (and bastion if Case 2) must have the operator's public key in `authorized_keys` |
| `known_hosts` | Entries for all SSH hosts must be present before first run (`ssh-keyscan`) |
| `sudo` access on target | Probe runs `sudo iptables-save` — requires passwordless sudo or root |
| Multipass | For local development/testing with `--provider ssh` |

---

## 9. Intentional Omissions

See `architecture.md` §5 for the full list. Key omissions at the design level:

| Omission | Where scoped out |
|----------|-----------------|
| nftables-native parsing | Parser and probe script both. `framework_detector` identifies it; parsing is deferred. |
| `--explain` feature | `firewall-inspector/docs/explain-feature-design.md`. Not part of this pipeline. |
| Fleet-wide scanning | A loop around the tool. Not a concern inside it. |
| Multi-subscription Azure support | Post-MVP. Provider instantiation currently takes one subscription ID. |
| Cloud blob storage for baselines | Post-MVP. Local filesystem only. |
