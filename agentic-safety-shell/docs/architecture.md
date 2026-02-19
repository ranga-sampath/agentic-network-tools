# Architecture: Safe-Exec Shell

## Design Decisions

| Decision | Choice | Rationale (per sw-principles) |
|----------|--------|-------------------------------|
| Safety Model | Allowlist (default deny) | Per sw-principles: whitelist over blacklist. Any command not explicitly classified SAFE is treated as RISKY. False positives cause a UX interruption; false negatives cause production damage. The cost asymmetry demands default-deny. |
| Classification Approach | Static rules, not AI-based | The safety boundary must be deterministic and auditable. An LLM classifying commands could be manipulated via prompt injection or hallucinate a safe classification for a destructive command. Classification is a lookup, not a judgment call. |
| HITL Gate | Synchronous, blocking | The agent pipeline halts completely for risky commands. No background queuing, no optimistic execution. This prevents the Brain from racing ahead of user approval and acting on assumed outcomes. |
| Architecture | Library consumed by the Brain | Not a standalone service. A module the Brain imports and calls — function: `execute(request) -> response`. No network boundary, no serialization overhead, no deployment complexity. |
| Dual Environment | Single shell, unified command space | No "modes" or environment switching. Local macOS and Azure Cloud commands flow through the same classification pipeline. The command itself determines the target environment. |
| Audit Storage | Append-only JSONL to disk | Per sw-principles: intermediate artifacts to disk. No database. One file per agent session. The Memory layer reads these; the Shell only writes. |
| Output Processing | Truncate + redact before Brain sees it | Token efficiency and privacy enforced at the Shell boundary. The Brain never receives raw command output. |
| Privacy | Regex-based redaction at output boundary | Keys, tokens, passwords, and connection strings replaced with `[REDACTED]` markers. Unredacted output is never persisted — not in audit logs, not in response objects. An optional topology anonymization layer (off by default) can replace internal IPs and resource IDs with consistent session-scoped placeholders for external audits. |
| Topology Privacy | Opt-in anonymization mode (off by default) | IP addresses are core diagnostic data — anonymizing by default cripples forensic value. But for external audits or client networks, consistent anonymization preserves correlation while hiding topology. |

---

## System Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AI Brain (LLM)                                │
│                                                                         │
│   Sends: { command, reasoning }                                         │
│   Receives: { status, classification, action, output, metadata, ... }   │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Safe-Exec Shell                                 │
│                                                                         │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌──────────────────┐  │
│  │  Stage 1  │   │  Stage 2  │   │  Stage 3  │   │     Stage 4      │  │
│  │ CLASSIFY  │──>│   GATE    │──>│  EXECUTE  │──>│ PROCESS OUTPUT   │  │
│  │           │   │  (HITL)   │   │           │   │ truncate + redact│  │
│  └───────────┘   └───────────┘   └───────────┘   └──────────────────┘  │
│        │               │               │                   │            │
│        └───────────────┴───────────────┴───────────────────┘            │
│                                    │                                    │
│                                    ▼                                    │
│                         ┌────────────────┐                              │
│                         │   Audit Log    │                              │
│                         │  (JSONL file)  │                              │
│                         └────────────────┘                              │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Infrastructure                                   │
│                                                                         │
│   ┌─────────────────────────┐    ┌──────────────────────────────────┐   │
│   │    Local macOS          │    │       Azure Cloud                │   │
│   │                         │    │                                  │   │
│   │  ping, traceroute, dig  │    │  az network watcher             │   │
│   │  netstat, ss, lsof      │    │  az vm list/show                │   │
│   │  tshark, tcpdump        │    │  az network nsg rule list       │   │
│   │  pcap_forensics.py      │    │  az monitor metrics list        │   │
│   └─────────────────────────┘    └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Four-Stage Pipeline

Every command flows through four stages in strict sequence. No stage can be skipped, bypassed, or reordered.

### Stage 1 — Classify

Deterministic classification via allowlists and pattern matching. Four tiers are evaluated in sequence (see **The Hard Boundary** below). Tier 0 (Forbidden List) is checked first — commands matching Tier 0 are classified FORBIDDEN and short-circuit to an error response without entering Stage 2. Remaining commands must pass ALL three subsequent tiers (1–3) to be classified SAFE. Default classification: **RISKY**.

**Input:** Raw command string + reasoning from Brain.
**Output:** Classification (FORBIDDEN | SAFE | RISKY) + which tier triggered the classification. FORBIDDEN short-circuits to error response immediately — no HITL prompt, no execution.

### Stage 2 — Gate (HITL)

SAFE commands pass through immediately. RISKY commands block the entire pipeline and present the user with the command, the Brain's reasoning, and a risk explanation. The user must explicitly approve, deny, or modify the command before execution proceeds.

**Fail-closed:** If the user closes the terminal, the session times out, or any error occurs during the approval flow, the command is treated as **denied**.

### Stage 3 — Execute

Run the command via subprocess with an explicit argument list (never `shell=True`). Enforce a per-command timeout. Capture stdout, stderr, and exit code separately.

**No shell interpretation:** Commands are split into argument vectors and passed directly to `subprocess.run()`. This prevents shell injection, glob expansion, and unintended command chaining at the execution layer.

### Stage 4 — Process Output

Two-step output processing before the Brain sees anything:

1. **Truncate** — Apply format-aware truncation rules to keep output within token budget (see design.md for detailed rules per output type).
2. **Redact** — Scan for sensitive patterns (API keys, tokens, passwords, connection strings) and replace with `[REDACTED]` markers.

**Output:** Structured response object with processed output + metadata (truncation stats, redaction categories, timing, audit ID).

---

## The Hard Boundary — Four-Tier Defense

The core safety guarantee: **100% of mutative commands must be caught and routed through HITL approval, and catastrophic commands are blocked unconditionally.** This is achieved through four tiers of classification. Tier 0 blocks catastrophic commands outright — no HITL prompt, no Approve button. The remaining three tiers classify commands as SAFE or RISKY. A command must pass ALL three (Tiers 1–3) to be classified SAFE. Any single tier flagging a command as RISKY triggers the HITL gate.

| Tier | Mechanism | What It Catches | Example |
|------|-----------|-----------------|---------|
| 0 | Forbidden list | Catastrophic commands that are never appropriate for network forensics — blocked unconditionally, no HITL prompt | `rm -rf /` rejected; `mkfs` rejected |
| 1 | Command allowlist | Known safe commands pass; everything else is RISKY by default | `ping` passes; `systemctl` blocked |
| 2 | Azure verb-based rules | Read verbs (`list`/`show`/`get`/`check`/`exists`/`wait`) = SAFE; mutative verbs (`create`/`delete`/`update`/`set`/`start`/`stop`/`restart`, etc.) = RISKY | `az vm list` passes; `az vm delete` blocked |
| 3 | Dangerous pattern detection | Privilege escalation, shell evasion, destructive operators, command chaining | `sudo ping` blocked; `ping 8.8.8.8 && rm -rf /` blocked |

**Why four tiers instead of one?**

A single allowlist would require enumerating every safe `az` subcommand-verb combination — hundreds of entries that grow with every Azure CLI update. Tier 2 (verb rules) handles this with a compact rule set. Tier 3 catches evasion attempts that could slip past the first two tiers (e.g., an allowed command wrapped in `sudo` or chained with `&&`). Tier 0 prevents catastrophic mistakes during high-pressure sessions — the Approve button is not available for commands that have zero legitimate forensic value.

**Defense in depth:** The tiers are intentionally redundant. Tier 0 catches catastrophic commands before any other classification logic runs. If a command somehow bypasses Tier 1 (e.g., `az` is in the allowlist as a command family), Tier 2 catches mutative Azure verbs. If a command bypasses both (e.g., a safe local command), Tier 3 catches dangerous patterns like `sudo` wrapping or output redirection. There is no path through all four tiers for a destructive command.

---

## Dual-Environment Strategy

The Shell does not switch modes or maintain separate pipelines for local and cloud commands. The command family determines the environment:

| Command Family | Target Environment | Examples |
|---------------|-------------------|----------|
| System utilities | Local macOS | `ping`, `traceroute`, `dig`, `netstat`, `arp`, `lsof` |
| `az` CLI | Azure Cloud | `az network watcher`, `az vm list`, `az monitor metrics` |
| Analysis tools | Local data analysis | `tshark -r`, `tcpdump -r`, `pcap_forensics.py` |

**Same classification pipeline for both.** A local `ping` and an `az vm list` both flow through the same four-tier classification, the same HITL gate, and the same output processing. The Shell does not know or care which environment a command targets until Stage 3 (Execute).

**Environment parity:** If the Shell is later deployed on an Azure VM instead of local macOS, the same rules apply — local commands target the VM's OS, `az` commands work identically via the installed CLI. No code changes, no configuration switches.

---

## Integration with the Network Ghost Agent

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Network Ghost Agent                              │
│                                                                         │
│  ┌─────────────┐     ┌──────────────┐     ┌────────────────────────┐   │
│  │   AI Brain  │────>│  Safe-Exec   │     │    PCAP Forensic       │   │
│  │   (LLM)     │<────│  Shell       │────>│    Engine               │   │
│  │             │     │              │     │    (invoked as safe cmd)│   │
│  └──────┬──────┘     └──────┬───────┘     └────────────────────────┘   │
│         │                   │                                           │
│         │                   │  writes audit logs                        │
│         │                   ▼                                           │
│         │            ┌──────────────┐                                   │
│         └───────────>│ Memory Layer │                                   │
│          writes      │              │                                   │
│          context     │  reads audit │                                   │
│                      │  logs from   │                                   │
│                      │  Shell       │                                   │
│                      └──────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

**Coupling rules:**

| Relationship | Direction | Mechanism |
|-------------|-----------|-----------|
| Brain -> Shell | Brain calls Shell | `execute(request) -> response` function call |
| Shell -> PCAP Engine | Shell invokes PCAP Engine | Classified as a safe command; executed via subprocess |
| Shell -> Audit Log | Shell writes | Append-only JSONL; one write per command lifecycle |
| Memory Layer -> Audit Log | Memory reads | Memory layer reads Shell's JSONL files for persistent context |
| Shell -> Brain | Never | Shell returns results via function return, never initiates calls to Brain |
| Shell -> Memory | Never | Shell does not write to Memory's data structures |
| Shell -> PCAP Engine | Never imports | PCAP Engine is invoked as a subprocess command, not imported as a library |

**Shell is deliberately decoupled.** It has no knowledge of the Brain's reasoning, the Memory layer's schema, or the PCAP Engine's internals. It receives a command, classifies it, optionally gates it, executes it, processes the output, logs it, and returns a structured response. That is the entire scope of its responsibility.

---

## Error Handling Strategy

| Error | Behavior | Returned to Brain |
|-------|----------|-------------------|
| Forbidden command | Rejected immediately, no HITL prompt | `{ status: "error", error: "forbidden_command", classification: "FORBIDDEN" }` |
| Command timeout | Kill subprocess after configured timeout | `{ status: "error", error: "timeout", duration_seconds: N }` |
| Non-zero exit code | Capture stderr, do NOT retry | `{ status: "completed", exit_code: N, stderr: "..." }` — non-zero exit is not an error from the Shell's perspective; the Brain decides what to do |
| Unknown command | Classified RISKY (default deny), presented to user via HITL | Normal HITL flow; if approved and still fails, return the OS-level error |
| User closes terminal during HITL | Treated as denial (fail-closed) | `{ status: "denied", action: "user_abandoned" }` |
| Redaction failure (regex error) | Fail closed — do not return output to Brain | `{ status: "error", error: "redaction_failure" }` — raw output is never exposed |
| Audit log write failure | Log warning, do NOT block command execution | Command still executes and returns results; audit gap is logged to stderr |
| Empty command | Reject immediately, do not classify | `{ status: "error", error: "empty_command" }` |
| Command not found (OS-level) | Return OS error via normal exit code path | `{ status: "completed", exit_code: 127, stderr: "command not found: ..." }` |

---

## What This Architecture Intentionally Omits

| Omitted | Why |
|---------|-----|
| AI-based classification | Manipulable via prompt injection; non-deterministic; cannot guarantee the hard boundary. The safety layer must be simpler and more reliable than the system it protects. |
| Asynchronous HITL | Defeats the purpose of blocking safety. If the pipeline continues while waiting for approval, the Brain can issue dependent commands that assume approval. Synchronous blocking is the only safe design. |
| Async execution / task queuing | Long-running commands (e.g., `az packet-capture create`, 30-60s) block the Brain intentionally. The cost is latency; the benefit is the Brain never acts on assumed results. If the Brain could issue commands concurrently, it might depend on outcomes that haven't happened yet — violating the sequential safety model. |
| Command suggestion / auto-correction | That is the Brain's job. The Shell classifies, gates, and executes. It does not reason about what command *should* be run. |
| Network architecture (HTTP/gRPC) | The Shell is a library, not a service. Adding a network boundary introduces latency, serialization, and a new failure mode with zero benefit for a single-agent system. |
| Role-based access control (RBAC) | Single-user system. The agent has one operator. RBAC adds complexity without a use case. |
| Undo / rollback | Infrastructure commands are not generically reversible. `az vm delete` cannot be undone by the Shell. Rollback is the Brain's responsibility (if it chooses to implement recovery logic). |
| Output caching | Cached network state is stale network state. Every command should reflect the current reality. The Brain can re-request if needed. |
| Retry logic | The Shell does not retry failed commands. Retrying is a policy decision that belongs to the Brain. The Shell reports what happened; the Brain decides what to do next. |
