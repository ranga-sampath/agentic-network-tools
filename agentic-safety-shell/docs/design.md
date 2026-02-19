Design: Safe-Exec Shell

> This document specifies the behavioral details of the Safe-Exec Shell — how commands are classified, how the HITL gate works, how output is processed, and how audit records are structured. Read `architecture.md` first for structural context and design rationale.

---

## Brain-Shell Interface Contract

### Request (Brain -> Shell)

```json
{
  "command": "az network nsg rule list --resource-group prod-rg --nsg-name web-nsg",
  "reasoning": "Need to inspect firewall rules to determine if port 443 is blocked"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | Yes | The exact command to execute. The Brain does NOT specify safe/risky — the Shell decides. |
| `reasoning` | string | Yes | Why the Brain wants to run this command. Displayed to the user during HITL approval and recorded in the audit log. |

### Response (Shell -> Brain)

```json
{
  "status": "completed",
  "classification": "SAFE",
  "action": "auto_approved",
  "output": "Name    Priority  Access  Direction  Protocol ...\nallow-https  100  Allow  Inbound  Tcp ...",
  "stderr": "",
  "exit_code": 0,
  "output_metadata": {
    "truncation_applied": false,
    "total_lines": 12,
    "lines_shown": 12,
    "output_type": "tabular",
    "redactions_applied": false,
    "redaction_categories": []
  },
  "audit_id": "sess_abc123_007"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always present. `completed` / `denied` / `error` |
| `classification` | string | Always present. `FORBIDDEN` / `SAFE` / `RISKY` |
| `action` | string | Always present. `auto_approved` (SAFE) / `user_approved` / `user_denied` / `user_modified` / `user_abandoned` |
| `output` | string | Processed stdout (truncated + redacted). Empty string if denied or errored before execution. |
| `stderr` | string | Processed stderr (redacted, never truncated). Empty string if not executed. |
| `exit_code` | integer or null | OS exit code (0 = success). Null if command was not executed (denied, error). |
| `error` | string or null | Error code when `status` is `error`: `"forbidden_command"`, `"timeout"`, `"redaction_failure"`, `"empty_command"`. Null otherwise. |
| `duration_seconds` | float or null | Wall-clock execution time. Null if command was not executed. Present even on timeout (shows elapsed time before kill). |
| `output_metadata` | object | Truncation and redaction statistics. Empty object if not executed. |
| `audit_id` | string | Always present. Reference to the audit log entry for this command. |

---

## Command Lifecycle

```
Brain sends { command, reasoning }
         │
         ▼
┌─────────────────┐
│   Parse Command  │──── empty/malformed? ──> return error
│                  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Tier 0:        │
│   Forbidden      │──── forbidden? ──> return { status: error,
│   List           │                     error: forbidden_command,
│                  │                     classification: FORBIDDEN }
└────────┬────────┘                     (logged to audit trail)
         │ (not forbidden)
         ▼
┌─────────────────┐
│   Tier 1:        │
│   Command        │──── not in allowlist? ──> RISKY
│   Allowlist      │
└────────┬────────┘
         │ (in allowlist)
         ▼
┌─────────────────┐
│   Tier 2:        │
│   Azure Verb     │──── mutative verb? ──> RISKY
│   Rules          │
└────────┬────────┘
         │ (read-only verb or non-Azure)
         ▼
┌─────────────────┐
│   Tier 3:        │
│   Dangerous      │──── pattern match? ──> RISKY
│   Patterns       │
└────────┬────────┘
         │ (no dangerous patterns)
         ▼
    Classification: SAFE
         │
         ├──── SAFE ─────────────────────────────┐
         │                                        │
         ├──── RISKY ──> ┌──────────────────┐     │
         │               │   HITL Gate       │     │
         │               │                  │     │
         │               │  Show: command,  │     │
         │               │  reasoning, risk │     │
         │               │                  │     │
         │               │  [Approve]       │     │
         │               │  [Deny]    ──────┼──> return { status: denied }
         │               │  [Modify]  ──────┼──> re-classify modified command
         │               └────────┬─────────┘     │
         │                        │ (approved)     │
         │                        │                │
         ▼                        ▼                │
┌─────────────────────────────────────────────┐   │
│   Execute via subprocess                     │<──┘
│   (argument list, never shell=True)          │
│   (timeout enforced)                         │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│   Process Output                             │
│   1. Truncate (format-aware)                 │
│   2. Redact (regex-based)                    │
│   3. Structure response with metadata        │
└────────────────────┬────────────────────────┘
                     │
                     ├──> Write audit log entry (JSONL)
                     │
                     ▼
            Return response to Brain
```

---

## Command Classification — Detailed Rules

### Tier 0 — Forbidden Commands

Tier 0 is the first check in the classification pipeline. Commands matching this list are classified **FORBIDDEN** and rejected immediately — no HITL prompt, no Approve button, no execution. The error response is returned to the Brain and the attempt is logged to the audit trail.

The list is intentionally small. Only commands with zero legitimate network forensics value and catastrophic consequences qualify. The bar: "no sane person would ever run this during network diagnostics."

| Pattern | Example | Why Forbidden |
|---------|---------|---------------|
| `rm -rf /` or `rm -rf /*` | `rm -rf /` | Filesystem destruction — no forensic value |
| `mkfs` | `mkfs.ext4 /dev/sda1` | Formats a disk |
| `dd` to block devices | `dd if=/dev/zero of=/dev/sda` | Overwrites disk |
| Fork bomb patterns | `:(){ :\|:& };:` | System crash |
| `shutdown` / `reboot` / `halt` / `poweroff` | `shutdown now` | System shutdown — terminates the agent session |
| `init 0` / `init 6` | `init 0` | System state change |

**Tier 0 vs. Tier 3:** Tier 3 (Dangerous Patterns) catches commands like `rm`, `sudo`, and `chmod` and classifies them as RISKY — the user can still approve them via HITL. Tier 0 catches the subset of commands so catastrophic that approval should not be possible. A user might legitimately `rm` a temp file (RISKY, approvable), but there is no legitimate reason to `rm -rf /` during network forensics (FORBIDDEN, blocked).

### Tier 1 — Local Command Allowlist

Commands in the allowlist are candidates for SAFE classification. Commands not in the allowlist are immediately classified RISKY — no further tiers are evaluated.

**Network Discovery (SAFE)**

| Command | Allowed Arguments | Notes |
|---------|-------------------|-------|
| `ping` | All flags | Read-only; sends ICMP echo |
| `traceroute` | All flags | Read-only; traces packet path |
| `dig` | All flags | DNS lookup |
| `nslookup` | All flags | DNS lookup |
| `host` | All flags | DNS lookup |
| `whois` | All flags | Domain registration lookup |
| `mtr` | All flags | Combined ping + traceroute |

**System State (SAFE)**

| Command | Allowed Arguments | Notes |
|---------|-------------------|-------|
| `netstat` | All flags | Display network connections/stats |
| `ss` | All flags | Socket statistics |
| `ifconfig` | Display only (no arguments, or specific interface name) | **RISKY if flags `up`, `down`, `mtu`, `metric`, or any address assignment are present** |
| `ip` | `addr show`, `route show`, `link show`, `neigh show` | **RISKY if subcommand is `add`, `del`, `set`, `change`, `replace`, `flush`** |
| `arp` | `-a`, `-n` | Display ARP table. **RISKY if `-d` (delete) or `-s` (set) present** |
| `route` | `get` | Display routing for a destination. **RISKY if `add`, `delete`, `change`, `flush` present** |
| `lsof` | `-i` | List open network files |
| `scutil` | `--dns`, `--proxy`, `--nwi` | macOS network config queries |
| `networksetup` | `-list*`, `-get*` | macOS network preferences (read). **RISKY if `-set*`, `-add*`, `-remove*` present** |

**Data Analysis (SAFE)**

| Command | Allowed Arguments | Notes |
|---------|-------------------|-------|
| `tshark` | `-r` (read from file) required | **RISKY without `-r`** (live capture requires privileges) |
| `tcpdump` | `-r` (read from file) required | **RISKY without `-r`** |
| `pcap_forensics.py` | All arguments | The PCAP Forensic Engine; always safe |
| `curl` | GET requests only (no `-X` flag, or `-X GET`) | **RISKY if `-X POST`, `-X PUT`, `-X DELETE`, `-X PATCH`, `-d`, `--data`, or `--upload-file` present** |

**Flag-Sensitive Classification Summary**

| Command | SAFE When | RISKY When |
|---------|-----------|------------|
| `ifconfig` | No arguments or interface name only | `up`, `down`, `mtu`, `metric`, address assignment |
| `ip` | `show` subcommand | `add`, `del`, `set`, `change`, `replace`, `flush` |
| `curl` | GET (default or explicit) | `-X POST/PUT/DELETE/PATCH`, `-d`, `--data`, `--upload-file` |
| `tshark` | `-r` flag present | No `-r` flag (live capture) |
| `tcpdump` | `-r` flag present | No `-r` flag (live capture) |
| `arp` | `-a`, `-n` | `-d`, `-s` |
| `route` | `get` | `add`, `delete`, `change`, `flush` |
| `networksetup` | `-list*`, `-get*` | `-set*`, `-add*`, `-remove*` |

### Tier 2 — Azure CLI Verb Rules

All `az` commands are in the Tier 1 allowlist as a command family. Tier 2 provides fine-grained classification based on the Azure CLI verb (the action word in the command).

**SAFE Verbs (read-only operations)**

| Verb | Meaning | Example |
|------|---------|---------|
| `list` | Enumerate resources | `az vm list` |
| `show` | Display resource details | `az network nsg show` |
| `get` | Retrieve a value | `az keyvault secret get` |
| `check` | Validate a condition | `az network dns record-set check` |
| `exists` | Test existence | `az group exists` |
| `wait` | Poll until condition met | `az vm wait --created` |

**RISKY Verbs (mutative operations)**

| Verb | Meaning | Example |
|------|---------|---------|
| `create` | Provision new resources | `az vm create` |
| `delete` | Remove resources | `az group delete` |
| `update` | Modify resource properties | `az vm update` |
| `set` | Set a configuration value | `az network nsg rule set` |
| `add` | Add sub-resources | `az network vnet subnet add` |
| `remove` | Remove sub-resources | `az network nsg rule remove` |
| `start` | Start a resource | `az vm start` |
| `stop` | Stop a resource | `az vm stop` |
| `restart` | Restart a resource | `az vm restart` |
| `deallocate` | Release compute resources | `az vm deallocate` |
| `move` | Move between resource groups | `az resource move` |
| `import` | Import configuration | `az network dns zone import` |
| `export` | Export configuration | `az network dns zone export` |

**Special Cases**

| Command Pattern | Classification | Why |
|----------------|---------------|-----|
| `az rest` | Always RISKY | Arbitrary HTTP method against any Azure endpoint — impossible to classify statically |
| `az network watcher show-topology` | SAFE | Read-only topology view |
| `az network watcher show-next-hop` | SAFE | Read-only routing query |
| `az network watcher packet-capture create` | RISKY | Creates a resource (packet capture session) |
| `az network watcher flow-log list` | SAFE | Read verb |
| `az network watcher flow-log create` | RISKY | Mutative verb |
| `az login` | SAFE (but output redacted) | Authentication — not mutative, but tokens in output must be redacted |
| `az account show` | SAFE | Read-only account info |

### Tier 3 — Dangerous Pattern Detection

Tier 3 scans the entire command string (not just the base command) for patterns that indicate privilege escalation, shell evasion, or destructive intent. These patterns override any SAFE classification from Tiers 1 and 2.

**Privilege Escalation**

| Pattern | Example | Why Dangerous |
|---------|---------|---------------|
| `sudo` | `sudo ping 8.8.8.8` | Elevates privileges; even safe commands become risky under root |
| `su` | `su -c "netstat -an"` | Switches user context |
| `doas` | `doas traceroute 10.0.0.1` | OpenBSD privilege escalation |

**Shell Evasion**

| Pattern | Example | Why Dangerous |
|---------|---------|---------------|
| `bash -c` / `sh -c` | `bash -c "ping 8.8.8.8"` | Wraps command in a subshell; bypasses argument-list execution |
| `eval` | `eval "ping 8.8.8.8"` | Interprets string as command |
| `exec` | `exec ping 8.8.8.8` | Replaces current process |
| Backtick substitution | `` ping `hostname` `` | Executes embedded command |
| `$()` substitution | `ping $(hostname)` | Executes embedded command |

**Destructive Operators**

| Pattern | Example | Why Dangerous |
|---------|---------|---------------|
| `>` / `>>` to system paths | `netstat > /etc/resolv.conf` | Overwrites system files |
| `rm` | `rm -rf /tmp/results` | File deletion |
| `chmod` | `chmod 777 /etc/hosts` | Permission modification |
| `chown` | `chown root:root /tmp/file` | Ownership modification |
| `kill` / `killall` / `pkill` | `kill -9 1234` | Process termination |
| `mv` to system paths | `mv /etc/hosts /etc/hosts.bak` | File relocation |

**Command Chaining**

| Pattern | Rule | Example |
|---------|------|---------|
| `&&` | Entire chain classified as highest risk | `ping 8.8.8.8 && rm -rf /tmp` — RISKY because `rm` |
| `\|\|` | Entire chain classified as highest risk | `ping 8.8.8.8 \|\| reboot` — RISKY because `reboot` |
| `;` | Entire chain classified as highest risk | `dig google.com ; shutdown now` — RISKY because `shutdown` |
| `\|` (pipe) | RISKY if right side is destructive | `netstat -an \| tee /etc/hosts` — RISKY because `tee` to system path |

**Chaining rule:** If any segment of a chained command is RISKY, the entire chain is RISKY. The Shell does not attempt to split and classify segments independently for execution — that would create a bypass vector.

---

## HITL Interruption Mechanism

### When It Activates

The HITL gate activates whenever the classification result is RISKY, regardless of which tier triggered it.

### Approval Prompt Format

```
┌──────────────────────────────────────────────────────────────┐
│  RISKY COMMAND — Approval Required                           │
│                                                              │
│  Command:   az vm stop --resource-group prod --name web-01   │
│  Reason:    Need to stop the VM to resize its disk           │
│  Risk:      Mutative Azure operation (verb: stop)            │
│             Tier 2: Azure verb 'stop' is classified RISKY    │
│                                                              │
│  [A] Approve    [D] Deny    [M] Modify                      │
└──────────────────────────────────────────────────────────────┘
```

### User Response Options

| Option | Behavior | Returned to Brain |
|--------|----------|-------------------|
| **Approve** | Execute the command exactly as submitted | `{ action: "user_approved", ... }` with command output |
| **Deny** | Do not execute; return denial to Brain immediately | `{ status: "denied", action: "user_denied" }` |
| **Modify** | User edits the command text; the modified command is re-classified from Tier 1. If still RISKY, the user is prompted again. If now SAFE, execute without further prompting. | `{ action: "user_modified", ... }` with modified command and output |

### Timeout and Abandonment

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| User does not respond within timeout | Treated as Deny | Fail-closed: silence is not consent |
| User closes the terminal | Treated as Deny | Fail-closed: broken session is not approval |
| HITL prompt mechanism fails | Treated as Deny | Fail-closed: if we can't ask, we can't execute |

---

## Output Processing Pipeline

Output processing happens in Stage 4, after command execution. Two steps in fixed order: truncate first, then redact.

### Truncation ("Anti-Wall Filter")

**Why truncate?** A single `az resource list` can return thousands of lines. Sending raw output to the Brain wastes tokens and degrades LLM reasoning quality. The Shell enforces a token-conscious output budget.

**Threshold:** ~200 lines or ~4,000 tokens (whichever is hit first).

**Format-Aware Rules**

| Output Type | Detection | Truncation Strategy |
|-------------|-----------|---------------------|
| JSON array | Starts with `[`, valid JSON | First 3 items + last 1 item + `"[truncated: showing 4 of N items]"` |
| JSON object | Starts with `{`, valid JSON | Preserve all top-level keys; truncate nested arrays (same rule); cap object depth at 3 levels |
| Tabular text | Consistent column alignment, header row detected | Header row + first N data rows + `[truncated: showing N of M rows]` |
| Log / stream text | Line-oriented, no structure detected | First 20 lines + last 10 lines + `[truncated: N lines omitted]` |
| Binary / non-text | Non-UTF-8 bytes detected | Replace entirely with `[binary output: N bytes, not displayed]` |

**Stderr:** NEVER truncated. Error output is always shown in full — it is typically short and always diagnostically critical.

**Truncation Metadata**

```json
{
  "truncation_applied": true,
  "total_lines": 1847,
  "lines_shown": 30,
  "total_bytes": 94521,
  "output_type": "json_array",
  "items_total": 312,
  "items_shown": 4
}
```

### Privacy Redaction

**Why redact?** Command output may contain secrets — Azure connection strings, API keys, bearer tokens, private key material. These must never reach the Brain (which may log them) or persist in audit logs.

**Redaction happens AFTER truncation.** If redaction happened first, a truncation cut point could land mid-secret, exposing a partial credential. By redacting after truncation, only the final visible output is scanned, and no partial secrets survive.

**Redaction Patterns**

| Category | Pattern Description | Example Before | Example After |
|----------|-------------------|----------------|---------------|
| API keys | Alphanumeric strings following `key=`, `apikey=`, `api-key:` | `api-key: sk-abc123def456` | `api-key: [REDACTED]` |
| Passwords | Values following `password=`, `passwd=`, `pwd=` | `password=MyS3cret!` | `password=[REDACTED]` |
| Bearer tokens | Strings following `Bearer ` | `Authorization: Bearer eyJ0eX...` | `Authorization: Bearer [REDACTED]` |
| Connection strings | JDBC, ODBC, Azure-style connection strings | `Server=tcp:mydb.database...;Password=abc` | `[REDACTED_CONNECTION_STRING]` |
| Private keys | PEM-formatted key blocks | `-----BEGIN RSA PRIVATE KEY-----\nMIIE...` | `[REDACTED_PRIVATE_KEY]` |
| Azure subscription IDs | GUID patterns in Azure context | `"subscriptionId": "a1b2c3d4-..."` | `"subscriptionId": "[REDACTED]"` |
| Azure storage keys | Base64 strings following storage key patterns | `AccountKey=abc123base64...==` | `AccountKey=[REDACTED]` |
| SAS tokens | Azure Shared Access Signature query parameters | `?sv=2021-06-08&ss=b&srt=co&sp=...&sig=abc` | `[REDACTED_SAS_TOKEN]` |

**Redaction Metadata**

```json
{
  "redactions_applied": true,
  "redaction_count": 3,
  "redaction_categories": ["bearer_token", "connection_string", "storage_key"]
}
```

**Unredacted output is never persisted.** The audit log records the same redacted output that the Brain receives. There is no "raw" version stored anywhere.

### Topology Anonymization (Opt-In)

An optional anonymization layer that replaces internal network topology details with consistent session-scoped placeholders. Designed for external audits or client-network diagnostics where preserving correlation is necessary but exposing actual topology is not.

**Default: OFF.** Must be explicitly enabled. When off, IPs pass through to the Brain unmodified (secrets are still redacted by the standard pipeline).

**When enabled:** Internal IPs (RFC 1918: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`), subnet CIDRs, and Azure resource IDs are replaced with consistent session-scoped placeholders.

**Consistent mapping:** Same IP always maps to the same placeholder within a session (`10.0.0.5` -> `[INTERNAL_IP_1]` everywhere). This preserves the Brain's ability to correlate across commands.

**Anonymization Categories**

| Category | Pattern | Example Before | Example After |
|----------|---------|----------------|---------------|
| Internal IPv4 | RFC 1918 ranges | `10.0.0.5` | `[INTERNAL_IP_1]` |
| Subnet CIDRs | Private ranges with `/` prefix length | `10.0.1.0/24` | `[INTERNAL_SUBNET_1]` |
| Azure Resource IDs | `/subscriptions/.../resourceGroups/...` | `/subscriptions/abc/resourceGroups/prod-rg` | `[AZURE_RESOURCE_1]` |

**Ordering:** Anonymization runs AFTER standard redaction (secrets first, then topology if enabled). This ensures that secret patterns are caught first and that anonymization placeholders do not interfere with redaction regex.

**Metadata:** When enabled, the following fields are added to `output_metadata`:

```json
{
  "anonymization_applied": true,
  "anonymization_mappings_count": 7
}
```

---

## Audit Trail

### Record Schema

Every command lifecycle produces exactly one audit record, regardless of outcome — with one exception: empty/malformed commands are rejected before entering the pipeline and are not logged (there is no meaningful command to record). Forbidden commands (Tier 0) ARE logged because they represent a forensically interesting event — the Brain attempted something catastrophic.

```json
{
  "timestamp": "2025-01-15T14:32:07.123Z",
  "session_id": "sess_abc123",
  "sequence": 7,
  "command": "az vm stop --resource-group prod --name web-01",
  "reasoning": "Need to stop the VM to resize its disk",
  "status": "completed",
  "classification": "RISKY",
  "tier_triggered": 2,
  "error": null,
  "action": "user_approved",
  "user_decision": "approve",
  "modified_command": null,
  "environment": "azure",
  "exit_code": 0,
  "output_summary": "VM 'web-01' stopping... done.",
  "output_truncated": false,
  "redactions_applied": true,
  "redaction_categories": ["bearer_token"],
  "duration_seconds": 12.4
}
```

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string (ISO 8601) | When the command was received |
| `session_id` | string | Unique identifier for the agent session |
| `sequence` | integer | Monotonically increasing command number within session |
| `command` | string | The command as submitted by the Brain |
| `reasoning` | string | Brain's stated reason for the command |
| `status` | string | `completed`, `denied`, or `error` — matches the response status returned to Brain |
| `classification` | string | `FORBIDDEN`, `SAFE`, or `RISKY` |
| `tier_triggered` | integer or null | Which tier triggered the classification (0 for FORBIDDEN, 1, 2, or 3 for RISKY); null if SAFE |
| `error` | string or null | Error code when status is `error`: `"timeout"`, `"redaction_failure"`, etc. Null otherwise. |
| `action` | string | `auto_approved`, `user_approved`, `user_denied`, `user_modified`, `user_abandoned` |
| `user_decision` | string or null | Raw user response; null for SAFE commands |
| `modified_command` | string or null | If user chose Modify, the edited command; null otherwise |
| `environment` | string | `local` or `azure` |
| `exit_code` | integer or null | OS exit code; null if command was denied or errored before execution |
| `output_summary` | string | First 200 chars of processed (truncated + redacted) output |
| `output_truncated` | boolean | Whether truncation was applied |
| `redactions_applied` | boolean | Whether any secrets were redacted |
| `redaction_categories` | array of strings | Which redaction categories matched |
| `duration_seconds` | float or null | Wall-clock execution time; null if not executed |
| `anonymization_applied` | boolean | Whether topology anonymization was active for this command's output |

### Storage

- **Format:** JSONL (one JSON object per line)
- **File naming:** `shell_audit_{session_id}.jsonl`
- **Location:** Configurable directory, defaults to `./audit/`
- **Write mode:** Append-only; records are never modified or deleted during a session
- **Rotation:** One file per session; no intra-session rotation

### Consumers

| Consumer | Purpose | Access Pattern |
|----------|---------|---------------|
| Memory Layer | Build persistent context from Shell activity | Read JSONL files after session; extract command history, outcomes, patterns |
| Human operator | Compliance, debugging, incident review | Read JSONL files directly or via `jq` queries |

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Forbidden command (Tier 0 match) | Return error immediately (`forbidden_command`), no HITL prompt; logged to audit trail |
| Empty command (`""` or whitespace only) | Return error immediately; do not classify or log |
| Newlines in command string | Treat as dangerous pattern (potential command injection); classify RISKY |
| Command produces no output | Return `{ output: "", exit_code: 0 }` — empty output is valid |
| Command hangs (exceeds timeout) | Kill subprocess; return `{ status: "error", error: "timeout" }` |
| User modifies RISKY command to a SAFE one | Re-classify from Tier 1; if now SAFE, execute without further prompting |
| User modifies RISKY command to a still-RISKY one | Re-classify; still RISKY triggers HITL again; user sees new prompt |
| `az login` (safe but sensitive output) | Classified SAFE (not mutative); output is redacted (tokens, tenant IDs) |
| Prompt injection in command output | Redaction and truncation are pattern-based, not AI-driven; injection text passes through as inert output. The Shell does not interpret output content. |
| Concurrent requests from Brain | Not supported. The Shell processes one command at a time, synchronously. If the Brain sends concurrent requests, they must be serialized by the caller. |
| Brain requests its own audit log | Classified as a safe file-read command (e.g., `cat audit/shell_audit_sess_abc123.jsonl`); normal classification pipeline applies |
| Command with extremely long arguments | No argument length limit enforced by the Shell; OS-level limits apply. If the OS rejects the command, return the OS error. |
| Pipe to a safe command | `netstat -an \| grep 443` — `grep` is not in the allowlist, but piped commands are evaluated as a chain. `grep` alone is not destructive, but the chaining rule classifies the entire pipe based on the highest-risk segment. Since `grep` is not in the allowlist, the chain is RISKY. |
| Allowed command with disallowed redirect | `dig google.com > /etc/resolv.conf` — Tier 3 catches the redirect to a system path; classified RISKY |
