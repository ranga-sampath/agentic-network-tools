# VM Firewall Inspector — Build Plan

*Tool position: Layer 3 — OS firewall state, between NSG/route control plane (Layer 1) and wire traffic (Layer 4)*
*Status: Approved for build — 2026-03-14*

---

## Problem

Azure's control plane (NSG, UDR, peering) has no visibility into the OS-layer firewall. A packet that passes subnet NSG → NIC NSG → VM NIC hits iptables or nftables inside the VM and can still be dropped there silently. Azure Change Analysis, Network Watcher, and Activity Log have no record of this layer. The VM Firewall Inspector makes it observable.

Three-layer filtering order (inbound):
```
Subnet NSG → NIC NSG → OS firewall (iptables / nftables)
```

Azure tools cover layers 1 and 2. This tool covers layer 3.

---

## Architecture Overview

```
netfilter-inspector/
  iptables_parser.py           Module 1+2  (Done) — parses iptables-save output
  iptables_diff.py             Module 5    (Done) — diffs two parser outputs (now in iptables-parser/)
  framework_detector.py        Module 4    (Done) — detects iptables-legacy / nft / mixed
  chain_classifier.py          Module 6    (Done) — classifies chains by drift significance
  firewall_inspector.py        Main orchestrator (Done)
  providers.py                 Cloud providers + LocalShell (Done)
  iptables-samples/            Fixture files
  tests/
    conftest.py
    test_parser.py             (Done — 57 tests)
    test_diff.py               (Done — 29 tests)
    test_framework_detector.py (Done — 18 tests)
    test_chain_classifier.py   (Done — 21 tests)
    test_inspector.py          (Done — 57 tests)
```

---

## Module 4: `framework_detector.py`

### Purpose

Detect which netfilter framework is active on the VM. The detection result gates which commands the probe script runs. Prevents running `iptables-legacy-save` on a system where only `nftables` is present, and vice versa.

### Detection inputs

Four version strings retrieved from the VM:
1. `iptables --version` output
2. `iptables-legacy --version` output (may be absent)
3. `nft --version` output
4. `update-alternatives --query iptables` output (Debian/Ubuntu) — detects whether `iptables` symlinks to `nft` or `xtables`

### Detection outcomes

| Result | Meaning |
|--------|---------|
| `iptables-legacy` | Kernel uses xt_tables; `iptables-save` talks to the legacy backend |
| `iptables-nft` | `iptables` symlinked to `iptables-nft` wrapper; rules stored in nftables |
| `nftables-native` | `nft` present, no iptables-compatible layer |
| `mixed` | Both iptables-legacy and nftables-native stacks active (seen in some Kubernetes nodes) |
| `unknown` | Could not determine from available version strings |

### Public API

```python
def detect_framework(version_strings: dict) -> dict:
    """
    version_strings keys: "iptables", "iptables_legacy", "nft", "update_alternatives"
    Returns:
      {"framework": str, "iptables_cmd": str | None, "nft_available": bool, "confidence": str}
    """
```

`iptables_cmd` is either `"iptables-save"`, `"iptables-legacy-save"`, or `None`.
`confidence` is `"high"` | `"low"` — `"low"` means the detector defaulted because version strings were ambiguous.

### MVP scope

MVP detects `iptables-legacy` and `iptables-nft`. `nftables-native` and `mixed` return `framework="unknown"` with a `parse_warnings` entry — the inspector falls back to iptables-only output and notes the limitation. Full nftables support is Module 3 (deferred post-MVP).

---

## Module 6: `chain_classifier.py`

### Purpose

Classify chains by how much drift noise they generate and whether drift in them is operationally significant. The diff engine reports all changes; the inspector uses classification to decide how to present them.

### Three-tier classification

| Tier | Class | Meaning | Diff treatment |
|------|-------|---------|----------------|
| 1 | `user-defined` | Created by the operator or security team | Full diff — every added/removed/repositioned rule reported |
| 2 | `structural` | Created by a known service (docker, kube-proxy, fail2ban, ufw) but stable once initialised | Full diff — changes are operationally significant |
| 3 | `ephemeral` | High-churn chains generated per-connection or per-endpoint | Summarised count only — rule-level diff suppressed |

### Classification logic

```python
_EPHEMERAL_PATTERNS = [
    re.compile(r"^KUBE-SEP-"),      # kube-proxy: per-endpoint chains
    re.compile(r"^KUBE-SVC-"),      # kube-proxy: per-service chains
    re.compile(r"^KUBE-FW-"),       # kube-proxy: external LoadBalancer
    re.compile(r"^KUBE-XLB-"),      # kube-proxy: external LB hairpin
]

_STRUCTURAL_PATTERNS = [
    re.compile(r"^DOCKER"),         # Docker bridge and NAT rules
    re.compile(r"^f2b-"),           # fail2ban per-service jail chains
    re.compile(r"^ufw-"),           # UFW generated chains
    re.compile(r"^LIBVIRT_"),       # libvirt bridge chains
]
```

Classification order: ephemeral patterns checked first; structural patterns checked second; everything else is `user-defined`.

### Extensibility requirement

Adding VPN chain patterns (OpenVPN, WireGuard, strongSwan) later must require **only** adding entries to `_STRUCTURAL_PATTERNS` or a new `_VPN_PATTERNS` list — no changes to classification logic or caller code. The function signature is:

```python
def classify_chain(chain_name: str) -> str:
    """Returns 'user-defined' | 'structural' | 'ephemeral'."""
```

New pattern lists can be added and checked in sequence without touching this signature.

### Public API

```python
def classify_chain(chain_name: str) -> str: ...

def classify_diff(diff_result: dict) -> dict:
    """
    Annotate a diff_rulesets() output with chain classification.
    Ephemeral-tier chains: rule-level changes suppressed, replaced with summary counts.
    Returns augmented diff dict with 'chain_classifications' top-level key.
    """
```

---

## Probe Script Design

The probe script runs **inside the VM** via `az vm run-command invoke`. It must be self-contained (no dependencies beyond standard tools) and must handle partial availability gracefully.

### Section delimiter protocol

Each output section is wrapped:
```
###SECTION:framework_detection###
<content>
###SECTION:iptables_ipv4###
<content>
###SECTION:iptables_ipv6###
<content>
###UNAVAILABLE###
```

`###UNAVAILABLE###` immediately follows the section header when the command is not available or exits non-zero. The inspector parser reads sections by delimiter, not by line count.

### Probe script structure (pseudocode)

The probe always collects **both** IPv4 and IPv6 regardless of the `--family` CLI flag. The
inspector filters by family when parsing. This eliminates any family-based interpolation into
the script body — `SESSION_ID` (validated `^[a-zA-Z0-9_-]{1,64}$`) and `SSH_USER` are the
only runtime values passed as parameters; they are never interpolated into the script body.

```bash
#!/bin/bash
set -euo pipefail     # -e: abort on error; -u: unset vars are errors; -o pipefail

SESSION_ID="$1"
SSH_USER="$2"         # used to chown output file (see note below)
OUT=$(mktemp /tmp/fw_XXXXXX.txt)
chmod 600 "$OUT"      # belt-and-suspenders: mktemp creates 0600 on most systems

collect() {
  printf '###SECTION:framework_detection###\n'
  iptables --version 2>&1          || true
  iptables-legacy --version 2>&1   || true
  nft --version 2>&1               || true
  update-alternatives --query iptables 2>&1 || true

  printf '###SECTION:iptables_ipv4###\n'
  if command -v iptables-legacy-save >/dev/null 2>&1; then
    iptables-legacy-save -c 2>&1 || printf '###UNAVAILABLE###\n'
  elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save -c 2>&1        || printf '###UNAVAILABLE###\n'
  else
    printf '###UNAVAILABLE###\n'
  fi

  printf '###SECTION:iptables_ipv6###\n'
  if command -v ip6tables-legacy-save >/dev/null 2>&1; then
    ip6tables-legacy-save -c 2>&1 || printf '###UNAVAILABLE###\n'
  elif command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save -c 2>&1        || printf '###UNAVAILABLE###\n'
  else
    printf '###UNAVAILABLE###\n'
  fi
}

collect > "$OUT" 2>&1
chown "$SSH_USER" "$OUT" 2>/dev/null || true  # see note below

# These printf lines go to stdout — what az run-command / SSH captures
printf 'PROBE_OUTPUT_PATH=%s\n' "$OUT"
printf 'PROBE_OUTPUT_BYTES=%d\n' "$(wc -c < "$OUT")"
```

**chown note:** `az vm run-command invoke` executes as root. The output file is root-owned
mode 600. The SSH user (`azureuser`) cannot read it for SCP retrieval. `chown "$SSH_USER"`
transfers ownership so SCP succeeds. For `--provider ssh` (probe runs via `sudo bash -s`)
the same behaviour applies — root creates the file, SSH user needs to read it.

The probe stdout contains only the two `printf` lines (< 100 bytes). The full probe output
lives in the `mktemp`-generated file on the VM with mode 0600.

---

## Output Retrieval: Write-to-File-then-SCP

**Why:** `az vm run-command invoke` has a documented ~4 KB output limit. `iptables-save` for a production system with fail2ban, Docker, and kube-proxy can easily exceed 10–50 KB. Silent truncation at the byte boundary produces a partial JSON parse or a missing COMMIT, both of which are silent failures harder to detect than an explicit retrieval step.

**Two SSH topology cases (both providers):**

```
Case 1 — Target VM has a public IP (direct SSH/SCP):
  TARGET_VM_IP = target's public IP
  BASTION_PUBLIC_IP not set

  scp -o StrictHostKeyChecking=yes -o BatchMode=yes \
      -i "{target_ssh_key}" \
      {ssh_user}@{target_vm_ip}:{PROBE_OUTPUT_PATH} \
      {local_tmp_path}

Case 2 — Target VM has only a private IP (via bastion host):
  TARGET_VM_IP = target's private IP
  BASTION_PUBLIC_IP = bastion's public IP

  scp -o StrictHostKeyChecking=yes -o BatchMode=yes \
      -i "{target_ssh_key}" \
      -o "ProxyCommand=ssh -W %h:%p -i '{bastion_ssh_key}' \
          -o StrictHostKeyChecking=yes -o BatchMode=yes \
          {ssh_user}@{bastion_public_ip}" \
      {ssh_user}@{target_vm_ip}:{PROBE_OUTPUT_PATH} \
      {local_tmp_path}

  ProxyCommand is used (not ProxyJump) so that a separate -i key can be specified
  for the bastion hop without relying on agent forwarding.
  bastion_ssh_key defaults to target_ssh_key when both hosts share the same key.

  Prerequisite: known_hosts must contain entries for both bastion and target VM.
  One-time setup: ssh-keyscan on each host.
```

**Retrieval flow (both cases):**
```
1. Run probe:
   --provider azure: az vm run-command invoke --scripts @probe.sh --parameters SESSION_ID SSH_USER
   --provider ssh:   ssh ... {ssh_user}@{target_vm_ip} "sudo bash -s -- SESSION_ID SSH_USER" < probe.sh
   → response contains PROBE_OUTPUT_PATH and PROBE_OUTPUT_BYTES only

2. SCP retrieval (Case 1 or Case 2 as above)

3. Parse the local file with section delimiter protocol
   → hand each section to the appropriate parser

4. Remove remote temp file via SSH (in finally block — cleanup failure → warning, not abort):
   If this fails: log warning to _commands.log; investigation result is still valid.
```

**Post-MVP option:** Staged retrieval via blob storage (probe writes to Azure Blob, inspector reads from blob). Not needed for MVP.

---

## Shell Injection Pattern: Standalone vs Ghost Agent

`FirewallInspector` never imports `safe_exec_shell`. The shell is always injected.

```python
class FirewallInspector:
    def __init__(self, shell, provider):
        self._shell = shell        # LocalShell or SafeExecShell — same dict contract
        self._provider = provider
```

### `LocalShell` (standalone CLI mode)

```python
import subprocess

class LocalShell:
    """Thin subprocess wrapper. Same return contract as SafeExecShell. No HITL. No audit log."""

    def execute(self, cmd: dict) -> dict:
        result = subprocess.run(
            cmd["command"], shell=True, capture_output=True, text=True, timeout=60
        )
        return {
            "status":    "success" if result.returncode == 0 else "error",
            "output":    result.stdout + result.stderr,
            "exit_code": result.returncode,
            "audit_id":  "local",
        }
```

### Ghost Agent mode

```python
# In ghost_agent.py — no changes to FirewallInspector
from safe_exec_shell import SafeExecShell
shell = SafeExecShell(hitl_callback=..., audit_dir=...)
inspector = FirewallInspector(shell=shell, provider=AzureProvider(shell, ...))
```

All `az vm run-command invoke` calls flow through the HITL classifier automatically. No `FirewallInspector` code changes needed.

---

## Safety Classification

The SafeExecShell four-tier classification for each command issued by this tool:

| Command | Classification | Why |
|---------|---------------|-----|
| `az vm run-command invoke` (probe script) | **RISKY** (HITL gate fires) | Verb `invoke` is not in `_AZ_SAFE_VERBS` → Tier 2 "unknown verb — default RISKY". Correct: this command runs code on a VM as root and creates a file there. |
| `scp -o StrictHostKeyChecking=yes -o ProxyJump=...` | **RISKY** (HITL gate fires) | `scp` is not in `_ALWAYS_SAFE` → Tier 1 returns RISKY. Correct: this is a file-transfer operation the operator should approve. |
| `ssh ... rm {remote_path}` | **RISKY** (HITL gate fires) | `ssh` not in allowlist; `rm` is in `_DESTRUCTIVE_COMMANDS` → Tier 3 flags it. Correct: operator should confirm cleanup. |

**In standalone mode (`LocalShell`):** all three commands execute directly with no HITL gate, which is correct for single-engineer CLI use.

**In Ghost Agent mode:** all three fire the HITL gate. The probe invocation gate must display the full script content and its sha256 hash. This is one approval set per investigation session.

The probe script itself makes no changes to firewall rules. It calls `iptables-save -c` (read-only). The `run-command invoke` classification reflects the power of the mechanism (arbitrary code on VM as root), not the intent of this specific script.

---

## Output Schema

### Snapshot (`{session_id}_snapshot.json`)

```json
{
  "snapshot_at": "2026-03-14T10:00:00Z",
  "session_id": "fw_20260314_100000",
  "vm_name": "prod-vm-01",
  "resource_group": "prod-rg",
  "family": "ipv4",
  "framework": "iptables-legacy",
  "framework_confidence": "high",
  "parse_warnings": [],
  "tables": { ... }       // parse_iptables_save() output
}
```

### Drift report (`{session_id}_drift.json`)

```json
{
  "diff_at": "2026-03-14T12:00:00Z",
  "session_id": "fw_20260314_120000",
  "vm_name": "prod-vm-01",
  "resource_group": "prod-rg",
  "baseline_snapshot": "fw_20260314_100000_snapshot.json",
  "drift_detected": true,
  "has_critical_changes": true,
  "chain_classifications": {
    "INPUT": "user-defined",
    "DOCKER": "structural",
    "KUBE-SEP-XXXX": "ephemeral"
  },
  "summary": { ... },     // diff_rulesets() summary
  "changes": { ... },     // diff_rulesets() changes (ephemeral-tier rules suppressed)
  "ephemeral_summary": {  // count-only for suppressed tiers
    "KUBE-SEP-*": {"baseline_rule_count": 142, "current_rule_count": 148}
  }
}
```

---

## Baseline / Drift Pattern

Mirrors `--is-baseline` / `--compare-baseline` from Pipe Meter.

```bash
# Azure VM — capture baseline before maintenance window
python3 firewall_inspector.py \
  --provider azure \
  --vm-name prod-vm-01 \
  --resource-group prod-rg \
  --target-vm-ip 172.190.88.171 \
  --target-ssh-key ~/.ssh/id_rsa \
  --ssh-user azureuser \
  --is-baseline \
  --session-id pre_change_20260314

# Azure VM — after change, compare
python3 firewall_inspector.py \
  --provider azure \
  --vm-name prod-vm-01 \
  --resource-group prod-rg \
  --target-vm-ip 172.190.88.171 \
  --target-ssh-key ~/.ssh/id_rsa \
  --ssh-user azureuser \
  --compare-baseline pre_change_20260314

# Multipass / bare metal — same pattern, no Azure flags needed
python3 firewall_inspector.py \
  --provider ssh \
  --target-vm-ip 192.168.2.6 \
  --ssh-user ubuntu \
  --is-baseline \
  --session-id pre_change_20260314

# Using a config file (recommended for repeated use)
python3 firewall_inspector.py --config config.env --is-baseline
python3 firewall_inspector.py --config config.env --compare-baseline pre_change_20260314
```

Artifacts are written to `{audit_dir}/{session_id}_snapshot.json` and (when diffing) `{session_id}_drift.json`.

---

## CLI Interface

```
firewall_inspector.py
  --config FILE               KEY=VALUE config file (CLI flags override)
  --provider {azure,ssh}      azure (default): probe via az vm run-command invoke
                              ssh: probe via direct SSH — use for Multipass, bare metal,
                                   any SSH-accessible Linux host without az CLI
  --vm-name NAME              Azure VM name (required for --provider azure)
                              Optional display label for --provider ssh
  --resource-group RG         Azure resource group (required for --provider azure)
  --subscription-id ID        Azure subscription ID (optional; uses az default if omitted)
  --target-vm-ip IP           IP of the VM to inspect
                              Case 1 (direct): public IP
                              Case 2 (via bastion): private IP
                              --provider ssh: any reachable IP
  --target-ssh-key PATH       SSH private key for target VM (default: ~/.ssh/id_rsa)
  --bastion-public-ip IP      Bastion public IP (Case 2 only)
  --bastion-ssh-key PATH      SSH key for bastion host (Case 2 only; defaults to --target-ssh-key)
  --ssh-user USER             SSH username (default: azureuser; use ubuntu for Multipass)
  --audit-dir DIR             Directory for artifacts (default: ./audit)
  --is-baseline               Save snapshot as baseline
  --compare-baseline ID       Session ID of baseline snapshot to compare against
  --session-id ID             Override auto-generated session ID (format: fw_YYYYMMDD_HHMMSS)
  --family {ipv4,ipv6,both}   Address family to inspect (default: ipv4)
```

All flags can be supplied via config file (KEY=VALUE format). CLI flags always override config file values.

---

## MVP Scope

**Shipped:**
- iptables-legacy and iptables-nft detection (Module 4)
- iptables-save -c parse via existing Module 1+2
- Diff via existing Module 5
- Three-tier chain classification (Module 6) — ephemeral tier suppressed in drift report
- Write-to-file-then-SCP retrieval (challenge 2 mitigation)
- `--is-baseline` / `--compare-baseline` pattern
- Standalone CLI with `LocalShell`
- IPv4 and IPv6 (`--family ipv4 | ipv6 | both`)
- Two SSH topology cases: Case 1 (direct) and Case 2 (via bastion, ProxyCommand)
- `--provider {azure|ssh}` — Azure VM or any SSH-accessible Linux host (Multipass, bare metal)
- `--provider ssh` validated end-to-end on Multipass Ubuntu 22.04 (iptables-legacy)
- Single VM scope

**Post-MVP:**
- nftables-native probe and parse path (Module 3)
  - Ubuntu 22.04/24.04 default to iptables-nft; fresh VMs with no rules return 0 tables
  - Requires native `nft list ruleset` probe section and nft-specific parser
- `mixed` framework detection
- `--explain` feature — LLM explanation of snapshot via Claude API (design doc: `docs/explain-feature-design.md`)
- Azure Blob baseline storage (team sharing)
- Ghost Agent `detect_firewall_drift` tool integration
- VPN chain patterns in `chain_classifier.py` (extensible by design — add to `_STRUCTURAL_PATTERNS`)

---

## Build Order

1. `framework_detector.py` + tests (Module 4)
2. `chain_classifier.py` + tests (Module 6)
3. `providers.py` (`LocalShell` + `AzureProvider` with SCP retrieval)
4. `firewall_inspector.py` (orchestrator — ties all modules together)
5. End-to-end test with `LocalShell` against a fixture probe output file

---

*Concept document: `../concepts/vm-firewall-inspector-concept.md`*
*Build challenges: `../concepts/vm-firewall-inspector-build-challenges.md`*
*Analysis: `../concepts/vm-firewall-inspector-analysis.md`*
