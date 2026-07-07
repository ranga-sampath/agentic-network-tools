# Ghost Agent — AI Network Forensics Investigator 👻

**Autonomous, audited network diagnostics for Azure cloud environments.**

Ghost Agent is a conversational CLI that acts as a senior network forensics investigator. You describe a symptom in plain English. It forms hypotheses, runs Azure control-plane queries and packet captures, gates every risky action through you, and produces a forensic RCA report with a full audit trail.

---

## What It Does

- Forms 2-4 falsifiable hypotheses from a vague symptom description
- Escalates autonomously: local probes → Azure API reads → packet captures
- Every command is classified by the Safety Shell (SAFE / RISKY / BLOCKED) — risky commands require your explicit approval before running
- Captures wire traffic via Azure Network Watcher and runs automated PCAP forensic analysis
- Produces a structured investigation report and audit trail (`audit/`)
- Supports session resume after interruption, with SHA-256 integrity checking

---

## Dependencies

Ghost Agent requires four sibling modules. **Clone the full repo** — do not download this directory alone.

```
agentic-network-tools/
├── agentic-safety-shell/            ← required: command execution safety layer
├── agentic-pcap-forensic-engine/    ← required: PCAP forensic analysis
├── agentic-cloud-orchestrator/      ← required: Azure packet capture orchestration
├── agentic-pipe-meter/              ← required: VM-to-VM performance measurement (use cases G–L)
├── netfilter-inspector/             ← required: OS-layer firewall inspection (use cases J–K, M–O, T)
├── effective-network-inspector/     ← required: Azure control-plane drift detection (use cases P–R)
├── effective-route-inspector/       ← required: Azure route selection / LPM verdict (use cases S–T)
├── security-rule-inspector/         ← required: Azure NSG effective rule evaluation (use cases U–V)
└── network-ghost-agent/             ← you are here
```

---

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Azure CLI authenticated: `az login`
- A Gemini API key: [aistudio.google.com](https://aistudio.google.com)
- Azure infrastructure: two VMs in the same VNet, Azure Network Watcher enabled, a storage account for captures

---

## Installation

```bash
git clone https://github.com/<your-org>/agentic-network-tools
cd agentic-network-tools/network-ghost-agent
```

Set your API key (or add to a `.env` file):
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```

---

## Run

### Full-feature run (recommended — Pipe Meter + Netfilter Inspector enabled)
```bash
# Fill in demo/config.env once, then:
python ghost_agent.py --config demo/config.env
```

### NSG / routing investigation (no captures, no config file)
```bash
uv run --python 3.12 python ghost_agent.py \
  --resource-group  <your-resource-group> \
  --location        <azure-region>
```

### With packet capture support (no config file)
```bash
uv run --python 3.12 python ghost_agent.py \
  --resource-group    <your-resource-group> \
  --location          <azure-region> \
  --storage-account   <storage-account-name> \
  --storage-container <container-name>
```

> **Note:** `run_pipe_meter` (use cases G–L), `detect_config_drift` (use cases J–K, M–O, T), `detect_effective_network_drift` (use cases P–R), `effective_route_inspector` (use cases S–T), and `inspect_nsg` (use cases U–V) all require a `--config` file. Individual flags are sufficient for use cases A–F only.

### OS firewall inspection (`detect_config_drift`)

The agent uses `detect_config_drift` to probe iptables/nftables state on the target VM. The config file governs whether to connect via the Azure control plane (`PROVIDER=azure`) or direct SSH (`PROVIDER=ssh`).

```bash
# Prompt the agent to capture a baseline
"Take a firewall baseline snapshot of the destination VM"

# Prompt the agent to detect drift
"Compare the current firewall state against the baseline from session fw_20260318_095645"

# Ask for an explanation of the current firewall state
"Explain the current firewall rules on the destination VM"

# Ask for an explanation of what changed
"Explain what changed in the firewall since the baseline"
```

The `explain` mode delegates to the LLM explanation engine (`iptables_explain` or `nftables_explain`) and includes the explanation verbatim in the investigation report.

### Resume an interrupted session
```bash
uv run --python 3.12 python ghost_agent.py --resume <session-id>
```

A resumed session continues on the `--llm-provider` and `--model` stored in the session file —
no need to repeat the flags you started with. Passing either flag explicitly on resume overrides
the stored value (a `[WARN]` notice is printed) and the session record is updated to match.

---

## Demo Scripts

Twenty-two end-to-end demo scenarios with full presenter guides are in `demo/`. Use cases A–F cover NSG, routing, and packet capture investigations. Use cases G–L add VM-to-VM performance measurement via Pipe Meter and require `agentic-pipe-meter/` to be present. Use cases M–O cover OS-layer firewall faults (fail2ban, CIS hardening, Docker daemon) invisible to the Azure control plane and require `netfilter-inspector/` to be present. Use cases P–R cover Azure control-plane drift detection — ENI baseline diffs, change-window verification, and the `drift_detected: false` certificate — and require `effective-network-inspector/` to be present. Use cases S–T cover routing layer fault diagnosis via the effective route inspector — LPM-based verdict, blackhole detection, and multi-fault iterative investigation. Use cases U–V cover Azure NSG effective rule evaluation — dual-gate verdict for a specific flow and full compliance audit — and require `security-rule-inspector/` to be present.

| Use Case | Scenario | Duration |
|---|---|---|
| A — "The Invisible Wall" | NSG deny rule blocks a port | ~8 min |
| B — "The Wire Doesn't Lie" | Single-VM packet capture + PCAP forensics | ~15 min |
| C — "Show Me Both Sides" | Dual-end capture + asymmetry comparison | ~20 min |
| D — "The Two-Headed Hydra" | Two independent NSG misconfigurations | ~10 min |
| E — "The Phantom Route" | UDR black hole — NSG clean, traffic vanishes | ~15 min |
| F — "The Silent Gatekeeper" | Service endpoint removed — storage silently fails | ~12 min |
| G — "Bandwidth Heist" | tc tbf throttle on dest VM — throughput drops 90% | ~12 min |
| H — "Latency Landmine" | tc netem 50ms delay + jitter — latency spikes with HIGH_VARIANCE | ~12 min |
| I — "Packet Grinder" | Combined loss + delay + corruption → both metrics degraded | ~15 min |
| J — "The Shadow Firewall" | iptables DROP port 5001 invisible to NSG audit; PCAP proves OS-level block | ~20 min |
| K — "The Bandwidth Thief" | tc tbf rate throttle + iptables ICMP drop — two independent OS-level faults | ~20 min |
| L — "The Double Lock" | NSG deny + tc netem on the same dest VM — two faults, two remediations | ~15 min |
| M — "The Banned Guest" | fail2ban ban blocks partner IP — NSG says port 22 open | ~8 min |
| N — "The Hardening Surprise" | CIS hardening flips INPUT policy to DROP — NSG clean, all traffic dropped | ~10 min |
| O — "The Docker Coup" | Docker daemon restart silently rewrites OS firewall — NSG unchanged | ~10 min |
| P — "The Rollback That Wasn't" | ENI baseline diff proves incomplete rollback — NSG DENY + OS DROP left behind | ~12 min |
| Q — "The Rule Nobody Checked" | Subnet NSG priority-100 deny overrides NIC NSG allow; customer claims nothing changed | ~12 min |
| R — "The 60-Second Sign-Off" | `drift_detected: false` as a machine-readable change-management certificate | ~10 min |
| S — "The Accidental Blackhole" | User /32 UDR → None wins by LPM; NSG clean, VM-to-VM traffic silently dropped | ~8 min |
| T — "The Phantom Firewall" | Phantom NVA all-internet blackhole + iptables port 80 — two-phase iterative investigation | ~15 min |
| U — "The Hidden Gate" | Subnet NSG denies at Gate 1 — portal NIC NSG shows all ALLOW | ~10 min |
| V — "The Open Doorway" | NSG audit surfaces forgotten allow-all rule after 18 months of drift | ~8 min |

```bash
# One-time setup
cp demo/sample_config.env demo/config.env
vi demo/config.env   # fill in your Azure resource names

# Run a demo scenario
./demo/use_case_a/setup.sh
uv run --python 3.12 python ghost_agent.py --resource-group <rg>
./demo/use_case_a/teardown.sh
```

See `demo/README.md` for the full presenter guide and narration cues.

---

## Audit Output

| File | Contents |
|---|---|
| `audit/ghost_report_<session>.md` | Investigation findings, root cause, recommended fix |
| `audit/ghost_audit_<session>.md` | Full command evidence, hypothesis log, integrity statement |
| `audit/shell_audit_<session>.jsonl` | Every command: classification, HITL decision, output summary |
| `audit/orchestrator_tasks_<session>.jsonl` | Capture task registry with blob paths and forensic report refs |

---

## Running Tests

```bash
cd network-ghost-agent
uv run --python 3.12 python -m pytest tests/ -v
# → 106 passed, 3 skipped, 2 xfailed
```

Skipped tests (I5, I6, I7) require live Azure or Gemini API credentials.
xFailed tests (L8, E6) are known unimplemented items tracked in the design doc.
