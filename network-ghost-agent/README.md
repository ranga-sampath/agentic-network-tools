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

Ghost Agent requires three sibling modules from this repository. **Clone the full repo** — do not download this directory alone.

```
agentic-network-tools/
├── agentic-safety-shell/            ← required: command execution safety layer
├── agentic-pcap-forensic-engine/    ← required: PCAP forensic analysis
├── agentic-cloud-orchestrator/      ← required: Azure packet capture orchestration
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

### NSG / routing investigation (no captures)
```bash
uv run --python 3.12 python ghost_agent.py \
  --resource-group  <your-resource-group> \
  --location        <azure-region>
```

### With packet capture support
```bash
uv run --python 3.12 python ghost_agent.py \
  --resource-group    <your-resource-group> \
  --location          <azure-region> \
  --storage-account   <storage-account-name> \
  --storage-container <container-name>
```

### Resume an interrupted session
```bash
uv run --python 3.12 python ghost_agent.py --resume <session-id>
```

---

## Demo Scripts

Six end-to-end demo scenarios with full presenter guides are in `demo/`:

| Use Case | Scenario | Duration |
|---|---|---|
| A — "The Invisible Wall" | NSG deny rule blocks a port | ~8 min |
| B — "The Wire Doesn't Lie" | Single-VM packet capture + PCAP forensics | ~15 min |
| C — "Show Me Both Sides" | Dual-end capture + asymmetry comparison | ~20 min |
| D — "The Two-Headed Hydra" | Two independent NSG misconfigurations | ~10 min |
| E — "The Phantom Route" | UDR black hole — NSG clean, traffic vanishes | ~15 min |
| F — "The Silent Gatekeeper" | Service endpoint removed — storage silently fails | ~12 min |

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
uv run pytest tests/ -v
```
