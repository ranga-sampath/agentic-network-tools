# Agentic Network Tools

A collection of AI-powered tools for autonomous network diagnostics, packet forensics, and safe command execution in cloud environments.

---

Built according to the principles of Deterministic Agency and Evidence Hierarchy. See the full [Engineering Manifesto](https://github.com/ranga-sampath/engineering-manifesto) for the architectural philosophy.

## Tools

### 👻 [Network Ghost Agent — AI Network Forensics Investigator](./network-ghost-agent/)
Conversational CLI that investigates Azure network problems autonomously. Describe a symptom; it forms hypotheses, runs Azure API queries and packet captures, gates every risky action through you, and produces a forensic RCA report.

> Requires the sibling libraries below. Clone the full repo.

### 📏 [Agentic Pipe Meter](./agentic-pipe-meter/)
VM-to-VM network performance measurement tool. Runs `qperf` (TCP latency) and `iperf2` (8 parallel TCP streams) between two Azure VMs, computes P90 statistics over configurable iterations, checks NSG ports pre-flight, compares against a stored baseline, and uploads a structured JSON artifact to Azure Blob Storage. Usable as a standalone CLI tool or as an integrated component of Ghost Agent for performance investigation scenarios.

### 🛡️ [Agentic Safety Shell](./agentic-safety-shell/)
Security-first middleware that sits between an AI agent and your infrastructure. Classifies every proposed command into four tiers (SAFE / RISKY / BLOCKED / DENIED) and enforces a human-in-the-loop gate on anything that could affect infrastructure state. Usable as a standalone library.

### 🔍 [Agentic PCAP Forensic Engine](./agentic-pcap-forensic-engine/)
AI-powered packet inspection engine. Feeds a `.pcap` or `.cap` file through `tshark`, extracts structured network metrics, and produces an expert forensic report with root-cause analysis. Usable as a standalone CLI tool.

### ☁️ [Agentic Cloud Orchestrator](./agentic-cloud-orchestrator/)
Azure Network Watcher packet capture lifecycle manager. Handles capture creation, status polling, blob download, and forensic analysis as a single audited async task. Usable as a standalone library.

---

## Quick Start

```bash
git clone https://github.com/<your-org>/agentic-network-tools
cd agentic-network-tools

# Run Ghost Agent (uses all sibling libraries)
cd network-ghost-agent
cp demo/sample_config.env demo/config.env   # fill in your Azure details
export GEMINI_API_KEY="your-key"
uv run --python 3.12 python ghost_agent.py --resource-group <your-rg> --location <region>

# Measure VM-to-VM latency and throughput with Pipe Meter
cd agentic-pipe-meter
cp config.env.example config.env   # fill in your Azure details
uv run python pipe_meter.py --config config.env

# Use the Safety Shell standalone
cd agentic-safety-shell
uv run python safe_exec_shell.py

# Use the PCAP engine standalone
cd agentic-pcap-forensic-engine
uv run python pcap_forensics.py your-capture.pcap
```

---

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Azure CLI (`az login`) — for Ghost Agent, Pipe Meter, and Cloud Orchestrator
- `tshark` — for PCAP Forensic Engine
- `qperf` and `iperf2` on both VMs — for Pipe Meter (Pipe Meter can install them with your approval)
- A Gemini API key from [aistudio.google.com](https://aistudio.google.com)

---

## ✍️ Writing & Deep Dives

* **[Network Ghost Agent: An Agentic Network Forensics Investigator for Cloud Infrastructure](https://youplusai.com/network-ghost-agent/)** *A deep dive into encoding senior network engineering methodology into autonomous, safe-exec AI agents.*

