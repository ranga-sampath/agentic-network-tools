# Agentic Network Tools

A collection of AI-powered tools for autonomous network diagnostics, packet forensics, and safe command execution in cloud environments.

---

## Tools

### 👻 [Ghost Agent — AI Network Forensics Investigator](./agentic-network-ghost-troubleshooter/)
Conversational CLI that investigates Azure network problems autonomously. Describe a symptom; it forms hypotheses, runs Azure API queries and packet captures, gates every risky action through you, and produces a forensic RCA report.

> Requires the three sibling libraries below. Clone the full repo.

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

# Run Ghost Agent (uses all three sibling libraries)
cd agentic-network-ghost-troubleshooter
cp demo/sample_config.env demo/config.env   # fill in your Azure details
export GEMINI_API_KEY="your-key"
uv run --python 3.12 python ghost_agent.py --resource-group <your-rg> --location <region>

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
- Azure CLI (`az login`) — for Ghost Agent and Cloud Orchestrator
- `tshark` — for PCAP Forensic Engine
- A Gemini API key from [aistudio.google.com](https://aistudio.google.com)
