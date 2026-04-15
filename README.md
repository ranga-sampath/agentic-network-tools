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

### 🔥 [Netfilter Inspector](./netfilter-inspector/)
OS-layer firewall state capture and drift detection for Linux VMs. Retrieves `iptables`/`ip6tables` rulesets from any SSH-accessible VM (Azure, Multipass, bare-metal), stores point-in-time baseline snapshots, and diffs against a prior baseline to detect configuration drift. Classifies changes by security significance (DROP/REJECT rule additions, default policy changes) and suppresses ephemeral chain noise (Kubernetes pod chains). Covers both IPv4 and IPv6 in a single operation. Usable as a standalone CLI tool or as an integrated component of Ghost Agent for OS-layer firewall investigation scenarios.

### 🌐 [Effective Network Inspector](./effective-network-inspector/)
Azure control-plane computed state capture and drift detection. Snapshots the **effective route table** (`az network nic show-effective-route-table`) and **effective NSG evaluation** (`az network nic list-effective-nsg`) per NIC — the combined subnet NSG + NIC NSG computed result that no individual NSG resource query can surface. Diffs two snapshots to detect BGP route withdrawal, UDR changes, and NSG evaluation drift that produce no ARM resource change and therefore appear in no existing Azure audit tool. Produces `drift_detected: false` as an explicit, SHA-256 verified negative confirmation — usable as a machine-readable change-record artifact. Integrated into Ghost Agent as `detect_effective_network_drift`.

### 🔐 [Security Rule Inspector](./security-rule-inspector/)
Point-in-time Azure NSG effective rule evaluator. Applies the **dual-gate model** (`az network nic list-effective-nsg`) to produce a machine-evaluated verdict for a specific traffic flow (ALLOW / DENY / INDETERMINATE) or a full inbound/outbound rule inventory for compliance audits. Correctly handles the inbound evaluation order — subnet NSG at Gate 1, NIC NSG at Gate 2 — which the Azure portal does not surface. Returns the decisive rule, the gate it fired at, and any unresolvable service tags. Integrated into Ghost Agent as `inspect_nsg`.

### 🗺️ [Effective Route Inspector](./effective-route-inspector/)
Deterministic Azure route selection engine. Queries the effective route table at the VM NIC, runs the full Azure LPM algorithm in pure Python (CIDR containment → longest prefix match → source precedence: User > VirtualNetworkGateway > Default → BGP tie-break), and returns a structured verdict naming the winning route, its source tier, and any anomalies (BLACKHOLE, INVALID_SHADOW, NVA). No AI in the analysis path — deterministic end to end. Integrated into Ghost Agent as `effective_route_inspector` for routing-layer fault investigation.

---

## Quick Start

```bash
git clone https://github.com/<your-org>/agentic-network-tools
cd agentic-network-tools

# Run Ghost Agent (uses all sibling libraries)
cd network-ghost-agent
cp demo/sample_config.env demo/config.env   # fill in your Azure details
export GEMINI_API_KEY="your-key"
python ghost_agent.py --config demo/config.env

# Measure VM-to-VM latency and throughput with Pipe Meter
cd agentic-pipe-meter
cp config.env.example config.env   # fill in your Azure details
uv run python pipe_meter.py --config config.env

# Capture OS-layer firewall baseline and compare
cd netfilter-inspector/firewall-inspector
cp config.env.example config.env   # fill in VM details
python3 firewall_inspector.py --config config.env --is-baseline --session-id pre_change
python3 firewall_inspector.py --config config.env --compare-baseline pre_change

# Snapshot Azure effective routes + NSG evaluation and compare
cd effective-network-inspector
python effective_network_inspector.py \
  --scope vm --vm-name <vm-name> \
  --resource-group <rg> \
  --is-baseline --session-id pre_window
python effective_network_inspector.py \
  --scope vm --vm-name <vm-name> \
  --resource-group <rg> \
  --compare-baseline pre_window

# Use the Safety Shell standalone
cd agentic-safety-shell
uv run python safe_exec_shell.py

# Use the PCAP engine standalone
cd agentic-pcap-forensic-engine
uv run python pcap_forensics.py your-capture.pcap
```

---

## Prerequisites

- Python 3.12+ (3.9+ sufficient for Netfilter Inspector standalone)
- [uv](https://docs.astral.sh/uv/) package manager
- Azure CLI (`az login`) — for Ghost Agent, Pipe Meter, and Cloud Orchestrator
- `tshark` — for PCAP Forensic Engine
- `qperf` and `iperf2` on both VMs — for Pipe Meter (Pipe Meter can install them with your approval)
- SSH key access to target VM — for Netfilter Inspector (`--provider ssh`)
- A Gemini API key from [aistudio.google.com](https://aistudio.google.com)

---

## ✍️ Writing & Deep Dives

* **[Network Ghost Agent: An Agentic Network Forensics Investigator for Cloud Infrastructure](https://youplusai.com/network-ghost-agent/)** *A deep dive into encoding senior network engineering methodology into autonomous, safe-exec AI agents.*

