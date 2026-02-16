# Agentic PCAP Forensic Engine 🔍🌐

An AI-powered diagnostic engine designed to perform packet inspection and automated root-cause analysis on network captures (`.pcap`).

## 🚀 Overview
This tool bridges the gap between raw network telemetry and actionable engineering insights. It solves the "LLM Context Window" problem by using a **local semantic pre-processor** to surgically extract protocol metadata using TShark, reducing data volume by up to 95% before leveraging **Gemini 2.0 Flash** for intelligent forensic reasoning.



## 🛠️ Key Capabilities
- **Layer 2 (ARP):** Detects IP-MAC conflicts (Spoofing) and identifies "Silent Hosts" in the broadcast domain.
- **Layer 3 (ICMP):** Automated **Path MTU Discovery (PMTUD)** failure detection, identifying exact next-hop MTU bottlenecks.
- **Layer 4 (TCP):** Correlates retransmission storms with underlying ICMP "Host Unreachable" signals.
- **Layer 7 (DNS):** Detects Malware Beaconing (DGA patterns), NXDOMAIN spikes, and resolution latency.

## ⚡ Technical Stack
- **Orchestration:** [uv](https://docs.astral.sh/uv/) for ultra-fast, reproducible Python environment management.
- **Extraction:** TShark (Wireshark CLI) for surgical header-field parsing.
- **AI Brain:** Google Gemini 2.0 (Flash/Pro) for protocol heuristics and RCA.
- **Data Engineering:** Custom Semantic JSON schema optimized for LLM token efficiency.

---

## 📦 Installation & Setup

### 1. Prerequisites
Ensure you have `tshark` (Wireshark) installed on your system.
```bash
# macOS (Homebrew)
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark

# Dependency management
We use uv for dependency management. If you don't have it, install it via curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone [https://github.com/your-username/nw-forensics.git](https://github.com/your-username/nw-forensics.git)
cd nw-forensics

# Sync dependencies and create virtual environment
uv sync

# API Key
The PCAP forensic engine requires a Google Gemini API key. Add your key to the .env file in the project root directory

GEMINI_API_KEY=your_actual_api_key_here

### Flexibility & Extensibility
The architecture is provider-agnostic. While it defaults to **Gemini 2.0 Flash**, you can modify the model initialization in `pcap_forensics.py` to target other Gemini versions (e.g., Gemini 2.5 Pro) or swap the client logic to support other providers like OpenAI or Anthropic.

# Running the forensic engine
Run the script by pointing it to any .pcap or .pcapng file. The tool will validate the input, extract metadata, and generate a final Markdown report.

uv run python pcap_forensics.py --semantic_dir <dir to keep semantic .json files> --report_dir <dir where forensic report will be created> path/to/capture.pcap

# Understanding the Output
The tool produces a technical, detailed report including:

Executive Summary: A 2-3 sentence high-level Root Cause Analysis.

Anomaly Table: Severity-ranked protocol violations with frame-level references.

Remediation: Actionable CLI commands (e.g., ip link set dev eth0 mtu 1400) to resolve the issue.

# Test data

The repository includes a script to generate binary .pcap files with specific anomalies for testing and verification.

uv run tests/generate_test_pcaps.py

