# Agentic Cloud Orchestrator ☁️

**Azure Network Watcher packet capture orchestrator for autonomous network agents.**

The **Agentic Cloud Orchestrator** manages the full lifecycle of Azure Network Watcher packet captures — creation, polling, download, and forensic analysis — as a single, audited async task. It is designed to be called by an AI agent (such as Ghost Agent) but can also be used standalone.

---

## What It Does

- Creates Azure Network Watcher packet captures on target VMs via the Azure CLI
- Burst-polls capture status (5-second intervals) and reports live provisioning state
- Downloads the completed `.cap` file from Azure Blob Storage to `/tmp/captures/`
- Invokes the `agentic-pcap-forensic-engine` for automated forensic analysis
- Manages orphan capture cleanup across sessions
- Writes a structured task registry (`audit/orchestrator_tasks_<session>.jsonl`) for full audit trail

---

## Prerequisites

- Python 3.12+
- Azure CLI (`az`) authenticated: `az login`
- Azure Network Watcher enabled in your subscription region
- `NetworkWatcherAgentLinux` extension installed on target VMs
- `agentic-pcap-forensic-engine` in the sibling directory (for forensic analysis step)
- A storage account and container for capture blobs

---

## Standalone Usage

```python
from agentic_safety_shell import SafeExecShell  # or any shell wrapper
from cloud_orchestrator import CloudOrchestrator

shell = SafeExecShell(session_id="my_session", audit_dir="./audit")
orch = CloudOrchestrator(
    shell=shell,
    session_id="my_session",
    task_dir="./audit",
    storage_container="pktcaptures",
    location="eastus",
)

result = orch.orchestrate(
    intent="capture_traffic",
    parameters={
        "target":               "my-vm",
        "resource_group":       "my-rg",
        "storage_account":      "mystorageaccount",
        "duration_seconds":     60,
        "investigation_context": "Checking for TCP retransmissions on port 8080",
    },
)
print(result["status"])   # task_completed | task_failed | task_pending
```

---

## Key Design Decisions

- **`.cap` extension required** — Azure Network Watcher writes captures as `.cap`, not `.pcap`. The orchestrator enforces this.
- **One capture per VM** — Azure allows only one registered Network Watcher capture per VM at a time. The orchestrator tracks active tasks and rejects duplicate requests.
- **`--location` required** — `az network watcher packet-capture` commands (`show`, `delete`, `list`) require `--location`, not `--resource-group`. The orchestrator resolves the location automatically.
- **Forensic analysis runs inside polling** — the PCAP engine is invoked immediately after a successful download, within the `check_task` polling loop.

---

## Audit Output

| File | Contents |
|---|---|
| `audit/orchestrator_tasks_<session>.jsonl` | One JSON record per task: intent, parameters, status, blob path, forensic report path |

---

## Running Tests

```bash
cd agentic-cloud-orchestrator
uv run pytest tests/ -v
```
