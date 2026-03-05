# Agentic Pipe Meter — VM-to-VM Network Performance Measurement 📏

**Automated, audited latency and throughput testing between Azure VMs.**

Agentic Pipe Meter orchestrates a complete VM-to-VM performance measurement pipeline. It checks NSG ports, verifies tool installation on both VMs, runs `qperf` (TCP latency) and `iperf2` (8 parallel TCP streams) over configurable iterations, computes P90 statistics, compares against a stored baseline, and uploads a structured JSON artifact to Azure Blob Storage — with every shell command classified, gated if risky, and written to an audit trail.

---

## What It Does

- **Pre-flight checks:** verifies NSG ports 5001 (iperf2) and 19765 (qperf) are open between source and destination VMs; generates exact `az network nsg rule create` commands for any blocked port and applies them only with your explicit approval
- **Tool verification:** confirms `qperf` and `iperf2` are installed on both VMs; detects whether `apt` or `yum` is available and offers to install missing tools, proceeding only on your approval through the HITL gate
- **Warm-up + N iterations:** runs one unrecorded warm-up pass, then N recorded iterations (default: 8) to eliminate cold-start skew
- **P90 statistics:** computes the 90th-percentile latency (µs) and throughput (Gbps); flags `CONNECTIVITY_DROP` if any iteration records a zero measurement, or `HIGH_VARIANCE` if the spread between max and min exceeds 50% of the minimum — both written to the artifact
- **Baseline comparison:** optionally downloads a previously stored baseline result from Azure Blob Storage and reports the percentage delta
- **Structured artifacts:** writes six JSON files to a local audit directory, one per pipeline stage
- **Blob upload:** uploads the final result artifact to Azure Blob Storage; routes through the source VM via SSH tunnel if the storage account is firewall-restricted to the VNet
- **Safety Shell integration:** every shell command — SSH, `az` CLI, `qperf`, `iperf2` — is routed through the Safety Shell (SAFE / RISKY / BLOCKED / DENIED); risky commands require your approval before running

---

## Dependencies

Pipe Meter uses the Safety Shell sibling library. **Clone the full repo** — do not download this directory alone.

```
agentic-network-tools/
├── agentic-safety-shell/            ← required: command execution safety layer
└── agentic-pipe-meter/              ← you are here
```

---

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Azure CLI authenticated: `az login`
- Azure infrastructure: two VMs in the same VNet, an NSG on the destination VM, a storage account for artifact upload
- `qperf` and `iperf2` on both VMs — Pipe Meter will check and offer to install them if missing

---

## Installation

```bash
git clone https://github.com/<your-org>/agentic-network-tools
cd agentic-network-tools/agentic-pipe-meter
```

Copy and fill in the config file:
```bash
cp config.env.example config.env
vi config.env
```

---

## Run

### Using a config file (recommended)
```bash
uv run python pipe_meter.py --config config.env
```

### Using CLI flags directly
```bash
uv run python pipe_meter.py \
  --source-ip 10.0.0.4 \
  --dest-ip 10.0.0.5 \
  --ssh-user azureuser \
  --test-type both \
  --resource-group my-rg \
  --storage-account-name mystorageaccount \
  --storage-container-name pipe-meter-results
```

CLI flags always override values in the config file.

### Record a baseline
```bash
uv run python pipe_meter.py --config config.env --is-baseline
```

### Compare against an existing baseline
```bash
uv run python pipe_meter.py --config config.env --compare-baseline
```

### Running from outside the VNet (SSH keys required)
When running from a machine that cannot reach the destination VM directly, supply the source VM's public IP and SSH keys. Pipe Meter routes all commands to the destination through the source VM via `ProxyCommand`.

```bash
uv run python pipe_meter.py --config config.env \
  --source-public-ip 20.30.40.50 \
  --ssh-source-vm-key-path ~/.ssh/source-vm.pem \
  --ssh-dest-vm-key-path ~/.ssh/dest-vm.pem
```

---

## Key Parameters

| Flag | Required | Description |
|------|----------|-------------|
| `--source-ip` | Yes | Private IP of the client (source) VM |
| `--dest-ip` | Yes | Private IP of the server (destination) VM |
| `--ssh-user` | Yes | SSH username on both VMs |
| `--test-type` | Yes | `latency` / `throughput` / `both` |
| `--resource-group` | Yes | Azure resource group containing both VMs |
| `--storage-account-name` | Yes | Azure storage account name for artifact upload |
| `--storage-container-name` | Yes | Blob container name |
| `--iterations` | No | Number of recorded iterations (default: `8`) |
| `--is-baseline` | No | Mark this run as the reference baseline for this IP pair |
| `--compare-baseline` | No | Download and compare against a stored baseline |
| `--source-public-ip` | No | Public IP of source VM for SSH (required outside VNet) |
| `--ssh-source-vm-key-path` | No | SSH key path for the source VM |
| `--ssh-dest-vm-key-path` | No | SSH key path for the destination VM |
| `--subscription-id` | No | Azure subscription ID (uses default if omitted) |
| `--audit-dir` | No | Local directory for artifacts (default: `./audit`) |
| `--session-id` | No | Override the auto-generated session ID |
| `--config` | No | Path to a config file; flags take precedence over file values |

---

## Console Output

A successful `--test-type both` run with baseline comparison produces output like:

```
[preflight] Checking NSG ports (5001, 19765) between 10.0.0.4 and 10.0.0.5...
[preflight] NSG ports OK. Checking tools on VMs...
[preflight]   Checking 10.0.0.4...
[preflight]   Checking 10.0.0.5...
[preflight] Tools OK. Preflight passed.

=====================================
=== Agentic Pipe Meter — Results ===
=====================================
Session:    pmeter_20260303T175346
Source:     10.0.0.4  →  10.0.0.5
Test:       both  |  8 iterations
Status:     SUCCESS

Latency  (P90):     124.5 µs  ← +2.1% vs baseline (slower)
Throughput (P90):     9.40 Gbps  ← -0.5% vs baseline (lower)

Stability:  STABLE
Audit:      ./audit/pmeter_20260303T175346_result.json
Blob:       https://mystorageaccount.blob.core.windows.net/pipe-meter-results/10_0_0_4_10_0_0_5_pmeter_20260303T175346.json
=====================================
```

If the gap rule fires, `Stability` shows `UNSTABLE — HIGH_VARIANCE` (or `UNSTABLE — CONNECTIVITY_DROP` if any measurement returned zero) and the anomaly type is recorded in the artifact.

---

## Pipeline Stages

```
validate → preflight → measure → compute → compare → report
```

| Stage | What it does | Stops if |
|-------|--------------|----------|
| `validate` | Parses and validates all config parameters | Invalid IP, missing required field |
| `preflight` | NSG port check, tool availability, auto-remediation | NSG fix denied; tools not installable |
| `measure` | Warm-up pass + N iterations of qperf / iperf2 via SSH | SSH unreachable; output parse error |
| `compute` | P90, min, max, gap rule (is_stable, anomaly_type) | — |
| `compare` | Baseline blob download + percentage delta | — (skipped unless `--compare-baseline`) |
| `report` | Assembles final artifact and uploads to blob | Local artifact write fails (blob upload failure prints a warning and continues) |

---

## Artifacts

All six files are written to `{audit_dir}/{session_id}_{type}.json`:

| File | Written by | Contents |
|------|------------|----------|
| `_manifest.json` | pipeline start | config snapshot, session ID, timestamp |
| `_preflight.json` | preflight stage | port status, tool check results, actions taken |
| `_raw.json` | measure stage | per-iteration latency (µs) and throughput (Gbps) samples |
| `_computed.json` | compute stage | P90, min, max, is_stable, anomaly_type |
| `_comparison.json` | compare stage | delta vs baseline, baseline P90 values and timestamp |
| `_result.json` | report stage | full merged artifact; also uploaded to blob storage |

The blob name in Azure Blob Storage follows the pattern:
`{source_ip_underscored}_{dest_ip_underscored}_{session_id}.json`

For example: `10_0_0_4_10_0_0_5_pmeter_20260303T175346.json`

When `--is-baseline` is used, a second blob is also written as:
`{source_ip_underscored}_{dest_ip_underscored}_baseline.json`

---

## Running Tests

```bash
cd agentic-pipe-meter
uv run pytest tests/ -v
```

194 tests across 16 files covering all pipeline stages, NSG parsing, HITL callbacks, SSH command templates, blob routing, and Azure provider logic.
