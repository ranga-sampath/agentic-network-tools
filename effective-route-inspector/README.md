# effective-route-inspector

Deterministic Azure VM effective route table inspector. Applies the Azure route selection algorithm in pure Python and returns a structured verdict naming the winning route, its source tier, and any anomalies.

No AI in the analysis path — deterministic end to end.

## What it does

Given a VM name and an optional destination IP, the inspector:

1. Resolves the VM's primary NIC (`az vm show`)
2. Retrieves the effective route table at the NIC (`az network nic show-effective-route-table`)
3. Applies the Azure route selection algorithm:
   - **CIDR containment** — filters Active routes that cover the destination IP
   - **Longest Prefix Match (LPM)** — highest prefix length wins unconditionally
   - **Source precedence** (equal prefix only) — User (1) > VirtualNetworkGateway (2) > Default (3)
   - **BGP tie-break** — if two VirtualNetworkGateway routes remain tied, returns `TIED_BGP`
4. Checks for anomalies on the winning route:
   - `BLACKHOLE_WARNING` — `next_hop_type == "None"` (Azure discards all matching packets)
   - `NVA_WARNING` — `next_hop_type == "VirtualAppliance"` (traffic forwarded to an NVA)
   - `INVALID_SHADOW_WARNING` — an Invalid route with a longer prefix exists for the destination

**Audit mode** (no `--dst-ip`): lists all routes sorted by prefix length and flags blackhole and NVA routes across the full table.

Both modes write structured artifacts to `audit/`:
- `rt_<session>_raw.json` — raw Azure CLI output
- `rt_<session>_verdict.json` — analysis result (read by Ghost Agent Brain)

## Modes

| Mode | Invocation | When to use |
|------|-----------|-------------|
| Single-target | `--dst-ip <ip>` | Diagnose silent drops, wrong path, NVA bypass for a specific destination |
| Audit | (no `--dst-ip`) | Full route table review — surface all blackholes and NVA routes |

## Usage

### Standalone CLI

```bash
# Single-target: which route wins for 8.8.8.8?
python effective_route_inspector.py \
  --vm-name     tf-source-vm \
  --resource-group nw-forensics-rg \
  --dst-ip      8.8.8.8

# Audit: full route table review
python effective_route_inspector.py \
  --vm-name     tf-source-vm \
  --resource-group nw-forensics-rg

# Skip NIC lookup if you already know the NIC name
python effective_route_inspector.py \
  --vm-name     tf-source-vm \
  --resource-group nw-forensics-rg \
  --dst-ip      10.0.1.5 \
  --nic-name    tf-source-vm-nic

# Custom session ID and audit directory
python effective_route_inspector.py \
  --vm-name     tf-source-vm \
  --resource-group nw-forensics-rg \
  --dst-ip      10.0.1.5 \
  --session-id  rt_pre_change \
  --audit-dir   ./audit
```

### Ghost Agent tool

The inspector is registered as `effective_route_inspector` in Ghost Agent. The Brain calls it when the symptom is routing-layer (silent drop, wrong path, NVA bypass):

```
# Prompts that trigger effective_route_inspector
"tf-source-vm cannot reach tf-dest-vm — no error, just silence. NSG is clean."
"All internet access from the VM is timing out. Route table was changed this morning."
"Traffic is going to the wrong NVA."
```

The verdict artifact (`rt_*_verdict.json`) is read back by the handler and returned to the Brain. The `session_id` field satisfies the pre-completion checklist requirement: *cite the rt_* audit artifact for any routing finding*.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success — verdict written and rendered |
| `2` | Fatal — Azure CLI error, RBAC failure, or preprocessing failure. No verdict artifact written. |
| `1` | Never emitted |

## Prerequisites

- Python 3.12+
- Azure CLI (`az login`) — Network Reader role on the resource group minimum
- `uv` — `curl -LsSf https://astral.sh/uv/install.sh | sh`

## Files

```
effective-route-inspector/
├── effective_route_inspector.py   # CLI entry point + pipeline orchestrator
├── lpm_engine.py                  # Pure-function route selection algorithm + anomaly detection
├── providers.py                   # Azure CLI boundary (AzureRouteProvider, LocalShell)
├── route_preprocessor.py          # JSON normaliser — converts raw az CLI output to route objects
├── fixtures/                      # 15 real-world fixtures + 3 adversarial fixtures
├── tests/
│   ├── test_preprocessor.py       # Preprocessor unit tests (§4 of test plan)
│   ├── test_lpm_engine.py         # LPM algorithm correctness tests (§5–6 of test plan)
│   ├── test_providers.py          # Provider + retry + exception tests (§7 of test plan)
│   ├── test_pipeline.py           # Pipeline integration tests (§8–9 of test plan)
│   └── test_adversarial.py        # Adversarial input tests (§3 of test plan)
└── docs/
    ├── design.md                  # Function inventory, data schemas, error handling
    └── test_plan.md               # Test plan — fixture ground truth and algorithm checks
```

## Running tests

```bash
uv run --python 3.12 python -m pytest tests/ -v
```
