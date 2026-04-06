# Effective Network Inspector

**Baseline and diff Azure control-plane computed network state — effective routes and NSG evaluation — for forensic investigation and change-window sign-off.**

---

## The Problem

Two classes of Azure network failures are invisible to every existing Azure tool:

**BGP route withdrawal.** When a VPN gateway or ExpressRoute circuit withdraws routes — due to maintenance, a session flap, or the "propagate gateway routes" flag being disabled — no UDR resource changes. Azure Change Analysis has nothing to log. Only a diff of the effective route table, comparing `VirtualNetworkGateway`-sourced routes before and after, reveals what disappeared.

**NSG evaluation drift.** The effective security rules applied to a NIC are a *computed result* of subnet NSG and NIC NSG evaluated in sequence. A deny at priority 100 in the subnet NSG overrides all NIC NSG allow rules, regardless of their priority numbers. No existing tool baselines this combined evaluation result or diffs it over time. Querying each NSG in isolation cannot surface the interaction.

Both computed states are derived on-demand from the Azure network stack. They are not ARM resources and have no Activity Log entries.

---

## What This Tool Does

Snapshots and diffs two Azure control-plane computed states per NIC:

1. **Effective route table** — `az network nic show-effective-route-table` — all routes by source: `User` (UDR), `Default` (system), `VirtualNetworkGateway` (BGP-propagated).
2. **Effective security rules** — `az network nic list-effective-nsg` — combined subnet NSG + NIC NSG evaluation result, IPv4 and IPv6.

Stores timestamped snapshots locally. On demand, diffs two snapshots to produce a structured change report categorised by impact type.

---

## Quick Start

```bash
# Baseline before a change window
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --is-baseline --session-id pre_change_0401

# After the window — compare against baseline
python effective_network_inspector.py \
  --scope vm --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --compare-baseline pre_change_0401
```

The diff artifact (`audit/eni_pre_change_0401_vs_eni_<timestamp>_diff.json`) contains `drift_detected: true/false` plus per-category change lists. `drift_detected: false` is an explicit, SHA-256 verified negative confirmation — usable as a machine-readable change record.

---

## CLI Reference

```
effective_network_inspector.py
  --scope           vm | vnet           (required)
  --vm-name         VM_NAME             (required when --scope vm)
  --vnet-id         VNET_RESOURCE_ID    (required when --scope vnet)
  --resource-group  RG_NAME             (required)
  --is-baseline                         store this snapshot as baseline
  --compare-baseline SESSION_ID         load baseline; produce diff
  --session-id      ID                  timestamp portion of the ID
                                        (eni_ prefix always enforced;
                                         --session-id foo → eni_foo)
  --audit-dir       PATH                artifact dir (default: ./audit)
  --subscription-id SUBSCRIPTION_ID    (optional; uses az default if absent)
  --max-workers     N                   concurrent NIC queries (default: 4)
  --config          PATH                load defaults from key=value file
```

**Session ID prefix rule:** all snapshots are stored with an `eni_` prefix, regardless of whether `--session-id` is supplied. If you pass `--session-id pre_change_0401`, the file is saved as `eni_pre_change_0401_snapshot.json` and the session ID is referred to as `eni_pre_change_0401` in diff artifacts and tool references. If the supplied ID already starts with `eni_`, no prefix is added.

---

## Outputs

### Snapshot artifact
```
audit/eni_{session_id}_snapshot.json
audit/eni_{session_id}_snapshot.json.sha256   ← GNU sha256sum format
```

### Diff artifact
```
audit/eni_{baseline_id}_vs_eni_{compare_id}_diff.json
```

```json
{
  "baseline_session_id": "eni_pre_change_0401",
  "compare_session_id":  "eni_20260406_082000",
  "drift_detected": true,
  "changes_count": 1,
  "changes_by_category": { "security_rule_change": 1 },
  "skipped_nics": [],
  "nic_diffs": [...]
}
```

### Change categories

| Category | Meaning |
|---|---|
| `bgp_route_change` | Route with source `VirtualNetworkGateway` appeared or disappeared |
| `udr_route_change` | Route with source `User` changed (next-hop, prefix, or state) |
| `system_route_change` | Route with source `Default` changed (rare; Azure maintenance events) |
| `security_rule_change` | Effective security rule added, removed, or priority shifted |

---

## Config File

Pass `--config path/to/file.env` to load defaults from a `KEY=value` file. CLI flags override config file values.

```env
RESOURCE_GROUP=nw-forensics-rg
VM_NAME=tf-dest-vm
SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AUDIT_DIR=./audit
MAX_WORKERS=4
```

---

## Use Cases

**Maintenance window bracket**
```bash
# Before
python effective_network_inspector.py --scope vm --vm-name prod-vm \
  --resource-group prod-rg --is-baseline --session-id pre_window_cr1234

# After — any effective network change surfaces immediately
python effective_network_inspector.py --scope vm --vm-name prod-vm \
  --resource-group prod-rg --compare-baseline pre_window_cr1234
```

**Environment parity (staging vs production)**
```bash
python effective_network_inspector.py --scope vnet --vnet-id <staging-id> \
  --resource-group staging-rg --is-baseline --session-id staging_snap

python effective_network_inspector.py --scope vnet --vnet-id <prod-id> \
  --resource-group prod-rg --compare-baseline staging_snap
```

**Post-incident forensics before restore**
```bash
# Capture evidence before tearing down the environment
python effective_network_inspector.py --scope vm --vm-name affected-vm \
  --resource-group incident-rg --compare-baseline last_known_good
```

---

## RBAC Requirements

| Permission | Required for |
|---|---|
| `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | `az network nic list-effective-nsg` |
| `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` | `az network nic show-effective-route-table` |

Neither is included in the built-in `Reader` role. Both are in `Network Contributor`. For least-privilege deployments, a custom role with only these two action-type permissions is appropriate.

---

## Ghost Agent Integration

This tool is the backend for the `detect_effective_network_drift` tool in Ghost Agent. The Ghost Agent calls it as a subprocess, reads the diff artifact, and returns structured findings to its reasoning loop.

```
detect_effective_network_drift  ←→  effective_network_inspector.py
detect_config_drift             ←→  firewall_inspector.py (OS-layer iptables/nftables)
```

These are different state spaces. `eni_*` session IDs belong to `detect_effective_network_drift`; `fw_*` session IDs belong to `detect_config_drift`.

---

## Module Structure

```
effective-network-inspector/
├── effective_network_inspector.py   ← CLI entry point + orchestration
├── providers.py                     ← Azure CLI boundary (NIC discovery, route + NSG queries)
├── diff.py                          ← Pure comparison engine (no I/O)
├── docs/
│   ├── product-requirements.md
│   ├── architecture.md
│   ├── design.md
│   └── test_plan.md
└── tests/
    ├── test_effective_network_inspector.py   ← 60 orchestrator/CLI tests
    ├── test_providers.py                     ← provider unit tests
    ├── test_diff.py                          ← diff engine unit tests
    └── test_providers_ag456.py               ← typed exceptions, retry, concurrency
```

---

## Running Tests

```bash
python3.12 -m pytest tests/ -v
```

All tests run without Azure credentials. `AzureNetworkProvider` is replaced with mocks throughout.
