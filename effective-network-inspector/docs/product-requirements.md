# Product Requirements — Azure Effective Network Inspector

## Problem

Azure network failures have two classes that are invisible to every existing Azure tool:

**BGP route withdrawal.** When a VPN gateway or ExpressRoute circuit withdraws BGP-advertised routes — due to maintenance, a session flap, or the "propagate gateway routes" flag being disabled on a route table — no UDR resource changes. Azure Change Analysis has nothing to log. The Activity Log has no entry. Only a diff of the effective route table, comparing routes with source `VirtualNetworkGateway` before and after, reveals what disappeared.

**NSG evaluation drift.** The effective security rules applied to a NIC are a computed result of subnet NSG and NIC NSG evaluated in sequence. For inbound traffic, the subnet NSG fires first; a deny at priority 100 there overrides all NIC NSG allow rules, regardless of their priority numbers. No existing tool baselines this combined evaluation result or diffs it over time. Querying each NSG in isolation cannot surface the interaction.

Both computed states — effective routes and effective security rules — are derived on-demand from the Azure network stack. They are not ARM resources and have no Activity Log entries. They differ from the configured resource properties (UDR route tables, individual NSG rule lists) in ways that are operationally significant and currently undetectable without manual per-VM CLI queries.

The gap: **there is no tool that baselines these two computed states and diffs them.**

---

## What This Tool Does

The **Azure Effective Network Inspector** (`effective_network_inspector.py`) snapshots and diffs the two Azure control-plane computed states that determine actual network behaviour for a VM:

1. **Effective route table per NIC** — `az network nic show-effective-route-table` — all routes by source: `User` (UDR), `Default` (system routes), `VirtualNetworkGateway` (BGP-propagated). BGP route withdrawal shows as `VirtualNetworkGateway`-sourced routes disappearing between snapshots.

2. **Effective security rules per NIC** — `az network nic list-effective-nsg` — the combined subnet NSG + NIC NSG evaluation result, for both IPv4 and IPv6. A high-priority deny added to the subnet NSG shows in the effective rules diff even when the NIC NSG is unchanged.

It stores timestamped snapshots locally, and on demand diffs two snapshots to produce a structured change report categorised by impact type.

For VNet scope, the tool discovers NICs by traversing all subnets in the VNet. A NIC is included in the snapshot regardless of whether its subnet has an associated route table.

---

## Scope

### In scope (MVP)

- Effective route table per NIC (all sources: User, Default, VirtualNetworkGateway)
- Effective security rules per NIC, IPv4 and IPv6 (combined subnet+NIC NSG evaluation result)
- VM scope: all NICs attached to a named VM
- VNet scope: all NICs in all subnets of the VNet, discovered by subnet traversal
- Baseline storage: local `./audit/` directory only
- Structured diff with four change categories
- `drift_detected: false` explicit no-drift confirmation field (compliance / change-record use case)
- SHA-256 integrity check on snapshot artifacts
- RBAC error detection when az CLI returns `AuthorizationFailed`
- Per-NIC progress output during snapshot (e.g., `Snapshotting NIC 3/12: tf-dest-vm-nic...`)
- Exponential backoff on Azure 429 (throttle) responses, configurable concurrency limit

### Out of scope (MVP)

- VNet peering state, service endpoint presence, NSG association state — raw ARM properties; Azure Change Analysis covers these within 14 days
- VPN/ExpressRoute BGP peer state and connection state — separate query; not an effective-state API
- Multi-subscription scope
- Azure Blob Storage for baselines
- `--explain` AI flag — post-MVP, same pattern as `netfilter-inspector/iptables-parser/ --explain-diff`
- Blast radius annotation (graph traversal for affected subnets/VNets per change)
- Azure Firewall policy resolved state
- Private DNS zone A record tracking
- Load balancer backend pool membership

---

## CLI Interface

```
effective_network_inspector.py
  --scope           vm | vnet                  (required)
  --vm-name         VM_NAME                    (required when --scope vm)
  --vnet-id         VNET_RESOURCE_ID           (required when --scope vnet)
  --resource-group  RG_NAME                    (required)
  --is-baseline                                store this run as the reference baseline
  --compare-baseline SESSION_ID               load stored baseline; produce diff
  --session-id      ID                         override the timestamp component of the ID.
                                               The eni_ prefix is always enforced: --session-id foo
                                               stores as eni_foo. If the supplied ID already starts
                                               with eni_, the prefix is not duplicated.
                                               Auto-generated default: eni_YYYYMMDD_HHMMSS.
  --audit-dir       PATH                       artifact storage (default: ./audit)
  --subscription-id SUBSCRIPTION_ID           (optional; uses az default if omitted)
```

Flags mirror `firewall_inspector.py` and `pipe_meter.py` exactly. The `--is-baseline` / `--compare-baseline` pattern is consistent across all tools in the suite.

---

## Outputs

### Snapshot artifact

File: `{audit_dir}/{session_id}_snapshot.json`
Integrity file: `{audit_dir}/{session_id}_snapshot.json.sha256`

```json
{
  "session_id": "eni_20260325_140000",
  "scope": "vm",
  "scope_target": "tf-dest-vm",
  "resource_group": "nw-forensics-rg",
  "timestamp": "2026-03-25T14:00:00Z",
  "nics": [
    {
      "nic_name": "tf-dest-vm-nic",
      "effective_routes": [...],
      "effective_nsg_rules": [...],
      "error": null
    }
  ]
}
```

### Per-NIC error handling

When a NIC query fails (stopped VM, RBAC error, timeout), the tool:
- Records the error in `"error"` and leaves `effective_routes` and `effective_nsg_rules` as `null` for that NIC
- Continues snapshotting remaining NICs (partial snapshot is valid)
- Exits with a non-zero status code if any NIC errored
- When diffing, skips NICs where either snapshot has `"error"` set and notes the skipped NICs in the diff artifact; a NIC that was healthy in the baseline and errored in the compare snapshot is not reported as drift

### Diff artifact

File: `{audit_dir}/{baseline_session_id}_vs_{compare_session_id}_diff.json`

```json
{
  "baseline_session_id": "eni_20260325_130000",
  "compare_session_id":  "eni_20260325_140000",
  "drift_detected": true,
  "changes_count": 1,
  "changes_by_category": { "bgp_route_change": 1 },
  "skipped_nics": [],
  "nic_diffs": [
    {
      "nic_name": "tf-dest-vm-nic",
      "changes": [
        {
          "change_type": "removed",
          "category": "bgp_route_change",
          "route": {
            "addressPrefix": "10.2.0.0/24",
            "nextHopType": "VirtualNetworkGateway",
            "nextHopIpAddress": null,
            "source": "VirtualNetworkGateway",
            "state": "Active"
          }
        }
      ]
    }
  ]
}
```

### Diff categories

| Category | Meaning |
|---|---|
| `bgp_route_change` | Route with source `VirtualNetworkGateway` appeared or disappeared |
| `udr_route_change` | Route with source `User` changed (next-hop, prefix, or state) |
| `system_route_change` | Route with source `Default` changed (rare; Azure maintenance events) |
| `security_rule_change` | Effective security rule added, removed, or priority shifted |

### No-drift confirmation

When no changes are detected, `drift_detected: false` is written explicitly to the diff artifact. This is the machine-readable change-record artifact: an empty diff is an explicit confirmation that effective network state is unchanged, not an absent result.

---

## Use Cases

### 1. Maintenance window bracket

Take a baseline before any changes. After the window closes, compare.

```bash
# Before the window
python effective_network_inspector.py \
  --scope vnet --vnet-id <id> --resource-group nw-forensics-rg \
  --is-baseline --session-id pre_change_20260401

# Apply changes

# After the window
python effective_network_inspector.py \
  --scope vnet --vnet-id <id> --resource-group nw-forensics-rg \
  --compare-baseline pre_change_20260401
```

The diff shows every effective-state change the window produced — intended and unintended. BGP routes that disappeared because a UDR modification changed route precedence surface immediately. The diff artifact becomes the change record evidence.

### 2. "Why does it work in staging but not production?"

Take a snapshot of each VNet and diff them.

```bash
python effective_network_inspector.py \
  --scope vnet --vnet-id <staging-vnet-id> --resource-group staging-rg \
  --is-baseline --session-id staging_snap

python effective_network_inspector.py \
  --scope vnet --vnet-id <prod-vnet-id> --resource-group prod-rg \
  --compare-baseline staging_snap
```

A single structured diff replaces querying each resource type in both environments manually.

### 3. Post-incident: was the config different at incident time?

Before restoring the environment, snapshot the current state and compare against the last known-good baseline.

```bash
python effective_network_inspector.py \
  --scope vm --vm-name affected-vm --resource-group nw-forensics-rg \
  --compare-baseline last_known_good
```

Captures the drift evidence before the environment is torn down. Answers "was the network posture when the incident occurred different from the documented baseline?" without Activity Log archaeology.

### 4. IaC blind spot — BGP routes that Terraform cannot see

After a Terraform apply that modified a UDR, compare against the pre-apply baseline. The diff surfaces BGP-propagated routes that shifted precedence as a result of the UDR change — zero Terraform-visible drift, no Activity Log UDR entry, but a real effective-topology change.

---

## Ghost Agent Integration

### Tool name

`detect_effective_network_drift` — a new, separate tool distinct from `detect_config_drift`.

- `detect_config_drift` → OS-layer iptables/nftables state inside the VM
- `detect_effective_network_drift` → Azure control-plane effective routes + NSG evaluation

### Required config keys (`config.env`)

| Key | Description |
|---|---|
| `RESOURCE_GROUP` | Target resource group |
| `DEST_VM_NAME` | Default VM target when no override is set |
| `AUDIT_DIR` | Artifact storage directory |
| `ENI_VM_NAME` | Optional override VM name for this tool (takes precedence over `DEST_VM_NAME`) |
| `SUBSCRIPTION_ID` | Optional; uses az CLI default if absent |

### Position in the investigation hierarchy

```
Layer 0:  detect_effective_network_drift    "What changed at the Azure fabric layer?"
              ↓
Layer 1:  NSG + route checks                "What is the control plane doing right now?"
              ↓
Layer 2:  pipe_meter                        "Is the path performing correctly?"
              ↓
Layer 3:  detect_config_drift               "What is the OS firewall doing to traffic?"
              ↓
Layer 4:  PCAP engine                       "What is actually on the wire?"
```

`detect_effective_network_drift` is the first call for any "nothing changed but it broke" scenario at the Azure layer.

### Tool decision rules additions

| Scenario | First tool | Follow-up |
|---|---|---|
| "Nothing changed but it broke" | `detect_effective_network_drift(compare_session_id=...)` | Then `detect_config_drift` if Azure layer clean |
| BGP route withdrawal suspected | `detect_effective_network_drift` | `az network vnet-gateway list-advertised-routes` |
| Change window sign-off (Azure) | `detect_effective_network_drift --compare-baseline` | Approve only if `drift_detected=false` or all changes explained |
| Post-incident before restore | `detect_effective_network_drift --compare-baseline` | `complete_investigation` with diff artifact as evidence |

### SafeExecShell classification

Both `az network nic show-effective-route-table` and `az network nic list-effective-nsg` are read-only and classified **SAFE** — no HITL approval prompt required.

---

## Azure RBAC Requirements

| Permission | Required for |
|---|---|
| `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | `az network nic list-effective-nsg` |
| `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` | `az network nic show-effective-route-table` |

Neither permission is included in the built-in `Reader` role. Both are included in `Network Contributor`. For least-privilege deployments, a custom role with only these two action-type permissions plus standard ARM read permissions is appropriate.

The tool must detect `AuthorizationFailed` in az CLI output and print a clear RBAC error message identifying which permission is missing.

---

## Acceptance Criteria

1. VM-scope snapshot of `tf-dest-vm` produces a valid `_snapshot.json` with SHA-256 file and per-NIC `effective_routes` and `effective_nsg_rules` populated.
2. Injecting a priority-100 inbound deny rule to `tf-dest-vm-nsg` and re-snapshotting produces a diff with `security_rule_change` and `drift_detected: true`.
3. Removing the injected rule and re-snapshotting produces a diff with `drift_detected: false`.
4. Disabling "propagate gateway routes" on the subnet's route table (when a VPN gateway is available) produces a diff with `bgp_route_change` entries for the withdrawn prefixes.
5. Running against a VM with insufficient RBAC produces a clear error message identifying the missing permission, not a Python traceback.
6. Running against a stopped VM (NIC query fails) completes for other NICs, records the error in the snapshot, exits non-zero, and does not report the errored NIC as drift in a subsequent compare.

---

## Relationship to Existing Azure Tools

This tool is **complementary**, not a replacement, for:

- **Azure Change Analysis** — remains the authoritative source for raw resource property changes and attribution ("who changed what, when"). This tool covers what the network was actually doing (computed effective state). Both are needed for a complete investigation.
- **Network Watcher Effective Security Rules** — answers point-in-time per-NIC questions. No baseline storage, no diff, no fleet-wide query. This tool uses the same underlying API but adds the temporal dimension.
- **Terraform / Bicep what-if** — compares IaC desired state against ARM state. Cannot see BGP-propagated routes, computed effective security rules, or resources created outside IaC. This tool fills that blind spot.

The specific, operationally painful gap this tool owns: **BGP route withdrawal and NSG evaluation drift that produce no ARM resource change and therefore appear in no existing audit tool.**
