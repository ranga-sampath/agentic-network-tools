# Product Requirements — effective-route-inspector

## Overview

`effective-route-inspector` is a network routing analysis tool for Azure VMs. Given a VM
name and resource group, it autonomously collects the effective route table from Azure and
applies the Azure route selection algorithm to return a structured, deterministic verdict.

The tool operates in two surfaces:
1. **Standalone CLI** — a network engineer runs it directly to investigate or audit routing.
2. **Ghost Agent tool** — Ghost Agent calls it autonomously during a connectivity
   investigation, using the verdict as evidence for root cause analysis.

---

## The Problem

Azure routing failures are invisible. Traffic disappears silently. The effective route table
is computed state — it is not the route table configured on the subnet, but the result of
Azure merging user-defined routes (UDRs), BGP routes from gateways, VNet peering routes,
and system defaults. Engineers frequently query the wrong table and conclude there is no
issue.

Even when an engineer queries the correct table, interpreting it requires applying the Azure
route selection algorithm correctly: longest prefix match (LPM) wins unconditionally, then
source precedence applies only among routes of equal prefix length, then BGP tie-breaking
rules apply. Errors in applying this algorithm lead to misdiagnosis.

Common failure modes that are invisible without this tool:
- **Routing blackhole** — a route exists with `next_hop_type = None`; Azure's routing
  subsystem drops the packet silently without generating an ICMP unreachable.
- **NVA bypass** — traffic routes around a firewall appliance because a UDR is missing or
  invalid on the subnet; NSG rules pass the traffic correctly, and the routing path taken
  is not visible to any other tool.
- **Invalid route shadowing** — a more specific route exists but is in `Invalid` state;
  traffic falls back to a broader, less secure path.
- **BGP vs UDR precedence dispute** — a field engineer expects the UDR to win but a more
  specific system route takes precedence via LPM; the engineer never checks prefix lengths.

---

## Users

| User | Context |
|------|---------|
| Network engineer | Investigating a reported connectivity failure to or from an Azure VM |
| Cloud architect | Auditing routing on a VM after a topology change (peering added, UDR modified, gateway failover) |
| Ghost Agent Brain | Calling the tool as part of an autonomous RCA investigation |

---

## Standalone Tool — Use Cases

### UC-S1: Investigate routing failure for a specific destination

The engineer knows a VM cannot reach a specific IP address. They provide the VM name,
resource group, and destination IP. The tool returns:

- The winning route that Azure will use for that destination
- All candidate routes considered (shadowed routes)
- The reason the winning route was selected (LPM, source precedence)
- Any anomaly warnings: blackhole, invalid shadowing, NVA route detected

The engineer gets a single structured verdict without manually running `az` commands,
parsing JSON, or applying the selection algorithm by hand.

### UC-S2: Audit all routes on a VM

The engineer wants a full picture of the VM's routing state — after a topology change, as a
pre-change check, or as a scheduled audit. No destination IP is specified. The tool returns:

- All active routes, sorted by prefix length (most specific first)
- Any invalid routes present in the table
- Notable findings: blackhole routes, NVA routes, BGP-propagated routes, whether a default
  route is present and its source

This mode surfaces anomalies the engineer may not have thought to look for.

### UC-S3: Verify routing after a change

An engineer has added a UDR, modified a peering, or changed a gateway configuration. They
want to confirm the effective routing state reflects the intended change. They run
single-target mode before and after the change to compare the winning route and selection
reason.

The tool does not perform before/after diff — that is left to the engineer. It provides the
authoritative current-state verdict at each point in time.

---

## Ghost Agent Integration — Use Cases

Ghost Agent calls this tool autonomously. The engineer describes a connectivity symptom in
plain language. Ghost Agent decides when and how to call the tool. The engineer does not
interact with the tool directly.

### UC-G1: Traffic bypassing the firewall NVA

**Symptom:** Spoke VM traffic is going directly to the internet instead of through the hub
firewall appliance.

Ghost Agent calls the tool with the spoke VM and a sample internet-bound destination IP
(e.g., `8.8.8.8`). The tool finds whether a UDR pointing to the NVA is present and in
`Active` state, and flags if the UDR is `Invalid` or absent. Ghost Agent uses this finding
to diagnose whether the UDR association is missing on the VM's subnet and to issue a precise
remediation.

### UC-G2: Silent blackhole — traffic disappearing with no error

**Symptom:** Packets to a specific IP are not arriving. No ICMP unreachable. No error
message on either end.

Ghost Agent calls the tool with the source VM and destination IP. If the winning route has
no valid next hop, the tool returns a blackhole warning. Ghost Agent incorporates this into
the RCA, identifies the likely cause (deleted peering, withdrawn BGP route, stale route),
and directs the engineer to the specific remediation step.

### UC-G3: BGP route expected but not winning

**Symptom:** ExpressRoute is up but on-premises traffic is still going over VPN.

Ghost Agent calls the tool with the hub or gateway VM and a specific on-premises
destination IP. If two `VirtualNetworkGateway` routes exist with identical prefixes, the
tool flags the result as `TIED (BGP)` — the AS Path tiebreaker cannot be determined from
the effective route table alone. Ghost Agent incorporates the tie into the RCA and directs
the engineer to the specific command to inspect AS Path lengths at the gateway.

### UC-G4: Routing correct but traffic still failing

Ghost Agent has called the tool and the route verdict shows a valid path to the destination.
Ghost Agent uses this as confirmation that routing is not the cause and proceeds to call
`security_rule_inspector` (planned) to check NSG rules, or `detect_config_drift` to check
OS-level iptables/nftables rules. The route verdict eliminates routing from suspicion and
narrows the investigation to the next layer.

---

## Modes of Operation

| Mode | Trigger | Returns |
|------|---------|---------|
| Single-target | Destination IP provided | Winning route, shadowed candidates, selection reason, anomaly warnings |
| Audit | No destination IP | All routes by prefix length, invalid routes, notable findings |

---

## Inputs

| Input | Required | Notes |
|-------|----------|-------|
| VM name | Yes | The VM whose effective route table is inspected |
| Resource group | Yes | The resource group containing the VM |
| Destination IP | No | If provided: single-target mode. If omitted: audit mode |
| Subscription ID | No | Defaults to the active `az` CLI subscription |

The tool collects all other data autonomously. No manual `az` command output needs to be
provided.

---

## Outputs

### Single-target mode
- **Winning route** — prefix, next hop type, next hop IP (if applicable), source, state
- **Selection reason** — LPM only, source precedence applied, or BGP tied
- **Shadowed candidates** — other routes considered but not selected
- **Anomaly warnings** (if applicable):
  - Blackhole: winning route has no valid next hop
  - Invalid shadowing: a more specific route exists but is in `Invalid` state
  - NVA route: winning route points to a Virtual Appliance (verify IP forwarding and return path)
  - BGP tie: two or more BGP routes with identical prefix; AS Path not determinable from this tool

### Audit mode
- All active routes, sorted by prefix length descending
- Invalid routes listed separately
- Notable findings: blackhole routes, NVA routes, BGP routes, default route presence and source

---

## Behaviour Rules

**Never fabricate a winner.** If two BGP routes tie on prefix length and the AS Path
tiebreaker is not available in the effective route table, the tool returns `TIED (BGP)` and
stops. It does not guess or select arbitrarily.

**No matching route is a finding.** If no active route encompasses the destination IP, the
tool returns an explicit no-route verdict. It does not fall through or approximate.

**Primary NIC by default.** For VMs with multiple NICs, the tool uses the primary NIC. If
the relevant NIC is secondary, the caller must specify it.

**Routing verdict is L3 only.** A correct routing verdict does not mean traffic will reach
the application. NSG rules (L4) and OS-level firewall rules (host) are outside this tool's
scope.

---

## Positioning in the Investigation Stack

```
1. Client resolves FQDN → IP            ← private_endpoint_dns_inspector (planned)
2. Client sends packet to resolved IP
3. L3: routing selects the path         ← effective_route_inspector  [this tool]
4. L4: NSG evaluates allow/deny         ← security_rule_inspector (planned)
5. Host: iptables/nftables evaluated    ← detect_config_drift
```

**Relationship to `detect_effective_network_drift`.** The existing Ghost Agent tool
`detect_effective_network_drift` answers a different question: did the effective route table
or effective NSG rules *change* between two points in time? It compares a captured baseline
against current state and reports drift. `effective_route_inspector` answers a point-in-time
question: given the current effective route table, which route wins for a specific
destination, and why? It applies the Azure route selection algorithm and returns a routing
verdict. The two tools are complementary — drift detection surfaces that something changed;
route inspection determines what the current state means for a specific destination.

**When Ghost Agent calls this tool.** When the reported symptom is consistent with a
routing-layer cause — silent packet loss, traffic taking an unexpected path, or suspected
NVA bypass — Ghost Agent calls this tool before proceeding to NSG or host-layer tools. A
blackhole or wrong next hop at L3 makes downstream analysis irrelevant. For symptoms clearly
attributable to other layers (DNS resolution failure, known firewall rule change), Ghost
Agent calls the appropriate tool for that layer first.

---

## Known Limitations

| Limitation | Behaviour |
|------------|-----------|
| BGP AS Path tie | AS Path is not in the effective route table JSON. Two BGP routes with identical prefix result in `TIED (BGP)`. Ghost Agent Brain directs the engineer to inspect gateway BGP peer status to resolve the tie. |
| Azure Virtual WAN | Spoke NIC routes do not reflect routing inside the managed vWAN hub. If VirtualNetworkGateway routes are absent but expected, the tool flags the gap. |
| Multiple NICs | Only the primary NIC is queried by default. Multi-NIC VMs may require explicit NIC selection. |
| OS-level blocking | A correct route does not guarantee delivery. OS firewall rules are out of scope — use `detect_config_drift` for that layer. |
| NSG evaluation | NSG rules are out of scope — use `security_rule_inspector` (planned) for that layer. |
