# security-rule-inspector — Product Requirements

## Overview

`security_rule_inspector` is a tool that gives engineers and the Ghost Agent a precise, authoritative answer to one question: **is this traffic allowed or blocked by Azure NSG policy, and why?**

Azure NSG denials are silent. Traffic times out with no error, no ICMP unreachable, and no log unless diagnostics are explicitly enabled. The effective NSG policy applied to a VM is computed state — it merges subnet-level and NIC-level rules into the actual policy enforced at the VM's network interface. Engineers routinely inspect the wrong NSG or misread the evaluation order, leading to remediation actions that have no effect.

This tool eliminates that ambiguity. Given a VM and optionally a traffic description, it retrieves the effective security policy autonomously and evaluates it against Azure's dual-gate NSG model to return a structured, trustworthy verdict.

---

## Who Uses This Tool

**Ghost Agent (primary consumer).** Ghost Agent calls this tool as part of a connectivity investigation. It provides the VM name and traffic description; the tool returns a structured verdict that Ghost Agent synthesizes with routing and DNS findings to produce a root cause analysis.

**Field engineers (secondary consumer).** Engineers investigating NSG-related connectivity failures can invoke the tool directly — either through Ghost Agent or as a standalone utility — to get an immediate verdict without manually collecting and interpreting raw NSG data.

---

## What the Tool Does Not Do

- It does not diagnose routing failures. A routing blackhole drops the packet before the NSG is reached. Use the route inspector first.
- It does not inspect OS-level firewall rules (iptables/nftables) inside the VM. NSG ALLOW does not guarantee the application receives traffic. Use the firewall inspector if NSG is clean.
- It does not resolve Private Link DNS mismatches. If the client resolved to a public IP, the NSG being evaluated may be on the wrong path entirely.
- It does not make AI inferences. The verdict is a fact derived from the effective NSG rules — not a model judgment. The AI (Ghost Agent Brain) synthesizes findings across tools; it does not produce the verdict itself.

---

## Operating Modes

### Verdict Mode

Used when a specific connectivity failure is under investigation. The engineer or Ghost Agent provides the full traffic description: source IP, destination IP, destination port, protocol, and direction. The tool evaluates the effective NSG rules through the Azure dual-gate model and returns a complete verdict.

**Output includes:**
- Gate-by-gate evaluation result (which gate evaluated first, which rule matched, what decision was made)
- Whether the second gate was reached or short-circuited
- The final ALLOW or DENY verdict for the traffic
- The specific rule that produced the verdict (priority number, rule name, gate)
- Any shadowed ALLOW rules that exist but are unreachable
- A plain-language root cause statement
- A specific remediation action (which NSG, which rule, what change)

### Audit Mode

Used when no specific traffic failure is under investigation — the goal is to understand the full security posture applied to a VM, typically before a workload change, a security review, or onboarding a new VM to an existing subnet.

The tool collects and evaluates all effective rules across both gates and both directions.

**Output includes:**
- Full rule inventory for both NSGs (subnet and NIC), both directions (inbound and outbound), sorted by priority
- Shadowed rules flagged: rules that exist but can never be reached because a higher-priority rule above them matches the same traffic
- Overly permissive rules highlighted: custom ALLOW rules with wildcard source, destination, or port that may represent unintended exposure
- Gates relying only on Azure default rules identified (no custom rules applied — policy entirely determined by defaults)
- Summary posture assessment across all four rule sets

---

## Use Cases

### Use Case 1 — Port silently blocked, no error visible

An application VM cannot reach a database on port 1433. The connection times out with no error.

The engineer or Ghost Agent invokes verdict mode with the source VM, destination IP and port, TCP protocol, and outbound direction. The tool evaluates both gates and identifies the blocking rule. Common findings in this scenario: a deny-all-outbound rule at a low priority number shadowing a legitimate allow rule that was added later at a higher number.

The output names the blocking gate, the blocking rule, and whether the allow rule exists but is shadowed — giving the engineer an exact, actionable fix.

### Use Case 2 — Inbound traffic blocked by the wrong gate

HTTPS traffic cannot reach a web server. The NIC NSG has an ALLOW rule for port 443. The engineer has verified it and cannot understand why traffic is still blocked.

Ghost Agent invokes verdict mode with inbound direction. The tool evaluates the subnet NSG first (correct for inbound traffic) and finds a deny-all-inbound rule at priority 100. The NIC NSG is never reached. The NIC NSG ALLOW rule the engineer found is irrelevant — traffic was dropped at the subnet gate before it ever reached the NIC.

The output identifies the correct blocking gate and makes the dual-gate ordering visible. The engineer has been looking at the right rule in the wrong NSG.

### Use Case 3 — Connectivity investigation as part of a multi-tool RCA

Ghost Agent is investigating a full connectivity failure. It has already confirmed the routing path is correct (VNetLocal, no blackhole). It calls verdict mode next.

The tool returns a DENY verdict: gate 1 matches a deny rule, gate 2 never evaluated. Ghost Agent now has a complete, two-step RCA — correct route, NSG block — without needing to involve the user in any data collection step. The verdict is structured and unambiguous, so Ghost Agent can proceed directly to root cause and remediation.

### Use Case 4 — Security posture audit before a workload deployment

A new service is being deployed to a subnet. The team wants to understand what security rules are currently applied to that subnet before adding the new VM.

Ghost Agent invokes audit mode against an existing VM in the target subnet. The tool returns the full rule inventory, flags any shadowed rules, identifies overly permissive entries, and notes whether any gate relies only on Azure defaults with no custom rules.

Ghost Agent produces a posture summary and flags specific rules that need tightening before the new workload is deployed. No manual rule export, no spreadsheet comparison, no risk of misreading JSON.

### Use Case 5 — Post-change verification

A rule change was applied to an NSG. The engineer wants to confirm the effective policy at a VM now reflects the expected state.

Audit mode surfaces the current effective rules at that VM in a structured, readable form. The engineer reviews the output against the expected post-change state. The tool shows what is actually in effect — the engineer makes the judgement about whether it matches intent.

---

## Inputs

| Input | Required | Description |
|---|---|---|
| VM name | Always | The Azure VM under investigation |
| Resource group | Always | The resource group containing the VM |
| Source IP | Verdict mode | Source address of the traffic being evaluated |
| Destination IP and port | Verdict mode | Destination address and port |
| Protocol | Verdict mode | TCP, UDP, ICMP, or any |
| Direction | Verdict mode | Inbound or outbound |
| NIC name | Optional override | For multi-NIC VMs; defaults to primary NIC |

Audit mode requires only VM name and resource group.

---

## Outputs

### Verdict Mode Output

The following is an illustrative example. Exact formatting is a design decision.

```
Traffic:        10.1.0.5 → 10.2.0.10:1433 TCP outbound

Gate 1 (NIC NSG — evaluated first for outbound):
  Rule matched:   deny-all-outbound (priority 1000)
  Decision:       DENY
  Gate 2:         Not evaluated (short-circuited)

Final verdict:  DENY

Shadowed rules: allow-sql-outbound (priority 2000) — matches same traffic,
                unreachable because deny-all-outbound at 1000 takes precedence

Root cause:     deny-all-outbound (priority 1000) in NIC NSG blocks outbound TCP
                to 10.2.0.10:1433 before allow-sql-outbound (priority 2000) is reached.

Remediation:    Lower the priority of allow-sql-outbound to a value below 1000,
                or remove deny-all-outbound if it is overly broad.
```

### Audit Mode Output

The following is an illustrative example. Exact formatting is a design decision.

```
VM:             app-vm  (rg-networking)
NIC:            app-vm-nic

─── INBOUND ───────────────────────────────────────────

Subnet NSG (evaluated first for inbound):
  Priority  Name                      Action   Protocol  Source          Destination
  100       DenyAllInbound            DENY     *         *               *
  65000     AllowVnetInBound          ALLOW    *         VirtualNetwork  VirtualNetwork
  65001     AllowAzureLoadBalancer    ALLOW    *         AzureLoadBalancer *
  65500     DenyAllInBound            DENY     *         *               *          [default]

NIC NSG (evaluated second for inbound):
  Priority  Name                      Action   Protocol  Source          Destination
  ...

─── OUTBOUND ──────────────────────────────────────────

NIC NSG (evaluated first for outbound):
  ...

Subnet NSG (evaluated second for outbound):
  ...

─── FINDINGS ──────────────────────────────────────────

Shadowed rules:
  [Subnet NSG / Inbound] allow-ssh (priority 500) — shadowed by DenyAllInbound (100)

Overly permissive rules:
  [NIC NSG / Outbound] allow-all-outbound (priority 200) — source *, dest *, port *

Default-only gates:
  None — custom rules present in all four rule sets

Posture summary:
  Inbound traffic to this VM is effectively blocked by DenyAllInbound at priority 100
  in the subnet NSG. No inbound traffic can reach this VM regardless of NIC NSG rules.
  Review whether DenyAllInbound is intentional or a misconfiguration.
```

---

## Handling Unresolvable Rules

Some NSG rules reference constructs that cannot be fully resolved from the effective NSG JSON alone. The tool handles these predictably:

**Application Security Groups (ASGs).** When a rule uses an ASG as source or destination, the tool cannot determine which IPs belong to that ASG without additional data. The rule is flagged with the ASG name and marked as UNRESOLVABLE for matching purposes. The user is asked to provide the ASG membership if a verdict is needed.

**Non-standard service tags.** Service tags other than `VirtualNetwork`, `Internet`, and `AzureLoadBalancer` require tag membership data not available in the effective NSG JSON. These are flagged as UNRESOLVABLE. The verdict for rules using these tags is marked indeterminate.

**Multi-NIC VMs.** The tool evaluates the primary NIC by default. For VMs with multiple NICs, the relevant NIC may not be the primary. An explicit NIC name override resolves this.

---

## Integration with Ghost Agent

Ghost Agent calls this tool after confirming the routing path is correct. A correct route combined with an NSG block is a common and frequently misdiagnosed failure pattern — engineers often look at the wrong NSG or the wrong rule until the effective policy is evaluated in full.

The tool is integrated into Ghost Agent's investigation sequence:

```
1. DNS resolution check       ← private_endpoint_dns_inspector (if applicable)
2. Route path confirmation    ← effective_route_inspector
3. NSG evaluation             ← security_rule_inspector  (this tool)
4. Host firewall check        ← firewall_inspector (if NSG is clean)
```

Ghost Agent calls verdict mode when investigating a specific connectivity failure, providing the full traffic tuple. If the tool returns DENY, Ghost Agent has the root cause and can proceed to remediation guidance without additional data collection. If the tool returns ALLOW, Ghost Agent continues to the host firewall layer.

Ghost Agent calls audit mode when asked for a security posture assessment or before recommending configuration changes that could affect security policy.

The tool returns structured output that Ghost Agent incorporates into its root cause analysis alongside routing and DNS findings. Ghost Agent produces the narrative and remediation guidance — the tool produces the facts.

---

## Relationship to the azure-security-rule-resolver Skill

`azure-security-rule-resolver` is a Claude Code skill for field engineers. The engineer collects the effective NSG data manually and hands it to the skill, which applies the dual-gate algorithm and returns a human-readable verdict.

`security_rule_inspector` is a Ghost Agent tool. It retrieves the effective NSG data autonomously — no manual step from the engineer — and returns a structured verdict the Brain can trust when building a multi-tool RCA. The verdict is produced without AI involvement.

Neither replaces the other. They serve different users and different workflows.

| | Claude Code Skill | Ghost Agent Tool |
|---|---|---|
| Who invokes | Field engineer | Ghost Agent Brain |
| Data collection | Engineer collects NSG data manually | Tool retrieves NSG data autonomously |
| Verdict | AI applies dual-gate algorithm | Algorithm applied without AI involvement |
| Output | Human-readable narrative | Structured output to Brain |
| Synthesis | Standalone — one-shot verdict | Brain synthesizes with routing + DNS findings |

---

## Known Limitations

| Limitation | Behaviour |
|---|---|
| Application Security Groups | ASG membership not available in effective NSG JSON — rule flagged as UNRESOLVABLE, user prompted for ASG definition |
| Non-standard service tags | Tags other than VirtualNetwork, Internet, AzureLoadBalancer — flagged as UNRESOLVABLE |
| Multiple NICs | Primary NIC used by default; explicit NIC override required for secondary NICs |
| OS firewall | NSG ALLOW does not guarantee traffic reaches the application — use firewall inspector if NSG is clean |
| Routing | Packet dropped by a routing blackhole never reaches the NSG — use route inspector first |
| Private Link DNS | NSG on the correct route may be the wrong NSG if the client resolved to a public IP |
