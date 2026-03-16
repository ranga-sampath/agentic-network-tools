# Netfilter Inspector — Product Requirements

*Status: MVP shipped — 2026-03-15*
*Architecture: `docs/architecture.md`*

---

## 1. Users

**Primary user — network engineer / cloud operator**
An operator responsible for the security posture and change hygiene of Linux VMs in Azure or other SSH-accessible environments. They run the tool from their workstation before and after a change window, or during an incident investigation.

**Secondary user — Ghost Agent**
An AI forensics agent that calls the tool programmatically as one step in a multi-layer investigation. It supplies session IDs, reads structured drift output, and uses the result as evidence before escalating to deeper diagnostics.

---

## 2. Problem

Azure's control plane — NSG rules, UDRs, VNet peering — has no visibility into the OS-layer firewall inside the VM. A packet that passes all Azure network checks can still be silently dropped by iptables or nftables on the VM. Azure Change Analysis, Network Watcher, and the Activity Log have no record of this layer.

This creates a specific, recurring failure class: a firewall rule change inside the VM causes a connectivity fault, but every Azure-visible control is clean. The operator has no baseline to compare against and no structured way to detect what changed.

---

## 3. Functional Requirements

**FR-1 — Remote ruleset capture**
The tool must retrieve the complete active iptables/nftables ruleset from a target VM.

**FR-2 — Baseline storage**
The tool must store a point-in-time snapshot of the retrieved ruleset as a structured, machine-readable artifact. See C-4 for integrity constraints on load.

**FR-3 — Drift comparison**
The tool must compare a current ruleset against a previously stored baseline and produce a structured report identifying: rules added, rules removed, rules repositioned, chains added, chains removed, chains with a changed default policy, and tables added or removed.

**FR-4 — Security significance classification**
The drift report must distinguish changes that directly affect security posture (DROP/REJECT rule additions or removals, default policy changes) from structural or positional noise (LOG rules moving, user-defined chains appearing). This distinction must be machine-readable, not require the operator to read and interpret raw diff output.

**FR-5 — Ephemeral chain suppression**
The drift report must suppress noise from chains that are expected to change on every workload scheduling event (Kubernetes pod chains, short-lived service chains). Changes in these chains must not obscure security-relevant changes in the same report.

**FR-6 — Multi-family coverage**
The tool must capture and diff both IPv4 and IPv6 rulesets in a single operation. A drift report that covers only IPv4 is incomplete.

**FR-7 — Framework detection**
Before capturing rules, the tool must determine which netfilter framework is active on the VM (iptables-legacy, iptables-nft, nftables-native, or mixed) and report this as metadata. The operator must not need to know or specify the framework.

**FR-8 — Audit trail**
Every shell command executed on the operator's machine during a session must be recorded in a session-scoped, append-only log. The log must contain enough information to reconstruct what happened without replaying the session.

**FR-9 — Machine-readable artifacts**
All artifacts — baseline snapshots, drift reports, command logs — must be machine-readable in a format consumable by Ghost Agent and operator tooling without screen-scraping.

**FR-10 — Ghost Agent integration**
The tool must be callable as a subprocess by Ghost Agent. The integration must support a read-only classification (no human approval gate required) for all capture and compare operations. Mutative operations, if any, must be gated for human approval before execution.

---

## 4. Constraints

**C-1 — No persistent agent on target VM**
The tool must not install software, create persistent processes, or leave files on the target VM after the session ends. A temporary probe script may be delivered and cleaned up within the same session.

**C-2 — Read-only on target VM**
The tool must not modify firewall rules, network configuration, or any system state on the target VM. Observation only.

**C-3 — No elevated privileges on the operator's machine**
The tool must run as a normal user process on the operator's workstation. It must not require sudo on the operator's side.

**C-4 — Baseline integrity is non-negotiable**
A stored baseline that has been modified after writing must never be loaded silently. The tool must refuse to use a corrupted or tampered baseline and must surface this as an explicit error.

**C-5 — No installation step on the operator's machine**
The tool must run without requiring the operator to install additional packages, build dependencies, or manage a virtual environment before use.

**C-6 — Session IDs must be filename-safe**
Session IDs are used as filename prefixes for all artifacts. They must be validated to contain only characters that are safe in filenames across Linux, macOS, and common CI environments.

**C-7 — SSH topology support**
The tool must support both direct SSH to the target VM and two-hop SSH via a bastion host. The operator must be able to configure both topologies without modifying the tool's code.

---

## 5. Out of Scope

| Capability | Reason excluded |
|-----------|-----------------|
| nftables-native rule parsing | Requires a separate parsing strategy; deferred post-MVP |
| Active remediation — modifying firewall rules on the VM | Out of the read-only constraint; a separate, explicitly mutative workflow |
| Fleet-wide scanning across multiple VMs in one invocation | A loop around this tool; not a concern inside it |
| Cloud blob storage for baseline artifacts | Post-MVP; local filesystem is sufficient for the primary use cases |
| Multi-subscription Azure support | Adds credential-management complexity; single-subscription scope sufficient for MVP |
| Windows Firewall | Different OS layer, different tooling, different scope |
| `--explain` — natural language explanation of drift findings | Useful but not required for the core observe-and-compare workflow; design exists, implementation deferred |
| Scheduled / continuous monitoring | A scheduler around this tool; not a concern inside it |
