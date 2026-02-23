# Network Engineering Principles

These principles reflect two decades of experience designing, operating, and
building tools for cloud and enterprise networks. They govern how I approach
network investigation, diagnostic system design, and the automation of network
operations. Sections I through IV apply regardless of vendor, cloud provider, or
tooling generation. Section V addresses patterns specific to cloud networking
automation, using cloud APIs and CLIs as the primary reference point.

---

## I. Investigation Methodology

**Model the network path before issuing a single diagnostic command.**
An investigation without a model is just guessing in sequence. Know the layers,
the enforcement points, and the expected path of a packet before you start querying.
The model defines what "clean" means at each layer and determines when the
investigation is complete.

**Start with the most recent change, not the most obvious symptom.**
When connectivity breaks, the most probable cause is the most recent configuration
change. Establish the change timeline before forming other hypotheses. This does
not mean other causes can be dismissed — but it determines the investigation order
and the burden of evidence required to rule the change in or out.

**A clean result at one layer narrows the investigation — it does not close it.**
Each layer of the network stack must be cleared independently. A firewall rule that
permits all traffic says nothing about routing, DNS, or the service layer. Work
source-to-destination through every layer — DNS resolution, routing, access control,
application — and continue until either the failure is located or every layer is
explicitly cleared. The most expensive failures hide in the layer nobody checked
after the first one came back clean.

```
  DNS resolution ── clean ──→  narrows investigation; check routing next
         ↓
  Routing tables ── clean ──→  narrows investigation; check access control next
         ↓
  Access control ── clean ──→  narrows investigation; check application next
         ↓
  Application    ─── FAIL ──→  failure domain located
```

**Isolate the failure domain before escalating to packet capture.**
Packet captures are expensive, time-consuming, and produce results that require
interpretation. Exhaust control-plane queries first — routing tables, firewall rules,
DNS records, peering state. Escalate to wire-level capture when and only when
control-plane evidence is inconclusive or contradictory. A capture taken before
the control plane is understood generates data without context.

---

## II. Configuration Intent vs. Effective State

**What is configured and what is enforced are two different things. Always verify both.**
A route in a route table is intent. The effective route on a specific interface,
at the actual enforcement point, is truth. These can differ: a more-specific route
may override a broader one, a system default may win over a custom entry, or a
recently applied change may not yet be reflected in the data plane. The configured
state tells you where to look. The effective state tells you what is actually
happening to traffic.

```
  Route table (configured intent)     Effective route on NIC (enforced truth)
  ──────────────────────────────────  ──────────────────────────────────────
  10.0.0.0/16  →  VNet local          10.0.1.5/32  →  10.0.1.100  ← UDR wins
  0.0.0.0/0    →  internet gateway    10.0.0.0/16  →  VNet local
                                      0.0.0.0/0    →  internet gateway
```

**Always query the effective state at the enforcement point, not the configuration store.**
The enforcement point is the interface, the NIC, the gateway — wherever the traffic
classification decision is actually made. The configuration store shows what was
intended. The enforcement point shows what is applied. For any layer that has both
configured and enforced state, both queries are required for a complete, defensible
finding. Either alone is insufficient.

---

## III. Multi-Component and Relational Failures

### Diagnosing Relational Failures

**The hardest failures to diagnose are those where each component is individually
correct and only the relationship between them is broken.**
A storage access control that permits traffic from a subnet, paired with a subnet
that lacks the service endpoint required to authenticate that traffic — each
component checks out, the relationship fails. An IAM policy that grants access to
a resource, paired with a resource that requires a specific network origin —
same pattern. Single-component health checks will always pass for this class of
failure. Design diagnostic workflows to verify both sides of every dependency
relationship simultaneously.

```
  Component A  ── isolated check ──→  ✓ PASS
  Component B  ── isolated check ──→  ✓ PASS
  ─────────────────────────────────────────────
  A ──────────→ B  relationship   ──→  ✗ FAIL  ← the contract between them is broken
```

**Investigate relationships with the same rigour as components.**
Add "verify the relationship between A and B" as an explicit step in diagnostic
runbooks — not an afterthought after A and B individually check out. The mismatch
is often invisible unless both sides are examined in the same diagnostic step.
A component that "passes" its individual health check may still be contributing
to a failure through a broken contract with its neighbour.

### Preventing Relational Failures

**When two components interact, define the contract between them explicitly.**
Relational failures occur when the contract is implicit and one side changes
without the other being updated. Document what component A expects from component B
and what component B expects from A. Changes to either side that affect the
contract must trigger a review of both sides. This applies to service endpoints,
trust relationships, peering configurations, and any two-sided access control model.

---

## IV. Evidence and Fidelity

**Evidence has a hierarchy. Higher fidelity always wins when sources conflict.**

```
  Highest fidelity:  Wire-level packet capture at the hypervisor or physical NIC
                     → truth about what bytes were actually transmitted
                         ↓
                     Cloud platform control-plane API (route tables, firewall rules)
                     → authoritative statement of configured policy
                         ↓
                     Active probe from within the same network segment
                     → live path test, subject to OS rate-limiting and NVA behaviour
                         ↓
  Lowest fidelity:   Observation from outside the target network
                     → affected by local DNS resolvers, VPN routing, ISP paths
```

When sources at different tiers contradict, trust the higher-fidelity source.
Document explicitly why the lower-fidelity result was discarded. A local probe
failure alongside a cloud API reporting "permit" is not a firewall problem — it is
a local environment problem. Misattributing evidence tier is among the most frequent
causes of wrong root-cause conclusions — and the one most easily avoided by applying
an explicit hierarchy.

**Absence of evidence is a positive finding, not a failed diagnostic.**
A packet capture on the destination VM showing zero arriving packets is not an
inconclusive result — it is definitive proof of a complete black hole between
source and destination. A firewall log with no deny entries for a given port and
address is useful diagnostic information. Design investigation workflows to surface
and interpret null results explicitly. "Nothing was found" is a conclusion that
requires as much documentation as "something was found."

**Do not treat a failing local probe as definitive evidence of a cloud network failure.**
Local observations — pings, traceroutes, curl responses — reflect the local machine's
network environment: its DNS resolver, its VPN tunnel, its ISP's routing table.
A local probe failure is first-tier evidence about the local environment, not
third-tier evidence about the cloud infrastructure. Always qualify local probe
conclusions explicitly and corroborate them with cloud-tier evidence before reporting.

---

## V. Automation and Cloud Networking

**The cloud API and the cloud CLI are not the same interface.**
The CLI presents a convenience abstraction over the REST API. For most read
operations they are equivalent. For write operations — particularly those that
modify relationships between resources, remove associations, or set fields to null —
they can diverge in critical ways. Any operation that removes or resets a resource
association should be verified at the REST API level, not assumed from the CLI's
accepted input. When the CLI abstraction proves inadequate, step around it to the
raw REST API directly.

**In cloud networking automation, the create operation and the read/update/delete
operations are distinct behavioral contracts — not variations of the same one.**
Cloud CLI subcommands within the same namespace routinely require different mandatory
parameters, access different underlying APIs, and produce different error modes.
Test the full resource lifecycle end-to-end as a network automation concern: a
packet capture orchestrator that can create captures but cannot reliably list, show,
or delete them is not a complete tool. The behavioral contracts that break in
production are almost always in the non-create path.

**Encode platform constraints in the orchestrator, not in convention.**
Cloud platforms impose singleton constraints, quota limits, and ordering dependencies
that are not reliably enforced with clear error messages. An orchestrator managing
a resource lifecycle must model and enforce these constraints locally — one active
capture per VM, one route table per subnet — rather than relying on the platform
to reject violations gracefully. Platform error messages for quota and constraint
violations are rarely actionable; pre-validation in the orchestrator is.

---

## VI. Diagnostic System Design

**Build investigation workflows as evidence accumulators, not binary pass/fail tests.**
A single "does this firewall rule block this traffic" query is a test. An
investigation collects evidence from multiple layers, weighs evidence by fidelity,
resolves contradictions by escalating to higher-fidelity sources, and produces a
conclusion that cites specific evidence. Design investigation systems to accumulate
and track evidence state across multiple steps, not to short-circuit at the first
positive or negative result. This is the foundational design decision from which
escalation logic, evidence hierarchy, and contradiction resolution all follow.

**A diagnostic system is only as good as the escalation logic encoded in it.**
Human practitioners escalate instinctively: firewall clean, check routing; routing
clean, check DNS; DNS clean, check the service. Automated systems have no instinct.
For each failure class the system investigates, encode an explicit escalation path:
the initial query, the condition that triggers escalation, and the confirming
diagnostic at the next layer. Escalation logic that exists only in the practitioner's
head produces correct manual investigations and incorrect automated ones.

**The investigation specification is the senior practitioner's knowledge, codified.**
For any diagnostic system — runbook, automated tool, or AI-driven agent — the
specification encodes what an experienced engineer would do: escalation patterns,
evidence hierarchy, pivot logic after a negative result, confirmation requirements
before concluding. Every investigation that reveals a gap — a step an expert would
have taken but the system did not — is a missing rule in the specification. Review
investigation records systematically and update the specification. It is a living
document, not a one-time artifact.

---

## Summary

| Principle | In One Line |
|-----------|-------------|
| Model first | Know the expected path before issuing the first diagnostic command |
| Recent change first | The most probable cause is the most recent change |
| Full stack investigation | A clean layer narrows the investigation; it does not close it |
| Escalate deliberately | Exhaust control-plane queries before initiating packet capture |
| Intent vs. effective | Configured state is where to look; effective state is what is happening |
| Relational failures | Design diagnostics to verify both sides of a dependency simultaneously |
| Define the contract | Document what each component expects from its neighbours; changes to either side trigger a review |
| Evidence accumulator | An investigation accumulates and weighs evidence; it does not short-circuit on the first result |
| Evidence hierarchy | Higher fidelity wins; document why lower-fidelity results were discarded |
| Null results | Absence of evidence is a positive diagnostic finding |
| Local probe limits | A failing local probe is evidence about the local environment, not the cloud |
| CLI vs REST | Remove/unset operations require REST-level verification, not CLI trust |
| Full lifecycle testing | Non-create operations carry the majority of undocumented behavioral contracts |
| Platform constraints | Model quota and singleton constraints in the orchestrator, not in convention |
| Escalation encoded | Escalation logic that exists only in the practitioner's head is not in the system |
