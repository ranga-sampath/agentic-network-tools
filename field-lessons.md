# Engineering Challenges: Agentic Infrastructure Tooling

Lessons from building an AI-driven network forensics system for cloud environments.
Audience: Senior Network and Cloud Architects evaluating or building similar systems.

---

## Theme 1 — The Cloud API Is Not One Thing

> **Scope:** This theme applies to any automation that drives cloud infrastructure
> through a CLI or REST API — whether the orchestrator is an LLM agent, a CI/CD
> pipeline, or a hand-written script. The gotchas here are properties of the cloud
> platform's API surface, not of the automation layer above it.

Cloud CLIs, REST APIs, and managed service behaviours each have their own contracts.
Assuming they are interchangeable is the single most common source of subtle,
hard-to-diagnose failures in infrastructure automation.

### 1.1 CLI "Unset" Operations Can Silently Construct Invalid Resources

When you pass an empty string to a CLI flag expecting a resource reference,
the CLI may construct a valid-looking but semantically broken ARM/API resource ID —
and submit it without complaint.

```
  az subnet update --route-table ""

  What you expect:     route table association → null
  What the CLI sends:  /subscriptions/.../routeTables/   ← empty name → rejected by platform
```

**Lesson:** For any "remove association" operation, verify what the CLI actually
sends over the wire. When the CLI proves inadequate, use the raw REST API:
GET the resource (raw JSON, nested structure intact), strip the offending field in
one line of code, PUT it back. Don't fight the CLI abstraction — step around it.

---

### 1.2 CLI Output Structure ≠ REST API Input Structure

The cloud CLI's `-o json` returns a flattened convenience representation. The
REST API's PUT expects properties nested under a `properties` key. They are the
same data in different shapes.

```
  az subnet show -o json              →  { "name": "default", "routeTable": {...} }
                                                 ↑ flattened

  az rest GET (raw ARM)               →  { "name": "default",
                                           "properties": { "routeTable": {...} } }
                                                              ↑ nested — correct for PUT
```

**Lesson:** Never round-trip CLI JSON into a REST write. Use `az rest GET` to read,
transform in memory, and `az rest PUT` to write. Treat CLI output as a display
format, not an API payload.

---

### 1.3 Commands in the Same CLI Namespace Can Require Different Parameters

A CLI command group may look uniform but contain subcommands with structurally
different required arguments — and there is no warning when you use the wrong one.

> Example: `az network watcher packet-capture create` requires `--resource-group`.
> Every other subcommand in the same group (`show`, `delete`, `list`) requires
> `--location` instead. Passing `--resource-group` to those commands produces
> silently incorrect behaviour — discovered only at runtime.

**Lesson:** In any orchestrator that manages a resource lifecycle, test the full
cycle — create, show, update, delete — end-to-end before releasing. Non-create
subcommands routinely have different behavioral contracts than create, and those
contracts are only discovered at runtime if untested. Create-path-only coverage is
the specific gap that bites most automation projects.

---

## Theme 2 — LLMs in the Loop Require Explicit Contracts

> **Scope:** This theme applies specifically to agentic systems where an LLM drives
> infrastructure operations through tool calls. It does not apply to deterministic
> automation pipelines.

An LLM agent operating on live infrastructure is only as reliable as the
constraints you have written down explicitly. Expertise that a human practitioner
applies "automatically" is invisible to the model unless it is formally encoded.

### 2.1 Ambient Prompt Context Pollutes Agent Reasoning

Any resource name, identifier, or value present in the investigation prompt
becomes a candidate for the agent's reasoning — including as the target of the
agent's own operational actions.

```
  Investigation prompt:
    "Storage account nwdemosa1234 is unreachable..."
                         ↑
                         Agent uses this for:
                         [1] investigation target ✓  (intended)
                         [2] packet capture destination ✗  (not intended)
```

**Lesson:** Separate the *subject under investigation* from the *agent's
operational infrastructure* — at the naming level and at the prompt level.
Never reference the agent's own infrastructure resources in the investigation
prompt. Inject operational configuration through a dedicated, unambiguous channel
(CLI arguments or a clearly delimited system prompt block) that is structurally
distinct from user-provided context.

---

### 2.2 Transient Failures Can Corrupt the Agent's State Machine

A rate limit or dropped response on turn 1 can silently skip the state
initialization step that all subsequent turns depend on. The agent continues
operating — but its reasoning has no foundation.

> Context: this agent maintains a list of active working hypotheses — the specific
> failure modes it is currently testing. The list is initialized on turn 1 and
> drives all subsequent diagnostic decisions and termination logic.

```
  Turn 1:  [API rate limit — response dropped]
           → working hypothesis list never initialized → []

  Turn 2:  Agent checks: "are all hypotheses resolved?" → yes (list is empty)
           → signals "investigation complete" with no evidence collected

  Correct: Turn 2 should detect the empty list and re-initialize
           before issuing any diagnostic commands
```

**Lesson:** For every state machine invariant in your agent loop, encode a recovery
rule directly in the system prompt: *"If you arrive at a turn where X is empty and
the investigation has not concluded, re-initialize X before any other action."*
Do not assume the happy path always executes. Transient failures are first-class
events the agent must self-diagnose.

---

### 2.3 The System Prompt Is Your Formal Specification

Pivot logic that a human expert applies instinctively — "NSG clean, check the
route table next" — does not exist for the model unless it is written down as an
explicit rule. An agent without this encoded will correctly identify a clean NSG
and stop there, reporting a false negative.

**Lesson:** For each failure class the agent investigates, write a named escalation
block in the system prompt:

```
  ROUTING ANOMALY PATTERN:
  1. az network route-table route list  →  find suspicious route
  2. az network nic show-effective-route-table  →  confirm it is winning
  Only report a routing failure after BOTH steps produce confirming evidence.
```

Treat the system prompt as a living specification. Audit investigation transcripts
regularly; every case where an expert would have taken one more step is a missing
rule.

---

## Theme 3 — Network Failures Require Layered, Relational Investigation

> **Scope:** This theme applies to anyone designing or operating network diagnostic
> workflows — human-driven or automated. The patterns here reflect how cloud network
> failures actually present and are transferable across cloud providers and tooling
> choices.

The most expensive production failures hide in the gap between layers, or in the
relationship between two components that each appear healthy in isolation.

### 3.1 A Clean Layer Is Not a Clean Path

Each layer in the network stack must be verified independently. "NSG is clean"
rules out the NSG — it says nothing about routing, DNS, or the service layer above.

```
  Traffic path:

  Source VM
     │
     ▼
  [DNS Resolution]      ← clean? → continue
     │
     ▼
  [Routing / UDR]       ← BLACK HOLE FOUND HERE
     │
     ▼
  [NSG / Firewall]      ← checked first, came back clean — investigation stopped here
     │
     ▼
  Destination VM
```

**Lesson:** Model diagnostic logic as an explicit stack, not a checklist. A clean
result at one layer narrows the investigation to the remaining layers — it does not
close it. Continue through the full stack until either the failure is located or
every layer is cleared. The most expensive failures hide in the layer nobody checked
after the first layer came back clean.

---

### 3.2 Configuration Intent ≠ Effective Configuration

A route in the route table is what was *configured*. The effective route table on
a specific NIC is what is *actually winning* for that interface's traffic. These
can differ — and only one of them explains the failure.

> In one scenario: a route table contained `10.0.1.5/32 → VirtualAppliance →
> 10.0.1.100`. The NVA at 10.0.1.100 was never provisioned. The route table
> showed the intent. The NIC's effective route table confirmed the /32 host route
> was overriding the system VnetLocal route — the traffic was going to a black hole.
> Both queries were required for a complete, defensible finding.

**Lesson:** For routing and firewall investigations, always query both the
*configured* state and the *effective* state at the enforcement point. The effective
state at the NIC/interface is the ground truth. The configured state tells you
where to look; the effective state tells you what is actually happening.

---

### 3.3 Multi-Component Dependency Failures Are Invisible to Single-Component Inspection

The hardest failures to diagnose are those where each component, inspected
individually, is correctly configured. The failure lives only in the relationship
between two components.

```
  Component A: Storage account firewall
    Rule: allow traffic from subnet X          ← looks correct in isolation

  Component B: Subnet X
    Service endpoints: none configured         ← looks correct in isolation

  The broken relationship:
    The storage firewall only recognises traffic as "from subnet X" if the
    subnet has a service endpoint that presents the subnet's identity to the
    PaaS service. Without it, the VM's traffic arrives at the storage
    public endpoint — which the firewall rejects by default.

  Inspect A alone: ✓     Inspect B alone: ✓     Inspect the relationship: ✗
```

**Lesson:** For failure classes that span a dependency between two components
(service endpoints, IAM role bindings, certificate trust chains, API gateway
integrations), design diagnostic patterns that explicitly verify *both sides of
the relationship in the same step*. Single-component health checks will always
pass for this class of failure.

---

### 3.4 Evidence Has a Hierarchy — Higher Fidelity Always Wins

Multiple evidence sources will routinely produce conflicting results. Without an
explicit hierarchy, automated systems default to recency bias; human analysts
default to confirmation bias.

```
  Fidelity (highest → lowest):

  ┌─────────────────────────────────────────────┐
  │  Wire-level PCAP (hypervisor capture)       │  ← cannot be spoofed by OS
  ├─────────────────────────────────────────────┤
  │  Cloud platform API (az show / list)        │  ← authoritative control-plane state
  ├─────────────────────────────────────────────┤
  │  Active probe from inside Azure VM          │  ← affected by OS rate-limits, NVA
  ├─────────────────────────────────────────────┤
  │  Local probe (ping from engineer's laptop)  │  ← affected by local DNS, VPN, ISP
  └─────────────────────────────────────────────┘
```

> Example: `ping` timed out. NSG showed all-permit. PCAP showed ICMP round-trip
> completing successfully at the wire level. Root cause: ICMP rate-limiting by the
> guest OS. The ping failure was not network evidence — it was OS evidence. The
> PCAP was the correct source.

**Lesson:** Define and publish your evidence hierarchy before building any
diagnostic system. When sources contradict, always trust the higher-fidelity source
and document exactly why the lower-fidelity result was discarded. Encode this
hierarchy in any automated reasoning system — the model has no instinct for it.

---

### 3.5 The Third Filtering Layer: OS-Level Packet Filtering Is Invisible to Cloud Control-Plane APIs

The cloud control plane exposes two filtering layers — subnet NSG and NIC NSG —
and provides structured APIs for both. A third layer exists at every VM: the
OS-level packet filter (iptables/nftables on Linux; Windows Firewall on Windows).
This layer is structurally invisible to the cloud control plane. No cloud API
returns parsed OS firewall state. A NIC with fully permissive NSG rules at both
cloud layers can silently drop or reject traffic due to an OS rule that no portal
view, no CLI query, and no policy evaluation will surface.

```
  Inbound traffic path:

  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────────┐
  │   Subnet NSG     │ → │    NIC NSG       │ → │  OS firewall             │
  │                  │   │                  │   │  (iptables / nftables)   │
  │  Cloud API ✓     │   │  Cloud API ✓     │   │  No cloud API ✗          │
  └──────────────────┘   └──────────────────┘   └──────────────────────────┘
         ↑                      ↑                          ↑
    Structured,            Structured,              Raw command output
    queryable              queryable                only — no parsed API
```

The OS-layer gap is compounded on modern Linux distributions by the coexistence
of iptables and nftables. Rules created via `nft` directly are invisible to
`iptables -L` — an engineer checking only iptables on a RHEL 8 or Ubuntu 20.04
VM may conclude the OS firewall is permissive while an active nftables rule is
silently dropping traffic.

**Lesson:** Any diagnostic system that stops at the NIC NSG has structurally
missed a filtering layer. Design diagnostic workflows to treat OS-level firewall
state as a mandatory check when the cloud control plane is clean and traffic is
still failing. This layer requires active inspection — SSH access or a VM
run-command invocation — and returns unstructured text that must be parsed.
Treating it as an afterthought means the hardest class of failures will
consistently reach the end of your diagnostic checklist unresolved.

---

## Theme 4 — Safety Architecture for Agentic Infrastructure Systems

> **Scope:** This theme applies specifically to agentic systems where an LLM
> proposes and executes actions against live infrastructure. The patterns here
> assume a human operator is present and co-located in time with the agent.

An agent operating on live infrastructure needs safety constraints that are
structurally enforced, not behaviorally assumed.

### 4.1 Synchronous Human-in-the-Loop (HITL) Is Safer Than an Async Approval Queue

Async approval queues are architecturally elegant but create a window where the
agent continues reasoning while a risky action awaits human review.

```
  Async:                                  Synchronous:

  Agent proposes action                   Agent proposes action
        ↓                                        ↓
  Action queued                           Main thread BLOCKS  ← OS-level guarantee
        ↓                                        ↓
  Agent state must be frozen          Human approves or denies
  by convention — complex                        ↓
  to implement correctly                  Agent resumes with
        ↓                                 full context of decision
  Human approves
```

**Lesson:** For agentic systems on live infrastructure, block the main thread at
every risky action until the human decides. Synchronous HITL is not a performance
decision — it is a structural guarantee: the agent cannot advance because the
thread is blocked at the OS level, not by convention. An async approval system
*can* be made safe, but doing so requires correctly freezing all agent state pending
approval — a non-trivial design problem that synchronous HITL eliminates entirely.

---

### 4.2 Safety Classification Must Be Deterministic, Not AI-Driven

It is tempting to ask the LLM to classify whether a proposed command is safe or
risky — the model understands semantics. But this makes the safety gate dependent
on the most unpredictable component in the system.

We used a four-tier deterministic pipeline:

```
  Tier 1 — Always-safe allowlist    (ping, dig, az ... list/show — never blocked)
  Tier 2 — Read-only verb matching  (az verbs: list, show, get → auto-approved)
  Tier 3 — Dangerous-pattern regex  (rm, stop, delete, update → RISKY, requires approval)
  Tier 4 — Default                  (anything not matching tiers 1–3 → RISKY)
```

The default tier is the most important design decision: **anything unrecognised is
treated as risky, not as safe.** Each tier's behaviour is independently unit-testable
with adversarial inputs, and none of it depends on the LLM's state of mind.

**Lesson:** The safety layer is the one component that must not fail. Build it with
deterministic logic. Reserve the LLM for *what to do*; reserve deterministic logic
for *whether it is safe to do it*. These are different questions that belong in
different parts of the system. Ensure your classifier defaults to "risky" for
unrecognised inputs — a safety system that defaults to "safe" for the unknown is
not a safety system.

---

### 4.3 Denial Feedback Is a Signal — Inject It Back Into the Agent

When a human denies an agent's proposed action, the denial alone is nearly useless.
Without the reason, the agent will generate variations of the same wrong command.

```
  Without reason:
    Agent proposes: az network route-table route update --resource-group prod-rg
    Human: [D]eny
    Agent proposes: az network route-table route update --resource-group prod-rg  ← same

  With reason ("Wrong resource group — use cache-rg"):
    Agent proposes: az network route-table route update --resource-group cache-rg  ← corrected
```

**Lesson:** Capture a one-line reason at every denial event and inject it as
structured metadata into the agent's next tool response. The interface cost is
a single prompt; the improvement to replanning behaviour is significant. Design
your HITL interface to make the reason field feel natural to fill in, not optional
to skip.

---

## Theme 5 — Network Performance Measurement as a Discipline

> **Scope:** This theme applies to anyone designing or operating network performance
> measurement tooling — standalone or embedded in a larger diagnostic pipeline.
> The patterns here reflect what distinguishes rigorous measurement from a reading,
> and are applicable across cloud providers and transport protocols.

The difference between a measurement and a reading is discipline. A reading
is whatever the tool returned. A measurement is a value you can defend, reproduce,
and compare meaningfully over time.

### 5.1 Cold-Start Bias Is Systematic: Warmup and Statistic Selection Are Inseparable

The first result in any TCP performance test is drawn from a different distribution
than subsequent results. TCP slow start has not completed, receive buffers are not
fully allocated, and ARP cache may not be populated — all introducing a systematic
bias into the first sample. A single unrecorded warm-up pass before data collection
eliminates this bias at minimal cost.

The choice of summary statistic is inseparable from this decision. P90 is
appropriate when the SLA tolerates the worst 10% of experiences. For
latency-sensitive workloads — trading systems, real-time voice, control-plane APIs
— P99 or P99.9 captures the tail that actually matters. For sustained throughput
governed by average capacity, a mean is more representative than any percentile.
Defaulting to "average" or "P90" because it is familiar means you may be measuring
a different quantity than your SLA requires.

```
  8 latency samples (µs), no warmup: [842, 124, 127, 119, 121, 125, 123, 126]
                                        ↑ cold-start outlier

  Mean (all 8 samples):   225.9 µs  ← systematically wrong
  P90  (all 8 samples):   342.6 µs  ← systematically wrong

  Mean (samples 2–8, after warmup):  123.6 µs  ← correct
  P90  (samples 2–8, after warmup):  126.4 µs  ← correct
```

**Lesson:** A warm-up pass is the minimal correct implementation of any TCP
performance measurement — not optional, not a heuristic. The P-statistic must
follow from the SLA being tested. These two decisions are coupled: make them
together and explicitly, or the resulting numbers are defensible only by accident.

---

### 5.2 Measurement Direction Asymmetry: A→B Is Not B→A

Throughput and latency from VM A to VM B are not guaranteed to equal measurements
in the reverse direction — even on the same physical host pair, in the same
availability zone, with identical VM SKUs and identical accelerated networking
configuration.

Transmission performance is governed by the sender: TCP segmentation offloading
(TSO), send buffer sizing, and pacing all operate on the transmit path.
Reception performance is governed by the receiver: Receive Side Scaling (RSS)
maps incoming flows to CPU cores based on a hash of the 5-tuple, and hardware
receive queue depth limits how many parallel streams a NIC can sustain without
dropping. Two VMs with identical configurations can produce materially different
throughput in opposite directions because their RSS mappings resolve differently
against the underlying hardware and the specific flow hashes used by the test.

```
  In one scenario (same VNet, same SKU, accelerated networking enabled on both):

  VM-A → VM-B:  9.4 Gbps  (VM-B's RSS distributes 8 streams across 4 cores)
  VM-B → VM-A:  6.1 Gbps  (VM-A's RSS maps 8 streams to 2 cores — CPU-bound on receive)

  The asymmetry is in the receiver's RSS configuration, not in the network path.
```

**Lesson:** A unidirectional measurement characterises the path in one direction
only. Any performance baseline or SLA validation that does not account for
direction is potentially incomplete. Decide whether your use case requires
unidirectional or bidirectional measurement, make that decision explicit, and
document which direction was measured. The default assumption of symmetry is
frequently wrong in production environments.

---

### 5.3 Absolute Thresholds and Baseline Regression Detection Answer Different Questions

Two distinct measurement questions are routinely conflated in performance tooling:
"Is this path behaving acceptably right now?" and "Has this path regressed from a
prior known-good state?" The first requires an absolute threshold derived from the
application's SLA. The second requires a stored baseline — a reference measurement
from a known-good point — against which percentage delta is computed.

A path can satisfy every absolute threshold while showing a material regression
versus baseline — the critical signal after a change window that an absolute check
will never surface. Conversely, a high-jitter path (cross-region, over a shared
internet exchange) may routinely exceed a variance threshold while being perfectly
consistent with its own historical baseline, making the absolute threshold produce
persistent false positives that the baseline comparison correctly suppresses.

```
  Path state after a maintenance window:

  Latency P90:      142 µs    ← within the 200 µs SLA ceiling          ✓
  vs. baseline:     +18%      ← material regression from prior 120 µs  ✗

  Absolute check alone:   PASS  ← misses the regression
  Baseline comparison:    FLAG  ← catches it

  The two tools answer different questions.
  Implementing only one leaves a blind spot the other would have caught.
```

**Lesson:** Implement both. Absolute thresholds catch paths that violate SLA
requirements. Baseline comparison catches paths that are regressing — the more
sensitive signal for post-change validation and trend analysis. Design your
measurement system to store baselines at known-good moments (post-deployment,
post-change-window) and to run comparison as a first-class operation alongside
absolute checks. Neither subsumes the other.

---

### 5.4 The Measurement Tool Reports Observations; the Diagnostic Layer Assigns Causes

When a measurement produces multiple anomalous results simultaneously — degraded
throughput on one protocol, complete connection failure on another — the temptation
is to synthesise them into a single verdict at the measurement layer. This is a
separation-of-concerns error.

The measurement tool has evidence of what happened to the packets it sent. It has
no evidence of why. Causal attribution requires access to NSG rules, route tables,
OS firewall state, packet captures — evidence that lives in the diagnostic layer
above. A tool that conflates measurement with attribution makes both worse: the
measurement becomes interpretation-dependent, and the diagnostic layer loses the
independent raw observations it needs to reason correctly.

```
  Measurement layer returns two independent observations:
    throughput_p90:          4.2 Gbps    (HIGH_VARIANCE — baseline 9.4 Gbps)
    latency_connectivity:    FAILED      (server unreachable — zero samples)

  Incorrect design — measurement layer synthesises:
    → "path degraded, likely due to packet loss"

  Correct design — diagnostic layer reasons over both observations independently:
    • A rate-limiting fault reduces throughput proportionally across all traffic
      — it does not cause complete connection failure on a separate protocol
    • Two observations, mechanically distinct failure signatures
      → two independent hypotheses, two independent investigations
```

**Lesson:** Keep the measurement contract narrow and factual: values, units, sample
counts, and anomaly flags. Reserve causal language for the layer that has access
to the full evidence set. A diagnostic system that receives pre-synthesised
conclusions cannot perform independent hypothesis testing — it can only confirm or
deny what the measurement layer already decided, which is the wrong place to decide
it.

---

*Extracted from development of an AI-driven network forensics and performance
measurement system for cloud infrastructure — combining LLM tool-use, Azure
infrastructure APIs, human-in-the-loop safety gating, and forensic audit trail
requirements across a suite of tools covering autonomous network investigation,
VM-to-VM performance measurement, packet capture forensics, and safe command
execution.*
