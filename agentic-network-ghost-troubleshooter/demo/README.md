# Ghost Agent Demo — Presenter's Guide

**Audience:** Senior network engineers, cloud architects, SRE leads
**Duration:** 20-40 minutes depending on which use cases you run
**Prerequisites:** Complete `config.env` and pass `./00_prereqs.sh` before the session

---

## One-Time Setup

```bash
# 1. Fill in your Azure resource names
vi demo/config.env

# 2. Validate everything is ready
chmod +x demo/00_prereqs.sh
./demo/00_prereqs.sh

# 3. Export GEMINI_API_KEY into your shell for ghost_agent
export GEMINI_API_KEY="<your key>"

# 4. How to invoke ghost_agent
#    Use Case A — NSG investigation (no captures needed):
uv run --python 3.12 python ghost_agent.py \
  --resource-group nw-forensics-rg

#    Use Cases B & C — packet captures (include storage + location):
uv run --python 3.12 python ghost_agent.py \
  --resource-group    nw-forensics-rg \
  --location          eastus \
  --storage-account   nwlogs080613 \
  --storage-container pktcaptures
```

---

## The Opening Hook (60 seconds)

> "Every senior network engineer in this room has spent hours — sometimes days — on three classes of problem: something is blocked and nobody owns the rule that's blocking it, something is dropping packets but only intermittently, or a capture was taken but no one had time to parse it.
>
> What we've built doesn't replace your judgment. It extends your reach. You type a sentence. The system forms hypotheses, runs diagnostics, gates every risky action through you, captures wire traffic, and hands you a forensic RCA with the exact audit trail of everything it did. Let me show you."

---

## Use Case A — "The Invisible Wall"
**NSG misconfiguration discovery | ~8 minutes**

### What this shows
- Hypothesis formation from a vague symptom
- Autonomous escalation: local probes → Azure API queries
- HITL gate on the `az network nsg rule list` command
- RCA that cites the exact deny rule name, priority, and the fix

### Before the session
```bash
chmod +x demo/use_case_a/setup.sh demo/use_case_a/teardown.sh
./demo/use_case_a/setup.sh
# Wait 30 seconds for NSG rule propagation, then start
```

### Run the demo
```bash
uv run --python 3.12 python ghost_agent.py
```
When prompted for an investigation, paste:
```
My application team says their service on the destination VM is running and
listening on port 8080. But the source VM cannot connect to it — connections
just hang with no response or error. Ping between the VMs works fine.
Investigate why TCP port 8080 is not reachable from the source VM to the
destination VM.
```

### What to narrate while it runs
- **Turn 1 (hypothesis formation):** "Notice it's forming specific, falsifiable hypotheses before running a single command — NSG block, service not listening, routing issue. It's thinking before acting."
- **Turn 2-3 (ping, ss — auto-approved):** "SAFE commands go straight through — no interruption."
- **Turn 4 (az nsg rule list — HITL gate fires):** "Here's the safety gate. Azure CLI read commands are RISKY by default — they can reveal security posture. The engineer decides. In a real environment this gate catches privilege escalation."
- **After NSG results:** "Watch it update the hypothesis board — routing and service hypotheses refuted, NSG block confirmed."
- **RCA:** "The report cites the exact rule name `ghost-demo-block-8080`, priority 150, and the one-line fix."

### After the demo
```bash
./demo/use_case_a/teardown.sh
```

---

## Use Case B — "The Wire Doesn't Lie"
**Single-VM packet capture + PCAP forensic analysis | ~15 minutes**

### What this shows
- The full escalation ladder: local probes → Azure Network Watcher capture
- HITL gate on capture creation (Azure resource creation is always gated)
- Live burst-poll status updates while Azure provisions the capture
- PCAP forensic engine: tshark extraction → Semantic JSON → Gemini analysis
- RCA with wire-level TCP, DNS, and ICMP findings

### Before the session
```bash
chmod +x demo/use_case_b/setup.sh demo/use_case_b/teardown.sh
./demo/use_case_b/setup.sh
# Wait 30 seconds for traffic to establish, then start
```

### Run the demo
```bash
uv run --python 3.12 python ghost_agent.py
```
Paste the prompt from `demo/use_case_b/PROMPT.txt`.

### What to narrate while it runs
- **Local probes (turns 1-3):** "It starts local — cheapest, fastest. Ping and dig tell it L3 is fine and DNS resolves. Inconclusive. It escalates."
- **capture_traffic HITL gate:** "Creating an Azure Network Watcher capture is a real Azure resource — costs money, writes to your storage account. The gate fires. You see exactly what it's going to create: the VM name, resource group, storage account. You approve or deny."
- **check_task polling:** "It's burst-polling Azure — checks every 5-10 seconds, shows you the provisioning state live. No magic waiting. When Azure reports Succeeded it immediately moves to download."
- **PCAP download + analysis:** "The .pcap lands in /tmp/captures. The forensic engine — tshark under the hood — extracts TCP connection stats, retransmission rates, DNS latency percentiles, ICMP unreachables. All structured as Semantic JSON. Then Gemini applies expert network forensics prompts to it."
- **Report appears:** "This is the output of manual work that would take a senior engineer 30-45 minutes. TCP connection success rate, the retransmission stream it flagged, DNS query timing. RFC-cited root cause, remediation commands targeted to the specific host."

### Bonus: Interrupt & Resume (weave into this demo)
After capture_traffic is approved but before check_task completes:
- Press **Ctrl+C**
- Show the audience `ghost_session.json` — point out the SHA-256 checksum
- Resume: `uv run --python 3.12 python ghost_agent.py --resume <session_id_printed_above>`
- At startup, ghost detects the running capture as an orphan, offers to check its status
- Investigation picks up exactly where it left off

> "The session file has a SHA-256 integrity checksum. If anyone tampers with it between sessions, the agent asks you what to do. The hypothesis state, denial history, everything is preserved."

### After the demo
```bash
./demo/use_case_b/teardown.sh
```

---

## Use Case C — "Show Me Both Sides"
**Dual-end capture + comparison analysis | ~20 minutes**

### What this shows
- Paired captures on both VMs simultaneously (two tasks, two task IDs)
- The agent coordinates them — waits for both before running analysis
- PCAP engine comparison mode: source metrics vs destination metrics, delta table
- Forensic verdict: where the asymmetry is and what caused it

### Before the session
```bash
chmod +x demo/use_case_c/setup.sh demo/use_case_c/teardown.sh
./demo/use_case_c/setup.sh
# Wait 60 seconds for traffic to warm up, then start
```

### Run the demo
```bash
uv run --python 3.12 python ghost_agent.py
```
Paste the prompt from `demo/use_case_c/PROMPT.txt`.

### What to narrate while it runs
- **Dual capture intent:** "It recognized 'both endpoints simultaneously' and is setting up two linked captures. Watch for two task IDs. They're paired — the analysis waits for both to complete."
- **Two HITL gates:** "One approval per capture. Each VM's capture is a separate Azure resource."
- **Comparison report:** "This is the forensic diff — what source-vm saw vs what dest-vm saw. TCP retransmission rate on the sending side vs receiving side. If there's a gap, that's your in-transit drop evidence. If both sides agree, the problem is at the application layer."
- **RCA:** "The system doesn't say 'something might be wrong'. It says: source saw X retransmissions, destination saw Y, delta is Z%, which indicates drop in transit vs endpoint."

### After the demo
```bash
./demo/use_case_c/teardown.sh
```

---

## Use Case D — "The Two-Headed Hydra"
**Dual NSG misconfiguration — two independent deny rules | ~10 minutes**

### What this shows
- Ghost Agent forming 4 simultaneous hypotheses: H1 (PostgreSQL NSG block), H2 (Redis NSG block), H3 (VNet routing issue affecting both services), H4 (services not running)
- Two NSG deny rules with **different priorities** (110 vs 150) — implying two separate engineer changes during the same maintenance window
- Agent independently confirms H1 and H2, refutes H3 (route table clean) and H4 (listeners confirmed running)
- RCA names both rules, both ports, and attributes them as two distinct misconfiguration events

### Before the session
```bash
chmod +x demo/use_case_d/setup.sh demo/use_case_d/teardown.sh
./demo/use_case_d/setup.sh
# Wait 30 seconds for NSG rule propagation, then start
```

### Run the demo
```bash
uv run --python 3.12 python ghost_agent.py --resource-group nw-forensics-rg
```
Paste the prompt from `demo/use_case_d/PROMPT.txt`.

### What to narrate while it runs
- **Turn 1 (hypothesis formation):** "Four hypotheses — notice it's not just checking NSG. It's also asking: are the services actually running? Is there a VNet-level routing problem affecting both at once?"
- **NSG results appear:** "Two deny rules. Priorities 110 and 150. That's not one engineer doing one thing. Those are two separate changes, made at different times."
- **H3 refuted (route table clean):** "It ruled out the infrastructure-level explanation. The VNet is fine. This is a policy problem — and it's two separate policy problems."
- **H4 refuted (services confirmed running):** "Both ports have listeners. The services are up. The network is blocking them, not the application."
- **RCA:** "The report shows two independent misconfiguration events: `ghost-demo-block-postgres` and `ghost-demo-block-redis`. One fix per rule. You can hand this directly to the two engineers who made the changes."
- **Money moment:** "It wasn't one network problem. It was two separate mistakes that happened to look like one."

### After the demo
```bash
./demo/use_case_d/teardown.sh
```

---

## Use Case E — "The Phantom Route"
**UDR black hole — NSG is clean, traffic vanishes before reaching destination | ~15 minutes**

### What this shows
- NSG investigation comes back completely clean → H1 (NSG block) REFUTED immediately
- Agent correctly pivots to route table layer — the escalation path traditional troubleshooting misses
- `az network route-table route list` reveals a stale UDR: `10.0.1.5/32 → VirtualAppliance → 10.0.1.100` (non-existent NVA)
- `az network nic show-effective-route-table` confirms the /32 host route is **winning over** the system VnetLocal route on source NIC
- Optional PCAP on dest-vm shows **zero packets arriving** from source — silence as definitive evidence
- Root cause: NVA was planned in a capacity design but never deployed; the route was created and forgotten

### Before the session
```bash
chmod +x demo/use_case_e/setup.sh demo/use_case_e/teardown.sh
./demo/use_case_e/setup.sh
# Wait 60 seconds for effective route table to update on source-vm NIC, then start
```

### Run the demo
```bash
uv run --python 3.12 python ghost_agent.py --resource-group nw-forensics-rg
```
Paste the prompt from `demo/use_case_e/PROMPT.txt`.

### What to narrate while it runs
- **NSG comes back clean:** "Completely clean NSG. Traditional troubleshooting is already stuck here. The portal says 'everything is ALLOW.' But the agent doesn't stop there."
- **Route table pivot:** "It escalated to the routing layer. This is where most engineers miss it — they check NSG, declare it healthy, and file a ticket with the application team."
- **UDR discovered:** "`10.0.1.5/32 → VirtualAppliance → 10.0.1.100`. That IP doesn't exist. Someone configured a route for an NVA that was planned but never provisioned."
- **Effective routes confirm it:** "The effective route table on the source NIC shows the /32 host route winning over the system VnetLocal route. Azure is actively redirecting every packet to a black hole."
- **PCAP on dest (if run):** "Zero packets from source. The destination never saw a single packet. The black hole is complete."
- **Money moment:** "You planned an NVA but never deployed it. The route is a ghost pointing at a ghost IP."

### After the demo
```bash
./demo/use_case_e/teardown.sh
```

---

## Use Case F — "The Silent Gatekeeper"
**Service endpoint removed — Azure Storage silently fails while NSG and routes are clean | ~12 minutes**

### What this shows
- NSG: clean. Routes: clean. Azure portal shows VM and storage account both healthy.
- Agent must correlate **two separate service configurations** that each look correct in isolation
- `az storage account show --query networkRuleSet` → `defaultAction: Deny` + VNet rule referencing the subnet ✓
- `az network vnet subnet show --query serviceEndpoints` → empty list ✗
- The mismatch: storage expects service-endpoint-authenticated VNet traffic, but subnet has no endpoint → VM traffic hits the public storage endpoint → rejected by default-action Deny
- Root cause: platform team accidentally removed Microsoft.Storage endpoint while adding Azure SQL endpoint during routine subnet maintenance

### Before the session
```bash
chmod +x demo/use_case_f/setup.sh demo/use_case_f/teardown.sh
./demo/use_case_f/setup.sh
# setup.sh locks down nwlogs080613 and removes the subnet endpoint
# Run teardown.sh before running Use Cases B or C
```

### Run the demo
```bash
# NOTE: do NOT pass --storage-account here — nwlogs080613 is locked down during this demo
uv run --python 3.12 python ghost_agent.py \
  --resource-group nw-forensics-rg \
  --location eastus
```
Paste the prompt from `demo/use_case_f/PROMPT.txt`.

### What to narrate while it runs
- **NSG clean, routes clean:** "First two layers: completely clean. This is where the Azure portal gives up and tells you 'everything looks fine.' Most teams would open a support ticket here."
- **Storage firewall query:** "The storage account is configured to only allow traffic from the VNet subnet. That sounds right. But watch what comes next."
- **Subnet service endpoints:** "Empty. The subnet has no Microsoft.Storage service endpoint. Without it, the VM's traffic doesn't get routed as authenticated VNet traffic — it goes to the public storage endpoint. And the storage firewall rejects everything from the public endpoint."
- **Correlation:** "Two configurations that each look correct in isolation — storage allows the subnet, subnet has no endpoint. You can only find this mismatch by looking at both at the same time."
- **RCA:** "Root cause in under 5 minutes: service endpoint removed during subnet maintenance. The fix is one command: `az network vnet subnet update --service-endpoints Microsoft.Storage`."
- **Money moment:** "In under 5 minutes it found what typically takes 2 hours — because you have to know to check both sides of a service endpoint relationship simultaneously. That's the value of a system that holds the full network model in context."

### After the demo
```bash
./demo/use_case_f/teardown.sh
# This restores nwlogs080613 to defaultAction=Allow before you run B or C
```

---

## Likely Questions and Answers

**"What model is it using?"**
Gemini 2.0-flash by default. Can be switched to Gemini 2.5-pro for deeper reasoning on complex cases: `ghost_agent.py --model gemini-2.5-pro`.

**"What if the agent tries to run something dangerous?"**
It can't. The import boundary is enforced at the code level — `ghost_agent.py` never imports `subprocess`. All execution goes through `SafeExecShell`, which has a 4-tier classification pipeline. Tier 0 commands (rm -rf /, mkfs, fork bombs, shutdown) are unconditionally blocked — no human override possible.

**"Can it investigate across VNet peerings or through a firewall/NVA?"**
The Azure API commands work anywhere in the subscription. For cross-VNet forensics, point it at the peering VM's resource group. Packet captures work at the VM NIC level, so they capture pre/post NVA traffic if you choose the right VM.

**"What's the audit trail look like?"**
Every command, every HITL decision, every output summary is in `./audit/shell_audit_<session>.jsonl`. The RCA references `audit_id` records from that file — it never stores raw output in the session, only references. Full forensic chain.

**"Can two people share a session?"**
Not concurrently — that's an explicit design omission. One session, one engineer. The session file has integrity checksumming to detect external modification.

**"How long does a capture take?"**
Azure Network Watcher capture provisioning is typically 30-60 seconds. The agent polls it and shows you live status. You set the duration (default 60s, configurable). Download and analysis adds another 30-60 seconds.

---

## Cleanup After All Demos

```bash
# Remove any ghost_* Azure captures left behind (the orphan sentinel handles
# most cleanup, but this ensures nothing leaks after a demo)
az network watcher packet-capture list \
  --location $LOCATION \
  --query "[?starts_with(name,'ghost_')].[name]" -o tsv | \
  xargs -I{} az network watcher packet-capture delete \
    --location $LOCATION --name {} 2>/dev/null || true

# Remove local PCAP files
rm -f /tmp/captures/ghost_*.cap /tmp/captures/ghost_*_forensic_report.md
```
