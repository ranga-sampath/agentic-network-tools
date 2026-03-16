# `--explain` Feature Design Notes

*Captured from design conversation — March 14 2026*

---

## The Idea

Add an optional `--explain` flag to `firewall_inspector.py` that passes the snapshot JSON
to an LLM with a carefully crafted system prompt encoding iptables semantics. The LLM
produces a human-readable explanation of the firewall state: executive summary, a
traffic allow/block table, and plain-language interpretation.

**Motivation:** Not all network engineers are iptables SMEs. The JSON snapshot is accurate
but opaque to most readers. The `--explain` flag brings iptables expertise to anyone
running the tool, without requiring specialist knowledge to interpret the output.

**Pattern precedent:** The Agentic PCAP Forensic Engine already does exactly this —
semantic JSON in, expert system prompt, LLM-generated interpretation. The iptables case
is simpler: rule evaluation semantics are deterministic and fully enumerable.

---

## Design Decisions (Agreed)

- **Optional flag** — `--explain` is not part of the core pipeline. The snapshot JSON is
  always written first. The tool is fully useful without `--explain`.
- **Runs after snapshot is saved** — does not block or affect the core forensics pipeline.
- **Output:** `{session_id}_explanation.md` written to the audit directory alongside the
  snapshot.
- **Config additions:** `EXPLAIN_MODEL` (e.g., `claude-opus-4-6`) in config.env.
  API key via environment variable (`ANTHROPIC_API_KEY`) — never stored in config.env.
- **Explicit scope boundary disclaimer** in every explanation: *"This analysis covers the
  iptables rule layer only. Azure NSG enforcement and native nftables rulesets are outside
  this view."*
- **Clearly labelled as AI-generated** — caveat preserved in the output file header so it
  survives copy-paste into incident reports.

---

## System Prompt Design

The system prompt is the core investment. It must encode:

| Concept | What to encode |
|---------|---------------|
| Table evaluation order | raw → mangle → nat → filter (for each packet) |
| First-match semantics | First matching rule in a chain wins; subsequent rules are not evaluated |
| Chain jump propagation | JUMP transfers evaluation context; RETURN sends it back to the calling chain |
| Default policy | Only fires when no rule in the chain matches — not a catch-all at the end |
| ESTABLISHED/RELATED | Stateful tracking creates implicit permit for return traffic; must be explained when present |
| Stateless vs stateful rules | Rules without `-m state` or `-m conntrack` apply to every packet regardless of connection state |
| INPUT / OUTPUT / FORWARD | INPUT = traffic to this host; OUTPUT = traffic from this host; FORWARD = traffic routed through |
| Table responsibilities | filter = allow/block; nat = address translation; mangle = packet modification; raw = conntrack bypass |
| Counter values `[pkts:bytes]` | Indicate whether rules have actually been hit; zero counters = rule exists but has not matched |
| User-defined chains | Not built-in; created by the operator; meaning must be inferred from name and rules |
| `-j RETURN` in a chain | Returns to the calling chain without a terminal verdict — does not mean the packet is accepted |

**Scope boundary (explicit in system prompt):**
- This analysis covers iptables rules only
- Azure NSG rules above this layer are not visible
- Native nftables rulesets (`nft list ruleset`) are not captured
- Routing table and interface configuration are not included
- The explanation describes what the rules *say*, not necessarily what they *do* for all traffic on this specific VM

**Model on:** the pcap forensic engine system prompt structure — role definition, input format
description, evaluation rules, output format specification, explicit uncertainty instructions.

---

## Expected Output Format

```markdown
# Firewall State Explanation
*AI-generated analysis. Verify against raw snapshot before acting.*
*Scope: iptables rules only. Azure NSG and native nftables rulesets not included.*

## Executive Summary
<2-4 sentences: what this firewall is broadly doing — permissive, restrictive,
default-deny vs default-accept, any notable rules>

## Traffic Table

| Direction | Protocol | Port / Type | Source | Action | Notes |
|-----------|----------|-------------|--------|--------|-------|
| Inbound   | TCP      | 22 (SSH)    | Any    | ALLOW  | Stateful — return traffic permitted |
| Inbound   | TCP      | 80, 443     | Any    | ALLOW  | |
| Inbound   | Any      | Any         | Any    | DROP   | Default policy |
| Outbound  | Any      | Any         | Any    | ALLOW  | Default policy |

## Notable Rules
<Any rules that are unusual, potentially dangerous, or worth operator attention>

## Counters
<If -c output was captured: which rules have non-zero hit counts, indicating active traffic>

## Warnings
<Rules that are unreachable, shadowed by earlier rules, or that have ambiguous intent>
```

---

## Top 3 Reasons TO Build

1. **Proven pattern in this codebase.** The pcap forensic engine already does this:
   semantic JSON + expert system prompt = reliable LLM interpretation. The iptables case
   is actually simpler — rule evaluation is deterministic, not probabilistic. The precedent
   is live, validated, and in the same repo.

2. **System prompt converts hallucination risk from open-ended to bounded.** A generic LLM
   guesses at iptables semantics. A system prompt that explicitly encodes first-match
   semantics, chain jump propagation, and ESTABLISHED/RELATED behaviour constrains the
   LLM's reasoning space to what the prompt says. Failure modes shift from "wrong about
   iptables" to "misapplies an edge case" — a much smaller surface, improvable by iteration.

3. **The parser JSON is ideal LLM input.** The parser has already done the structurally hard
   work: tables, chains, rules, matches, targets are all broken out into clean JSON. The LLM
   reasons over structure, not text. This is significantly better input quality than raw
   `iptables-save` output.

---

## Top 3 Reasons NOT To Build

1. **The context-free problem survives even a perfect system prompt.** The LLM sees rules,
   not their operational effect. "Port 22 inbound is permitted" is a correct reading of the
   rules and potentially wrong about what happens to actual SSH traffic on this VM if the
   NSG blocks it upstream. The system prompt cannot add context that isn't in the JSON. Every
   explanation carries this structural blind spot silently.

2. **Confident-looking output will be copy-pasted without its caveat.** Security findings
   end up in change records and compliance reports. The disclaimer gets dropped. If the LLM
   misreads one multi-chain interaction and that misreading enters a compliance document, the
   tool loses credibility for everything it does correctly. The pcap engine produces
   investigation hypotheses; a firewall state summary feels authoritative — a higher bar.

3. **nftables gap means `--explain` can mislead on modern VMs right now.** On a VM using
   `iptables-nft` where the actual rules are in native nftables (as seen today: 0 tables
   parsed), `--explain` would confidently summarise an empty ruleset. "No rules configured,
   all traffic follows default policies" — technically correct for the iptables compatibility
   layer, operationally wrong. *Agreed: nftables capture is deferred from MVP. This risk
   must be explicitly acknowledged in the explanation output whenever 0 tables are detected.*

---

## Open Judgement Call

**Should `--explain` call the Claude API directly from `firewall_inspector.py`, or should
the Ghost Agent be responsible for generating the explanation from the snapshot JSON?**

Two modes are possible and can coexist:

| Mode | Invocation | API call made by |
|------|-----------|-----------------|
| Standalone | `python3 firewall_inspector.py --config config.env --explain` | `firewall_inspector.py` directly calls Claude API |
| Ghost Agent | Agent passes snapshot JSON into its reasoning chain | Ghost Agent's LLM call; no direct API call from inspector |

**Arguments for standalone direct call:**
- The tool is useful independently of the Ghost Agent
- A network engineer running the tool standalone gets the explanation without needing the
  full Ghost Agent stack
- Consistent with how the pcap forensic engine works as a standalone tool

**Arguments for Ghost Agent only:**
- Avoids duplicating the LLM call infrastructure in two places
- The Ghost Agent already has the session context, NSG data, and other findings — its
  explanation would be richer than a standalone explanation of iptables rules in isolation
- Keeps `firewall_inspector.py` dependency-free for library use

**Likely resolution:** Implement standalone `--explain` in `firewall_inspector.py` using
the Claude API (same pattern as pcap engine). The Ghost Agent uses the snapshot JSON
directly in its reasoning chain without calling `--explain` — it has richer context anyway.
The two paths produce different outputs for different audiences: standalone for a single
engineer inspecting a VM, Ghost Agent for a full investigation chain.

*Decision not yet made — to be confirmed before implementation.*

---

## Implementation Checklist (when ready to build)

- [ ] Write iptables expert system prompt (see table above)
- [ ] Implement `--explain` flag in `firewall_inspector.py`
- [ ] Add `EXPLAIN_MODEL` to `_KEY_MAP` and CLI args
- [ ] Implement LLM call (Claude API, `anthropic` SDK)
- [ ] Write `{session_id}_explanation.md` to audit directory
- [ ] Add 0-tables guard: if all rulesets are empty, include prominent warning in explanation
- [ ] Unit tests: prompt builder, output writer, LLM call mocked
- [ ] Update `config.env.example` with `EXPLAIN_MODEL` commented out
- [ ] Update `test_report_firewall_inspector.md`

---

## Derivative Idea: iptables Parser + `--explain` as an Independent Claude Skill

*Captured March 14 2026*

### The Idea

With the `--explain` feature in place, the iptables parser becomes a complete
**parse → explain** pipeline:

```
iptables-save output  →  iptables_parser.py  →  snapshot JSON  →  LLM (--explain)  →  explanation.md
```

This pipeline can be packaged as a **standalone Claude skill** — callable from Claude Code
or any Claude agent — that accepts raw `iptables-save` text (or a snapshot JSON file path)
and returns a structured firewall state explanation without needing the full firewall
inspector stack (no Azure, no SSH, no VM connectivity required).

### What the Skill Would Do

```
Input:  raw iptables-save text  OR  path to an existing snapshot JSON
Output: executive summary + traffic table + notable rules + warnings
```

The skill operator (Claude Code or a Claude agent) can invoke it with:
- A pasted `iptables-save` output from any source (live VM, ticket attachment, config backup)
- A snapshot JSON already on disk from a previous firewall inspector run
- A drift report JSON to explain *what changed* rather than what the state is

### Why This Has Standalone Value

1. **Decoupled from Azure.** Any engineer with an `iptables-save` dump — from any Linux
   host, any cloud, any on-premises VM — can get an explanation. The skill has no cloud
   dependency. It is a pure parse-and-explain tool.

2. **Reusable across the entire tool stack.** The Ghost Agent, the Network Drift Detector,
   and any future tool that captures iptables state can call the skill without duplicating
   the system prompt or the parsing logic. The skill becomes the single source of iptables
   interpretation in the entire stack.

3. **Useful in passive investigation contexts.** An engineer reviewing a past incident,
   auditing a config backup, or evaluating a ticket attachment does not need to connect to
   a live VM. They paste or point to the iptables output and get an explanation immediately.

### Skill Interface (proposed)

```
Skill name:   iptables-explain
Inputs:       iptables_save_text: str  (raw iptables-save output)
              OR snapshot_path: str    (path to existing _snapshot.json)
              family: "ipv4" | "ipv6" | "both"  (default: inferred from input)
Outputs:      explanation: str  (markdown — same format as --explain output)
              parse_warnings: list[str]
```

### Relationship to Existing Skills

| Skill | Input | What it explains |
|-------|-------|-----------------|
| `pcap-forensics` | semantic.json from PCAP engine | Wire-level traffic behaviour |
| `iptables-explain` (new) | iptables-save text or snapshot JSON | OS firewall rule layer |

Together they cover adjacent layers of the same network investigation stack.

### Open Questions for Skill Design

1. **Raw text vs pre-parsed JSON?** Raw `iptables-save` text is more flexible (any source).
   Pre-parsed JSON is safer (parser has already validated the input). Both can be supported:
   if text is provided, run the parser first; if JSON is provided, skip parsing.

2. **Repo home?** Given the skill depends on `iptables_parser.py`, it belongs in
   `netfilter-inspector` as a skill file, with `claude-skills-library` holding a pointer
   or a thin wrapper.

3. **Drift explanation variant?** Should the skill also accept a `_drift.json` report and
   explain *what changed* rather than what the current state is? This would be a second
   invocation mode: `iptables-explain --mode drift --drift-path fw_xxx_drift.json`.

    Drift Explanation Mode

    A second invocation mode for the iptables-explain skill: accept a _drift.json report
    (produced by firewall_inspector.py --compare-baseline) and explain what changed rather
    than what the current state is.

    Skill name:   iptables-explain
    Mode:         drift
    Input:        drift_path: str  (path to existing _drift.json)
                  OR  before: str / after: str  (two raw iptables-save texts)
    Output:       drift_explanation: str  (markdown)
                  — what rules were added/removed
                  — security posture impact of each change
                  — whether any change is a regression or an improvement
                  — unreachable or shadowed rules introduced by the diff

    Why this adds value over the state explanation mode:

    1. An engineer reviewing a drift report wants to know what the change means, not a full
    re-explanation of the entire ruleset. The diff is already scoped — the explanation
    should be too.
    2. The LLM has a smaller, more focused input (only the changed rules plus their chain
    context), which reduces the risk of the model getting distracted by large unchanged
    rulesets.
    3. This directly supports the post-incident use case: "the baseline was clean, the
    current state has a new rule — is this rule dangerous?" That question is answered by
    diff explanation, not state explanation.

    Build order addition: --explain in firewall inspector → extract state explanation as
    skill → add drift explanation mode → register both in skills library.


### Implementation Dependency

The Claude skill can only be built after `--explain` is implemented in
`firewall_inspector.py`, since the skill reuses:
- `iptables_parser.py` (parse step)
- The iptables expert system prompt (explain step)
- The `explanation.md` output format

**Build order:** `--explain` in firewall inspector → extract as skill → register in skills library.
