# Software Engineering Principles

These are technology-agnostic beliefs that guide how I design and build software.
They have been distilled from building production tools across multiple domains —
web applications, data pipelines, AI-integrated systems, and infrastructure automation.
They reflect not what is fashionable, but what consistently produces reliable,
maintainable outcomes with minimal waste.

---

## I. Simplicity Is a Design Decision, Not a Default

**Start with the minimum viable structure and earn every layer of complexity you add.**
A single file is a complete module. A monolith is a complete architecture. A known
technology is a complete choice. Split, decompose, or replace only when a specific,
observed need makes the current structure inadequate — not in anticipation of a need
that may never arrive.

**The cost of complexity is paid at every future interaction with the code.**
Every abstraction, every framework dependency, every service boundary adds cognitive
overhead to every read, debug, and extension that follows. Three similar lines of
code are often better than an abstraction built for two uses. Design for today's
requirements, not hypothetical future scale.

**The adoption bar for a novel technology scales with your dependency on it.**
A utility you call once from a script can be novel. A foundational technology you
will debug under production pressure must have known failure modes, an active
community, and a predictable support horizon. The question is not "is this new?"
but "how much will I pay to learn its failure modes, and when will I pay it?"

---

## II. Human Oversight Is Structural, Not Procedural

A procedural gate is a convention — a comment, a code review checklist, a
developer's memory. A structural gate is a code path: the risky action cannot
execute unless the gate function is called and returns approval. The difference is
that structural gates cannot be skipped by accident.

**For any action that is hard to reverse, consequential, or mutative — gate it.**
Confirmation of destructive operations, review of AI-generated results, and approval
of infrastructure changes are not UX niceties. They are load-bearing safety
requirements. Build the gate into the architecture, not into a comment or a convention.

**The safety gate must not depend on the system's most complex component.**
If classification, authorization, or safety decisions are delegated to an LLM or any
non-deterministic component, the gate becomes as reliable as its least predictable
moment. Safety-critical paths use deterministic logic: allowlists, verb matching,
pattern rules. Reserve probabilistic components for reasoning about what to do,
not for deciding whether it is safe to do it.

```
  LLM proposes action
          │
          ▼
  ┌─────────────────────────────────┐
  │     Deterministic classifier    │  ← allowlist, verb match, pattern rules
  └─────────────────────────────────┘
          │                   │
          ▼                   ▼
      APPROVED              DENIED
    (action runs)       (LLM notified;
                         never the decider)
```

**Default to denial for unknowns.** An access control system, a safety classifier, or
an authorization check that defaults to "permit" for unrecognised inputs is not a
safety system. The default for anything not explicitly permitted must be denial.
Fail closed.

---

## III. The Audit Trail Is the Product

**In any system that touches infrastructure or user data, the audit record is as
important as the output it describes.** Design it first, not as an afterthought.
It must be append-only, owned by a single writer, and consumed read-only by
everything else. A system where two components can both write to the same audit
file has a broken ownership model.

**Session state stores references, not content.** Persistent state — session files,
context stores, caches — holds identifiers that point to the authoritative record.
It never holds raw outputs, full API responses, or command results inline. This
keeps state small, safe across sessions, and free from the risk of sensitive data
leaking between contexts.

**Scope audit analysis to the current session explicitly.** Audit logs accumulate
across sessions. Any query, aggregation, or report generated from an audit log must
be bounded by a starting offset or timestamp recorded at the beginning of the
current operation — not by session ID alone. Housekeeping and startup activity from
the same session can otherwise contaminate the analysis of the actual work.

---

## IV. Pipelines Have Contracts, Not Conventions

**Structure processing as an explicit pipeline where each stage has one
responsibility and a well-defined input/output contract.** Validate → extract →
transform → output. Stages may be sequential, looped, or include feedback paths —
what matters is that each stage's interface is explicit and its concerns are isolated.
The pipeline is not a framework: each stage is a function, and the main entry point
calls them in order.

**Write intermediate artifacts to disk between stages.** This produces a reusable
machine-readable artifact independent of the final output, enables debugging each
stage in isolation, and makes the pipeline restartable at any stage without
reprocessing. The artifact is a contract between stages, not an implementation detail.

**For any pipeline whose output is consumed by both engineers and stakeholders —
analysis tools, forensic reports, monitoring dashboards — produce dual output.**
Engineers need structured data (JSON, CSV) for scripting and downstream processing.
Stakeholders need a readable report (Markdown, HTML). Generate both from the same
pipeline run. They serve different audiences and neither substitutes for the other.

---

## V. AI Is a Reasoning Layer, Not a Data Layer

**Never send raw data to a model. Preprocess, aggregate, and reduce first.**
The model's job is reasoning and correlation — pattern recognition across a
structured representation of the domain. Data wrangling is the pipeline's job.
A large raw input compressed to a well-structured summary will produce better
reasoning than the raw input at ten times the token cost.

**The system prompt or prompt template is a formal specification.**
It is not a suggestion. It encodes the analytical framework, the output structure,
the evidence hierarchy, the escalation logic, and the recovery rules. Domain
knowledge that a senior practitioner would "just know" does not exist in the model
unless it is written down explicitly. Every gap in the specification is a gap in
the system's reliability. Treat prompt templates as critical code artifacts, version
them, and review them after every investigation transcript that reveals a missing rule.

**Isolate all AI interaction to a single stage with two concerns:** constructing a
prompt from structured input, and reading structured output from an API call.
Every other stage in the system is AI-provider-agnostic. If switching providers
requires changes in more than one function, the integration is too tightly coupled.

**Encode recovery invariants for every state machine the model operates.**
For every invariant the system expects the model to maintain — a working hypothesis
list, an active task registry, an investigation state — write an explicit recovery
rule: "If you arrive at a turn where X is empty and the work has not concluded,
re-initialize X before proceeding." Transient API failures will break initialization
paths. The model has no instinct for recovery without an explicit rule.

---

## VI. Documentation Is Architecture

**Write three documents, in order, before writing code:**
Requirements (the user, the problem, the constraints — one page maximum).
Architecture (what was chosen and why, as a decision table: Decision | Choice | Rationale).
Design (how it works precisely — function signatures, data schemas, edge cases — at
a level where another engineer could implement from the document alone).
Each document answers a different question: *what*, *why*, *how*. All three are
necessary; none substitutes for the others.

**Document what you chose not to build, and why.** The intentional omissions list is
as important as the feature list. It prevents future contributors from adding
complexity the design specifically excluded. Every omission entry should name the
capability, state why it was excluded, and identify the principle it would have violated.

**Every document you create carries a maintenance commitment — honour it.**
Update architecture and design docs when the implementation changes. A stale
document actively misleads future readers. If a document has drifted, the correct
response is to update it or explicitly remove it — not to leave it in place.
Deleting a document is a deliberate decision; letting it decay is negligence.

---

## VII. Build Additive, Not Reconstructive

**New capabilities are new code paths alongside existing ones — not refactors of
working code.** When adding a feature, add a branch at the entry point and new
functions alongside existing ones. Do not restructure working code to accommodate
the addition. Existing paths remain untouched, tested, and reliable.

```
  Additive (correct)                  Reconstructive (avoid)

  entry_point()                       entry_point()
    ├── existing_a()   stable           └── refactored_core()
    ├── existing_b()   stable                 ├── a_logic  (modified)
    └── new_feature()  ← add here             ├── b_logic  (modified)
                                              └── new_logic (mixed in)
```

---

## VIII. Trust Is Verified at the Boundaries, Not Assumed in the Centre

**Test the full resource lifecycle, not just creation.** In any automation that
manages a resource lifecycle — create, show, update, delete — test every operation
end-to-end before releasing. Non-create operations routinely have different
behavioral contracts from create, and those contracts are discovered only at runtime
if untested. Create-path-only coverage is the specific gap that produces the most
surprising production failures.

**Prefer mature external tools over fresh reimplementations of the same logic.**
A domain-specific tool with a decade of production use and a large user base has
absorbed failure modes your fresh implementation has not yet encountered. Shell out
to it, request structured output, parse at the boundary. The decision to reimplement
a well-established tool requires the same justification as the decision to adopt a
novel technology: the cost must be clearly understood and clearly worth paying.

---

## Summary

| Principle | In One Line |
|-----------|-------------|
| Simplicity | Earn every layer of complexity you add |
| Adoption bar | Novel technology adoption cost scales with your dependency on it |
| Human oversight | Gate consequential actions structurally, not by convention; default to denial for the unknown |
| Audit trail | Append-only, single writer, cite by reference not value |
| Session state | An index of references, never a cache of content |
| Pipeline contracts | One stage, one responsibility, one well-defined interface |
| Dual output | Analysis pipelines produce both machine-readable and human-readable output |
| AI is a reasoning layer | Preprocess first; the prompt is the formal specification |
| Recovery rules | Every state machine invariant needs an explicit recovery path |
| Documentation | Requirements → Architecture → Design, written before code |
| Build additive | New paths alongside existing ones; never restructure to accommodate |
| Test full lifecycle | Create-path-only coverage is an incomplete test strategy |
| Trust mature tools | Do not reimplement what a better-tested tool already does |
