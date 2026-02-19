# Design Paradigms & Values

This document captures core design values and preferences distilled from building prior apps. These paradigms are technology-agnostic principles to guide future software design decisions.

---

## 1. Technology Selection Philosophy

### Cost-Consciousness First
- **Prefer free tiers** — Choose services with generous free tiers over paid alternatives when functionality is comparable
- **Pay only for variable costs** — Fixed infrastructure costs should be zero or minimal; pay for usage (API calls, storage) not capacity
- **Calculate total cost of ownership** — Consider not just the service cost but time spent on setup, maintenance, and debugging

### Simplicity Over Sophistication
- **Monolithic until proven otherwise** — Start with a single codebase; split into services only when there's a clear scaling need
- **Familiar over trendy** — Choose well-understood technologies (SQL over NoSQL, Python over new languages) unless there's a compelling reason
- **Managed over self-hosted** — Use managed services (PaaS, managed databases) to eliminate operational burden

### Developer Experience
- **Single-language stacks** — Prefer stacks that minimize context-switching (e.g., Python end-to-end vs Python + JavaScript + SQL)
- **Fast feedback loops** — Choose tools with hot-reload, instant deploys, and minimal build times
- **Git-centric deployment** — Push to deploy; no manual steps or complex CI/CD pipelines for simple apps

---

## 2. User Experience Principles

### The "Safety Net" Pattern
- **Never auto-commit AI results** — When AI extracts or generates data, always show it to the user for review and correction before saving
- **Editable everything** — Any data the system populates should be editable by the user
- **Confirm destructive actions** — Soft delete first; permanent delete requires explicit confirmation

### Minimal Friction Authentication
- **SSO over passwords** — Use OAuth providers (Google, GitHub) to eliminate password management
- **Remember me by default** — Sessions should persist; don't force frequent re-authentication
- **Graceful session expiry** — When a session expires, preserve context and redirect back after re-auth

### Responsive but Opinionated
- **Laptop-first, mobile-friendly** — Optimize for the primary use case; ensure mobile works but don't over-invest
- **Progressive disclosure** — Hide complexity in expanders, tabs, and modals; show essentials upfront
- **Immediate feedback** — Every action should have visible feedback (toasts, spinners, success messages)

### Non-Blocking Operations
- **Background long tasks** — Email sends, file processing, and API calls should not freeze the UI
- **Optimistic updates** — Show success immediately; handle failures gracefully in the background
- **Async with status** — For background operations, provide a way to check status later

### No Time Estimates
- **Never predict duration** — Avoid phrases like "this will take a few minutes" or "should be quick"
- **Focus on what, not when** — Describe what will happen, let users judge timing themselves
- **Progress over prediction** — Show progress indicators, not estimated completion times

---

## 3. Administrative Controls

### User Management
- **Active/inactive over delete** — Deactivate users rather than deleting them; preserve data and audit trail
- **Role-based access** — Clear admin vs regular user distinction; avoid complex permission matrices
- **Self-service where safe** — Let users manage their own preferences; reserve admin controls for system-wide settings

### Configurable Limits
- **Limits as guardrails** — Set reasonable defaults; make limits configurable for edge cases
- **Per-user limits** — Rate limits and quotas should be per-user to prevent abuse while allowing legitimate heavy users
- **Admin override capability** — Admins should be able to adjust limits for specific users or globally

### Access Control
- **Whitelist over blacklist** — When restricting access, use an allow-list (safer default: deny)
- **Admin cannot be locked out** — The primary admin email should always have access regardless of whitelist
- **Audit configuration changes** — Log when settings change and who changed them

### Visibility Boundaries
- **Aggregate, not individual** — Admins see total counts and system health, not individual user data
- **Privacy by default** — Admin should not be able to browse user data without explicit need
- **Separate concerns** — System health (DB status, API health) is separate from user data visibility

---

## 4. Observability Design

### Measure What Matters
- **Latency at boundaries** — Measure time for database calls, external API calls, and end-to-end workflows
- **Cost tracking** — For usage-based services (AI APIs), track tokens/calls and estimated cost
- **Error rates** — Count failures, not just successes
- **Resource consumption** — Database size, storage usage, quota consumption

### Non-Blocking Telemetry
- **Fire-and-forget logging** — Metrics should be logged asynchronously; never block user operations
- **Silent failure** — If metric logging fails, the app should continue working; observability is optional
- **Batch when possible** — Aggregate metrics before writing to reduce database load

### Dashboard Design
- **Time-windowed aggregates** — Show 7-day or 24-hour averages, not raw data points
- **Actionable metrics** — Every metric should answer "is something wrong?" or "should I do something?"
- **Comparison baselines** — Show current vs average, max values, thresholds
- **Self-service refresh** — Admins can refresh data on demand; don't rely solely on auto-refresh

### What NOT to Track
- **No PII in metrics** — Metrics should be anonymous and aggregatable
- **No per-request logging** — Log aggregates, not every single operation
- **No excessive granularity** — Daily or hourly granularity is usually sufficient

---

## 5. Data Privacy & Isolation

### Query-Level Isolation
- **owner_email on every query** — Every database query that returns user data must filter by owner
- **No cross-user queries in user context** — Regular users should never see other users' data
- **Admin queries are separate** — Admin aggregate queries are distinct functions, not parameter variations

### Soft Delete Pattern
- **Trash before delete** — Move items to trash (is_deleted flag) before permanent deletion
- **Retention period** — Keep deleted items recoverable for a reasonable period (30 days)
- **Permanent delete requires intent** — "Empty Trash" is a separate, explicit action

### Data Visibility Hierarchy
```
User sees:        Own data only (full details)
Admin sees:       Aggregate counts, system metrics (no individual data)
System logs:      Anonymized metrics (no PII)
```

### Export & Portability
- **User can export their data** — Provide CSV/JSON export of user's own data
- **No data hostage** — Users should be able to leave with their data
- **Clear data on account deletion** — When a user is permanently removed, remove their data

---

## 6. Security Posture

### Authentication
- **Delegate to experts** — Use OAuth providers rather than implementing password storage
- **No password resets** — OAuth eliminates password reset flows and associated vulnerabilities
- **Session management** — Server-side session state; tokens in memory, not localStorage

### Authorization
- **Check on every request** — Don't trust client-side state; verify permissions server-side
- **Fail closed** — If authorization check fails or errors, deny access
- **Least privilege** — Users get minimum access needed; admin access is explicit

### Input Handling
- **Sanitize everything** — All user input (strings, emails, filenames) goes through sanitization
- **Parameterized queries** — Use ORM or prepared statements; never concatenate SQL
- **Length limits** — All text fields have maximum lengths; reject oversized input
- **File validation** — Check file types, sizes, and names before processing

### Secrets Management
- **Environment variables** — Secrets come from environment, not code
- **No secrets in logs** — Sanitize error messages; never log API keys or passwords
- **Secrets rotation support** — Design so secrets can be rotated without code changes

### Rate Limiting
- **Per-user limits** — Prevent individual abuse without affecting other users
- **Graceful degradation** — When limits are hit, show helpful message with reset time
- **Different limits by role** — Admins may have higher limits for legitimate use

### Defense in Depth
- **Multiple layers** — Whitelist + authentication + authorization + input validation
- **Assume breach** — Even if one layer fails, others should limit damage
- **Audit trail** — Log security-relevant events (logins, permission changes)

---

## 7. Development Practices

### Code Quality
- **Minimal code churn** — Prefer small, targeted changes over large refactors
- **Stability over features** — A working feature is more valuable than two half-working ones
- **Avoid over-engineering** — Build for today's requirements, not hypothetical future needs

### Documentation
- **Document as you build** — Write lessons learned immediately, not at the end
- **Living documents** — Update docs when implementation changes
- **Three levels** — Architecture (why), Design (how), Skills (lessons learned)

### Testing Philosophy
- **Manual testing for MVPs** — Automated tests come after the design stabilizes
- **Test in production carefully** — Use feature flags, staged rollouts, easy rollback
- **Test the happy path first** — Ensure core flows work before edge cases

### Error Handling
- **User-friendly messages** — Translate technical errors to actionable guidance
- **Graceful degradation** — If a feature fails, the rest of the app should work
- **Log for debugging** — Technical details go to logs, not to users

---

## 8. Cost Optimization Patterns

### API Cost Reduction
- **Preprocess before API calls** — Resize images, truncate text before sending to AI
- **Cache expensive results** — If the same input produces the same output, cache it
- **Batch operations** — Combine multiple small operations into fewer large ones

### Storage Efficiency
- **Compress before storing** — Resize images, compress files before database/storage
- **Clean up regularly** — Delete orphaned files, expired temporary data
- **Measure and monitor** — Track storage growth; set alerts before hitting limits

### Compute Efficiency
- **Background processing** — Expensive operations run async, not blocking UI
- **Lazy loading** — Don't compute what isn't displayed
- **Connection pooling** — Reuse database connections; don't create per-request

---

## 9. Decision-Making Framework

When choosing between options, prioritize in this order:

1. **Stability** — Will it break existing functionality?
2. **Simplicity** — Is this the simplest solution that works?
3. **Cost** — What are the ongoing costs (money, time, complexity)?
4. **User experience** — How does it feel to use?
5. **Maintainability** — Can future-me understand this in 6 months?
6. **Performance** — Is it fast enough? (not "is it the fastest possible")
7. **Scalability** — Will it handle 10x growth? (not 1000x)

---

## 10. Anti-Patterns to Avoid

| Anti-Pattern | Better Approach |
|--------------|-----------------|
| Building for hypothetical scale | Build for current needs, design for extensibility |
| Complex abstractions for one use | Three similar lines are better than premature abstraction |
| Storing everything "just in case" | Store what's needed, delete what isn't |
| Showing raw errors to users | Translate to actionable messages |
| Admin sees all user data | Admin sees aggregates, system health |
| Auto-saving AI results | Always show for user confirmation |
| Blocking UI for slow operations | Background threads with status updates |
| Passwords for auth | OAuth/SSO delegation |
| Blacklist for access control | Whitelist (default deny) |
| Per-request metrics | Aggregated, time-windowed metrics |

---

## 11. Pipeline & Data Transformation Design

### Linear Pipeline Architecture
- **Stages with clear boundaries** — Structure processing as a pipeline (validate → extract → transform → output) where each stage has a single responsibility and a well-defined input/output contract. Stages may be sequential, looped, or include feedback paths — what matters is that each stage's interface is explicit and its concerns are isolated
- **Stages are functions, not frameworks** — Each stage is a plain function or group of functions. No pipeline framework, no DAG orchestrator, no event bus. The `main()` function calls stages in order
- **Intermediate artifacts to disk** — Write intermediate results (e.g., structured JSON) to disk between stages. This gives users a reusable machine-readable artifact independent of the final output, and enables debugging each stage in isolation
- **Dual-artifact output** — Produce both a machine-readable format (JSON, CSV) and a human-readable format (Markdown, HTML) from the same pipeline. Engineers want structured data for scripting; stakeholders want a readable report

### Semantic Reduction
- **Compress through meaning, not truncation** — When raw data is too large to process directly, reduce it by extracting meaning: count instead of listing, aggregate by conversation/group, surface statistical summaries (min/median/p95/max), and filter to anomalies only
- **Anomaly-only detail** — Include per-item details only for statistical outliers (e.g., values > 2x median). Everything else is aggregated. This keeps output compact without losing forensically relevant information
- **Omit empty sections** — If an entire category has no data, exclude it from the output entirely rather than including it with zero values. This keeps the data representation lean and signals absence clearly
- **Cap unbounded lists** — Any list that could grow with input size (top domains, error groups) should be capped (e.g., top 10) to maintain a predictable output size regardless of input volume

---

## 12. AI Integration Patterns

### AI as a Reasoning Layer
- **Preprocess before prompting** — Never send raw data to an AI. Transform, aggregate, and reduce first. A 10MB input should become <5,000 tokens of structured telemetry. The AI's job is reasoning and correlation, not data wrangling
- **Structured data in, structured report out** — Feed the AI well-organized JSON with clear field names, and specify an exact output format (sections, tables, severity levels). This constrains the AI to produce useful, consistent output rather than freeform text
- **Embed domain expertise in the prompt** — The prompt is not "summarize this data." It contains an expert-level diagnostic framework: what each data point means, how to correlate signals across categories, and what specific patterns indicate. The prompt encodes the knowledge of a senior practitioner
- **Prompt templates as first-class architecture** — Treat prompt templates as critical code artifacts, not throwaway strings. They define the analytical framework, output structure, and quality floor. Document them in your design docs alongside function signatures

### AI Provider Portability
- **Isolate AI to one stage** — All AI interaction should be confined to a single pipeline stage with exactly two concerns: (1) constructing a prompt from structured data, and (2) making an API call and reading back text. Every other stage is AI-provider-agnostic
- **Swap by changing one function** — If switching from Provider A to Provider B requires changes in more than one function, the AI integration is too tightly coupled
- **Sanitize errors from AI calls** — Never leak API keys in error messages. Scrub credentials from exception text before surfacing to the user

---

## 13. External Tool Integration

### Leverage Battle-Tested Tools
- **Shell out to experts** — When a mature, domain-specific tool exists (packet parsers, image processors, compilers), invoke it via subprocess rather than reimplementing its logic. A 20-year-old C tool with millions of users is more reliable than a fresh reimplementation
- **Typed field extraction** — When calling external tools, request structured output (field-separated, JSON) rather than parsing human-readable text. Parse fields into typed values (int, float, bool) immediately at the extraction boundary
- **One tool invocation per concern** — Prefer multiple focused invocations with specific filters over one monolithic invocation that returns everything. This keeps each extraction self-contained and makes the code easier to extend

### Subprocess Safety
- **List arguments, never shell=True** — Always pass subprocess commands as a list of strings. Never use `shell=True` or string interpolation into shell commands. This prevents command injection from user-supplied file paths or filter strings
- **Capture stderr for diagnostics** — When an external tool fails, its stderr usually contains the most useful diagnostic message. Capture it and include it in your error reporting
- **Streaming for large outputs** — When an external tool may produce output larger than memory, read stdout line by line instead of capturing all at once. Track only what you need (counters, first/last values) in a single pass

---

## 14. Additive Feature Design

### Grow Without Restructuring
- **New features as new code paths, not refactors** — When adding a capability (e.g., compare mode alongside single-capture mode), add a new branch in the entry point and new functions alongside existing ones. Do not restructure working code to accommodate the new feature
- **New protocol = new extractor + new reducer** — In pipeline architectures, extending to handle a new data type should mean adding a new extraction function and a new reduction function, then wiring them into the existing pipeline. Existing extractors remain untouched
- **Separate prompt templates per mode** — When the same AI pipeline serves different use cases (analysis vs. comparison), use separate prompt templates rather than conditionalizing a single template. Each template is self-contained and independently tunable

### Single-File Until Proven Otherwise
- **One file is fine** — A tool that fits in a single file (even 500-1000 lines) should stay in a single file. No `src/` directory, no package structure, no `__init__.py` until there is a concrete reason to split. A single file is easy to read top-to-bottom, easy to share, and has zero import complexity
- **Split trigger: distinct reuse** — Split into multiple files only when a clearly separable component needs to be reused independently (e.g., imported by a test harness, shared with another tool). Organizational preference alone is not a sufficient reason

---

## 15. Documentation as a Design Discipline

### Three Documents, Written Upfront
- **Requirements first** — Write a concise requirements document before designing. It captures the user persona, functional requirements, non-functional constraints (token budget, privacy), and nothing else. Keep it under one page
- **Architecture = decisions + rationale** — The architecture document captures what was chosen and why, in a decision table format: Decision | Choice | Rationale. Link rationale back to your principles document. This is the "why" document
- **Design = how it works, precisely** — The design document captures function signatures, data schemas, edge cases, and parsing details at a level where another engineer (or AI) could implement the tool from the doc alone. This is the "how" document

### Decision Tables Over Prose
- **Tabular decisions** — When documenting choices (technology selection, what to omit, error handling), use tables rather than paragraphs. Tables force conciseness and make it easy to scan the full set of decisions at a glance
- **Document what you omit** — Explicitly list what the architecture intentionally does not include and why. This prevents future contributors from adding complexity the design specifically avoided

---

## Summary: Core Values

1. **Cost-conscious** — Free tiers, minimal infrastructure, pay-per-use
2. **Simple** — Monolithic, single-language, managed services
3. **Private** — User data isolation, admin sees aggregates only
4. **Secure** — OAuth, whitelist, sanitization, rate limits
5. **User-first** — Safety nets, non-blocking, immediate feedback
6. **Observable** — Measure latency, costs, errors; async logging
7. **Stable** — Minimal churn, test carefully, document everything
8. **Pipeline-oriented** — Clear stages (sequential, looped, or with feedback), intermediate artifacts, dual outputs
9. **AI-disciplined** — Preprocess first, embed expertise in prompts, isolate the AI layer
10. **Tool-leveraging** — Shell out to experts, subprocess safety, streaming for scale
11. **Additive** — New features as new code paths, not rewrites; single-file until split is justified
12. **Documentation-driven** — Requirements → Architecture → Design, written upfront not after
