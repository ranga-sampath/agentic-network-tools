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

## Summary: Core Values

1. **Cost-conscious** — Free tiers, minimal infrastructure, pay-per-use
2. **Simple** — Monolithic, single-language, managed services
3. **Private** — User data isolation, admin sees aggregates only
4. **Secure** — OAuth, whitelist, sanitization, rate limits
5. **User-first** — Safety nets, non-blocking, immediate feedback
6. **Observable** — Measure latency, costs, errors; async logging
7. **Stable** — Minimal churn, test carefully, document everything
