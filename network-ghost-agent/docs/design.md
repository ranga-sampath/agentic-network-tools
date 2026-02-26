# Design: Unified Ghost Agent CLI

> **Status:** Design specification — no implementation code.
> **Companion:** Read `architecture.md` first for system boundaries and safety layers.
> **AI Brain:** Gemini via `google-genai` SDK — `genai.Client`, `genai.types.Tool`, `GenerateContentConfig`.

---

## 1. Tool-Use Contract: Six Gemini Function Declarations

The Brain interacts with the world exclusively through these six declared tools. Every tool maps to either `shell.execute()` or `orchestrator.orchestrate()`. No tool reaches below this boundary.

The tool set is passed to `generate_content()` as:

```
genai.types.Tool(function_declarations=[
    run_shell_cmd_decl,
    capture_traffic_decl,
    check_task_decl,
    cancel_task_decl,
    cleanup_task_decl,
    complete_investigation_decl,
])
```

---

### Tool 1: `run_shell_cmd`

**Maps to:** `shell.execute({"command": ..., "reasoning": ...})`
**When:** Synchronous local diagnostics (`ping`, `dig`, `traceroute`, `ss`, `netstat`, `curl GET`) and Azure read operations (`az nsg list`, `az vm show`, `az route-table list`).

```
FunctionDeclaration:
  name: "run_shell_cmd"
  description: |
    Execute a single diagnostic or Azure read-only command through the Safe-Exec Shell.
    The Shell will classify the command (SAFE/RISKY/FORBIDDEN) and apply HITL gating
    if needed. SAFE commands are auto-approved. RISKY commands require explicit user approval.
    FORBIDDEN commands are unconditionally blocked — do not retry them.
    Use this for: ping, dig, traceroute, ss, netstat, curl (GET only),
    az <service> <resource> list/show/get, cat <file_path>.
    RESTRICTION — cat: only permitted for paths under audit_dir (./audit/) or
    paths returned in result.report_path from a completed orchestrator task.
    Do not cat arbitrary system paths, home directories, or config files.
  parameters:
    type: OBJECT
    properties:
      command:
        type: STRING
        description: |
          The complete shell command to execute. Must be a single command (no && or ;
          chaining). Do not use sudo. Do not redirect to system paths.
      reasoning:
        type: STRING
        description: |
          One sentence explaining why this command is needed for the investigation.
          This is shown to the user during HITL review and written to the audit trail.
    required: [command, reasoning]

Response shape (from shell.execute()):
  status:         "completed" | "denied" | "error"
  classification: "SAFE" | "RISKY" | "FORBIDDEN"
  action:         "auto_approved" | "user_approved" | "user_denied" | "user_modified"
  output:         string (truncated, redacted)
  stderr:         string (truncated, redacted)
  exit_code:      integer or null
  error:          string or null  ("timeout" | "forbidden_command" | ...)
  audit_id:       string  (e.g. "ghost_20250115_143022_007")
```

---

### Tool 2: `capture_traffic`

**Maps to:** `orchestrator.orchestrate({"intent": "capture_traffic", ...})`
**When:** Long-running Azure Network Watcher packet captures.

```
FunctionDeclaration:
  name: "capture_traffic"
  description: |
    Start an Azure Network Watcher packet capture on a VM or between two VMs.
    Returns immediately with a task_id — the capture runs asynchronously.
    Use check_task to poll for completion. Requires storage_account and
    resource_group parameters. Capture is HITL-gated (RISKY az create command).
    For dual-end captures use "source_vm_name to dest_vm_name" as target.
  parameters:
    type: OBJECT
    properties:
      target:
        type: STRING
        description: |
          VM name, full Azure resource ID, or "source_vm to dest_vm" for
          dual-end comparison capture. Full resource IDs are unambiguous and
          required when multiple VMs share a name across resource groups:
            /subscriptions/{sub}/resourceGroups/{rg}/providers/
            Microsoft.Compute/virtualMachines/{vm-name}
          Short names are resolved within the given resource_group.
      resource_group:
        type: STRING
        description: Azure resource group containing the target VM(s).
      storage_account:
        type: STRING
        description: Azure storage account name for storing the capture blob.
      duration_seconds:
        type: INTEGER
        description: Capture duration in seconds. Default 60. Max 300.
      investigation_context:
        type: STRING
        description: |
          One sentence describing what network behaviour is being captured.
          Written to the audit trail and used in HITL approval reasoning.
      storage_auth_mode:
        type: STRING
        enum: [login, key]
        description: |
          Authentication mode for Azure Storage operations. Default: "login"
          (Entra ID / RBAC). Use "key" when the environment uses storage
          access keys rather than Entra ID. Maps directly to the Orchestrator's
          storage_auth_mode parameter, which is passed to every az storage command.
    required: [target, resource_group, storage_account]

Response shape (from orchestrator.orchestrate()):
  status:    "task_pending" | "task_completed" | "task_failed" | "task_cancelled" | "error"
  task_id:   string  (persist this — needed for check_task, cancel_task, cleanup_task)
  state:     string  (CREATED | PROVISIONING | WAITING | DOWNLOADING | ANALYZING | ...)
  message:   string  (human-readable status)
```

---

### Tool 3: `check_task`

**Maps to:** `orchestrator.orchestrate({"intent": "check_task", "task_id": ...})`
**When:** Poll an in-progress capture. Call repeatedly with delay between calls.

```
FunctionDeclaration:
  name: "check_task"
  description: |
    Poll the status of an Azure packet capture task created by capture_traffic.
    The Orchestrator burst-polls Azure internally (up to 45 seconds).
    Continue calling this tool until status is "task_completed", "task_failed",
    "task_cancelled", or "task_timed_out". Do not poll more than once per 10 seconds.
  parameters:
    type: OBJECT
    properties:
      task_id:
        type: STRING
        description: The task_id returned by capture_traffic.
    required: [task_id]

Response shape (from orchestrator.orchestrate()):
  status:           "task_pending" | "task_completed" | "task_failed" | "task_timed_out"
  state:            string  (lifecycle state)
  poll_count:       integer  (if still pending)
  max_polls:        integer  (if still pending)
  elapsed_seconds:  float   (if still pending)
  result:           object or null
    local_pcap_path:    string  (path to downloaded .pcap)
    semantic_json_path: string  (path to Semantic JSON)
    report_path:        string  (path to forensic report .md)
  cleanup_status:   "pending" | "completed" | "partial" | "skipped" | null
```

---

### Tool 4: `cancel_task`

**Maps to:** `orchestrator.orchestrate({"intent": "cancel_task", "task_id": ...})`
**When:** Abort an in-progress capture (user request or investigation pivot).

```
FunctionDeclaration:
  name: "cancel_task"
  description: |
    Abort an in-progress Azure packet capture. The Orchestrator will attempt
    to delete provisioned Azure resources. If resources were created, a HITL
    prompt will appear for each deletion (RISKY az delete commands).
    Idempotent if the task is already in a terminal state.
  parameters:
    type: OBJECT
    properties:
      task_id:
        type: STRING
        description: The task_id to cancel.
      reason:
        type: STRING
        description: Brief reason for cancellation (written to audit trail).
    required: [task_id]

Response shape:
  status:       "task_cancelled" | "task_completed" | "error"
  state:        string
  cleanup_status: "completed" | "partial" | "skipped"
  error_detail: string or null
```

---

### Tool 5: `cleanup_task`

**Maps to:** `orchestrator.orchestrate({"intent": "cleanup_task", "task_id": ...})`
**When:** Delete Azure resources after a completed capture (explicit cleanup step).

```
FunctionDeclaration:
  name: "cleanup_task"
  description: |
    Delete Azure resources (packet capture record, storage blob, local .pcap file)
    created by a completed or failed task. Each deletion is a RISKY command and
    will trigger a HITL prompt. Call after the forensic report has been read.
    Idempotent — safe to call if cleanup was already attempted.
  parameters:
    type: OBJECT
    properties:
      task_id:
        type: STRING
        description: The task_id whose resources should be cleaned up.
    required: [task_id]

Response shape:
  status:         "task_completed" | "error"
  state:          "DONE" | "CLEANING_UP"
  cleanup_status: "completed" | "partial" | "skipped"
```

---

### Tool 6: `complete_investigation`

**Maps to:** Loop exit trigger → RCA generation (not delegated to shell or orchestrator)
**When:** Brain signals investigation is complete (all hypotheses confirmed/refuted/unverifiable).

```
FunctionDeclaration:
  name: "complete_investigation"
  description: |
    Signal that the investigation is complete and request RCA report generation.
    Call this when: (a) the root cause has been identified with sufficient confidence,
    (b) all hypotheses are exhausted, or (c) denial_threshold_reached = true for
    all active hypotheses. The CLI will generate ghost_rca_{sid}.md and exit.
  parameters:
    type: OBJECT
    properties:
      confidence:
        type: STRING
        enum: [high, medium, low]
        description: |
          "high" — root cause confirmed with command evidence.
          "medium" — probable cause with partial evidence.
          "low" — all hypotheses unverifiable due to access denials.
      root_cause_summary:
        type: STRING
        description: One to three sentences summarising the finding.
      confirmed_hypotheses:
        type: ARRAY
        items: {type: STRING}
        description: List of hypothesis IDs confirmed by evidence.
      refuted_hypotheses:
        type: ARRAY
        items: {type: STRING}
        description: List of hypothesis IDs disproved by evidence.
      unverifiable_hypotheses:
        type: ARRAY
        items: {type: STRING}
        description: List of hypothesis IDs blocked by repeated HITL denials.
      contradicted_hypotheses:
        type: ARRAY
        items: {type: STRING}
        description: |
          List of hypothesis IDs where tool results produced contradictory evidence.
          Document the specific audit_ids of the conflicting results and the
          higher-fidelity source used for resolution in root_cause_summary.
      recommended_actions:
        type: ARRAY
        items: {type: STRING}
        description: Concrete next steps for the operator.
    required: [confidence, root_cause_summary]

Response shape:
  (No response — this tool exits the loop and triggers RCA generation)
```

---

## 2. System Prompt Design

The system prompt is a single string passed as `system_instruction` in `GenerateContentConfig`. It establishes three things: investigation framework, tool decision taxonomy, and denial recovery protocol.

### Investigation Framework (embedded in system prompt)

```
You are the Ghost Agent — an AI network forensics investigator.

Your job is to diagnose functional network failures in Azure cloud environments
using evidence gathered through controlled tool calls. Every action you take is
audited. Every command you propose must be justified with a clear reasoning string.

INVESTIGATION FRAMEWORK:
1. LOCAL DIAGNOSTICS FIRST — Use run_shell_cmd for ping, dig, traceroute, ss,
   netstat, curl (GET only). Establish baseline connectivity before any Azure operations.

2. AZURE READ OPERATIONS — Use run_shell_cmd for az <service> list/show/get commands.
   Read NSG rules, route tables, VNet peering, DNS zones. Identify configuration anomalies.

3. PACKET CAPTURE (if needed) — Use capture_traffic only when:
   - Local diagnostics are inconclusive AND
   - The failure is time-sensitive or intermittent AND
   - You have storage_account and resource_group information
   Then: poll with check_task, then read the forensic report:
   • Prefer: cat <task_id>_executive_summary.md (same directory as report_path)
     if it exists — a ~50-line capped summary that fits within Shell truncation limits.
   • Fallback: cat the full report_path. Long reports will be truncated by the
     Shell at 200 lines. The Executive Summary section appears near the top.
   • Note: cat is classified RISKY by the Shell — the engineer will see a HITL
     prompt to approve reading the file. This is expected behaviour.
   Then call cleanup_task after the report has been read.

4. CONCLUDE — Call complete_investigation when the root cause is identified
   OR all hypotheses are exhausted (including unverifiable ones).

HYPOTHESIS MANAGEMENT:
- Form 2-4 specific, falsifiable hypotheses from the symptom description.
- You may investigate up to 3 hypotheses simultaneously when evidence from
  one tool call is relevant to multiple failure modes (e.g., "az route-table list"
  provides evidence for both a routing hypothesis and an NSG hypothesis).
  Record all active hypothesis IDs in active_hypothesis_ids.
- When evidence is conclusive for one hypothesis, remove it from active_hypothesis_ids
  and mark its state (CONFIRMED/REFUTED). Continue with remaining active hypotheses.
- Test each hypothesis with the minimal set of commands that would confirm or refute it.
- Track denial counts per hypothesis. If a hypothesis cannot be tested due to
  repeated denials, mark it UNVERIFIABLE and remove it from active_hypothesis_ids.

RESUME RE-VALIDATION PROTOCOL:
When is_resume = True (this session was started with --resume):
- Network state may have changed since the session was interrupted.
  Do NOT assume any previously collected evidence is still current.
- Before continuing, re-run the 2-3 most critical diagnostic commands
  from the prior session (visible in the conversation history you have received).
  Prefer targeted commands — use --query filters, not full list dumps.
- Explicitly compare new results against prior audit_id references.
  If results have changed, update your hypothesis states and note the
  change in your next reasoning turn before proceeding.
- If a prior hypothesis was marked CONFIRMED but new evidence contradicts it,
  revert it to ACTIVE and investigate the discrepancy.
```

### Tool Decision Taxonomy (embedded in system prompt)

```
TOOL DECISION RULES:

SYMPTOM                          FIRST TOOL          FOLLOW-UP IF DENIED
─────────────────────────────────────────────────────────────────────────
Cannot reach endpoint            run_shell_cmd       capture_traffic
  (ping fails, connection reset)   (ping, traceroute)

DNS resolution failure           run_shell_cmd       run_shell_cmd
  (NXDOMAIN, timeout)              (dig, nslookup)     (az network dns zone list)

Intermittent packet loss         run_shell_cmd       capture_traffic
  (not time-correlated)            (mtr, ping -c 100)  (both ends)

NSG/firewall suspected           run_shell_cmd       run_shell_cmd
  (traffic permitted by rule?)     (az nsg show)       (az nsg rule list)

Routing anomaly suspected        run_shell_cmd       capture_traffic
  (asymmetric path?)               (az route-table...) (source to dest)

Service unreachable (TCP reset)  run_shell_cmd       capture_traffic
  (connection refused)             (ss -an, curl)      (single end)

FILE READ RESTRICTION:
cat is permitted ONLY for:
  - Files under ./audit/ (e.g., cat ./audit/ghost_20250115_143022_forensic_report.md)
  - Paths returned in result.report_path from a completed check_task response
Do NOT cat: ~/.ssh/*, .env, /etc/*, /proc/*, or any path outside audit_dir.
The engineer will see the command in the HITL prompt, but proposing a cat of
a sensitive path erodes trust and may result in investigation termination.

LOCAL PROBE CONTEXT WARNING:
Commands in LEVEL 1 (ping, dig, traceroute, ss, curl) execute on the engineer's
local machine, NOT inside Azure. Results are subject to:
  - Local DNS resolver (may not resolve Azure private DNS zones)
  - Local ISP or corporate VPN routing (not the Azure VNet data path)
  - ICMP rate-limiting on the local host or intermediate hops
When local probe results conflict with Azure API reads (az show/list), the Azure
API is the higher-fidelity source for cloud infrastructure state.
Always qualify local probe conclusions with: "from the engineer's local machine."
Do not treat a failing local ping as conclusive evidence of an Azure VNet failure.

TARGETED QUERY RULE:
When a run_shell_cmd response contains output_metadata.truncation_applied = true,
DO NOT re-issue the same command hoping for more output. Instead, reformulate
with a --query JMESPath expression that targets exactly what you need:

  Broad:    az network nsg rule list --nsg-name <nsg> -o json
  Targeted: az network nsg rule list --nsg-name <nsg> \
              --query "[?destinationPortRange=='6379']" -o json

Common JMESPath patterns for network forensics:
  Find deny rules for a port:   --query "[?access=='Deny' && destinationPortRange=='<port>']"
  Find routes to a prefix:      --query "[?addressPrefix=='<cidr>']"
  Filter by VM power state:     --query "[?powerState=='PowerState/running']"
  Extract a single field:       --query "provisioningState" -o tsv
  Check a specific peer:        --query "[?name=='<vnet-name>'].peeringState" -o tsv

JMESPATH SAFETY RULES:
  - Only use simple, single-condition filters: [?field=='value']
    or two-condition AND filters: [?field1=='val1' && field2=='val2']
  - Do NOT use nested projections, multi-level pipes (|), or
    complex sub-expressions — these are the patterns LLMs hallucinate.
  - Do NOT use -o table with --query; always use -o json or -o tsv.
  - If a run_shell_cmd result has exit_code != 0 AND the command contained
    --query, treat the failure as a JMESPATH SYNTAX ERROR — not as
    "resource does not exist". The resource may be present but the filter failed.
  - On JMESPath error: re-issue the same command WITHOUT --query to retrieve
    the full (possibly truncated) output, then identify the correct field names
    from that output before formulating a new targeted query.
```

### Denial Recovery Protocol (embedded in system prompt)

```
DENIAL RECOVERY RULES:

When a run_shell_cmd call returns status="denied":
  1. Acknowledge the constraint in your reasoning.
  2. Check _meta.denial_reason if present — use this to understand WHY the
     engineer denied the command (e.g., "Wrong resource group", "Too expensive",
     "Incorrect VM name"). Incorporate the reason directly into your re-plan.
  3. Do NOT retry the same command, even with minor variations, unless the
     denial_reason explicitly tells you how to correct it (e.g., use a different
     resource group name).
  4. Pivot to an alternative: lower-privilege diagnostic OR
     capture_traffic (managed Network Watcher, avoids direct tcpdump).

When denial_count for a hypothesis reaches 2:
  - Include a warning in your next reasoning: "This hypothesis may be unverifiable
    due to access restrictions."

When _meta.denial_threshold_reached = true appears in a tool result:
  - Mark that hypothesis as UNVERIFIABLE immediately.
  - Call complete_investigation if it was your last active hypothesis,
    setting confidence="low" and listing it in unverifiable_hypotheses.

SPECIFIC PIVOTS:
  sudo tcpdump       → capture_traffic (Network Watcher managed capture)
  az vm stop         → az vm show --query powerState (observe, don't change)
  ip route add       → az network route-table route list (inspect existing)
  rm {file}          → Note as pending manual cleanup; continue investigation
```

### Evidence Hierarchy and Conflict Resolution (embedded in system prompt)

```
EVIDENCE HIERARCHY (highest fidelity first):
  1. PCAP forensic report   — [CLOUD] wire-level truth captured at the Azure
                              hypervisor; cannot be influenced by OS rate-limiting
                              or application-layer behaviour.
  2. Azure platform API     — [CLOUD] control-plane state (az show/list/get);
                              authoritative for NSG rules, routes, and peering
                              configuration as the platform sees them.
  3. Active probe result    — [CLOUD if run inside Azure VM via capture_traffic;
                               LOCAL if run on engineer's machine via run_shell_cmd]
                              Reflects the live path but subject to ICMP
                              rate-limiting, load balancer affinity, and
                              transient state. LOCAL probes are further subject
                              to local DNS resolvers and ISP/VPN routing that
                              does not reflect the Azure VNet data path.
  4. Agent-reported state   — [LOCAL] VM OS view (ss, netstat, ip route) run
                              on the engineer's machine; reflects the local
                              environment, not the Azure guest.

  KEY RULE: A [LOCAL] probe result NEVER overrides a [CLOUD] API or PCAP finding.
  If a local ping fails but az nsg rule list shows all-permit, the NSG is not
  the cause — investigate the local VPN or DNS path instead.

CONFLICT RESOLUTION PROTOCOL:
When two tool results for the same network path contradict each other:

  STEP 1 — Identify fidelity levels.
    Determine which hierarchy tier each conflicting result occupies.

  STEP 2 — Trust the higher-fidelity source.
    Explicitly state in your reasoning which result you are relying on and why.
    Example: "The PCAP shows the ICMP echo reply completing at the wire level.
    The ping timeout is consistent with ICMP rate-limiting on the guest OS,
    not actual packet loss. Trusting the PCAP (Tier 1) over the ping (Tier 3)."

  STEP 3 — Mark the hypothesis CONTRADICTED in session state.
    A CONTRADICTED hypothesis is not terminal — it transitions to CONFIRMED or
    REFUTED once the higher-fidelity result is applied.

  STEP 4 — Record the conflict in complete_investigation.
    Include the hypothesis ID in contradicted_hypotheses. Reference the specific
    audit_ids of the conflicting results in root_cause_summary.

COMMON CONTRADICTION PATTERNS:
  ping timeout  + PCAP shows ICMP round-trip complete
    → ICMP rate-limited by guest OS or NVA; not a routing failure.
      Trust PCAP. Pivot to application-layer check.

  curl fails (connection refused)  + PCAP shows SYN-ACK received
    → Network path is open; failure is TLS or application-layer.
      Trust PCAP. Pivot to service-level diagnosis.

  NSG shows all-permit + PCAP shows TCP RST
    → RST injected by NVA inline or application server.
      Trust PCAP. Check for NVA in the effective route path.

  az vm show: running + ping unreachable
    → NSG or UDR blocking the data path; VM is up but isolated.
      Trust Azure API for VM state, use PCAP to confirm the block.
```

---

## 3. Startup / Handshake Flow (10 Steps)

```
STEP 1: Parse command-line arguments
  ghost_agent.py [--resume <session_id>]
  Optional: --model <gemini-model> (default: gemini-2.0-flash)
  Optional: --audit-dir <path>  (default: ./audit/)

STEP 2: Load or create ghost_session.json
  IF --resume provided:
    Load existing ghost_session.json
    // Integrity verification:
    stored_checksum = session_data.pop("_checksum", None)
    IF stored_checksum is not None:
      computed = sha256(json.dumps(session_data, sort_keys=True).encode()).hexdigest()
      IF computed != stored_checksum:
        Print: "Warning: session file checksum mismatch — file may have been modified."
        Offer: "[C]ontinue anyway  [F]resh session  [A]bort"
        IF abort:  exit with code 1
        IF fresh:  discard loaded data, treat as new session (goto ELSE branch)
        // If continue: proceed with loaded data, noting the integrity warning
    Validate session_id matches
    Reconstruct conversation_history from shell_audit_{sid}.jsonl
    (replay command+result pairs as function_call/function_response turns)
    Set is_resume = True in session state
  ELSE:
    session_id = "ghost_{YYYYMMDD}_{HHMMSS}"
    Create new ghost_session.json with empty state
    conversation_history = []

STEP 3: Instantiate SafeExecShell
  shell = SafeExecShell(
      session_id=session_id,
      hitl_callback=terminal_hitl_callback,
      audit_dir=audit_dir,
  )
  The terminal_hitl_callback prints the boxed RISKY prompt and blocks on input().

STEP 4: Instantiate CloudOrchestrator
  orchestrator = CloudOrchestrator(
      shell=shell,
      session_id=session_id,
      task_dir=audit_dir,
  )
  NOTE: _detect_orphans() runs automatically inside __init__.
  Three layers of orphan detection execute at this point:
    Layer 1 — Task Registry scan (non-terminal tasks from previous sessions)
    Layer 2 — Azure resource scan (ghost_* captures not in registry)
    Layer 3 — Local file age scan (ghost_* files older than 7 days)

STEP 5: Request orphan report via public API
  orphan_report = orchestrator.orchestrate({"intent": "list_tasks"})
  Extracts: orphan_report["tasks"] and orphan_report.get("orphans", [])

STEP 6: Classify orphans into 5 buckets
  abandoned_tasks    — tasks with non-terminal state from previous session_ids
  needs_cleanup      — COMPLETED/FAILED tasks with cleanup_status == "pending"
  partially_cleaned  — tasks with cleanup_status == "partial" (some Azure resources remain)
                       NOTE: CloudOrchestrator._detect_orphans() scans for
                       cleanup_status == "pending" only. The CLI performs a secondary
                       scan of the list_tasks response to identify tasks where
                       cleanup_status == "partial" — these represent a prior cleanup
                       attempt that was interrupted or partially denied by the engineer.
  untracked_azure    — ghost_* Azure resources with no matching task_id in registry
  stale_local_files  — ghost_* local files with mtime > local_artifact_max_age_days

STEP 7: Present orphan findings to user
  Print summary table. If any orphans exist, offer:
    "[C]lean up now  [S]kip  [R]eview each one"
  If 0 orphans: print "No orphaned resources found." and proceed.

STEP 8: Execute cleanup (if user chose to clean up)
  For each orphan in abandoned_tasks and needs_cleanup:
    orchestrator.orchestrate({"intent": "cleanup_task", "task_id": orphan["task_id"]})
  For each orphan in partially_cleaned:
    // Re-attempt cleanup via orchestrator — it is idempotent and will clean
    // whatever Azure resources remain from the prior partial attempt.
    result = orchestrator.orchestrate({"intent": "cleanup_task", "task_id": orphan["task_id"]})
    IF result["cleanup_status"] == "partial":
      // Some resources still could not be deleted (likely due to further HITL denials
      // or transient Azure errors). Record for manual follow-up.
      Append orphan["task_id"] to ghost_session.json["manual_cleanup_pending"]
      Print: "  [WARN] Task {task_id}: partial cleanup — some resources require manual deletion."
  For each orphan in untracked_azure and stale_local_files:
    Construct shell.execute() with rm or az delete command
    Each deletion is a RISKY command → HITL gate activates per deletion
    User may deny individual deletions — skip those and continue

STEP 9: Accept natural-language user intent
  Print: "=== Ghost Agent Ready ==="
  Print: "What network problem should I investigate?"
  user_intent = input("> ").strip()
  Append user_intent to conversation_history as a "user" role turn.

STEP 10: Save session state and begin Tool-Use Loop
  save_session()   — persists session_id, model, audit_dir, turn_count=0
  BEGIN TOOL-USE LOOP (see Section 4)
```

---

## 4. Tool-Use Loop Pseudocode

The loop is a `while True` with explicit exit conditions. Pseudocode uses indentation to show nesting; this is not executable Python.

```
MAX_LOOP_TURNS = 50
MAX_DENIALS_PER_HYPOTHESIS = 3

WHILE turn_count < MAX_LOOP_TURNS:

    turn_count += 1

    // ── CALL GEMINI API ──────────────────────────────────────────────
    response = client.models.generate_content(
        model       = GEMINI_MODEL,
        config      = GenerateContentConfig(
            tools              = [ghost_tools],
            system_instruction = SYSTEM_PROMPT,
        ),
        contents    = conversation_history,
    )

    // ── HANDLE NON-TOOL RESPONSE (STOP with text only) ───────────────
    IF response.candidates[0].finish_reason == "STOP"
       AND no function_call parts in response:

        brain_text = collect all text parts from response
        print("[Ghost Agent]", brain_text)

        choice = input("Continue investigation? [C]ontinue / [D]one > ")
        IF choice == "done":
            GOTO RCA_GENERATION
        ELSE:
            user_msg = input("Your next instruction > ")
            conversation_history.append({"role": "user", "parts": [user_msg]})
            // Append model response to history first
            conversation_history.append({"role": "model", "parts": response.parts})
            save_session()
            CONTINUE

    // ── APPEND MODEL TURN TO HISTORY ─────────────────────────────────
    conversation_history.append({"role": "model", "parts": response.parts})

    // ── DISPATCH ALL FUNCTION CALLS ───────────────────────────────────
    function_response_parts = []

    FOR each function_call in response.parts WHERE part.function_call EXISTS:

        tool_name = function_call.name
        tool_args = function_call.args   // dict

        // EXIT TRIGGER
        IF tool_name == "complete_investigation":
            save_session(final_args=tool_args)
            GOTO RCA_GENERATION

        // DISPATCH
        IF tool_name == "run_shell_cmd":
            result = shell.execute({
                "command":   tool_args["command"],
                "reasoning": tool_args["reasoning"],
            })

        ELIF tool_name == "capture_traffic":
            result = orchestrator.orchestrate({
                "intent":               "capture_traffic",
                "target":               tool_args["target"],
                "investigation_context": tool_args.get("investigation_context", ""),
                "parameters": {
                    "resource_group":    tool_args["resource_group"],
                    "storage_account":   tool_args["storage_account"],
                    "duration_seconds":  tool_args.get("duration_seconds", 60),
                },
            })

        ELIF tool_name == "check_task":
            result = orchestrator.orchestrate({
                "intent":  "check_task",
                "task_id": tool_args["task_id"],
            })

        ELIF tool_name == "cancel_task":
            result = orchestrator.orchestrate({
                "intent":  "cancel_task",
                "task_id": tool_args["task_id"],
            })

        ELIF tool_name == "cleanup_task":
            result = orchestrator.orchestrate({
                "intent":  "cleanup_task",
                "task_id": tool_args["task_id"],
            })

        ELSE:
            result = {"status": "error", "error": "unknown_tool", "tool": tool_name}

        // ── DENIAL DETECTION (per tool result) ───────────────────────
        is_denied = (result.get("status") in {"denied", "task_cancelled"}
                     AND result source was a HITL user_denied action)

        IF is_denied:
            // ── DENIAL REASON CAPTURE ─────────────────────────────────
            // Immediately after the engineer selects [D]eny in terminal_hitl_callback,
            // prompt for an optional one-line reason before returning to the loop.
            // This is captured in the callback closure and injected here.
            //
            // Console display:
            //   Denial reason (optional, press Enter to skip): _
            //
            denial_reason = terminal_hitl_callback.captured_reason  // "" if skipped
            IF denial_reason != "":
                result["_meta"] = result.get("_meta", {})
                result["_meta"]["denial_reason"] = denial_reason
                // This surfaces in the Brain's function_response turn, giving it
                // actionable context to avoid re-proposing the same command.

        IF is_denied AND active_hypothesis_ids is non-empty:
            FOR each h_id in active_hypothesis_ids:
                denial_tracker[h_id] += 1
                count = denial_tracker[h_id]

                result["_meta"] = result.get("_meta", {})
                result["_meta"]["denial_count"] = count

                IF count == 1:
                    result["_meta"]["pivot_instruction"] = (
                        "Command denied. Consider an alternative diagnostic approach."
                    )

                IF count == 2:
                    result["_meta"]["approaching_threshold"] = True
                    result["_meta"]["warning"] = (
                        "Second denial for hypothesis " + h_id + ". "
                        "If denied again, hypothesis will be marked UNVERIFIABLE."
                    )

                IF count >= MAX_DENIALS_PER_HYPOTHESIS:
                    result["_meta"]["denial_threshold_reached"] = True
                    mark h_id as UNVERIFIABLE in session state
                    remove h_id from active_hypothesis_ids
                    result["_meta"]["instruction"] = (
                        "Hypothesis " + h_id + " marked UNVERIFIABLE. "
                        "Move to next hypothesis or call complete_investigation "
                        "if active_hypothesis_ids is now empty."
                    )

        ELSE IF NOT is_denied AND active_hypothesis_ids is non-empty:
            // Reset consecutive denial counter for all active hypotheses (not cumulative total)
            FOR each h_id in active_hypothesis_ids:
                consecutive_denial_counter[h_id] = 0

        // ── CONFLICT DETECTION (semantic — Brain responsibility) ──────
        // The loop does not mechanically detect contradictions between results,
        // because contradiction requires semantic understanding of network state
        // (e.g., recognising that ping timeout + PCAP success are contradictory).
        // The system prompt Evidence Hierarchy instructs the Brain to identify
        // conflicts and mark hypotheses CONTRADICTED in its reasoning.
        //
        // The loop's role is to track conflicts the Brain has already identified
        // and recorded in session state (written by save_session() in a prior turn):
        IF any hypothesis was newly marked CONTRADICTED this turn:
            evidence_conflicts.append({
                "hypothesis_id":         active_hypothesis_id,
                "conflicting_audit_ids": [...],   // referenced by Brain in reasoning
                "higher_fidelity_source": ...,    // Tier number from evidence hierarchy
                "resolution":            ...,     // CONFIRMED or REFUTED after resolution
            })
            save_session()

        // ── BUILD FUNCTION RESPONSE PART ─────────────────────────────
        function_response_parts.append(
            genai.types.Part.from_function_response(
                name     = tool_name,
                response = result,
            )
        )

    END FOR

    // ── APPEND FUNCTION RESPONSES AS USER TURN ────────────────────────
    conversation_history.append({
        "role":  "user",
        "parts": function_response_parts,
    })

    save_session()

END WHILE

// MAX_LOOP_TURNS reached
print("[Ghost Agent] Maximum investigation turns (50) reached.")
print("Options: [E]xtend 10 more turns / [G]enerate RCA now")
choice = input("> ")
IF choice == "extend":
    MAX_LOOP_TURNS += 10
    CONTINUE LOOP
ELSE:
    GOTO RCA_GENERATION
```

---

## 5. Tool Decision Taxonomy (Escalation Ladder)

Tools are used in escalating order of cost, risk, and intrusiveness:

```
LEVEL 1 — Local non-privileged reads (always auto-approved)
  run_shell_cmd: ping -c 4 <host>
  run_shell_cmd: dig <fqdn> @<nameserver>
  run_shell_cmd: traceroute <host>
  run_shell_cmd: ss -an
  run_shell_cmd: netstat -rn
  run_shell_cmd: curl -s -o /dev/null -w "%{http_code}" <url>
        │
        │ If inconclusive → escalate
        ▼
LEVEL 2 — Azure read operations (auto-approved, SAFE verb)
  run_shell_cmd: az nsg list --resource-group <rg> -o json
  run_shell_cmd: az network nsg rule list --nsg-name <nsg> --resource-group <rg> -o json
  run_shell_cmd: az vm show --name <vm> --resource-group <rg> -o json
  run_shell_cmd: az network route-table list --resource-group <rg> -o json
  run_shell_cmd: az network vnet peering list --vnet-name <vnet> --resource-group <rg>
  run_shell_cmd: az network dns zone list --resource-group <rg>
        │
        │ If packet-level evidence needed → escalate
        ▼
LEVEL 3 — Managed packet capture (HITL-gated at each RISKY step)
  capture_traffic: {target, resource_group, storage_account, duration_seconds}
        │
        │ Poll loop:
        ▼
  check_task: {task_id}  (repeat until task_completed / task_failed)
        │
        │ On task_completed:
        ▼
  run_shell_cmd: cat <result.report_path>   (read forensic report)
        │
        ▼
LEVEL 4 — Conclude and clean up
  complete_investigation: {confidence, root_cause_summary, ...}
  cleanup_task: {task_id}   (call before or after complete_investigation)
```

### Denial Pivot Table

| Denied Command | Alternative Diagnostic Path |
|----------------|----------------------------|
| `sudo tcpdump -i eth0` | Use `capture_traffic` (Azure Network Watcher managed capture — no sudo required) |
| `az vm stop --name <vm>` | Use `az vm show --name <vm> --query powerState` to observe power state without changing it |
| `ip route add <cidr> via <gw>` | Use `az network route-table route list` to inspect existing effective routes |
| `ip link set eth0 down` | Use `ip addr show eth0` (safe, read-only) to inspect interface state |
| `az network watcher packet-capture delete` | Mark as pending manual cleanup; note in unverifiable_hypotheses |
| `rm /tmp/captures/<file>.pcap` | Note as stale_local_file; continue; will surface in next session's orphan detection |
| `az storage blob delete` | Note cleanup_status as "partial"; complete_investigation with cleanup note |

---

## 6. Denial Handling State Machine

Each hypothesis tracked in `ghost_session.json["hypothesis_log"]` progresses through this state machine independently.

### States

```
ACTIVE ──(command executed successfully)──────────────────────────────► CONFIRMED
   │                                                                      (evidence found)
   │
   │    ──(command disproves hypothesis)──────────────────────────────► REFUTED
   │                                                                      (evidence against)
   │
   │    ──(two results contradict — Brain identifies via Evidence Hierarchy)
   │                    │
   │                    ▼
   │             CONTRADICTED
   │          (awaiting resolution via    ──(higher-fidelity source confirms)──► CONFIRMED
   │           higher-fidelity tool)      ──(higher-fidelity source refutes)───► REFUTED
   │
   ├──(denial_count == 1)──► DENIED_ONCE
   │        │
   │        ├──(next command succeeds)──────────────────────────────── back to ACTIVE
   │        │
   │        └──(denial_count == 2)──► DENIED_TWICE
   │                   │
   │                   ├──(next command succeeds)──────────────────── back to ACTIVE
   │                   │
   │                   └──(denial_count >= 3)──► UNVERIFIABLE
   │                                               (no further testing possible)
   │
   └──(all other hypotheses CONFIRMED/REFUTED/UNVERIFIABLE/CONTRADICTED-resolved)
                 ──► triggers complete_investigation
```

### Transition Logic

```
State: ACTIVE
  ON: tool result with status == "denied" AND user_decision == "deny"
    denial_tracker[hypothesis_id] += 1
    consecutive_denial_counter[hypothesis_id] += 1
    count = denial_tracker[hypothesis_id]
    IF count == 1:
      hypothesis.state = DENIED_ONCE
      Inject: _meta.denial_count = 1
      Inject: _meta.pivot_instruction = "Command denied. Consider alternative approach."
    IF count == 2:
      hypothesis.state = DENIED_TWICE
      Inject: _meta.denial_count = 2
      Inject: _meta.approaching_threshold = true
      Inject: _meta.warning = "Second denial. One more denial marks this hypothesis UNVERIFIABLE."
    IF count >= 3:
      hypothesis.state = UNVERIFIABLE
      Inject: _meta.denial_count = count
      Inject: _meta.denial_threshold_reached = true
      Inject: _meta.instruction = "Hypothesis UNVERIFIABLE. Move to next or call complete_investigation."

  ON: tool result with status == "completed" or status == "task_completed"
    consecutive_denial_counter[hypothesis_id] = 0
    IF evidence confirms hypothesis:
      hypothesis.state = CONFIRMED
    IF evidence refutes hypothesis:
      hypothesis.state = REFUTED

State: DENIED_ONCE or DENIED_TWICE
  (Same transitions as ACTIVE — state transitions back to ACTIVE on success)

State: CONTRADICTED
  (Transient — awaiting higher-fidelity evidence to resolve the conflict)
  ON: Brain identifies that two completed results for the same scope contradict:
    hypothesis.state = CONTRADICTED
    evidence_conflicts entry created in session state with both audit_ids
    Brain issues a higher-fidelity tool call (escalating the evidence hierarchy)
  ON: higher-fidelity result confirms the hypothesis:
    hypothesis.state = CONFIRMED
  ON: higher-fidelity result refutes the hypothesis:
    hypothesis.state = REFUTED
  NOTE: CONTRADICTED is not terminal. A hypothesis stuck in CONTRADICTED with
  no higher-fidelity tool available escalates to complete_investigation with
  the hypothesis ID in contradicted_hypotheses and confidence = "medium".

State: UNVERIFIABLE
  (Terminal — no further tool calls made for this hypothesis)
  IF all hypotheses are in terminal states (CONFIRMED/REFUTED/UNVERIFIABLE):
    Brain must call complete_investigation immediately.
    confidence = "low" if any UNVERIFIABLE, "medium" or "high" otherwise.

State: CONFIRMED / REFUTED
  (Terminal — hypothesis resolved with evidence)
```

### N-Denial Closure Trigger

When `_meta.denial_threshold_reached = true` appears in any tool response:

1. The Brain marks the hypothesis UNVERIFIABLE.
2. The Brain checks remaining hypotheses:
   - If any hypothesis is still ACTIVE: pivot to that hypothesis.
   - If all hypotheses are terminal: call `complete_investigation` with:
     ```
     confidence = "low"
     unverifiable_hypotheses = [list of UNVERIFIABLE hypothesis IDs]
     root_cause_summary = "Investigation incomplete due to access restrictions. ..."
     ```

---

## 7. RCA Report Generation Algorithm (7 Phases)

Triggered when `complete_investigation` is called or user chooses Done.

```
PHASE 1: Read shell_audit_{sid}.jsonl
  Open ./audit/shell_audit_{sid}.jsonl for reading (read-only).
  Parse each line as JSON (skip malformed lines).
  Classify records by outcome:
    completed_records  = records WHERE status == "completed" AND exit_code == 0
    failed_records     = records WHERE status == "completed" AND exit_code != 0
    denied_records     = records WHERE status == "denied"
    forbidden_records  = records WHERE status == "error" AND error == "forbidden_command"
    timeout_records    = records WHERE status == "error" AND error == "timeout"
    risky_approved     = records WHERE action == "user_approved" OR action == "user_modified"
  NOTE: The "action" field distinguishes auto_approved vs user_approved vs user_denied.

  EVIDENCE CONTEXT TAGGING:
  For each record, read the "environment" field (written by SafeExecShell):
    record["_evidence_context"] = "LOCAL"  if environment == "local"
    record["_evidence_context"] = "CLOUD"  if environment == "azure"
  This tag is carried into Phase 5 to label each row in the Command Evidence table.
  LOCAL evidence reflects the engineer's machine context (local DNS, ISP/VPN routing).
  CLOUD evidence reflects the Azure control or data plane.

  FORENSIC CONSISTENCY CHECK (heuristic — supplements Brain's in-loop detection):
  After context tagging, scan for common contradiction patterns detectable without
  semantic understanding of network state:

    Pattern A — Local probe failure with Azure permit rule present:
      IF (any LOCAL record with exit_code != 0
          AND command starts with "ping" or "traceroute")
      AND (any CLOUD record with exit_code == 0
           AND command contains "az network nsg"
           AND output contains '"access": "Allow"'):
        Set potential_local_cloud_conflict = True
        Append advisory note to RCA Capture Evidence section:
          "Advisory: local probe failure detected alongside an Azure 'Allow' NSG rule.
           PCAP evidence may clarify whether the data path is actually blocked.
           See evidence hierarchy in design.md §2."

    Pattern B — Task completed but report unavailable (cat denied):
      IF any orchestrator task has state == "COMPLETED"
      AND executive_summary_text[report_path] == None:
        Set incomplete_capture_evidence = True
        Append advisory note to RCA Capture Evidence section:
          "Advisory: forensic report for task {task_id} unavailable — cat was denied
           by the engineer. The full report is at {report_path} for offline review."

  These flags are advisory-only and non-blocking. They surface as notes in the RCA.
  They are not authoritative contradiction detections — the Brain's in-loop Evidence
  Hierarchy reasoning (system prompt §2) is the primary contradiction-handling mechanism.
  These heuristics catch contradictions the Brain may have missed if a session was
  interrupted and resumed without re-validation.

PHASE 2: Read orchestrator_tasks_{sid}.jsonl
  Open ./audit/orchestrator_tasks_{sid}.jsonl for reading (read-only).
  Parse each line as JSON (skip malformed lines).
  Build: task_latest = {}
  FOR each record:
    task_latest[record["task_id"]] = record   // last-write-wins per task_id
  Result: dict of task_id → final task state

PHASE 3: Extract artifact paths from completed tasks
  FOR each task in task_latest.values():
    IF task["state"] in {"COMPLETED", "DONE"}:
      IF task.get("report_path"):
        artifact_reports.append(task["report_path"])
      IF task.get("local_pcap_path"):
        artifact_pcaps.append(task["local_pcap_path"])

PHASE 4: Read forensic report content (Executive Summary only)
  FOR each report_path in artifact_reports:
    // Preferred: read the pre-generated executive summary file if it exists.
    // The Orchestrator names it {task_id}_executive_summary.md in the same
    // directory as report_path. This file is ~50 lines and fits within the
    // Shell's 200-line truncation limit.
    exec_summary_path = report_path.replace("_forensic_report.md", "_executive_summary.md")
    TRY: shell.execute({
        "command": f"cat {exec_summary_path}",
        "reasoning": "Reading executive summary for RCA generation."
    })
    IF exit_code == 0:
      Store output as executive_summary_text[report_path]
    ELSE:
      // Fallback: cat the full forensic report.
      Use shell.execute({
          "command": f"cat {report_path}",
          "reasoning": "Reading forensic report for RCA generation (exec summary not found)."
      })
      Extract lines between "## Executive Summary" and next "##" heading.
      Store as executive_summary_text[report_path].
      NOTE: Full forensic reports may exceed 200 lines and will be truncated by the
            Shell. The Executive Summary section appears near the top of the report
            and should be captured even in a truncated response.

  NOTE ON CLASSIFICATION: cat is classified RISKY by SafeExecShell — it is NOT in
  the _ALWAYS_SAFE frozenset and requires explicit HITL approval. The engineer will
  see a SAFETY SHELL ALERT prompt for each cat call. This is expected behaviour during
  RCA generation.
  If denied: set executive_summary_text[report_path] = None and include
  "Report content unavailable (cat denied by engineer)." in the Capture Evidence section.

PHASE 5: Build Markdown report structure
  ghost_rca_{sid}.md contains:

  # Root Cause Analysis — {session_id}
  _Generated: {ISO-8601 timestamp}_
  _Confidence: {confidence}_

  ## Investigation Summary
  {root_cause_summary from complete_investigation args}

  ## Hypotheses Log
  | Hypothesis ID | Description | Final State | Denial Count |
  |...            |...          |...          |...           |
  (Sourced from ghost_session.json["hypothesis_log"])

  ## Command Evidence
  | Audit ID | Context | Command | Classification | Action | Exit Code | Outcome |
  |...       |...      |...      |...             |...     |...        |...      |
  (One row per record in completed_records + denied_records + forbidden_records)
  (Context column = [LOCAL] or [CLOUD] from the _evidence_context tag in Phase 1)
  (All audit_id values are primary references — raw output is NOT reproduced)

  NOTE ON LOCAL EVIDENCE: Rows tagged [LOCAL] reflect the engineer's local
  environment. Readers should not interpret [LOCAL] probe failures as definitive
  evidence of Azure infrastructure failures without corroborating [CLOUD] evidence.

  ## Capture Evidence
  | Task ID | Target | State | Report Path | PCAP Path |
  |...      |...     |...    |...          |...        |
  (One row per task in task_latest)
  (Executive Summary from Phase 4 appended inline if available)

  ## Recommended Actions
  {recommended_actions list from complete_investigation args}

  ## Integrity Statement
  All evidence in this report is cited by audit_id from append-only JSONL files:
  - Shell audit: ./audit/shell_audit_{sid}.jsonl
  - Task registry: ./audit/orchestrator_tasks_{sid}.jsonl
  Raw command output is retained in the audit trail; only summaries appear here.

PHASE 6: Write ghost_rca_{sid}.md
  Open ./audit/ghost_rca_{sid}.md for writing (new file).
  Write the Markdown report from Phase 5.
  Close file.

PHASE 7: Update ghost_session.json
  ghost_session.json["rca_report_path"] = "./audit/ghost_rca_{sid}.md"
  save_session()
  Print: "RCA report written: ./audit/ghost_rca_{sid}.md"
  Exit with code 0.
```

**Evidence Citation Rule:** Every conclusion in the RCA references `audit_id` (e.g., `ghost_20250115_143022_007`). The full command output lives in `shell_audit_{sid}.jsonl` at that record's line. The RCA never stores or reproduces raw output.

---

## 8. Session State Schema (ghost_session.json)

```json
{
  "session_id": "ghost_20250115_143022",
  "created_at": "2025-01-15T14:30:22Z",
  "resumed_from": null,
  "model": "gemini-2.0-flash",
  "audit_dir": "./audit/",
  "turn_count": 12,
  "rca_report_path": null,

  "hypothesis_log": [
    {
      "id": "h1",
      "description": "NSG rule blocking TCP 443 from subnet A to subnet B",
      "state": "REFUTED",
      "denial_count": 0,
      "created_at": "2025-01-15T14:31:05Z",
      "resolved_at": "2025-01-15T14:32:18Z",
      "resolving_audit_id": "ghost_20250115_143022_004",
      "denial_events": []
    },
    {
      "id": "h2",
      "description": "UDR sending traffic to wrong next-hop",
      "state": "CONFIRMED",
      "denial_count": 1,
      "created_at": "2025-01-15T14:32:30Z",
      "resolved_at": "2025-01-15T14:35:44Z",
      "resolving_audit_id": "ghost_20250115_143022_011",
      "denial_events": [
        {
          "turn": 7,
          "command": "az network route-table route update ...",
          "denial_reason": "Wrong resource group — use cache-rg, not prod-rg",
          "audit_id": "ghost_20250115_143022_007"
        }
      ]
    }
  ],

  "denial_tracker": {
    "h1": 0,
    "h2": 0
  },

  "consecutive_denial_counter": {
    "h1": 0,
    "h2": 0
  },

  "active_hypothesis_ids": ["h2"],

  "active_task_ids": [
    "ghost_vm-prod-01_20250115T143500"
  ],

  "evidence_conflicts": [
    {
      "hypothesis_id": "h1",
      "conflicting_audit_ids": [
        "ghost_20250115_143022_003",
        "ghost_20250115_143022_008"
      ],
      "higher_fidelity_source": "PCAP forensic report (Tier 1)",
      "resolution": "REFUTED",
      "description": "ping timeout contradicted by PCAP showing ICMP round-trip success"
    }
  ],

  "is_resume": false,
  "_checksum": "a3f1e9d2b7c04581..."
}
```

### Field Descriptions

| Field | Type | Description | Survives Crash |
|-------|------|-------------|---------------|
| `session_id` | string | Unique ID: `ghost_{YYYYMMDD}_{HHMMSS}` | Yes |
| `created_at` | ISO-8601 | Session creation time | Yes |
| `resumed_from` | string or null | Prior session ID if this is a resume | Yes |
| `model` | string | Gemini model name | Yes |
| `audit_dir` | string | Path to audit directory | Yes |
| `turn_count` | integer | Loop turns completed; saved every turn | Yes |
| `rca_report_path` | string or null | Set after RCA generation | Yes |
| `hypothesis_log` | array | Full hypothesis history with states. Each entry: `{id, description, state, denial_count, created_at, resolved_at, resolving_audit_id, denial_events}`. The `denial_events` array records each HITL denial for this hypothesis: `{turn, command, denial_reason, audit_id}`. Survives crash and is the authoritative source for the Hypotheses Log section of the RCA. | Yes |
| `denial_tracker` | object | Cumulative denial count per hypothesis | Yes |
| `consecutive_denial_counter` | object | Resets on any success (used for pivot warnings) | Yes |
| `active_hypothesis_ids` | array of strings | Currently active hypotheses (up to 3 simultaneously); Brain removes an ID when that hypothesis reaches a terminal state | Yes |
| `active_task_ids` | array of strings | Orchestrator task IDs this session | Yes |
| `evidence_conflicts` | array of objects | Each conflict: `{hypothesis_id, conflicting_audit_ids, higher_fidelity_source, resolution, description}` — populated by the Brain's reasoning via save_session() | Yes |
| `is_resume` | boolean | True when the session was started with `--resume`; instructs the Brain to run the Re-Validation Protocol | Yes |
| `_checksum` | string | SHA-256 hex digest of the session JSON content, computed over all fields excluding `_checksum` itself (using `json.dumps(sort_keys=True)`). Recomputed on every `save_session()` call. Verified on `--resume` load to detect accidental corruption or file tampering. Mismatch triggers the `[C]ontinue / [F]resh / [A]bort` prompt in Step 2. | Yes |

**What is NOT in session state:** Raw command output, full JSONL records, Gemini response text, conversation history (reconstructed from JSONL on resume).

---

## 9. Error Recovery Paths Table

| Error Condition | Detection | Recovery |
|-----------------|-----------|----------|
| **Shell timeout** | `result["error"] == "timeout"` | Inject `_meta.timeout = true` in function_response. Brain re-plans: shorter command, different approach, or pivot to `capture_traffic`. |
| **Task FAILED** | `result["status"] == "task_failed"` | Brain may retry `capture_traffic` with shorter `duration_seconds`, or pivot to local-only diagnosis. |
| **Task TIMED_OUT** | `result["status"] == "task_timed_out"` | Azure resources are auto-cleaned by Orchestrator. Brain pivots to available evidence. |
| **Gemini API error** | `google.api_core.exceptions.GoogleAPIError` raised | Catch exception. Print error message. Call `save_session()`. Print: "Session saved. Resume with: ghost_agent.py --resume {session_id}". Exit with code 1. |
| **KeyboardInterrupt** | `except KeyboardInterrupt` in `finally` block | `save_session()` in `finally`. Print: "Session saved. Resume with: ghost_agent.py --resume {session_id}". Exit gracefully. |
| **Missing GEMINI_API_KEY** | `os.environ.get("GEMINI_API_KEY")` is empty at startup | Print setup instructions: "Set GEMINI_API_KEY environment variable or add to .env file." Exit with code 1. Do not enter the loop. |
| **Session file corrupted** | `json.JSONDecodeError` when loading `ghost_session.json` | Print: "Warning: session file corrupted." Offer: "[F]resh session / [A]bort". If fresh: create new session. If abort: exit with code 1. |
| **Session checksum mismatch** | `_checksum` field present in loaded JSON but SHA-256 of remaining fields does not match the stored digest | Print: "Warning: session file checksum mismatch — file may have been modified externally." Offer: "[C]ontinue anyway  [F]resh session  [A]bort". If continue: proceed with a session-level integrity warning logged to the RCA. If fresh: discard and start new. If abort: exit with code 1. |
| **Audit JSONL missing on resume** | `FileNotFoundError` when opening `shell_audit_{sid}.jsonl` | Warn: "Audit file not found — conversation history cannot be reconstructed." Start with empty history but preserve session metadata. |
| **HITL callback exception** | `except Exception` in `shell.execute()` HITL path | Shell fails closed: returns `status == "denied"` with `action == "user_abandoned"`. Denial detection applies normally. |
| **RCA report write failure** | `IOError` / `PermissionError` when writing `ghost_rca_{sid}.md` | Print report to stdout instead. Update `ghost_session.json["rca_report_path"] = null`. Print error message. |
| **pcap_forensics not found** | `exit_code == 127` from `run_shell_cmd("python pcap_forensics.py ...")` | Orchestrator marks task FAILED. Brain receives `task_failed` status. Pivot to local-only evidence for RCA. |

---

## 10. Console Output Design

Distinct visual treatments prevent cognitive overload and make HITL prompts impossible to miss.

```
$ python ghost_agent.py

══════════════════════════════════════════════════════
  UNIFIED GHOST AGENT  v1.0  |  Session: ghost_20250115_143022
══════════════════════════════════════════════════════
Checking for orphaned resources from previous sessions...
  [OK] No orphaned tasks found.
  [OK] No stale local files found.

What network problem should I investigate?
> VMs in prod-subnet cannot reach the Redis cache on port 6379

[Ghost Agent] I'll investigate this connectivity failure systematically.
Hypothesis H1: NSG rule blocking TCP 6379 between prod-subnet and cache-subnet.
Hypothesis H2: UDR sending cache-bound traffic to wrong next-hop.
Let me start with Azure network configuration reads.

[Shell] SAFE — auto-approved: az nsg list --resource-group prod-rg -o json
[Shell] SAFE — auto-approved: az network nsg rule list --nsg-name prod-nsg ...

[Ghost Agent] NSG rules permit TCP 6379. H1 appears refuted.
Now checking route tables for prod-subnet.

[Shell] SAFE — auto-approved: az network route-table list --resource-group prod-rg -o json

┌─────────────────────────────────────────────────────────────────────┐
│                     SAFETY SHELL ALERT                              │
│  TIER:       2  |  CLASSIFICATION: RISKY                            │
│  COMMAND:    az network route-table route update ...                │
│  RISK:       Azure CLI verb 'update' is classified as mutative      │
│  REASONING:  Attempting to correct the next-hop for route 10.0.2.0  │
│                                                                     │
│  [A]pprove   [D]eny   [M]odify command                             │
└─────────────────────────────────────────────────────────────────────┘
Your choice: d
Denial reason (optional, press Enter to skip): Wrong resource group — use cache-rg, not prod-rg

[Ghost Agent] Route update denied (reason: "Wrong resource group — use cache-rg, not prod-rg"). I'll observe the existing route configuration
without modifying it and note the finding in the report.

[Shell] SAFE — auto-approved: az network route-table route list ...

[Ghost Agent] Found it. Route 10.0.2.0/24 next-hop is set to a decommissioned
NVA at 10.0.1.5 instead of the correct gateway. This explains the connectivity failure.
H2 CONFIRMED. Generating root cause analysis report.

══════════════════════════════════════════════════════
  RCA REPORT WRITTEN: ./audit/ghost_rca_ghost_20250115_143022.md
  Confidence: high  |  Turns: 14  |  Duration: 8m 32s
══════════════════════════════════════════════════════
```

### Output Style Guide

| Output Type | Format | Example |
|-------------|--------|---------|
| System messages | `══` border lines | `══ UNIFIED GHOST AGENT v1.0 ══` |
| Brain reasoning | `[Ghost Agent]` prefix | `[Ghost Agent] NSG rules permit...` |
| Shell auto-approval | `[Shell] SAFE — auto-approved:` | `[Shell] SAFE — auto-approved: dig...` |
| HITL prompt | Full box with `┌─┐│└─┘` borders | Blocks until user responds |
| User prompt | `>` prefix | `>` |
| Error messages | `[ERROR]` prefix | `[ERROR] Gemini API call failed` |
| RCA completion | `══` border lines | `══ RCA REPORT WRITTEN ══` |

---

## 11. Root-Level File Layout

```
nw-forensics/
├── ghost_agent.py                          ← NEW CLI entrypoint
├── ghost_session.json                      ← NEW session state (created at first run)
│
├── audit/                                  ← NEW shared audit directory
│   ├── shell_audit_{sid}.jsonl             ← Written by SafeExecShell (append-only)
│   ├── orchestrator_tasks_{sid}.jsonl      ← Written by CloudOrchestrator (append-only)
│   └── ghost_rca_{sid}.md                  ← Written by RCA generator on complete_investigation
│
├── docs/
│   ├── architecture.md                     ← DELIVERABLE (system-level design)
│   ├── design.md                           ← DELIVERABLE (this document)
│   └── product-requirements.md             ← EXISTING (root PRD)
│
├── agentic-safety-shell/                   ← UNCHANGED
│   ├── safe_exec_shell.py
│   └── examples/
│       └── ai_safety_demo.py
│
├── agentic-cloud-orchestrator/             ← UNCHANGED
│   └── cloud_orchestrator.py
│
└── agentic-pcap-forensic-engine/           ← UNCHANGED
    └── pcap_forensics.py
```

### Import Map for ghost_agent.py

```
ghost_agent.py imports:
  from agentic_safety_shell.safe_exec_shell import SafeExecShell, HitlDecision
  from agentic_cloud_orchestrator.cloud_orchestrator import CloudOrchestrator
  from google import genai
  from google.genai import types
  import json, os, sys, argparse, datetime

ghost_agent.py does NOT import:
  subprocess    ← ALL process execution via SafeExecShell
  pcap_forensics  ← invoked via shell.execute(), never imported
  threading, asyncio  ← no background threads (intentional omission)
```
