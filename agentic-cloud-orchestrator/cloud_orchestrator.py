"""Cloud Orchestrator — async bridge between the AI Brain and Azure operations.

Public API:
    orchestrator = CloudOrchestrator(shell, session_id)
    response = orchestrator.orchestrate(request)

Decomposes long-running Azure operations into sequences of synchronous Shell calls.
Each Shell call flows through the Shell's classify -> gate -> execute -> process pipeline.

See architecture.md and design.md for full specification.
"""

import glob
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Constants — Lifecycle states
# ---------------------------------------------------------------------------

CREATED = "CREATED"
DETECTING = "DETECTING"
APPROVED = "APPROVED"
PROVISIONING = "PROVISIONING"
WAITING = "WAITING"
DOWNLOADING = "DOWNLOADING"
ANALYZING = "ANALYZING"
COMPLETED = "COMPLETED"
CLEANING_UP = "CLEANING_UP"
DONE = "DONE"
FAILED = "FAILED"
CANCELLED = "CANCELLED"
TIMED_OUT = "TIMED_OUT"
ABANDONED = "ABANDONED"

TERMINAL_STATES = frozenset({DONE, FAILED, CANCELLED, TIMED_OUT, ABANDONED})

# ---------------------------------------------------------------------------
# Constants — Response status strings
# ---------------------------------------------------------------------------

STATUS_TASK_PENDING = "task_pending"
STATUS_TASK_COMPLETED = "task_completed"
STATUS_TASK_FAILED = "task_failed"
STATUS_TASK_CANCELLED = "task_cancelled"
STATUS_TASK_TIMED_OUT = "task_timed_out"
STATUS_ERROR = "error"

# ---------------------------------------------------------------------------
# Constants — Defaults
# ---------------------------------------------------------------------------

DEFAULT_TASK_DIR = "./audit/"
DEFAULT_MAX_POLLS = 20
DEFAULT_INITIAL_POLL_INTERVAL = 5
DEFAULT_MAX_POLL_INTERVAL = 30
DEFAULT_POLL_BURST_LIMIT = 90
DEFAULT_LOCAL_ARTIFACT_MAX_AGE_DAYS = 7
DEFAULT_LOCAL_CAPTURE_DIR = "/tmp/captures"
DEFAULT_STORAGE_CONTAINER = "captures"
DEFAULT_STORAGE_AUTH_MODE = "login"
DEFAULT_CAPTURE_NAME_PREFIX = "ghost"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _generate_task_id(prefix: str, target: str) -> str:
    """Generate a deterministic task ID: {prefix}_{target}_{YYYYMMDDTHHMMSS}."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "-", target)
    return f"{prefix}_{safe_target}_{ts}"


def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _compute_poll_interval(attempt: int, initial: int, max_interval: int) -> int:
    """Compute exponential backoff: min(initial * 2^(attempt-1), max_interval)."""
    if attempt < 1:
        attempt = 1
    return min(initial * (2 ** (attempt - 1)), max_interval)


# ---------------------------------------------------------------------------
# CloudOrchestrator
# ---------------------------------------------------------------------------

class CloudOrchestrator:
    """Cloud Orchestrator: async bridge between the AI Brain and Azure operations.

    Usage:
        orchestrator = CloudOrchestrator(shell, session_id="sess_001")
        response = orchestrator.orchestrate({"intent": "capture_traffic", ...})
    """

    def __init__(
        self,
        shell,
        session_id: str,
        task_dir: str = DEFAULT_TASK_DIR,
        max_polls: int = DEFAULT_MAX_POLLS,
        initial_poll_interval: int = DEFAULT_INITIAL_POLL_INTERVAL,
        max_poll_interval: int = DEFAULT_MAX_POLL_INTERVAL,
        local_capture_dir: str = DEFAULT_LOCAL_CAPTURE_DIR,
        storage_container: str = DEFAULT_STORAGE_CONTAINER,
        storage_auth_mode: str = DEFAULT_STORAGE_AUTH_MODE,
        capture_name_prefix: str = DEFAULT_CAPTURE_NAME_PREFIX,
        poll_burst_limit: int = DEFAULT_POLL_BURST_LIMIT,
        local_artifact_max_age_days: int = DEFAULT_LOCAL_ARTIFACT_MAX_AGE_DAYS,
        location: str = "",
    ):
        self._shell = shell
        self._session_id = session_id
        self._task_dir = Path(task_dir)
        self._max_polls = max_polls
        self._initial_poll_interval = initial_poll_interval
        self._max_poll_interval = max_poll_interval
        self._local_capture_dir = Path(local_capture_dir)
        self._storage_container = storage_container
        self._storage_auth_mode = storage_auth_mode
        self._capture_name_prefix = capture_name_prefix
        self._poll_burst_limit = poll_burst_limit
        self._local_artifact_max_age_days = local_artifact_max_age_days
        self._location = location  # Azure location for Network Watcher operations
        self._orphans = self._detect_orphans()

    # -----------------------------------------------------------------------
    # Main dispatch
    # -----------------------------------------------------------------------

    def orchestrate(self, request: dict) -> dict:
        """Main entry point. Dispatches by intent to the appropriate handler."""
        try:
            intent = request.get("intent", "")
            if not intent:
                return {"status": STATUS_ERROR, "error": "missing_parameter",
                        "message": "intent is required"}

            if intent == "capture_traffic":
                return self._handle_capture_traffic(request)
            if intent == "check_task":
                return self._handle_check_task(request)
            if intent == "cancel_task":
                return self._handle_cancel_task(request)
            if intent == "list_tasks":
                return self._handle_list_tasks(request)
            if intent == "cleanup_task":
                return self._handle_cleanup_task(request)

            return {"status": STATUS_ERROR, "error": "unknown_intent",
                    "message": f"Unsupported intent: {intent}"}
        except Exception as e:
            self._log(f"Unexpected error in orchestrate: {e}")
            return {"status": STATUS_ERROR, "error": "internal_error",
                    "message": f"Internal error: {e}"}

    # -----------------------------------------------------------------------
    # Intent: capture_traffic
    # -----------------------------------------------------------------------

    def _handle_capture_traffic(self, request: dict) -> dict:
        """Handle capture_traffic intent. Supports single and dual-end captures."""
        target = request.get("target", "")
        if not target:
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "target is required for capture_traffic"}

        parameters = request.get("parameters", {})
        if not parameters.get("storage_account"):
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "storage_account is required"}
        if not parameters.get("resource_group"):
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "resource_group is required"}

        investigation_context = request.get("investigation_context", "")

        # Dual-end capture: target contains " to "
        if " to " in target:
            parts = target.split(" to ", 1)
            source_target = parts[0].strip()
            dest_target = parts[1].strip()

            source_req = {
                "intent": "capture_traffic", "target": source_target,
                "parameters": parameters,
                "investigation_context": investigation_context,
            }
            dest_req = {
                "intent": "capture_traffic", "target": dest_target,
                "parameters": parameters,
                "investigation_context": investigation_context,
            }

            # Create both tasks without polling so we can link them before any
            # downloads occur. Auto-chain (burst_poll=True) would otherwise run
            # each capture to completion before pairing is established, causing
            # single-end analysis instead of the comparison analysis.
            source_resp = self._create_single_capture(source_req, burst_poll=False)
            dest_resp   = self._create_single_capture(dest_req,   burst_poll=False)

            # Link tasks via paired_task_id before polling
            src_id = source_resp.get("task_id")
            dst_id = dest_resp.get("task_id")
            if src_id and dst_id:
                src_task = self._load_task(src_id)
                dst_task = self._load_task(dst_id)
                if src_task and dst_task:
                    src_task["paired_task_id"] = dst_id
                    dst_task["paired_task_id"] = src_id
                    self._save_task(src_task)
                    self._save_task(dst_task)

            # Burst-poll source first: it downloads then waits for dest (returns
            # task_pending because pair is not yet ready — that response is ignored).
            # Then burst-poll dest: it downloads and, seeing source is ready,
            # triggers the comparison analysis and returns the final result.
            final_resp = {"status": STATUS_TASK_PENDING,
                          "message": "Dual capture initiated but polling failed"}
            if src_id:
                src_task = self._load_task(src_id)
                if src_task:
                    self._log(f"Dual capture: polling source ({source_target})…")
                    self._burst_poll(src_task)   # result ignored — source waits for dest
            if dst_id:
                dst_task = self._load_task(dst_id)
                if dst_task:
                    self._log(f"Dual capture: polling dest ({dest_target})…")
                    final_resp = self._burst_poll(dst_task)   # comparison runs here

            return final_resp

        return self._create_single_capture(request)

    def _create_single_capture(self, request: dict, burst_poll: bool = True) -> dict:
        """Create a single capture task through the full lifecycle start.

        burst_poll=True (default): auto-chains into _burst_poll so the caller
        gets a terminal result directly (single-capture path).
        burst_poll=False: returns after WAITING state is saved, leaving polling
        to the caller (dual-capture path, which must link tasks before polling).
        """
        target = request["target"]
        parameters = request["parameters"]
        investigation_context = self._sanitize_context(request.get("investigation_context", ""))
        resource_group = parameters["resource_group"]
        storage_account = parameters["storage_account"]
        duration_seconds = parameters.get("duration_seconds", 60)

        # Resolve Azure location (needed for show/delete which require --location, not --resource-group)
        location = self._get_azure_location(resource_group)
        parameters["location"] = location

        # Detect target type early for AKS short-circuit
        target_type = self._detect_target_type(target, resource_group)
        if target_type == "aks":
            return {
                "status": STATUS_TASK_COMPLETED,
                "target_type": "aks",
                "investigation_context": investigation_context,
                "message": ("AKS target detected. AKS capture pipeline not yet "
                            "available in Phase 2. Target type recorded for future use."),
            }
        if target_type is None:
            return {"status": STATUS_ERROR, "error": "detection_failed",
                    "message": f"Resource '{target}' not found or detection failed in resource group '{resource_group}'"}

        task_id = _generate_task_id(self._capture_name_prefix, target)

        task = {
            "task_id": task_id,
            "session_id": self._session_id,
            "intent": "capture_traffic",
            "target": target,
            "target_type": target_type,
            "state": CREATED,
            "investigation_context": investigation_context,
            "parameters": parameters,
            "azure_operation_id": task_id,
            "storage_account": storage_account,
            "storage_container": self._storage_container,
            "storage_blob_name": f"{task_id}.cap",
            "local_pcap_path": None,
            "semantic_json_path": None,
            "report_path": None,
            "paired_task_id": None,
            "cleanup_plan": [],
            "cleanup_status": None,
            "poll_count": 0,
            "max_polls": self._max_polls,
            "shell_audit_ids": [],
            "timestamps": {
                "created": _now_iso(),
                "approved": None,
                "provisioned": None,
                "first_poll": None,
                "last_poll": None,
                "completed": None,
                "cleanup_started": None,
                "cleanup_completed": None,
            },
            "error_detail": None,
            "duration_seconds": None,
        }

        self._log(f"New task: {task_id}")
        self._log(f"  Intent: capture_traffic")
        self._log(f"  Target: {target} (type: {target_type})")
        self._save_task(task)

        self._log(f"Target type: VM. Using Network Watcher packet capture.")
        self._log(f"  Capture duration: {duration_seconds} seconds")
        self._log(f"  Storage: {storage_account}/{self._storage_container}")

        # Verify storage access
        if not self._verify_storage_access(storage_account, self._storage_container, task):
            task["state"] = FAILED
            task["error_detail"] = (f"Storage account '{storage_account}' or container "
                                    f"'{self._storage_container}' is inaccessible")
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            self._save_task(task)
            return self._build_response(task)

        # DETECTING -> APPROVED
        task["state"] = APPROVED
        task["timestamps"]["approved"] = _now_iso()

        # Build cleanup plan before creating any resources
        task["cleanup_plan"] = self._build_cleanup_plan(task)
        self._save_task(task)

        # Send capture create to Shell (RISKY — HITL gated)
        capture_cmd = self._build_capture_command(task)
        result = self._shell.execute({
            "command": capture_cmd,
            "reasoning": (f"Creating packet capture for investigation: "
                          f"{investigation_context}. Duration: {duration_seconds} "
                          f"seconds. Capture name: {task_id}."),
        })
        if result.get("audit_id"):
            task["shell_audit_ids"].append(result["audit_id"])

        # Denied -> CANCELLED
        if result.get("status") == "denied":
            task["state"] = CANCELLED
            task["error_detail"] = "User denied capture creation"
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            self._save_task(task)
            return self._build_response(task)

        # Error -> FAILED (cleanup deferred to orphan sentinel or explicit cleanup_task)
        if result.get("status") != "completed" or result.get("exit_code", 1) != 0:
            task["state"] = FAILED
            task["error_detail"] = (f"Azure provisioning failed: "
                                    f"{result.get('stderr', result.get('error', 'unknown error'))}")
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            task["cleanup_status"] = "pending"
            self._save_task(task)
            return self._build_response(task)

        # APPROVED -> PROVISIONING -> WAITING
        task["state"] = PROVISIONING
        task["timestamps"]["provisioned"] = _now_iso()
        self._save_task(task)

        task["state"] = WAITING
        self._save_task(task)

        self._log(f"Task {task_id}: PROVISIONING")
        if burst_poll:
            self._log(f"  Status: Polling until capture completes or burst limit expires…")
            return self._burst_poll(task)
        return self._build_response(task)

    # -----------------------------------------------------------------------
    # Intent: check_task
    # -----------------------------------------------------------------------

    def _handle_check_task(self, request: dict) -> dict:
        """Handle check_task intent with burst polling."""
        task_id = request.get("task_id", "")
        if not task_id:
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "task_id is required for check_task"}

        task = self._load_task(task_id)
        if task is None:
            return {"status": STATUS_ERROR, "error": "unknown_task",
                    "message": f"No task found with ID: {task_id}"}

        # Terminal states: return current state (idempotent)
        if task["state"] in TERMINAL_STATES:
            return self._build_response(task)

        # COMPLETED with paired task: check if pair is ready
        if task["state"] == COMPLETED and task.get("paired_task_id"):
            return self._advance_paired(task)

        # COMPLETED without pair: already done
        if task["state"] == COMPLETED:
            return self._build_response(task)

        # WAITING: burst-poll Azure
        if task["state"] == WAITING:
            return self._burst_poll(task)

        # Any other non-terminal state
        return self._build_response(task)

    def _burst_poll(self, task: dict) -> dict:
        """Burst-poll Azure within the poll_burst_limit window."""
        start = time.monotonic()
        polls_this_burst = 0

        while time.monotonic() - start < self._poll_burst_limit:
            azure_state = self._poll_azure_status(task)
            polls_this_burst += 1
            self._save_task(task)

            if azure_state == "Stopped":
                # packetCaptureStatus=Stopped means the capture has finished and blob is ready
                response = self._advance_to_download(task)
                response["burst_polls"] = polls_this_burst
                response["burst_duration_seconds"] = round(time.monotonic() - start, 1)
                return response

            if azure_state == "Error":
                # Azure-reported capture error — defer cleanup to orphan sentinel
                task["state"] = FAILED
                task["error_detail"] = "Azure packet capture returned Error status"
                task["timestamps"]["completed"] = _now_iso()
                task["duration_seconds"] = self._compute_duration(task)
                task["cleanup_status"] = "pending"
                self._save_task(task)
                response = self._build_response(task)
                response["burst_polls"] = polls_this_burst
                response["burst_duration_seconds"] = round(time.monotonic() - start, 1)
                return response

            if task["poll_count"] >= task["max_polls"]:
                task["state"] = TIMED_OUT
                task["error_detail"] = "Azure operation did not complete within polling window"
                task["timestamps"]["completed"] = _now_iso()
                task["duration_seconds"] = self._compute_duration(task)
                task["cleanup_status"] = "pending"
                self._save_task(task)
                response = self._build_response(task)
                response["burst_polls"] = polls_this_burst
                response["burst_duration_seconds"] = round(time.monotonic() - start, 1)
                return response

            # Sleep with exponential backoff
            interval = _compute_poll_interval(
                task["poll_count"], self._initial_poll_interval, self._max_poll_interval
            )
            time.sleep(interval)

        # Burst expired, still waiting
        self._save_task(task)
        response = self._build_response(task)
        response["burst_polls"] = polls_this_burst
        response["burst_duration_seconds"] = round(time.monotonic() - start, 1)
        return response

    def _advance_to_download(self, task: dict) -> dict:
        """Advance from WAITING through DOWNLOADING -> ANALYZING -> COMPLETED."""
        task["state"] = DOWNLOADING
        self._save_task(task)

        local_path = self._download_capture(task)
        if local_path is None:
            # _download_capture sets CANCELLED if denied; cleanup deferred to orphan sentinel
            if task["state"] != CANCELLED:
                task["state"] = FAILED
                task["error_detail"] = "Blob download failed after retry"
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            task["cleanup_status"] = "pending"
            self._save_task(task)
            return self._build_response(task)

        task["local_pcap_path"] = local_path

        # Paired task: download done, wait for partner before analysis
        if task.get("paired_task_id"):
            task["state"] = COMPLETED
            task["timestamps"]["completed"] = _now_iso()
            self._save_task(task)
            return self._advance_paired(task)

        # Single-end: proceed to analysis
        return self._advance_to_analysis(task)

    def _advance_to_analysis(self, task: dict, compare_path: Optional[str] = None) -> dict:
        """Run PCAP Engine and advance to COMPLETED or FAILED."""
        task["state"] = ANALYZING
        self._save_task(task)

        analysis_result = self._run_pcap_engine(task, compare_path=compare_path)
        if analysis_result:
            task["state"] = COMPLETED
            task["semantic_json_path"] = analysis_result["semantic_json_path"]
            task["report_path"] = analysis_result["report_path"]
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            task["cleanup_status"] = "pending"
            self._save_task(task)
        else:
            task["state"] = FAILED
            task["error_detail"] = "PCAP Engine analysis failed"
            task["timestamps"]["completed"] = _now_iso()
            task["duration_seconds"] = self._compute_duration(task)
            task["cleanup_status"] = "pending"
            self._save_task(task)

        return self._build_response(task)

    def _advance_paired(self, task: dict) -> dict:
        """Check paired task status and advance to analysis if ready."""
        pair_status = self._check_paired_ready(task)

        if pair_status == "both_ready":
            partner = self._load_task(task["paired_task_id"])
            resp = self._advance_to_analysis(task, compare_path=partner["local_pcap_path"])
            # Store comparison report path in both tasks
            if task.get("report_path") and partner:
                partner["semantic_json_path"] = task.get("semantic_json_path")
                partner["report_path"] = task.get("report_path")
                self._save_task(partner)
            return resp

        if pair_status == "partner_failed":
            resp = self._advance_to_analysis(task)
            return resp

        # Waiting for partner — return pending with paired info
        return self._build_response(task)

    # -----------------------------------------------------------------------
    # Intent: cancel_task
    # -----------------------------------------------------------------------

    def _handle_cancel_task(self, request: dict) -> dict:
        """Handle cancel_task intent."""
        task_id = request.get("task_id", "")
        if not task_id:
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "task_id is required for cancel_task"}

        task = self._load_task(task_id)
        if task is None:
            return {"status": STATUS_ERROR, "error": "unknown_task",
                    "message": f"No task found with ID: {task_id}"}

        # Already terminal: idempotent
        if task["state"] in TERMINAL_STATES:
            return self._build_response(task)

        task["state"] = CANCELLED
        task["error_detail"] = "Task cancelled by user"
        task["timestamps"]["completed"] = _now_iso()
        task["duration_seconds"] = self._compute_duration(task)
        self._save_task(task)

        # Defer cleanup to orphan sentinel or explicit cleanup_task call
        if task["timestamps"].get("provisioned"):
            task["cleanup_status"] = "pending"
            self._save_task(task)

        return self._build_response(task)

    # -----------------------------------------------------------------------
    # Intent: list_tasks
    # -----------------------------------------------------------------------

    def _handle_list_tasks(self, request: dict) -> dict:
        """Handle list_tasks intent."""
        tasks = self._load_all_tasks()
        response = self._build_list_response(tasks)
        if self._orphans:
            response["orphans"] = self._orphans
        return response

    # -----------------------------------------------------------------------
    # Intent: cleanup_task
    # -----------------------------------------------------------------------

    def _handle_cleanup_task(self, request: dict) -> dict:
        """Handle cleanup_task intent for explicit cleanup of completed tasks."""
        task_id = request.get("task_id", "")
        if not task_id:
            return {"status": STATUS_ERROR, "error": "missing_parameter",
                    "message": "task_id is required for cleanup_task"}

        task = self._load_task(task_id)
        if task is None:
            return {"status": STATUS_ERROR, "error": "unknown_task",
                    "message": f"No task found with ID: {task_id}"}

        task["state"] = CLEANING_UP
        self._save_task(task)

        self._run_cleanup(task)

        # Always advance to DONE — "skipped" means nothing to clean up, which is
        # also a terminal condition. Leaving state=CLEANING_UP causes the orphan
        # sentinel to re-detect this task as abandoned on every subsequent startup.
        task["state"] = DONE
        self._save_task(task)

        return self._build_response(task)

    # -----------------------------------------------------------------------
    # Target detection
    # -----------------------------------------------------------------------

    def _detect_target_type(self, target: str, resource_group: str,
                            task: Optional[dict] = None) -> Optional[str]:
        """Detect whether the target is a VM or AKS cluster."""
        if target.startswith("/"):
            cmd = f"az resource show --ids {target} --query type -o tsv"
        else:
            cmd = (f"az resource list --name {target} --resource-group "
                   f"{resource_group} --query \"[0].type\" -o tsv")

        result = self._shell.execute({
            "command": cmd,
            "reasoning": f"Detecting target type for: {target}",
        })

        if task and result.get("audit_id"):
            task["shell_audit_ids"].append(result["audit_id"])

        if result.get("status") == "denied":
            return None
        if result.get("status") != "completed" or result.get("exit_code", 1) != 0:
            return None

        output = result.get("output", "").strip()
        if "Microsoft.Compute/virtualMachines" in output:
            return "vm"
        if "Microsoft.ContainerService/managedClusters" in output:
            return "aks"
        if output:
            self._log(f"Unsupported resource type: {output}")
        return None

    # -----------------------------------------------------------------------
    # Storage verification
    # -----------------------------------------------------------------------

    def _verify_storage_access(self, storage_account: str, container: str,
                               task: Optional[dict] = None) -> bool:
        """Verify the storage account and container are accessible."""
        cmd = (f"az storage container exists --account-name {storage_account} "
               f"--name {container} --auth-mode {self._storage_auth_mode} -o tsv")

        result = self._shell.execute({
            "command": cmd,
            "reasoning": f"Verifying storage access for {storage_account}/{container}",
        })

        if task and result.get("audit_id"):
            task["shell_audit_ids"].append(result["audit_id"])

        if result.get("status") == "denied":
            return False
        if result.get("status") != "completed" or result.get("exit_code", 1) != 0:
            return False

        output = result.get("output", "").strip().lower()
        return output == "true"

    # -----------------------------------------------------------------------
    # Command builders
    # -----------------------------------------------------------------------

    def _build_capture_command(self, task: dict) -> str:
        """Build az network watcher packet-capture create command."""
        target = task["target"]
        rg = task["parameters"]["resource_group"]
        sa = task["storage_account"]
        duration = task["parameters"].get("duration_seconds", 60)
        capture_name = task["task_id"]
        storage_path = (f"https://{sa}.blob.core.windows.net/"
                        f"{self._storage_container}/{capture_name}.cap")

        return (f"az network watcher packet-capture create"
                f" --vm {target}"
                f" --resource-group {rg}"
                f" --name {capture_name}"
                f" --storage-account {sa}"
                f" --storage-path {storage_path}"
                f" --time-limit {duration}")

    def _build_cleanup_plan(self, task: dict) -> List[dict]:
        """Build cleanup plan at task creation time, before any resources are created."""
        # delete (like show) requires --location, not --resource-group
        location = task["parameters"].get("location") or self._get_azure_location(
            task["parameters"]["resource_group"]
        )
        plan = []

        # Cloud resources first (cost money)
        plan.append({
            "command": (f"az network watcher packet-capture delete"
                        f" --location {location} --name {task['task_id']}"),
            "executed": False,
        })
        plan.append({
            "command": (f"az storage blob delete"
                        f" --account-name {task['storage_account']}"
                        f" --container-name {self._storage_container}"
                        f" --name {task['storage_blob_name']}"),
            "executed": False,
        })

        # Local file last
        local_path = str(self._local_capture_dir / f"{task['task_id']}.cap")
        plan.append({
            "command": f"rm \"{local_path}\"",
            "executed": False,
        })

        return plan

    # -----------------------------------------------------------------------
    # Polling
    # -----------------------------------------------------------------------

    def _poll_azure_status(self, task: dict) -> str:
        """Poll Azure for the runtime capture status using show-status.

        Returns packetCaptureStatus from Azure: Running, Stopped, Error, NotStarted, Unknown.
        Returns lowercase "error" on command failure (continue polling — may still be provisioning).
        "Stopped" means the capture has finished and the blob is available for download.
        """
        location = task["parameters"].get("location") or self._get_azure_location(
            task["parameters"]["resource_group"]
        )
        capture_name = task["task_id"]
        cmd = (f"az network watcher packet-capture show-status"
               f" --location {location} --name {capture_name}"
               f" --query packetCaptureStatus -o tsv")

        result = self._shell.execute({
            "command": cmd,
            "reasoning": (f"Polling capture status. "
                          f"Investigation: {task['investigation_context']}"),
        })

        if result.get("audit_id"):
            task["shell_audit_ids"].append(result["audit_id"])

        task["poll_count"] += 1
        if task["timestamps"]["first_poll"] is None:
            task["timestamps"]["first_poll"] = _now_iso()
        task["timestamps"]["last_poll"] = _now_iso()

        if result.get("status") == "denied":
            self._log(f"Poll {task['poll_count']}/{task['max_polls']}: Shell call denied")
            return "error"
        if result.get("status") != "completed" or result.get("exit_code", 1) != 0:
            # show-status can transiently fail while the capture is still provisioning
            self._log(f"Poll {task['poll_count']}/{task['max_polls']}: show-status unavailable (still provisioning?)")
            return "error"

        output = result.get("output", "").strip()
        self._log(f"Poll {task['poll_count']}/{task['max_polls']}: "
                  f"packetCaptureStatus = {output}")
        return output

    # -----------------------------------------------------------------------
    # Download
    # -----------------------------------------------------------------------

    def _download_capture(self, task: dict) -> Optional[str]:
        """Download capture blob from Azure storage. Retries once on failure."""
        self._local_capture_dir.mkdir(parents=True, exist_ok=True)
        local_path = str(self._local_capture_dir / f"{task['task_id']}.cap")

        sa = task["storage_account"]
        blob_name = task["storage_blob_name"]
        cmd = (f"az storage blob download"
               f" --account-name {sa}"
               f" --container-name {self._storage_container}"
               f" --name {blob_name}"
               f" --file {local_path}"
               f" --no-progress")

        for attempt in range(2):
            result = self._shell.execute({
                "command": cmd,
                "reasoning": (f"Downloading capture for analysis. "
                              f"Investigation: {task['investigation_context']}"),
            })

            if result.get("audit_id"):
                task["shell_audit_ids"].append(result["audit_id"])

            if result.get("status") == "denied":
                task["state"] = CANCELLED
                task["error_detail"] = "User denied blob download"
                return None

            if result.get("status") == "completed" and result.get("exit_code") == 0:
                self._log(f"Download complete: {local_path}")
                return local_path

            if attempt == 0:
                self._log("Download failed, retrying in 5 seconds...")
                time.sleep(5)

        return None

    # -----------------------------------------------------------------------
    # PCAP Engine
    # -----------------------------------------------------------------------

    # Absolute path to pcap_forensics.py — resolved relative to this file at import time.
    # Using sys.executable guarantees the same Python / venv that runs the orchestrator.
    _PCAP_ENGINE = str(
        Path(__file__).parent.parent / "agentic-pcap-forensic-engine" / "pcap_forensics.py"
    )

    def _run_pcap_engine(self, task: dict,
                         compare_path: Optional[str] = None) -> Optional[dict]:
        """Run the PCAP Forensic Engine on a downloaded capture."""
        local_path = task["local_pcap_path"]
        semantic_dir = str(self._local_capture_dir)
        report_dir = str(self._local_capture_dir)
        interp = sys.executable  # same Python / venv as the running process

        if compare_path:
            # compare_path is the SOURCE endpoint's capture (the sender, paired task).
            # local_path  is the DEST endpoint's capture (the receiver, this task).
            # The endpoint-correlation prompt requires SOURCE = pcap_a, DEST = pcap_b,
            # so SOURCE is passed as the positional argument and DEST as --compare.
            cmd = (f'"{interp}" "{self._PCAP_ENGINE}" "{compare_path}"'
                   f' --compare "{local_path}"'
                   f' --mode endpoint-correlation'
                   f' --semantic-dir "{semantic_dir}"'
                   f' --report-dir "{report_dir}"')
            reasoning = (f"Comparing captures from both ends of the path: "
                         f"{task['target']}. "
                         f"Investigation: {task['investigation_context']}")
        else:
            cmd = (f'"{interp}" "{self._PCAP_ENGINE}" "{local_path}"'
                   f' --semantic-dir "{semantic_dir}"'
                   f' --report-dir "{report_dir}"')
            reasoning = (f"Analyzing capture. "
                         f"Investigation: {task['investigation_context']}")

        result = self._shell.execute({
            "command": cmd,
            "reasoning": reasoning,
        })

        if result.get("audit_id"):
            task["shell_audit_ids"].append(result["audit_id"])

        if result.get("status") != "completed" or result.get("exit_code", 1) != 0:
            return None

        # Compute report filename to match what pcap_forensics.py actually writes.
        # Comparison mode: save_comparison_report → "{pcap_a.stem}_vs_{pcap_b.stem}_comparison.md"
        #   pcap_a = SOURCE (compare_path), pcap_b = DEST (local_path) — after the swap above.
        # Single mode:     save_report            → "{pcap_a.stem}_forensic_report.md"
        if compare_path:
            pcap_a_stem = Path(compare_path).stem   # SOURCE (pcap_a in the command)
            pcap_b_stem = Path(local_path).stem      # DEST   (pcap_b in the command)
            report_name = f"{pcap_a_stem}_vs_{pcap_b_stem}_comparison.md"
        else:
            report_name = f"{task['task_id']}_forensic_report.md"

        return {
            "semantic_json_path": str(self._local_capture_dir / f"{task['task_id']}_semantic.json"),
            "report_path": str(self._local_capture_dir / report_name),
        }

    # -----------------------------------------------------------------------
    # Paired task readiness
    # -----------------------------------------------------------------------

    def _check_paired_ready(self, task: dict) -> str:
        """Check if paired task is ready for comparison analysis.

        Returns: "both_ready", "partner_failed", or "waiting".
        """
        paired_id = task.get("paired_task_id")
        if not paired_id:
            return "both_ready"

        partner = self._load_task(paired_id)
        if partner is None:
            return "partner_failed"

        if partner["state"] == COMPLETED and partner.get("local_pcap_path"):
            return "both_ready"

        if partner["state"] in {FAILED, TIMED_OUT, CANCELLED, ABANDONED}:
            return "partner_failed"

        return "waiting"

    # -----------------------------------------------------------------------
    # Cleanup execution
    # -----------------------------------------------------------------------

    def _run_cleanup(self, task: dict) -> str:
        """Execute the task's cleanup plan through Shell. Does not change task state.

        Returns: "completed", "partial", or "skipped".
        """
        cleanup_plan = task.get("cleanup_plan", [])
        if not cleanup_plan:
            task["cleanup_status"] = "skipped"
            return "skipped"

        if all(cmd.get("executed") for cmd in cleanup_plan):
            task["cleanup_status"] = "skipped"
            return "skipped"

        task["timestamps"]["cleanup_started"] = _now_iso()

        all_success = True
        any_executed = False
        investigation = task.get("investigation_context", "")

        for cmd_entry in cleanup_plan:
            if cmd_entry.get("executed"):
                continue

            result = self._shell.execute({
                "command": cmd_entry["command"],
                "reasoning": (f"Cleanup for task {task['task_id']}. "
                              f"Investigation: {investigation}"),
            })

            if result.get("audit_id"):
                task["shell_audit_ids"].append(result["audit_id"])

            if result.get("status") == "denied":
                all_success = False
                self._log(f"Cleanup denied: {cmd_entry['command']}")
            elif result.get("status") != "completed" or result.get("exit_code", 1) != 0:
                stderr = result.get("stderr", "")
                if "not found" in stderr.lower() or "does not exist" in stderr.lower():
                    cmd_entry["executed"] = True
                    any_executed = True
                else:
                    all_success = False
            else:
                cmd_entry["executed"] = True
                any_executed = True

        task["timestamps"]["cleanup_completed"] = _now_iso()

        if all_success and any_executed:
            task["cleanup_status"] = "completed"
            return "completed"
        if any_executed:
            task["cleanup_status"] = "partial"
            return "partial"

        task["cleanup_status"] = "skipped"
        return "skipped"

    def mark_task_cleaned(self, task_id: str) -> bool:
        """Mark a task as fully cleaned in the registry without running shell commands.

        Used by the batch startup cleanup path after resources have already been
        deleted externally. Returns True if the task was found and updated.
        """
        task = self._load_task(task_id)
        if task is None:
            return False
        for cmd_entry in task.get("cleanup_plan", []):
            cmd_entry["executed"] = True
        task["state"] = DONE
        task["cleanup_status"] = "completed"
        task["timestamps"]["cleanup_completed"] = _now_iso()
        self._save_task(task)
        return True

    # -----------------------------------------------------------------------
    # Task registry — persistence
    # -----------------------------------------------------------------------

    def _save_task(self, task: dict):
        """Append the current task state to the Task Registry JSONL file."""
        try:
            self._task_dir.mkdir(parents=True, exist_ok=True)
            path = self._task_dir / f"orchestrator_tasks_{self._session_id}.jsonl"
            with open(path, "a") as f:
                f.write(json.dumps(task, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            self._log(f"WARNING: Task registry write failure: {e}")

    def _load_task(self, task_id: str) -> Optional[dict]:
        """Load the most recent state of a task from any session file."""
        last_record = None
        pattern = str(self._task_dir / "orchestrator_tasks_*.jsonl")

        for filepath in glob.glob(pattern):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if record.get("task_id") == task_id:
                                last_record = record
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue

        return last_record

    def _load_all_tasks(self) -> List[dict]:
        """Load the most recent state of all tasks from all session files.

        Files are processed in alphabetical (≈ chronological) order so that
        records from newer sessions overwrite records from older sessions for
        the same task_id. This guarantees that a DONE record written during
        cleanup in session N is never clobbered by a WAITING record from the
        original session M < N.
        """
        tasks_by_id: Dict[str, dict] = {}
        pattern = str(self._task_dir / "orchestrator_tasks_*.jsonl")

        for filepath in sorted(glob.glob(pattern)):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            tid = record.get("task_id")
                            if tid:
                                tasks_by_id[tid] = record
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue

        return list(tasks_by_id.values())

    # -----------------------------------------------------------------------
    # Orphan detection
    # -----------------------------------------------------------------------

    def _detect_orphans(self) -> List[dict]:
        """Three-layer orphan detection at init."""
        orphans: List[dict] = []

        # Layer 1: Task Registry scan — non-terminal tasks from previous sessions
        all_tasks = self._load_all_tasks()
        for task in all_tasks:
            if task.get("session_id") == self._session_id:
                continue
            state = task.get("state", "")
            if state not in TERMINAL_STATES:
                orphans.append({"type": "abandoned_task", "task": task})
            elif state == COMPLETED and task.get("cleanup_status") == "pending":
                orphans.append({"type": "needs_cleanup", "task": task})
            elif state in {FAILED, TIMED_OUT, CANCELLED} and task.get("cleanup_status") in (None, "pending"):
                orphans.append({"type": "needs_cleanup", "task": task})

        # Layer 2: Azure resource scan — ghost_* resources not in registry
        # packet-capture list requires --location (not --resource-group)
        list_location = self._location or "eastus"
        try:
            result = self._shell.execute({
                "command": (f"az network watcher packet-capture list"
                            f" --location {list_location}"
                            f" --query \"[?starts_with(name, "
                            f"'{self._capture_name_prefix}_')]\" -o json"),
                "reasoning": (f"Startup orphan detection: scanning for "
                              f"{self._capture_name_prefix}_* packet captures "
                              f"from previous sessions."),
            })

            if (result.get("status") == "completed"
                    and result.get("exit_code") == 0
                    and result.get("output", "").strip()):
                try:
                    azure_resources = json.loads(result["output"])
                    known_ids = {t.get("task_id") for t in all_tasks}
                    for resource in azure_resources:
                        name = resource.get("name", "")
                        if name and name not in known_ids:
                            orphans.append({
                                "type": "untracked_azure_resource",
                                "name": name,
                                "resource": resource,
                            })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        # Layer 3: Local file age scan — stale ghost_* files
        try:
            if self._local_capture_dir.exists():
                now = time.time()
                max_age_seconds = self._local_artifact_max_age_days * 86400
                prefix = self._capture_name_prefix + "_"
                for filepath in self._local_capture_dir.iterdir():
                    if not filepath.name.startswith(prefix):
                        continue
                    try:
                        age = now - filepath.stat().st_mtime
                        if age > max_age_seconds:
                            orphans.append({
                                "type": "stale_local_file",
                                "path": str(filepath),
                            })
                    except OSError:
                        continue
        except Exception:
            pass

        if orphans:
            self._log(f"Orphan detection: found {len(orphans)} orphaned resources")

        return orphans

    # -----------------------------------------------------------------------
    # Response builders
    # -----------------------------------------------------------------------

    def _build_response(self, task: dict) -> dict:
        """Build response dict for a single task."""
        state = task["state"]

        # Load partner once and pass to helpers
        partner = None
        if task.get("paired_task_id"):
            partner = self._load_task(task["paired_task_id"])

        status = self._state_to_status(task, partner=partner)

        response = {
            "task_id": task["task_id"],
            "status": status,
            "state": state,
            "investigation_context": task.get("investigation_context", ""),
            "message": self._build_message(task, partner=partner),
        }

        if status == STATUS_TASK_PENDING:
            response["poll_count"] = task.get("poll_count")
            response["max_polls"] = task.get("max_polls")
            response["elapsed_seconds"] = self._compute_duration(task)

        if status == STATUS_TASK_COMPLETED:
            result = {}
            if task.get("local_pcap_path"):
                result["local_pcap_path"] = task["local_pcap_path"]
            if task.get("semantic_json_path"):
                result["semantic_json_path"] = task["semantic_json_path"]
            if task.get("report_path"):
                result["report_path"] = task["report_path"]
            # Check for single-end fallback mode
            if partner and partner["state"] in {FAILED, TIMED_OUT, CANCELLED, ABANDONED}:
                result["mode"] = "single_end_fallback"
            response["result"] = result if result else None
            response["cleanup_status"] = task.get("cleanup_status")
            response["duration_seconds"] = task.get("duration_seconds")

        if status in {STATUS_TASK_FAILED, STATUS_TASK_TIMED_OUT, STATUS_TASK_CANCELLED}:
            response["error_detail"] = task.get("error_detail")
            response["cleanup_status"] = task.get("cleanup_status")

        # Paired task info
        if partner:
            paired_info = {
                "task_id": partner["task_id"],
                "state": partner["state"],
            }
            if partner.get("error_detail"):
                paired_info["error_detail"] = partner["error_detail"]
            if partner.get("poll_count"):
                paired_info["poll_count"] = partner["poll_count"]
            response["paired_task"] = paired_info

        return response

    def _state_to_status(self, task: dict, partner: Optional[dict] = None) -> str:
        """Map task state to response status string."""
        state = task["state"]

        # COMPLETED with waiting pair → task_pending
        if state == COMPLETED and task.get("paired_task_id"):
            if partner and partner["state"] not in TERMINAL_STATES | {COMPLETED}:
                return STATUS_TASK_PENDING

        status_map = {
            COMPLETED: STATUS_TASK_COMPLETED,
            DONE: STATUS_TASK_COMPLETED,
            FAILED: STATUS_TASK_FAILED,
            CANCELLED: STATUS_TASK_CANCELLED,
            TIMED_OUT: STATUS_TASK_TIMED_OUT,
            ABANDONED: STATUS_TASK_FAILED,
        }
        return status_map.get(state, STATUS_TASK_PENDING)

    def _build_list_response(self, tasks: List[dict]) -> dict:
        """Build response for list_tasks intent."""
        summaries = []
        for task in tasks:
            summaries.append({
                "task_id": task["task_id"],
                "state": task["state"],
                "target": task.get("target", ""),
                "investigation_context": task.get("investigation_context", ""),
                "created": task.get("timestamps", {}).get("created", ""),
            })

        return {
            "status": STATUS_TASK_COMPLETED,
            "tasks": summaries,
            "message": f"{len(summaries)} task(s) found",
        }

    def _build_message(self, task: dict, partner: Optional[dict] = None) -> str:
        """Build human-readable status message."""
        state = task["state"]
        target = task.get("target", "unknown")

        if state == CREATED:
            return f"Task created for {target}."
        if state == DETECTING:
            return f"Detecting target type for {target}."
        if state == APPROVED:
            return f"Capture approved for {target}. Waiting for provisioning."
        if state == PROVISIONING:
            return f"Packet capture starting on {target}. Check back in ~5-10 seconds."
        if state == WAITING:
            return (f"Packet capture running on {target}. "
                    f"Azure provisioning state: Running.")
        if state == DOWNLOADING:
            return f"Downloading capture from {target}."
        if state == ANALYZING:
            return f"Analyzing capture from {target}."
        if state == COMPLETED:
            if partner and partner["state"] not in TERMINAL_STATES | {COMPLETED}:
                return (f"Source capture complete. Waiting for destination "
                        f"capture ({partner.get('target', 'unknown')}) to "
                        f"finish before comparison analysis.")
            return "Capture complete. Forensic report generated."
        if state == CLEANING_UP:
            return f"Cleaning up resources for {target}."
        if state == DONE:
            return "Capture complete. Forensic report generated."
        if state == FAILED:
            return f"Capture failed. {task.get('error_detail', '')}"
        if state == CANCELLED:
            return "Task cancelled."
        if state == TIMED_OUT:
            return "Capture timed out. Cloud resources cleaned up."
        if state == ABANDONED:
            return "Task abandoned from previous session."
        return f"Unknown state: {state}"

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    def _compute_duration(self, task: dict) -> Optional[float]:
        """Compute wall-clock duration from task creation to now."""
        created = task.get("timestamps", {}).get("created")
        if not created:
            return None
        try:
            created_dt = datetime.fromisoformat(created)
            return round((datetime.now(timezone.utc) - created_dt).total_seconds(), 1)
        except (ValueError, TypeError):
            return None

    def _get_azure_location(self, resource_group: str) -> str:
        """Resolve the Azure location for a resource group (safe read, auto-approved).

        Needed because az network watcher packet-capture show/delete/list require
        --location, not --resource-group.  Falls back to self._location if set, then 'eastus'.
        """
        result = self._shell.execute({
            "command":   f"az group show --name {resource_group} --query location -o tsv",
            "reasoning": f"Looking up location of resource group '{resource_group}' for Network Watcher operations.",
        })
        location = (result.get("output") or "").strip()
        if not location or result.get("exit_code", 1) != 0:
            fallback = self._location or "eastus"
            self._log(f"[WARN] Could not resolve location for '{resource_group}'; using '{fallback}'.")
            return fallback
        return location

    @staticmethod
    def _sanitize_context(text: str) -> str:
        """Strip control characters from investigation context."""
        return re.sub(r"[\x00-\x1f\x7f]", "", text)

    def _log(self, message: str):
        """Print to stderr with prefix."""
        print(f"[Cloud Orchestrator] {message}", file=sys.stderr)
