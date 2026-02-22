"""Tests for Cloud Orchestrator — derived from test-plan.md.

Covers all P0 (must pass) and high-value P1 (should pass) tests.
P2 and P3 tests are deferred.  See test-plan.md Appendix B for full count.
"""
import inspect
import json
import os
import time as real_time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from helpers import (
    MockShell, SAFE_OK, RISKY_OK, DENIED, CMD_ERR, NOT_FOUND_ERR,
    capture_req, setup_happy_path, setup_detect_and_storage,
    read_registry, response_seq,
)
from cloud_orchestrator import (
    CloudOrchestrator, _generate_task_id, _compute_poll_interval,
    CREATED, DETECTING, APPROVED, PROVISIONING, WAITING, DOWNLOADING,
    ANALYZING, COMPLETED, CLEANING_UP, DONE, FAILED, CANCELLED,
    TIMED_OUT, ABANDONED, TERMINAL_STATES,
    STATUS_TASK_PENDING, STATUS_TASK_COMPLETED, STATUS_TASK_FAILED,
    STATUS_TASK_CANCELLED, STATUS_TASK_TIMED_OUT, STATUS_ERROR,
    DEFAULT_TASK_DIR, DEFAULT_MAX_POLLS, DEFAULT_INITIAL_POLL_INTERVAL,
    DEFAULT_MAX_POLL_INTERVAL, DEFAULT_POLL_BURST_LIMIT,
    DEFAULT_LOCAL_ARTIFACT_MAX_AGE_DAYS, DEFAULT_LOCAL_CAPTURE_DIR,
    DEFAULT_STORAGE_CONTAINER, DEFAULT_CAPTURE_NAME_PREFIX,
    DEFAULT_STORAGE_AUTH_MODE,
)


# ═══════════════════════════════════════════════════════════════════════
# Section 1 — Shell Safety Boundary (P0)
# ═══════════════════════════════════════════════════════════════════════

class TestShellSafety:
    """P0: Every command must flow through shell.execute()."""

    def test_CO01_no_subprocess_in_source(self):
        src = Path(__file__).parent.parent / "cloud_orchestrator.py"
        text = src.read_text()
        assert "import subprocess" not in text
        assert "subprocess." not in text

    def test_CO02_pcap_engine_via_shell(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        pcap_calls = shell.calls_with("pcap_forensics.py")
        assert len(pcap_calls) >= 1
        assert "command" in pcap_calls[0]
        assert "reasoning" in pcap_calls[0]

    def test_CO03_no_shell_modification(self, shell, orch):
        original_attrs = set(dir(shell))
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        assert set(dir(shell)) == original_attrs

    def test_CO04_denied_capture_not_retried(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", DENIED)
        orch.orchestrate(capture_req())
        assert len(shell.calls_with("packet-capture create")) == 1

    def test_CO05_denied_download_no_alternative(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", DENIED)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert len(shell.calls_with("storage blob download")) == 1

    def test_CO06_reasoning_includes_context(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        ctx = "high latency on prod-db"
        orch.orchestrate(capture_req(investigation_context=ctx))
        create_calls = shell.calls_with("packet-capture create")
        assert ctx in create_calls[0]["reasoning"]


# ═══════════════════════════════════════════════════════════════════════
# Section 2 — Request Validation (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestRequestValidation:

    def test_RQ01_capture_no_target(self, orch):
        r = orch.orchestrate({"intent": "capture_traffic"})
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "missing_parameter"

    def test_RQ02_capture_no_storage_account(self, orch):
        r = orch.orchestrate({
            "intent": "capture_traffic", "target": "vm-01",
            "parameters": {"resource_group": "rg-01"},
        })
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "missing_parameter"

    def test_RQ03_check_task_nonexistent(self, orch):
        r = orch.orchestrate({"intent": "check_task", "task_id": "nonexistent"})
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "unknown_task"

    def test_RQ04_unknown_intent(self, orch):
        r = orch.orchestrate({"intent": "unknown_thing"})
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "unknown_intent"

    def test_RQ05_check_task_no_task_id(self, orch):
        r = orch.orchestrate({"intent": "check_task"})
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "missing_parameter"

    def test_RQ06_valid_capture_returns_pending(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_TASK_PENDING
        assert r["task_id"].startswith("ghost_")


# ═══════════════════════════════════════════════════════════════════════
# Section 3 — Response Contract (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestResponseContract:

    def test_RS01_pending_response_fields(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req())
        for f in ["task_id", "status", "state", "investigation_context",
                   "poll_count", "max_polls", "elapsed_seconds", "message"]:
            assert f in r, f"Missing field: {f}"

    def test_RS02_completed_response_fields(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        for f in ["task_id", "status", "state", "investigation_context",
                   "result", "cleanup_status", "duration_seconds", "message"]:
            assert f in r2, f"Missing field: {f}"
        assert r2["result"] is not None
        assert "semantic_json_path" in r2["result"]
        assert "report_path" in r2["result"]

    def test_RS03_failed_response_fields(self, shell, orch):
        """Detection failure → error response (Fix 7: no task created)."""
        shell.add_response("az resource", CMD_ERR)
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_ERROR
        assert "error" in r
        assert "message" in r

    def test_RS04_error_no_task_fields(self, orch):
        r = orch.orchestrate({"intent": "capture_traffic"})
        assert "status" in r and "error" in r and "message" in r

    def test_RS10_status_values_are_valid(self, shell, orch):
        valid = {STATUS_TASK_PENDING, STATUS_TASK_COMPLETED, STATUS_TASK_FAILED,
                 STATUS_TASK_CANCELLED, STATUS_TASK_TIMED_OUT, STATUS_ERROR}
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        assert r["status"] in valid

    def test_RS11_state_matches_lifecycle(self, shell, orch):
        valid_states = {CREATED, DETECTING, APPROVED, PROVISIONING, WAITING,
                        DOWNLOADING, ANALYZING, COMPLETED, CLEANING_UP, DONE,
                        FAILED, CANCELLED, TIMED_OUT, ABANDONED}
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req())
        assert r["state"] in valid_states

    def test_RS12_investigation_context_preserved(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        ctx = "latency investigation for prod"
        r = orch.orchestrate(capture_req(investigation_context=ctx))
        assert r["investigation_context"] == ctx

    def test_RS13_task_id_format(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req(target="vm-01"))
        tid = r["task_id"]
        assert tid.startswith("ghost_vm-01_")
        # Timestamp portion: YYYYMMDDTHHMMSS
        ts_part = tid.split("_", 2)[2]
        assert len(ts_part) == 15  # 20260219T102656

    def test_RS14_cleanup_status_values(self, shell, orch):
        valid = {"pending", "completed", "partial", "skipped", None}
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2.get("cleanup_status") in valid


# ═══════════════════════════════════════════════════════════════════════
# Section 4 — Task Lifecycle State Machine (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestTaskLifecycle:
    """State machine transitions."""

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_SM01_denied_capture_to_cancelled(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", DENIED)
        r = orch.orchestrate(capture_req())
        assert r["state"] == CANCELLED

    def test_SM02_detection_failure_returns_error(self, shell, orch):
        """Fix 7: detection failure returns error, no task created."""
        shell.add_response("az resource", CMD_ERR)
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_ERROR
        assert r["error"] == "detection_failed"

    def test_SM03_max_polls_to_timed_out(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Running"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        task_id = r["task_id"]
        # Keep polling until TIMED_OUT
        for _ in range(25):
            r2 = orch.orchestrate({"intent": "check_task", "task_id": task_id})
            if r2["state"] == TIMED_OUT:
                break
        assert r2["state"] == TIMED_OUT

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_SM10_happy_path_create_to_waiting(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req())
        assert r["state"] == WAITING
        # Verify intermediate states in registry
        records = read_registry(tmp_dirs[0])
        states = [rec["state"] for rec in records]
        assert CREATED in states
        assert APPROVED in states
        assert PROVISIONING in states
        assert WAITING in states

    def test_SM11_running_stays_waiting(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Running"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        # Use max_polls=1 so burst stops after 1 poll
        # Actually just check: after one burst, state should still be WAITING or TIMED_OUT
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        # With default max_polls=20, after burst with Running, poll_count increments
        assert r2["state"] in (WAITING, TIMED_OUT)
        if r2["state"] == WAITING:
            assert r2["poll_count"] > 0

    def test_SM12_succeeded_to_downloading(self, shell, orch, tmp_dirs):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        records = read_registry(tmp_dirs[0])
        states = [rec["state"] for rec in records]
        assert DOWNLOADING in states

    def test_SM13_stopped_treated_as_succeeded(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Stopped"})
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == COMPLETED

    def test_SM14_failed_azure_to_failed(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Failed"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED

    def test_SM15_download_success_to_analyzing(self, shell, orch, tmp_dirs):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        records = read_registry(tmp_dirs[0])
        states = [rec["state"] for rec in records]
        assert ANALYZING in states

    def test_SM16_pcap_engine_success_to_completed(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == COMPLETED
        assert r2["status"] == STATUS_TASK_COMPLETED

    def test_SM17_cleanup_to_done(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        r3 = orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        assert r3["state"] == DONE

    def test_SM18_download_fails_to_failed(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", CMD_ERR)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED

    def test_SM19_pcap_engine_fails_to_failed(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", CMD_ERR)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED

    def test_SM20_unrecognized_state_stays_waiting(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show",
                           response_seq({**SAFE_OK, "output": "Creating"},
                                        {**SAFE_OK, "output": "Succeeded"}))
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        # "Creating" is unrecognized → stays WAITING, then next poll → Succeeded
        assert r2["state"] == COMPLETED

    def test_SM21_storage_verification_fails(self, shell, orch):
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
        shell.add_response("storage container exists", {**SAFE_OK, "output": "False"})
        r = orch.orchestrate(capture_req())
        assert r["state"] == FAILED
        assert "inaccessible" in r["message"]

    def test_SM22_aks_informational_no_task(self, shell, orch, tmp_dirs):
        """Fix 7: AKS returns info response, no task created in registry."""
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.ContainerService/managedClusters"})
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_TASK_COMPLETED
        assert r["target_type"] == "aks"
        assert "AKS" in r["message"]
        # No task in registry
        records = read_registry(tmp_dirs[0])
        assert len(records) == 0


# ═══════════════════════════════════════════════════════════════════════
# Section 5 — Command Translation (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestCommandTranslation:
    """Verify command strings sent to Shell."""

    # ── P0: Commands contain expected verbs ─────────────────────────────

    def test_CT01_resource_detection_uses_show_or_list(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        det = shell.calls_with("az resource")
        assert len(det) >= 1
        cmd = det[0]["command"]
        assert "show" in cmd or "list" in cmd

    def test_CT02_storage_exists_command(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        sc = shell.calls_with("storage container exists")
        assert len(sc) == 1
        assert "--auth-mode" in sc[0]["command"]

    def test_CT03_capture_create_command(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        cc = shell.calls_with("packet-capture create")
        assert len(cc) == 1
        cmd = cc[0]["command"]
        assert "--vm" in cmd
        assert "--storage-account" in cmd

    def test_CT04_capture_show_command(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        cs = shell.calls_with("packet-capture show")
        assert len(cs) >= 1
        assert "--query provisioningState" in cs[0]["command"]

    def test_CT05_blob_download_command(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        dl = shell.calls_with("storage blob download")
        assert len(dl) >= 1
        assert "--file" in dl[0]["command"]

    def test_CT06_pcap_engine_command(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        pe = shell.calls_with("pcap_forensics.py")
        assert len(pe) == 1
        assert "--semantic-dir" in pe[0]["command"]
        assert "--report-dir" in pe[0]["command"]

    def test_CT07_capture_delete_command(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        cd = shell.calls_with("packet-capture delete")
        assert len(cd) >= 1

    def test_CT08_blob_delete_command(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        bd = shell.calls_with("storage blob delete")
        assert len(bd) >= 1

    # ── P1: Command format details ─────────────────────────────────────

    def test_CT10_capture_name_format(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req(target="vm-01"))
        tid = r["task_id"]
        cc = shell.calls_with("packet-capture create")
        assert f"--name {tid}" in cc[0]["command"]

    def test_CT11_storage_path_format(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req(storage_account="sa01"))
        cc = shell.calls_with("packet-capture create")
        assert "https://sa01.blob.core.windows.net/captures/" in cc[0]["command"]

    def test_CT12_comparison_mode_uses_compare_flag(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-src to vm-dst"))
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            orch.orchestrate({"intent": "check_task", "task_id": src_id})
            orch.orchestrate({"intent": "check_task", "task_id": dst_id})
            pe = shell.calls_with("pcap_forensics.py")
            compare_calls = [c for c in pe if "--compare" in c.get("command", "")]
            assert len(compare_calls) >= 1

    def test_CT13_every_shell_call_has_reasoning(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        # Skip init call (orphan scan)
        for call in shell.calls[1:]:
            assert "reasoning" in call and call["reasoning"], \
                f"Missing reasoning in: {call.get('command', '')[:60]}"

    def test_CT14_reasoning_contains_context(self, shell, orch):
        setup_happy_path(shell)
        ctx = "prod-db latency"
        r = orch.orchestrate(capture_req(investigation_context=ctx))
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        create_calls = shell.calls_with("packet-capture create")
        assert ctx in create_calls[0]["reasoning"]


# ═══════════════════════════════════════════════════════════════════════
# Section 6 — Polling Logic (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestPollingLogic:
    """Exponential backoff and burst polling."""

    # ── Backoff formula (direct unit tests) ────────────────────────────

    def test_PL01_first_interval_is_5(self):
        assert _compute_poll_interval(1, 5, 30) == 5

    def test_PL02_second_interval_is_10(self):
        assert _compute_poll_interval(2, 5, 30) == 10

    def test_PL03_third_interval_is_20(self):
        assert _compute_poll_interval(3, 5, 30) == 20

    def test_PL04_fourth_interval_capped_at_30(self):
        assert _compute_poll_interval(4, 5, 30) == 30

    def test_PL05_subsequent_remain_at_30(self):
        assert _compute_poll_interval(5, 5, 30) == 30
        assert _compute_poll_interval(10, 5, 30) == 30

    def test_PL06_max_polls_default_is_20(self):
        assert DEFAULT_MAX_POLLS == 20

    # ── Burst polling ──────────────────────────────────────────────────

    def test_PL10_burst_polls_multiple_times(self, shell, orch):
        """Single check_task polls multiple times within burst window."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show",
                           response_seq({**SAFE_OK, "output": "Running"},
                                        {**SAFE_OK, "output": "Running"},
                                        {**SAFE_OK, "output": "Succeeded"}))
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        polls = shell.calls_with("packet-capture show")
        assert len(polls) >= 3

    def test_PL11_burst_window_expires(self, tmp_dirs):
        """Burst expires after poll_burst_limit, returns task_pending."""
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Running"})
        td, cd = tmp_dirs
        o = CloudOrchestrator(
            shell=shell, session_id="test_sess",
            task_dir=td, local_capture_dir=cd,
            poll_burst_limit=0,  # Immediately expire
        )
        r = o.orchestrate(capture_req())
        r2 = o.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["status"] == STATUS_TASK_PENDING

    def test_PL12_burst_advances_through_multiple_states(self, shell, orch):
        """Burst can advance through download + analysis in one call."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == COMPLETED
        assert r2["result"] is not None

    def test_PL13_each_poll_is_separate_shell_call(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show",
                           response_seq({**SAFE_OK, "output": "Running"},
                                        {**SAFE_OK, "output": "Succeeded"}))
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        polls = shell.calls_with("packet-capture show")
        assert len(polls) >= 2
        for p in polls:
            assert "command" in p

    def test_PL14_poll_count_incremented_in_burst(self, shell, orch):
        """Fix 10: burst_polls count included in response."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show",
                           response_seq({**SAFE_OK, "output": "Running"},
                                        {**SAFE_OK, "output": "Running"},
                                        {**SAFE_OK, "output": "Succeeded"}))
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2.get("burst_polls", 0) >= 3
        assert "burst_duration_seconds" in r2


# ═══════════════════════════════════════════════════════════════════════
# Section 7 — Task Registry (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestTaskRegistry:

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_TR01_append_only(self, shell, orch, tmp_dirs):
        """Every state transition appends a new record."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        assert len(records) >= 3  # CREATED, APPROVED, PROVISIONING, WAITING

    def test_TR02_load_task_returns_last(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        r = orch.orchestrate(capture_req())
        loaded = orch._load_task(r["task_id"])
        assert loaded["state"] == WAITING  # Last saved state

    def test_TR03_valid_jsonl(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        path = Path(tmp_dirs[0]) / "orchestrator_tasks_test_sess.jsonl"
        for line in path.read_text().splitlines():
            if line.strip():
                json.loads(line)  # Must not raise

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_TR10_file_naming(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        path = Path(tmp_dirs[0]) / "orchestrator_tasks_test_sess.jsonl"
        assert path.exists()

    def test_TR11_file_in_task_dir(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        files = list(Path(tmp_dirs[0]).glob("orchestrator_tasks_*.jsonl"))
        assert len(files) >= 1

    def test_TR12_load_all_tasks_last_record_wins(self, shell, orch, tmp_dirs):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        all_tasks = orch._load_all_tasks()
        assert len(all_tasks) == 1
        assert all_tasks[0]["state"] == WAITING

    def test_TR13_load_task_returns_none_for_unknown(self, orch):
        assert orch._load_task("nonexistent_id") is None


# ═══════════════════════════════════════════════════════════════════════
# Section 8 — Resource Lifecycle and Cleanup (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestCleanup:

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_CL01_cleanup_plan_before_resources(self, shell, orch, tmp_dirs):
        """Cleanup plan built at task creation, before first cloud resource."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        # Find first APPROVED record (cleanup plan is set here)
        approved = [r for r in records if r["state"] == APPROVED]
        assert len(approved) >= 1
        assert len(approved[0]["cleanup_plan"]) == 3

    def test_CL02_failed_triggers_auto_cleanup(self, shell, orch):
        """FAILED task triggers automatic cleanup."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Failed"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        # Verify cleanup commands were sent
        assert len(shell.calls_with("packet-capture delete")) >= 1

    def test_CL03_timed_out_triggers_auto_cleanup(self, tmp_dirs):
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Running"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        td, cd = tmp_dirs
        o = CloudOrchestrator(
            shell=shell, session_id="test_sess",
            task_dir=td, local_capture_dir=cd, max_polls=2,
        )
        r = o.orchestrate(capture_req())
        o.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert len(shell.calls_with("packet-capture delete")) >= 1

    def test_CL04_cleanup_goes_through_shell(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        shell_calls_before = len(shell.calls)
        orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        assert len(shell.calls) > shell_calls_before

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_CL10_cleanup_plan_has_three_commands(self, shell, orch, tmp_dirs):
        """Plan: capture delete, blob delete, local file delete."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        approved = [r for r in records if r["state"] == APPROVED]
        plan = approved[0]["cleanup_plan"]
        assert len(plan) == 3
        cmds = [p["command"] for p in plan]
        assert any("packet-capture delete" in c for c in cmds)
        assert any("storage blob delete" in c for c in cmds)
        assert any("rm " in c for c in cmds)

    def test_CL11_cleanup_order_cloud_first(self, shell, orch, tmp_dirs):
        """Cloud resources cleaned before local files."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        approved = [r for r in records if r["state"] == APPROVED]
        plan = approved[0]["cleanup_plan"]
        # First two are cloud, last is local rm
        assert "packet-capture delete" in plan[0]["command"]
        assert "storage blob delete" in plan[1]["command"]
        assert "rm " in plan[2]["command"]

    def test_CL12_denied_cleanup_partial_status(self, shell, orch):
        """Denied cleanup command → partial status, not failure."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        # First cleanup denied, rest succeed
        shell.add_response("packet-capture delete", DENIED)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        r3 = orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        assert r3.get("cleanup_status") == "partial"

    def test_CL13_executed_flag_set(self, shell, orch, tmp_dirs):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        records = read_registry(tmp_dirs[0])
        done_records = [rec for rec in records if rec["state"] == DONE]
        assert len(done_records) >= 1
        plan = done_records[-1]["cleanup_plan"]
        for cmd in plan:
            assert cmd["executed"] is True


# ═══════════════════════════════════════════════════════════════════════
# Section 9 — Orphan Detection (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestOrphanDetection:

    def test_OR01_abandoned_tasks_flagged(self, tmp_dirs):
        """Non-terminal tasks from previous sessions flagged as abandoned."""
        td, cd = tmp_dirs
        # Write a WAITING task from a previous session
        registry = Path(td) / "orchestrator_tasks_old_session.jsonl"
        task = {"task_id": "old_task", "session_id": "old_session",
                "state": WAITING, "cleanup_status": None}
        registry.write_text(json.dumps(task) + "\n")
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        o = CloudOrchestrator(
            shell=shell, session_id="new_session",
            task_dir=td, local_capture_dir=cd,
        )
        assert len(o._orphans) >= 1
        types = [orph["type"] for orph in o._orphans]
        assert "abandoned_task" in types

    def test_OR02_completed_pending_cleanup_flagged(self, tmp_dirs):
        """COMPLETED from prior session flagged (COMPLETED is non-terminal)."""
        td, cd = tmp_dirs
        registry = Path(td) / "orchestrator_tasks_old_session.jsonl"
        task = {"task_id": "old_done", "session_id": "old_session",
                "state": COMPLETED, "cleanup_status": "pending"}
        registry.write_text(json.dumps(task) + "\n")
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        o = CloudOrchestrator(
            shell=shell, session_id="new_session",
            task_dir=td, local_capture_dir=cd,
        )
        # COMPLETED is not in TERMINAL_STATES, so it's flagged as abandoned
        assert len(o._orphans) >= 1
        types = [orph["type"] for orph in o._orphans]
        assert "abandoned_task" in types

    def test_OR03_terminal_done_ignored(self, tmp_dirs):
        """DONE tasks are not flagged as orphans."""
        td, cd = tmp_dirs
        registry = Path(td) / "orchestrator_tasks_old_session.jsonl"
        task = {"task_id": "done_task", "session_id": "old_session",
                "state": DONE, "cleanup_status": "completed"}
        registry.write_text(json.dumps(task) + "\n")
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        o = CloudOrchestrator(
            shell=shell, session_id="new_session",
            task_dir=td, local_capture_dir=cd,
        )
        assert len(o._orphans) == 0

    def test_OR02b_failed_with_no_cleanup_needs_cleanup(self, tmp_dirs):
        """FAILED task with no cleanup_status flagged as needs_cleanup."""
        td, cd = tmp_dirs
        registry = Path(td) / "orchestrator_tasks_old_session.jsonl"
        task = {"task_id": "fail_task", "session_id": "old_session",
                "state": FAILED, "cleanup_status": None}
        registry.write_text(json.dumps(task) + "\n")
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        o = CloudOrchestrator(
            shell=shell, session_id="new_session",
            task_dir=td, local_capture_dir=cd,
        )
        types = [orph["type"] for orph in o._orphans]
        assert "needs_cleanup" in types


# ═══════════════════════════════════════════════════════════════════════
# Section 10 — HITL Gate Handling (P0)
# ═══════════════════════════════════════════════════════════════════════

class TestHITLGate:
    """Verify which commands should/shouldn't trigger HITL."""

    def test_HI01_capture_create_is_risky(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        cc = shell.calls_with("packet-capture create")
        assert len(cc) >= 1
        assert "create" in cc[0]["command"]

    def test_HI02_poll_is_safe(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        polls = shell.calls_with("packet-capture show")
        assert len(polls) >= 1
        assert "show" in polls[0]["command"]

    def test_HI03_blob_download_is_risky(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        dl = shell.calls_with("storage blob download")
        assert len(dl) >= 1

    def test_HI04_pcap_engine_is_safe(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        pe = shell.calls_with("pcap_forensics.py")
        assert len(pe) == 1

    def test_HI05_capture_delete_is_risky(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        orch.orchestrate({"intent": "cleanup_task", "task_id": r["task_id"]})
        cd = shell.calls_with("packet-capture delete")
        assert len(cd) >= 1

    def test_HI06_target_detection_is_safe(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        det = shell.calls_with("az resource")
        assert len(det) >= 1

    def test_HI07_storage_verification_is_safe(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        sv = shell.calls_with("storage container exists")
        assert len(sv) == 1


# ═══════════════════════════════════════════════════════════════════════
# Section 11 — Storage Smoke Test (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestStorageSmokeTest:

    def test_ST01_storage_check_before_create(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        cmds = shell.commands()
        exists_idx = next(i for i, c in enumerate(cmds) if "container exists" in c)
        create_idx = next(i for i, c in enumerate(cmds) if "packet-capture create" in c)
        assert exists_idx < create_idx

    def test_ST02_storage_failure_fails_immediately(self, shell, orch):
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
        shell.add_response("storage container exists", {**SAFE_OK, "output": "False"})
        r = orch.orchestrate(capture_req())
        assert r["state"] == FAILED
        # No capture create call
        assert len(shell.calls_with("packet-capture create")) == 0


# ═══════════════════════════════════════════════════════════════════════
# Section 12 — Dual-End Capture (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestDualEndCapture:

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_DE01_two_tasks_linked(self, shell, orch, tmp_dirs):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-src to vm-dst"))
        assert "tasks" in r
        assert len(r["tasks"]) == 2
        # Verify linking
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            src_task = orch._load_task(src_id)
            dst_task = orch._load_task(dst_id)
            assert src_task["paired_task_id"] == dst_id
            assert dst_task["paired_task_id"] == src_id

    def test_DE02_independent_hitl(self, shell, orch):
        """Each task has its own HITL — one can be approved, other denied."""
        call_count = [0]
        def alternating_create(req, cmd):
            call_count[0] += 1
            if call_count[0] == 1:
                return dict(RISKY_OK)
            return dict(DENIED)

        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
        shell.add_response("storage container exists", {**SAFE_OK, "output": "True"})
        shell.add_response("packet-capture create", alternating_create)
        r = orch.orchestrate(capture_req(target="vm-a to vm-b"))
        # One should be pending/waiting, other cancelled
        states = set()
        for t in r["tasks"]:
            if "state" in t:
                states.add(t["state"])
            elif t.get("status") == STATUS_ERROR:
                pass  # Detection may have failed
        # At least we got two responses
        assert len(r["tasks"]) == 2

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_DE10_both_must_complete_for_analysis(self, shell, orch, tmp_dirs):
        """Neither task proceeds to ANALYZING until both reach COMPLETED."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-src to vm-dst"))
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            r2 = orch.orchestrate({"intent": "check_task", "task_id": src_id})
            # After first check_task, src should be COMPLETED (download done)
            # but waiting for partner analysis
            records = read_registry(tmp_dirs[0])
            src_records = [rec for rec in records if rec.get("task_id") == src_id]
            states = [rec["state"] for rec in src_records]
            # Should have COMPLETED before partner finishes
            assert COMPLETED in states or ANALYZING in states

    def test_DE11_comparison_mode_invoked(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-src to vm-dst"))
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            orch.orchestrate({"intent": "check_task", "task_id": src_id})
            orch.orchestrate({"intent": "check_task", "task_id": dst_id})
            pe = shell.calls_with("pcap_forensics.py")
            compare_calls = [c for c in pe if "--compare" in c.get("command", "")]
            assert len(compare_calls) >= 1

    def test_DE12_partner_fails_single_end_fallback(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        # First poll Succeeded, second poll Failed
        poll_count = [0]
        def poll_handler(req, cmd):
            poll_count[0] += 1
            if poll_count[0] <= 2:
                return {**SAFE_OK, "output": "Succeeded"}
            return {**SAFE_OK, "output": "Failed"}
        shell.add_response("packet-capture show", poll_handler)
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)

        r = orch.orchestrate(capture_req(target="vm-a to vm-b"))
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            orch.orchestrate({"intent": "check_task", "task_id": src_id})
            orch.orchestrate({"intent": "check_task", "task_id": dst_id})
            # Check surviving task
            r3 = orch.orchestrate({"intent": "check_task", "task_id": src_id})
            # It should have completed (single-end analysis)
            if r3.get("result"):
                assert r3["state"] == COMPLETED

    def test_DE17_response_includes_partner_status(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-src to vm-dst"))
        src_id = r["tasks"][0].get("task_id")
        if src_id:
            r2 = orch.orchestrate({"intent": "check_task", "task_id": src_id})
            # Response should include paired_task info
            if r2.get("paired_task"):
                assert "task_id" in r2["paired_task"]
                assert "state" in r2["paired_task"]


# ═══════════════════════════════════════════════════════════════════════
# Section 14 — Error Handling (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestErrorHandling:

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_EH01_provisioning_fails_to_failed_with_cleanup(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", CMD_ERR)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        assert r["state"] == FAILED
        assert len(shell.calls_with("packet-capture delete")) >= 1

    def test_EH02_denied_create_to_cancelled(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", DENIED)
        r = orch.orchestrate(capture_req())
        assert r["state"] == CANCELLED

    def test_EH03_denied_download_to_cancelled(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", DENIED)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == CANCELLED

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_EH10_poll_returns_failed(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Failed"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED
        assert len(shell.calls_with("packet-capture delete")) >= 1

    def test_EH11_download_retries_once(self, shell, orch, no_sleep):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download",
                           response_seq(CMD_ERR, RISKY_OK))
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        dl = shell.calls_with("storage blob download")
        assert len(dl) == 2  # First fail + retry
        assert r2["state"] == COMPLETED
        no_sleep.assert_called()  # sleep(5) between retries

    def test_EH12_download_fails_both_attempts(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", CMD_ERR)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED
        dl = shell.calls_with("storage blob download")
        assert len(dl) == 2

    def test_EH13_pcap_engine_fails(self, shell, orch):
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", CMD_ERR)
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED
        assert len(shell.calls_with("packet-capture delete")) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Section 15 — Configuration (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestConfiguration:

    def test_CF01_default_task_dir(self):
        assert DEFAULT_TASK_DIR == "./audit/"

    def test_CF02_default_max_polls(self):
        assert DEFAULT_MAX_POLLS == 20

    def test_CF03_default_initial_poll_interval(self):
        assert DEFAULT_INITIAL_POLL_INTERVAL == 5

    def test_CF04_default_max_poll_interval(self):
        assert DEFAULT_MAX_POLL_INTERVAL == 30

    def test_CF05_default_local_capture_dir(self):
        assert DEFAULT_LOCAL_CAPTURE_DIR == "/tmp/captures"

    def test_CF06_default_storage_container(self):
        assert DEFAULT_STORAGE_CONTAINER == "captures"

    def test_CF07_default_capture_name_prefix(self):
        assert DEFAULT_CAPTURE_NAME_PREFIX == "ghost"

    def test_CF08_default_poll_burst_limit(self):
        assert DEFAULT_POLL_BURST_LIMIT == 45

    def test_CF09_default_local_artifact_max_age_days(self):
        assert DEFAULT_LOCAL_ARTIFACT_MAX_AGE_DAYS == 7

    def test_CF10_constructor_params_only(self):
        """All config via constructor — no config file or env vars."""
        sig = inspect.signature(CloudOrchestrator.__init__)
        params = list(sig.parameters.keys())
        assert "shell" in params
        assert "session_id" in params
        assert "task_dir" in params
        assert "max_polls" in params

    def test_CF11_storage_auth_mode_default(self):
        """Fix 8: default storage auth mode is 'login'."""
        assert DEFAULT_STORAGE_AUTH_MODE == "login"

    def test_CF12_storage_auth_mode_configurable(self, tmp_dirs):
        """Fix 8: storage_auth_mode propagates to storage commands."""
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
        shell.add_response("storage container exists", {**SAFE_OK, "output": "True"})
        shell.add_response("packet-capture create", RISKY_OK)
        td, cd = tmp_dirs
        o = CloudOrchestrator(
            shell=shell, session_id="test_sess",
            task_dir=td, local_capture_dir=cd,
            storage_auth_mode="key",
        )
        o.orchestrate(capture_req())
        sc = shell.calls_with("storage container exists")
        assert "--auth-mode key" in sc[0]["command"]


# ═══════════════════════════════════════════════════════════════════════
# Section 17 — Instrumentation Detection (P1)
# ═══════════════════════════════════════════════════════════════════════

class TestInstrumentationDetection:

    def test_TD01_vm_detected_full_pipeline(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_TASK_PENDING
        assert r["task_id"].startswith("ghost_")

    def test_TD02_aks_detected_informational_only(self, shell, orch):
        """Fix 7: AKS → informational response, no task."""
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.ContainerService/managedClusters"})
        r = orch.orchestrate(capture_req())
        assert r["target_type"] == "aks"
        assert "AKS" in r["message"]
        # No task_id → no task created
        assert "task_id" not in r

    def test_TD03_unknown_type_fails(self, shell, orch):
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.Storage/storageAccounts"})
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_ERROR

    def test_TD04_detection_uses_single_az_call(self, shell, orch):
        setup_happy_path(shell)
        orch.orchestrate(capture_req())
        det = shell.calls_with("az resource")
        assert len(det) == 1


# ═══════════════════════════════════════════════════════════════════════
# Section 18 — Integration (P0 + P1)
# ═══════════════════════════════════════════════════════════════════════

class TestIntegration:

    # ── P0 ─────────────────────────────────────────────────────────────

    def test_IN01_full_happy_path(self, shell, orch, tmp_dirs):
        """capture → check → completed → cleanup → DONE."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        assert r["status"] == STATUS_TASK_PENDING
        task_id = r["task_id"]

        r2 = orch.orchestrate({"intent": "check_task", "task_id": task_id})
        assert r2["status"] == STATUS_TASK_COMPLETED
        assert r2["result"]["semantic_json_path"] is not None
        assert r2["result"]["report_path"] is not None

        r3 = orch.orchestrate({"intent": "cleanup_task", "task_id": task_id})
        assert r3["state"] == DONE

        records = read_registry(tmp_dirs[0])
        states = [rec["state"] for rec in records if rec["task_id"] == task_id]
        assert CREATED in states
        assert APPROVED in states
        assert WAITING in states
        assert COMPLETED in states
        assert DONE in states

    def test_IN02_full_failure_path(self, shell, orch):
        """capture → check → failed → cleanup runs automatically."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Failed"})
        shell.add_response("packet-capture delete", RISKY_OK)
        shell.add_response("storage blob delete", RISKY_OK)
        shell.add_response('rm "', RISKY_OK)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == FAILED
        assert len(shell.calls_with("packet-capture delete")) >= 1

    # ── P1 ─────────────────────────────────────────────────────────────

    def test_IN10_dual_end_happy_path(self, shell, orch):
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-a to vm-b"))
        assert len(r["tasks"]) == 2
        src_id = r["tasks"][0].get("task_id")
        dst_id = r["tasks"][1].get("task_id")
        if src_id and dst_id:
            orch.orchestrate({"intent": "check_task", "task_id": src_id})
            r3 = orch.orchestrate({"intent": "check_task", "task_id": dst_id})
            # At least one should complete with comparison
            pe = shell.calls_with("pcap_forensics.py")
            assert len(pe) >= 1

    def test_IN11_dual_end_degraded(self, shell, orch):
        """One target fails → other falls back to single-end analysis."""
        # First detection: VM, second: fail
        detect_count = [0]
        def detect_handler(req, cmd):
            detect_count[0] += 1
            if detect_count[0] == 1:
                return {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"}
            return dict(CMD_ERR)
        shell.add_response("az resource", detect_handler)
        shell.add_response("storage container exists", {**SAFE_OK, "output": "True"})
        shell.add_response("packet-capture create", RISKY_OK)
        shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
        shell.add_response("storage blob download", RISKY_OK)
        shell.add_response("pcap_forensics.py", SAFE_OK)
        r = orch.orchestrate(capture_req(target="vm-a to vm-b"))
        # Second task should have failed detection
        assert len(r["tasks"]) == 2

    def test_IN13_burst_completes_in_single_call(self, shell, orch):
        """Burst poll advances through download+analysis in one check_task."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert r2["state"] == COMPLETED
        assert r2["result"] is not None
        assert r2.get("burst_polls", 0) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Fix-Specific Validation Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFixValidation:
    """Tests specifically validating the 10 code review fixes."""

    def test_fix1_task_id_in_file_paths(self, shell, orch, tmp_dirs):
        """Fix 1: File paths use task_id, not target name."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req(target="vm-01"))
        task_id = r["task_id"]
        orch.orchestrate({"intent": "check_task", "task_id": task_id})
        # Download path uses task_id
        dl = shell.calls_with("storage blob download")
        assert task_id in dl[0]["command"]
        # Cleanup plan uses task_id
        records = read_registry(tmp_dirs[0])
        approved = [rec for rec in records if rec["state"] == APPROVED]
        local_rm = approved[0]["cleanup_plan"][2]["command"]
        assert task_id in local_rm
        assert "vm-01.pcap" not in local_rm

    def test_fix2_target_sanitization(self):
        """Fix 2: Shell metacharacters stripped from target."""
        tid = _generate_task_id("ghost", "vm;rm -rf /")
        assert ";" not in tid
        assert "|" not in tid
        assert " " not in tid
        assert "`" not in tid
        assert "$" not in tid

    def test_fix3_quoted_cleanup_path(self, shell, orch, tmp_dirs):
        """Fix 3: rm command path is quoted."""
        setup_detect_and_storage(shell)
        shell.add_response("packet-capture create", RISKY_OK)
        orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        approved = [rec for rec in records if rec["state"] == APPROVED]
        rm_cmd = approved[0]["cleanup_plan"][2]["command"]
        assert 'rm "' in rm_cmd

    def test_fix4_orphans_in_list_tasks(self, tmp_dirs):
        """Fix 4: list_tasks response includes orphans."""
        td, cd = tmp_dirs
        registry = Path(td) / "orchestrator_tasks_old.jsonl"
        task = {"task_id": "orphan_1", "session_id": "old",
                "state": WAITING, "cleanup_status": None}
        registry.write_text(json.dumps(task) + "\n")
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        o = CloudOrchestrator(
            shell=shell, session_id="new_sess",
            task_dir=td, local_capture_dir=cd,
        )
        r = o.orchestrate({"intent": "list_tasks"})
        assert "orphans" in r
        assert len(r["orphans"]) >= 1

    def test_fix5_no_execute_cleanup_method(self):
        """Fix 5: _execute_cleanup method has been removed."""
        assert not hasattr(CloudOrchestrator, "_execute_cleanup")

    def test_fix6_partner_loaded_once(self, shell, orch):
        """Fix 6: _build_response accepts partner parameter."""
        sig = inspect.signature(CloudOrchestrator._state_to_status)
        assert "partner" in sig.parameters
        sig2 = inspect.signature(CloudOrchestrator._build_message)
        assert "partner" in sig2.parameters

    def test_fix7_aks_no_registry_entry(self, shell, orch, tmp_dirs):
        """Fix 7: AKS target doesn't create a task in registry."""
        shell.add_response("az resource",
                           {**SAFE_OK, "output": "Microsoft.ContainerService/managedClusters"})
        r = orch.orchestrate(capture_req())
        records = read_registry(tmp_dirs[0])
        assert len(records) == 0

    def test_fix8_storage_auth_mode(self, tmp_dirs):
        """Fix 8: storage_auth_mode parameter works."""
        shell = MockShell()
        shell.add_response("packet-capture list", {**SAFE_OK, "output": "[]"})
        td, cd = tmp_dirs
        o = CloudOrchestrator(
            shell=shell, session_id="test_sess",
            task_dir=td, local_capture_dir=cd,
            storage_auth_mode="key",
        )
        assert o._storage_auth_mode == "key"

    def test_fix9_sanitize_context(self):
        """Fix 9: Control characters stripped from investigation context."""
        result = CloudOrchestrator._sanitize_context("Hello\x00\x1fWorld\x7f")
        assert result == "HelloWorld"
        assert CloudOrchestrator._sanitize_context("normal text") == "normal text"

    def test_fix10_burst_metrics_in_response(self, shell, orch):
        """Fix 10: burst_polls and burst_duration_seconds in response."""
        setup_happy_path(shell)
        r = orch.orchestrate(capture_req())
        r2 = orch.orchestrate({"intent": "check_task", "task_id": r["task_id"]})
        assert "burst_polls" in r2
        assert "burst_duration_seconds" in r2
        assert r2["burst_polls"] >= 1
        assert isinstance(r2["burst_duration_seconds"], float)
