"""Shared test helpers: MockShell, response templates, request builders.

Importable by both conftest.py and test modules.
"""
import json
import os
import sys
from pathlib import Path

# Make cloud_orchestrator importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloud_orchestrator import CloudOrchestrator  # noqa: F401 (re-export)


# ── Response templates ────────────────────────────────────────────────

SAFE_OK = {"status": "completed", "exit_code": 0, "output": ""}
RISKY_OK = {"status": "completed", "exit_code": 0, "output": ""}
DENIED = {"status": "denied"}
CMD_ERR = {"status": "completed", "exit_code": 1, "stderr": "command failed"}
NOT_FOUND_ERR = {"status": "completed", "exit_code": 1, "stderr": "Resource not found"}


# ── MockShell ─────────────────────────────────────────────────────────

class MockShell:
    """Mock Shell: records all calls, returns pattern-matched responses."""

    def __init__(self):
        self.calls: list = []
        self._patterns: list = []
        self._seq = 0

    def add_response(self, pattern: str, response):
        """Register pattern -> response. First match wins."""
        self._patterns.append((pattern, response))

    def execute(self, request: dict) -> dict:
        self.calls.append(dict(request))
        cmd = request.get("command", "")
        for pat, resp in self._patterns:
            if pat in cmd:
                r = resp(request, cmd) if callable(resp) else dict(resp)
                self._seq += 1
                r.setdefault("audit_id", f"aud_{self._seq:04d}")
                return r
        self._seq += 1
        return {**SAFE_OK, "audit_id": f"aud_{self._seq:04d}"}

    def commands(self) -> list:
        return [c["command"] for c in self.calls]

    def reasonings(self) -> list:
        return [c.get("reasoning", "") for c in self.calls]

    def calls_with(self, pat: str) -> list:
        return [c for c in self.calls if pat in c.get("command", "")]


def response_seq(*responses):
    """Callable returning successive responses; repeats the last forever."""
    state = {"i": 0}

    def fn(req, cmd):
        i = min(state["i"], len(responses) - 1)
        state["i"] += 1
        return dict(responses[i])

    return fn


# ── Request helpers ───────────────────────────────────────────────────

def capture_req(target="vm-01", storage_account="sa01", resource_group="rg-01",
                investigation_context="investigate latency", **extra):
    """Build a valid capture_traffic request."""
    return {
        "intent": "capture_traffic",
        "target": target,
        "parameters": {
            "storage_account": storage_account,
            "resource_group": resource_group,
            **extra,
        },
        "investigation_context": investigation_context,
    }


# ── Shell setup helpers ──────────────────────────────────────────────

def setup_happy_path(shell):
    """Configure shell for full VM happy-path lifecycle."""
    shell.add_response("az resource", {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
    shell.add_response("storage container exists", {**SAFE_OK, "output": "True"})
    shell.add_response("packet-capture create", RISKY_OK)
    shell.add_response("packet-capture show", {**SAFE_OK, "output": "Succeeded"})
    shell.add_response("storage blob download", RISKY_OK)
    shell.add_response("pcap_forensics.py", SAFE_OK)
    shell.add_response("packet-capture delete", RISKY_OK)
    shell.add_response("storage blob delete", RISKY_OK)
    shell.add_response('rm "', RISKY_OK)


def setup_detect_and_storage(shell):
    """Configure shell for VM detection + storage verification only."""
    shell.add_response("az resource", {**SAFE_OK, "output": "Microsoft.Compute/virtualMachines"})
    shell.add_response("storage container exists", {**SAFE_OK, "output": "True"})


# ── Registry reader ──────────────────────────────────────────────────

def read_registry(task_dir, session_id="test_sess"):
    """Read all JSONL records from the task registry file."""
    path = Path(task_dir) / f"orchestrator_tasks_{session_id}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
