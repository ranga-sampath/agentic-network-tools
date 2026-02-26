"""conftest.py — shared fixtures and mock infrastructure for ghost_agent tests.

sys.modules patching MUST happen before ghost_agent is imported.
We use real types.ModuleType stubs, not MagicMock, so attribute access works correctly.
"""

import json
import sys
import types as _types
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub classes for google.genai.types so attribute access works without
# installing the real google-genai package.
# ---------------------------------------------------------------------------


class _Schema:
    def __init__(self, type=None, properties=None, required=None,
                 description=None, items=None, enum=None):
        self.type = type
        self.properties = properties or {}
        self.required = required or []
        self.description = description
        self.items = items
        self.enum = enum


class _Type:
    STRING = "STRING"
    INTEGER = "INTEGER"
    OBJECT = "OBJECT"
    ARRAY = "ARRAY"
    BOOLEAN = "BOOLEAN"


class _FunctionDeclaration:
    def __init__(self, name, description=None, parameters=None):
        self.name = name
        self.description = description
        self.parameters = parameters


class _Tool:
    def __init__(self, function_declarations=None):
        self.function_declarations = function_declarations or []


class _GenerateContentConfig:
    def __init__(self, tools=None, system_instruction=None):
        self.tools = tools or []
        self.system_instruction = system_instruction


class _Content:
    def __init__(self, role, parts=None):
        self.role = role
        self.parts = parts or []


class _FunctionCall:
    def __init__(self, name, args=None):
        self.name = name
        self.args = args or {}


class _FunctionResponse:
    def __init__(self, name, response=None):
        self.name = name
        self.response = response or {}


class _Part:
    def __init__(self, text=None, function_call=None, function_response=None):
        self.text = text
        self.function_call = function_call
        self.function_response = function_response


# ---------------------------------------------------------------------------
# Stub google.genai types module
# ---------------------------------------------------------------------------

_types_module = _types.ModuleType("google.genai.types")
_types_module.Schema = _Schema
_types_module.Type = _Type
_types_module.FunctionDeclaration = _FunctionDeclaration
_types_module.Tool = _Tool
_types_module.GenerateContentConfig = _GenerateContentConfig
_types_module.Content = _Content
_types_module.FunctionCall = _FunctionCall
_types_module.FunctionResponse = _FunctionResponse
_types_module.Part = _Part

_genai_module = _types.ModuleType("google.genai")
_genai_module.types = _types_module

_google_module = _types.ModuleType("google")
_google_module.genai = _genai_module

_genai_client_cls = MagicMock(name="Client")
_genai_module.Client = _genai_client_cls

# ---------------------------------------------------------------------------
# Stub HitlDecision + SafeExecShell + CloudOrchestrator
# ---------------------------------------------------------------------------


@dataclass
class _HitlDecision:
    action: str
    modified_command: Optional[str] = None


class _SafeExecShell:
    """Minimal stub matching the SafeExecShell public API."""

    def __init__(self, session_id, audit_dir, hitl_callback=None,
                 timeout_seconds=120, anonymization_enabled=False, starting_sequence=0):
        self.session_id = session_id
        self.audit_dir = audit_dir
        self.hitl_callback = hitl_callback
        self.starting_sequence = starting_sequence
        self.execute = MagicMock(return_value={
            "status": "completed",
            "classification": "SAFE",
            "action": "auto_approved",
            "output": "ok",
            "stderr": "",
            "exit_code": 0,
            "error": None,
            "duration_seconds": 0.1,
            "output_metadata": {"truncation_applied": False},
            "audit_id": f"{session_id}_001",
        })


class _CloudOrchestrator:
    """Minimal stub matching the CloudOrchestrator public API."""

    def __init__(self, shell=None, session_id=None, task_dir=None, storage_auth_mode="login"):
        self.shell = shell
        self.session_id = session_id
        self.task_dir = task_dir
        self.orchestrate = MagicMock(return_value={
            "status": "task_completed",
            "tasks": [],
            "orphans": [],
        })


# Stub modules for safe_exec_shell and cloud_orchestrator
_safe_exec_shell_module = _types.ModuleType("safe_exec_shell")
_safe_exec_shell_module.SafeExecShell = _SafeExecShell
_safe_exec_shell_module.HitlDecision = _HitlDecision

_cloud_orchestrator_module = _types.ModuleType("cloud_orchestrator")
_cloud_orchestrator_module.CloudOrchestrator = _CloudOrchestrator

# Stub dotenv
_dotenv_module = _types.ModuleType("dotenv")
_dotenv_module.load_dotenv = lambda: None

# ---------------------------------------------------------------------------
# Patch sys.modules BEFORE any import of ghost_agent
# ---------------------------------------------------------------------------

sys.modules.setdefault("google", _google_module)
sys.modules.setdefault("google.genai", _genai_module)
sys.modules.setdefault("google.genai.types", _types_module)
sys.modules.setdefault("safe_exec_shell", _safe_exec_shell_module)
sys.modules.setdefault("cloud_orchestrator", _cloud_orchestrator_module)
sys.modules.setdefault("dotenv", _dotenv_module)

# Now import ghost_agent (after stubs are in place)
import importlib
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ghost_agent  # noqa: E402

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_state(tmp_path):
    """A minimal valid session state dict."""
    state = ghost_agent._new_session("gemini-2.0-flash", str(tmp_path / "audit"))
    return state


@pytest.fixture()
def shell_stub():
    """A fresh _SafeExecShell stub."""
    return _SafeExecShell(session_id="ghost_20240101_120000", audit_dir="./audit")


@pytest.fixture()
def orchestrator_stub(shell_stub):
    """A fresh _CloudOrchestrator stub."""
    return _CloudOrchestrator(shell=shell_stub, session_id="ghost_20240101_120000")


@pytest.fixture()
def session_file(tmp_path):
    """Return a path string inside tmp_path for session JSON."""
    return str(tmp_path / "ghost_session.json")


@pytest.fixture()
def saved_session(sample_state, session_file):
    """Save sample_state to session_file and return (state, path)."""
    ghost_agent.save_session(sample_state, session_file)
    return sample_state, session_file


# ---------------------------------------------------------------------------
# Helper to build a minimal Gemini mock response
# ---------------------------------------------------------------------------

def make_fc_response(tool_name, tool_args, finish_reason="STOP"):
    """Build a mock response with one function_call part."""
    fc = _FunctionCall(name=tool_name, args=tool_args)
    part = _Part(function_call=fc)
    content = _Content(role="model", parts=[part])
    candidate = MagicMock()
    candidate.content = content
    candidate.finish_reason = finish_reason
    response = MagicMock()
    response.candidates = [candidate]
    return response


def make_text_response(text, finish_reason="STOP"):
    """Build a mock response with one text part and no function_calls."""
    part = _Part(text=text)
    content = _Content(role="model", parts=[part])
    candidate = MagicMock()
    candidate.content = content
    candidate.finish_reason = finish_reason
    response = MagicMock()
    response.candidates = [candidate]
    return response


# Export stubs for use in tests
STUB_CONTENT = _Content
STUB_PART = _Part
STUB_FC = _FunctionCall
STUB_FR = _FunctionResponse
STUB_SAFE_EXEC_SHELL = _SafeExecShell
STUB_CLOUD_ORCHESTRATOR = _CloudOrchestrator
