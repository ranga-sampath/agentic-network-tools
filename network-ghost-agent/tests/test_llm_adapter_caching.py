"""test_llm_adapter_caching.py — Anthropic prompt caching request shape (IMP-05).

Asserts AnthropicAdapter.generate sends cache_control markers on the system
prompt block and on the last tool definition, and that response handling is
unchanged. The anthropic SDK is stubbed — no network calls.
"""

import sys
import types as _types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from google.genai import types  # stubbed by conftest


@pytest.fixture
def anthropic_stub(monkeypatch):
    """Install a stub anthropic module and return the MagicMock messages API."""
    messages = MagicMock()
    messages.create.return_value = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="ok")]
    )

    class _FakeAnthropic:
        def __init__(self, api_key):
            self.messages = messages

    mod = _types.ModuleType("anthropic")
    mod.Anthropic = _FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return messages


def _tools():
    S, T = types.Schema, types.Type
    return types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="tool_a", description="first",
            parameters=S(type=T.OBJECT, properties={
                "x": S(type=T.STRING, description="x")}, required=["x"]),
        ),
        types.FunctionDeclaration(
            name="tool_b", description="last",
            parameters=S(type=T.OBJECT, properties={
                "y": S(type=T.STRING, description="y")}, required=["y"]),
        ),
    ])


def _history():
    return [types.Content(role="user", parts=[types.Part(text="investigate X")])]


def test_system_prompt_sent_as_cached_block(anthropic_stub):
    from llm_adapter import AnthropicAdapter

    adapter = AnthropicAdapter(api_key="k", model="claude-test")
    adapter.generate(_history(), _tools(), "SYSTEM PROMPT")

    kwargs = anthropic_stub.create.call_args.kwargs
    system = kwargs["system"]
    assert isinstance(system, list) and len(system) == 1
    assert system[0]["type"] == "text"
    assert system[0]["text"] == "SYSTEM PROMPT"
    assert system[0]["cache_control"] == {"type": "ephemeral"}


def test_cache_control_on_last_tool_only(anthropic_stub):
    from llm_adapter import AnthropicAdapter

    adapter = AnthropicAdapter(api_key="k", model="claude-test")
    adapter.generate(_history(), _tools(), "SYSTEM PROMPT")

    tools = anthropic_stub.create.call_args.kwargs["tools"]
    assert [t["name"] for t in tools] == ["tool_a", "tool_b"]
    assert "cache_control" not in tools[0]
    assert tools[1]["cache_control"] == {"type": "ephemeral"}


def test_response_conversion_unchanged(anthropic_stub):
    from llm_adapter import AnthropicAdapter

    adapter = AnthropicAdapter(api_key="k", model="claude-test")
    response = adapter.generate(_history(), _tools(), "SYSTEM PROMPT")

    assert len(response.candidates) == 1
    parts = response.candidates[0].content.parts
    assert parts[0].text == "ok"
    assert parts[0].function_call is None


def test_tools_converted_once_and_cached_marker_stable(anthropic_stub):
    """Second generate() reuses the converted tools; the marker must not stack."""
    from llm_adapter import AnthropicAdapter

    adapter = AnthropicAdapter(api_key="k", model="claude-test")
    adapter.generate(_history(), _tools(), "SYSTEM PROMPT")
    adapter.generate(_history(), _tools(), "SYSTEM PROMPT")

    tools = anthropic_stub.create.call_args.kwargs["tools"]
    assert tools[-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in tools[0]
