"""LLM provider adapter for Ghost Agent.

Provides GeminiAdapter and AnthropicAdapter. Both accept Gemini-typed
conversation history (types.Content objects) and return a response that
duck-types as a Gemini generate_content response, so _run_loop in
ghost_agent.py needs no changes to its response-parsing code.

All LLM API calls are isolated to the adapter classes in this file.
ghost_agent.py retains Gemini SDK imports for tool schema construction
(_build_ghost_tools) and history manipulation (_reconstruct_history, main).
"""
from __future__ import annotations

import json

from google import genai
from google.genai import types

# anthropic is imported lazily inside AnthropicAdapter.__init__ so that
# running with --llm-provider gemini has no hard dependency on the SDK.


# ---------------------------------------------------------------------------
# Shared exception — lets _run_loop catch rate limits by type, not by
# parsing provider-specific error strings.
# ---------------------------------------------------------------------------

class LLMRateLimitError(Exception):
    """Raised by adapters when the provider returns a rate-limit response.

    _run_loop catches this to apply retry backoff without knowing which
    provider is in use. All other provider exceptions propagate unchanged.
    """


# ---------------------------------------------------------------------------
# Duck-typed response objects used by the Anthropic path
# These make an Anthropic response look like a Gemini response to _run_loop.
# ---------------------------------------------------------------------------

class _CallInfo:
    """Duck-types as Gemini FunctionCall.

    Attributes mirror what _run_loop reads:
        fc_part.function_call.name
        dict(fc_part.function_call.args)
    The extra _tool_use_id is stored so _gemini_history_to_anthropic can
    recover the Anthropic tool_use_id on the next generate() call without a
    name-keyed lookup (which fails when two calls share the same tool name).
    """
    __slots__ = ("name", "args", "_tool_use_id")

    def __init__(self, name: str, args: dict, tool_use_id: str) -> None:
        self.name         = name
        self.args         = args
        self._tool_use_id = tool_use_id


class _TextPart:
    """Duck-types as Gemini Part for text content."""
    __slots__ = ("text", "function_call", "function_response")

    def __init__(self, text: str) -> None:
        self.text              = text
        self.function_call     = None
        self.function_response = None


class _FcPart:
    """Duck-types as Gemini Part for function-call content."""
    __slots__ = ("text", "function_call", "function_response")

    def __init__(self, call_info: _CallInfo) -> None:
        self.text              = None
        self.function_call     = call_info
        self.function_response = None


class _AnthropicContent:
    """Duck-types as Gemini types.Content.

    Used for model turns returned by AnthropicAdapter.generate().
    _run_loop appends this to history; on the next generate() call,
    _gemini_history_to_anthropic handles both real types.Content objects
    and _AnthropicContent objects uniformly via duck-typed attribute access.
    """
    __slots__ = ("role", "parts")

    def __init__(self, role: str, parts: list) -> None:
        self.role  = role
        self.parts = parts


class _AnthropicCandidate:
    __slots__ = ("content",)

    def __init__(self, content: _AnthropicContent) -> None:
        self.content = content


class _AnthropicResponse:
    """Duck-types as Gemini generate_content response for _run_loop.

    .candidates is always a one-element list (Anthropic raises exceptions
    rather than returning empty content, so is_empty logic in _run_loop
    never fires for this path).
    """
    __slots__ = ("candidates",)

    def __init__(self, candidates: list) -> None:
        self.candidates = candidates


# ---------------------------------------------------------------------------
# Schema and tool-spec conversion: Gemini types.Tool → Anthropic tools list
# ---------------------------------------------------------------------------

_GEMINI_TYPE_TO_JSON: dict[str, str] = {
    "STRING":  "string",
    "INTEGER": "integer",
    "BOOLEAN": "boolean",
    "OBJECT":  "object",
    "ARRAY":   "array",
    "NUMBER":  "number",
}


def _schema_to_json_schema(schema) -> dict:
    """Recursively convert a Gemini types.Schema to a JSON Schema dict."""
    if schema is None:
        return {"type": "object", "properties": {}}

    type_name = schema.type.name if hasattr(schema.type, "name") else str(schema.type)
    json_type = _GEMINI_TYPE_TO_JSON.get(type_name)
    if json_type is None:
        raise ValueError(f"Unrecognised Gemini schema type: {type_name!r}")
    result: dict = {"type": json_type}

    if schema.description:
        result["description"] = schema.description
    if schema.properties:
        result["properties"] = {
            k: _schema_to_json_schema(v) for k, v in schema.properties.items()
        }
    if schema.required:
        result["required"] = list(schema.required)
    if schema.enum:
        result["enum"] = list(schema.enum)
    if schema.items:
        result["items"] = _schema_to_json_schema(schema.items)

    return result


def _gemini_tools_to_anthropic(gemini_tool: types.Tool) -> list[dict]:
    """Convert a Gemini types.Tool to an Anthropic tools list."""
    return [
        {
            "name":         fd.name,
            "description":  fd.description or "",
            "input_schema": _schema_to_json_schema(fd.parameters),
        }
        for fd in gemini_tool.function_declarations
    ]


# ---------------------------------------------------------------------------
# History conversion: Gemini-typed history → Anthropic messages list
# ---------------------------------------------------------------------------

def _gemini_history_to_anthropic(history: list) -> list[dict]:
    """Convert a Gemini-typed conversation history to Anthropic messages format.

    Handles both real types.Content objects (from Gemini path, _reconstruct_history,
    and main() user-intent appends) and _AnthropicContent objects (from prior
    Anthropic response turns appended by _run_loop).

    Tool-call IDs are recovered from _CallInfo._tool_use_id when available
    (preserving the Anthropic tool_use_id from prior responses), or synthesised
    sequentially otherwise. Correlation between tool calls and tool results uses
    positional matching within each consecutive model/user turn pair.
    """
    messages: list[dict] = []
    _id_counter = 0

    def _next_id() -> str:
        nonlocal _id_counter
        _id_counter += 1
        return f"tc_{_id_counter:04d}"

    # IDs assigned to function calls in the most recent model turn; used to
    # supply matching tool_use_id values in the immediately following user turn.
    pending_tool_ids: list[str] = []

    for turn in history:
        role  = turn.role
        parts = turn.parts

        text_parts = [p for p in parts if getattr(p, "text", None)]
        fc_parts   = [p for p in parts if getattr(p, "function_call", None)]
        fr_parts   = [p for p in parts if getattr(p, "function_response", None)]

        if role == "model":
            if fc_parts:
                content_blocks: list[dict] = []

                if text_parts:
                    txt = " ".join(p.text for p in text_parts).strip()
                    if txt:
                        content_blocks.append({"type": "text", "text": txt})

                new_pending: list[str] = []
                for fc_part in fc_parts:
                    fc  = fc_part.function_call
                    tid = getattr(fc, "_tool_use_id", None) or _next_id()
                    new_pending.append(tid)
                    content_blocks.append({
                        "type":  "tool_use",
                        "id":    tid,
                        "name":  fc.name,
                        "input": dict(fc.args),
                    })

                pending_tool_ids = new_pending
                messages.append({"role": "assistant", "content": content_blocks})

            elif text_parts:
                txt = " ".join(p.text for p in text_parts).strip()
                if txt:
                    messages.append({"role": "assistant", "content": txt})
                pending_tool_ids = []

        elif role == "user":
            if fr_parts:
                tool_results: list[dict] = []
                for i, fr_part in enumerate(fr_parts):
                    # Positional match: response i corresponds to function call i
                    # in the preceding model turn.
                    tid = pending_tool_ids[i] if i < len(pending_tool_ids) else _next_id()
                    response_dict = dict(fr_part.function_response.response)
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": tid,
                        "content":     json.dumps(response_dict),
                    })
                messages.append({"role": "user", "content": tool_results})
                pending_tool_ids = []

            elif text_parts:
                txt = " ".join(p.text for p in text_parts).strip()
                if txt:
                    messages.append({"role": "user", "content": txt})

    return messages


# ---------------------------------------------------------------------------
# Anthropic response → duck-typed Gemini response
# ---------------------------------------------------------------------------

def _anthropic_to_gemini_response(response) -> _AnthropicResponse:
    """Convert an Anthropic Message to a duck-typed Gemini response.

    Each text block becomes a _TextPart; each tool_use block becomes a
    _FcPart containing a _CallInfo that stores the Anthropic tool_use_id.
    The _AnthropicContent is appended to history by _run_loop and later
    re-converted by _gemini_history_to_anthropic on the next generate() call.
    """
    parts: list = []
    for block in response.content:
        if block.type == "text" and block.text:
            parts.append(_TextPart(text=block.text))
        elif block.type == "tool_use":
            call_info = _CallInfo(
                name=block.name,
                args=block.input,
                tool_use_id=block.id,
            )
            parts.append(_FcPart(call_info=call_info))

    content = _AnthropicContent(role="model", parts=parts)
    return _AnthropicResponse(candidates=[_AnthropicCandidate(content=content)])


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

class GeminiAdapter:
    """Thin wrapper around google-genai. Accepts and returns Gemini-native types."""

    def __init__(self, api_key: str, model: str) -> None:
        self._client = genai.Client(api_key=api_key)
        self._model  = model

    def generate(self, history: list, tools: types.Tool, system_prompt: str):
        """Call generate_content and return the real Gemini response object.

        Raises LLMRateLimitError on 429 / RESOURCE_EXHAUSTED so _run_loop
        can apply backoff without knowing which provider is in use.
        All other exceptions propagate unchanged.
        """
        config_kwargs: dict = dict(
            tools              = [tools],
            system_instruction = system_prompt,
        )
        # Gemini 2.5+ extended thinking causes MALFORMED_FUNCTION_CALL in
        # tool-calling loops. Disable it when the SDK supports the config.
        if hasattr(types, "ThinkingConfig"):
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        try:
            return self._client.models.generate_content(
                model    = self._model,
                contents = history,
                config   = types.GenerateContentConfig(**config_kwargs),
            )
        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                raise LLMRateLimitError(str(e)) from e
            raise


class AnthropicAdapter:
    """Adapter for Anthropic Claude that accepts Gemini-typed history.

    On each generate() call:
      1. Converts Gemini-typed history → Anthropic messages list.
      2. Calls anthropic.Anthropic.messages.create.
      3. Returns a duck-typed _AnthropicResponse compatible with _run_loop.
    """

    _MAX_TOKENS = 8192

    def __init__(self, api_key: str, model: str) -> None:
        import anthropic  # lazy import — no hard dep when running Gemini path
        self._client          = anthropic.Anthropic(api_key=api_key)
        self._model           = model
        self._anthropic_tools: list[dict] | None = None

    def generate(
        self, history: list, tools: types.Tool, system_prompt: str
    ) -> _AnthropicResponse:
        """Convert history, call Anthropic API, return duck-typed response.

        Raises LLMRateLimitError on rate_limit_error / overloaded_error so
        _run_loop can apply backoff without knowing which provider is in use.
        All other exceptions propagate unchanged.
        """
        if self._anthropic_tools is None:
            self._anthropic_tools = _gemini_tools_to_anthropic(tools)
            # Prompt caching: the tool schemas and system prompt are identical
            # on every turn of the investigation loop. A cache_control marker
            # on the last tool caches the full tool block; one on the system
            # block caches the system prompt. Cache reads cost ~10% of input
            # tokens — a large saving over a 50-turn loop.
            if self._anthropic_tools:
                self._anthropic_tools[-1]["cache_control"] = {"type": "ephemeral"}

        messages = _gemini_history_to_anthropic(history)
        system_blocks = [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
        try:
            response = self._client.messages.create(
                model      = self._model,
                messages   = messages,
                tools      = self._anthropic_tools,
                system     = system_blocks,
                max_tokens = self._MAX_TOKENS,
            )
        except Exception as e:
            err_str = str(e)
            if "rate_limit_error" in err_str or "overloaded_error" in err_str:
                raise LLMRateLimitError(str(e)) from e
            raise
        return _anthropic_to_gemini_response(response)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_adapter(
    provider: str, api_key: str, model: str
) -> GeminiAdapter | AnthropicAdapter:
    """Return the adapter for the requested provider.

    Raises ValueError for unknown providers — fail closed, no silent permit.
    """
    if provider == "gemini":
        return GeminiAdapter(api_key=api_key, model=model)
    if provider == "anthropic":
        return AnthropicAdapter(api_key=api_key, model=model)
    raise ValueError(
        f"Unknown LLM provider: {provider!r}. Must be 'gemini' or 'anthropic'."
    )
