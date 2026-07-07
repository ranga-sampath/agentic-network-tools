"""test_resume_provider_model.py — resume provider/model resolution (BUG-02).

A resumed session must continue on the llm_provider and model stored in the
session file unless the operator explicitly overrides them on the CLI, in
which case a warning is produced and the session record is updated.
"""

from ghost_agent import DEFAULT_MODEL, _new_session, _resolve_provider_and_model


def _anthropic_session():
    return _new_session("claude-sonnet-5", "./audit", llm_provider="anthropic")


def test_resume_uses_stored_provider_and_model_when_no_flags():
    state = _anthropic_session()

    provider, model, warnings = _resolve_provider_and_model(None, None, state)

    assert provider == "anthropic"
    assert model == "claude-sonnet-5"
    assert warnings == []


def test_resume_explicit_flags_override_with_warning():
    state = _anthropic_session()

    provider, model, warnings = _resolve_provider_and_model(
        "gemini", "gemini-2.0-flash", state)

    assert provider == "gemini"
    assert model == "gemini-2.0-flash"
    assert len(warnings) == 2
    assert any("provider" in w for w in warnings)
    assert any("model" in w for w in warnings)
    # Session record must stay truthful about what actually runs
    assert state["llm_provider"] == "gemini"
    assert state["model"] == "gemini-2.0-flash"


def test_resume_matching_flags_produce_no_warning():
    state = _anthropic_session()

    provider, model, warnings = _resolve_provider_and_model(
        "anthropic", "claude-sonnet-5", state)

    assert (provider, model) == ("anthropic", "claude-sonnet-5")
    assert warnings == []


def test_resume_updates_state_in_place():
    state = _anthropic_session()

    _resolve_provider_and_model(None, None, state)

    assert state["llm_provider"] == "anthropic"
    assert state["model"] == "claude-sonnet-5"


def test_fresh_session_defaults_when_no_flags():
    provider, model, warnings = _resolve_provider_and_model(None, None, None)

    assert provider == "gemini"
    assert model == DEFAULT_MODEL
    assert warnings == []


def test_fresh_session_flags_win_without_warning():
    provider, model, warnings = _resolve_provider_and_model(
        "anthropic", "claude-sonnet-5", None)

    assert (provider, model) == ("anthropic", "claude-sonnet-5")
    assert warnings == []


def test_legacy_session_without_stored_fields_falls_back_to_defaults():
    """Sessions written before llm_provider existed must not crash resume."""
    state = _new_session("gemini-2.0-flash", "./audit")
    state["llm_provider"] = None
    state["model"] = None

    provider, model, warnings = _resolve_provider_and_model(None, None, state)

    assert provider == "gemini"
    assert model == DEFAULT_MODEL
    assert warnings == []
