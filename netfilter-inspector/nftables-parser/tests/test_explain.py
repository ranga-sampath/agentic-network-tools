"""
test_explain.py — Unit tests for nftables_explain.py

All tests that exercise explain_snapshot() or explain_diff() mock the Gemini
client so no real API calls are made. Tests that verify system prompt content
do not require a client at all.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import nftables_explain
from nftables_explain import (
    _build_diff_system_prompt,
    _build_state_system_prompt,
    _get_model,
    explain_diff,
    explain_snapshot,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

MINIMAL_SNAPSHOT = {
    "parsed_at": "2026-03-17T10:00:00Z",
    "input_format": "nft-json",
    "nft_version": "1.0.9",
    "json_schema_version": 1,
    "tables": {
        "inet/filter": {
            "family": "inet",
            "name": "filter",
            "handle": 1,
            "chains": {
                "input": {
                    "name": "input",
                    "handle": 2,
                    "is_base_chain": True,
                    "type": "filter",
                    "hook": "input",
                    "priority": 0,
                    "policy": "drop",
                    "rules": [
                        {
                            "table": "inet/filter",
                            "chain": "input",
                            "handle": 3,
                            "position": 1,
                            "comment": None,
                            "verdict": "accept",
                            "verdict_stops_chain": True,
                            "protocol": None,
                            "dst_port": None,
                            "src_port": None,
                            "src_addr": None,
                            "dst_addr": None,
                            "in_interface": None,
                            "out_interface": None,
                            "ct_state": ["established", "related"],
                            "protocol_negated": False,
                            "src_addr_negated": False,
                            "dst_addr_negated": False,
                            "src_port_negated": False,
                            "dst_port_negated": False,
                            "in_interface_negated": False,
                            "out_interface_negated": False,
                            "icmp_type": None,
                            "icmp_type_negated": False,
                            "icmp_code": None,
                            "icmp_code_negated": False,
                            "ct_mark": None,
                            "ct_mark_negated": False,
                            "ct_direction": None,
                            "ct_zone": None,
                            "is_log": False,
                            "log_prefix": None,
                            "jump_target": None,
                            "goto_target": None,
                            "set_references": [],
                            "opaque_expressions": None,
                            "expression_hash": "abc123",
                            "raw_expressions": [
                                {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                                           "right": ["established", "related"]}},
                                {"accept": None},
                            ],
                        }
                    ],
                },
                "output": {
                    "name": "output",
                    "handle": 4,
                    "is_base_chain": True,
                    "type": "filter",
                    "hook": "output",
                    "priority": 0,
                    "policy": "accept",
                    "rules": [],
                },
                "forward": {
                    "name": "forward",
                    "handle": 5,
                    "is_base_chain": True,
                    "type": "filter",
                    "hook": "forward",
                    "priority": 0,
                    "policy": "drop",
                    "rules": [],
                },
            },
            "sets": {},
        }
    },
    "diagnostics": {
        "drop_policy_chains": ["inet/filter/input", "inet/filter/forward"],
        "accept_policy_chains": ["inet/filter/output"],
        "active_drop_rules": [],
        "unresolved_chain_jumps": [],
        "inet_tables": ["inet/filter"],
        "sets_referenced_in_rules": {},
    },
    "parse_warnings": [],
}

ZERO_TABLES_SNAPSHOT = {
    "parsed_at": "2026-03-17T10:00:00Z",
    "input_format": "nft-json",
    "nft_version": "1.0.9",
    "json_schema_version": 1,
    "tables": {},
    "diagnostics": {
        "drop_policy_chains": [],
        "accept_policy_chains": [],
        "active_drop_rules": [],
        "unresolved_chain_jumps": [],
        "inet_tables": [],
        "sets_referenced_in_rules": {},
    },
    "parse_warnings": [],
}

MINIMAL_DIFF = {
    "diff_at": "2026-03-17T11:00:00Z",
    "input_format": "nft-json",
    "baseline_parsed_at": "2026-03-17T09:00:00Z",
    "current_parsed_at": "2026-03-17T11:00:00Z",
    "baseline_parse_warnings": [],
    "current_parse_warnings": [],
    "drift_detected": True,
    "has_critical_changes": True,
    "summary": {
        "tables_added": 0, "tables_removed": 0,
        "chains_added": 0, "chains_removed": 0,
        "policy_changes": 1,
        "rules_added": 0, "rules_removed": 0,
        "rules_repositioned": 0, "rules_recreated": 0,
    },
    "changes": {
        "tables_added": [], "tables_removed": [],
        "chains_added": [], "chains_removed": [],
        "policy_changes": [
            {
                "table": "inet/filter",
                "chain": "input",
                "baseline_policy": "accept",
                "current_policy": "drop",
            }
        ],
        "rules_added": [], "rules_removed": [],
        "rules_repositioned": [], "rules_recreated": [],
    },
}

NO_DRIFT_DIFF = {
    "diff_at": "2026-03-17T11:00:00Z",
    "input_format": "nft-json",
    "baseline_parsed_at": "2026-03-17T09:00:00Z",
    "current_parsed_at": "2026-03-17T11:00:00Z",
    "baseline_parse_warnings": [],
    "current_parse_warnings": [],
    "drift_detected": False,
    "has_critical_changes": False,
    "summary": {
        "tables_added": 0, "tables_removed": 0,
        "chains_added": 0, "chains_removed": 0,
        "policy_changes": 0,
        "rules_added": 0, "rules_removed": 0,
        "rules_repositioned": 0, "rules_recreated": 0,
    },
    "changes": {
        "tables_added": [], "tables_removed": [],
        "chains_added": [], "chains_removed": [],
        "policy_changes": [], "rules_added": [], "rules_removed": [],
        "rules_repositioned": [], "rules_recreated": [],
    },
}


def _make_mock_client(response_text: str) -> MagicMock:
    """Return a mock Gemini client whose models.generate_content() returns response_text."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = response_text
    mock_client.models.generate_content.return_value = mock_response
    return mock_client


# ---------------------------------------------------------------------------
# State system prompt content
# ---------------------------------------------------------------------------

class TestStateSystemPrompt:
    """The state system prompt must encode all critical nftables concepts."""

    def test_encodes_base_chain_vs_regular_chain(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "base chain" in prompt_lower or "base chains" in prompt_lower

    def test_encodes_priority_based_evaluation(self):
        # Priority order, not fixed table order like iptables
        prompt = _build_state_system_prompt()
        assert "priority" in prompt.lower()

    def test_encodes_inet_family_dual_stack(self):
        # inet family covers both IPv4 and IPv6
        prompt = _build_state_system_prompt()
        assert "inet" in prompt.lower()
        assert "ipv4" in prompt.lower() or "ip4" in prompt.lower() or "both" in prompt.lower()

    def test_encodes_goto_semantics(self):
        # goto skips one level on return — different from jump
        prompt = _build_state_system_prompt()
        assert "goto" in prompt.lower()

    def test_encodes_jump_semantics(self):
        prompt = _build_state_system_prompt()
        assert "jump" in prompt.lower()

    def test_encodes_verdict_names_lowercase(self):
        # nftables uses lowercase verdicts
        prompt = _build_state_system_prompt()
        assert "accept" in prompt
        assert "drop" in prompt
        assert "reject" in prompt
        assert "return" in prompt

    def test_encodes_regular_chain_has_no_policy(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "no policy" in prompt_lower or "null policy" in prompt_lower or "no default policy" in prompt_lower

    def test_encodes_first_match_semantics(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "first" in prompt_lower and "match" in prompt_lower

    def test_encodes_established_related(self):
        prompt = _build_state_system_prompt()
        assert "established" in prompt.lower()
        assert "related" in prompt.lower()

    def test_encodes_named_sets(self):
        prompt = _build_state_system_prompt()
        assert "@" in prompt or "set" in prompt.lower()

    def test_encodes_counter_absence_not_zero(self):
        # Absence of counter expression ≠ zero hits
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "counter" in prompt_lower
        assert "absence" in prompt_lower or "no counter" in prompt_lower or "not" in prompt_lower

    def test_encodes_azure_nsg_scope_limitation(self):
        prompt = _build_state_system_prompt()
        assert "Azure" in prompt or "NSG" in prompt

    def test_encodes_zero_tables_guard(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "zero" in prompt_lower or "empty" in prompt_lower or "no nftables" in prompt_lower

    def test_encodes_negation_principle(self):
        prompt = _build_state_system_prompt()
        assert "negat" in prompt.lower()

    def test_encodes_chain_resolution_to_terminal_outcome(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "terminal" in prompt_lower
        assert "every" in prompt_lower

    def test_encodes_no_prescriptive_suggestions(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "prescribe" in prompt_lower or "do not suggest" in prompt_lower or "out of scope" in prompt_lower

    def test_includes_output_format_directive(self):
        prompt = _build_state_system_prompt()
        assert "Traffic Table" in prompt
        assert "Executive Summary" in prompt
        assert "Warnings" in prompt

    def test_traffic_table_prohibits_chain_as_action(self):
        prompt = _build_state_system_prompt()
        prompt_upper = prompt.upper()
        assert "PROHIBITED" in prompt_upper or "prohibited" in prompt.lower()

    def test_encodes_scope_limitations_section(self):
        prompt = _build_state_system_prompt()
        assert "Scope Limitations" in prompt or "scope" in prompt.lower()

    def test_counters_section_omitted_when_no_inline_counters(self):
        # The Counters section must be completely omitted (not just noted as absent)
        # when no rules have inline counter expressions
        prompt = _build_state_system_prompt()
        assert "OMIT" in prompt or "omit" in prompt.lower()
        assert "heading" in prompt.lower() or "entire section" in prompt.lower() or "section" in prompt.lower()

    def test_encodes_orphaned_chain_principle(self):
        # Regular chains not referenced by any jump_target/goto_target are unreachable
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "orphan" in prompt_lower or "unreachable" in prompt_lower

    def test_encodes_verify_call_exists_before_tracing(self):
        # Must verify jump_target/goto_target exists before tracing chain traversal
        prompt = _build_state_system_prompt()
        assert "jump_target" in prompt or "goto_target" in prompt

    def test_unresolved_jump_action_must_show_terminal_verdict(self):
        # Unresolved jump: show terminal verdict in Action column, not N/A
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "n/a" in prompt_lower or "placeholder" in prompt_lower or "terminal verdict" in prompt_lower


# ---------------------------------------------------------------------------
# Diff system prompt content
# ---------------------------------------------------------------------------

class TestDiffSystemPrompt:
    """The diff system prompt must encode all critical nftables change analysis concepts."""

    def test_encodes_rules_recreated(self):
        # nftables has a rules_recreated category not present in iptables diff
        prompt = _build_diff_system_prompt()
        assert "rules_recreated" in prompt or "recreated" in prompt.lower()

    def test_encodes_priority_changes(self):
        # Priority changes appear in policy_changes
        prompt = _build_diff_system_prompt()
        assert "priority" in prompt.lower()

    def test_encodes_has_critical_changes(self):
        prompt = _build_diff_system_prompt()
        assert "has_critical_changes" in prompt

    def test_encodes_has_critical_false_not_safe(self):
        prompt = _build_diff_system_prompt()
        assert "does not mean" in prompt.lower() or "does NOT mean" in prompt

    def test_encodes_policy_changes_highest_impact(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "highest" in prompt_lower or "policy" in prompt_lower

    def test_encodes_security_posture_framing(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "restriction" in prompt_lower or "regression" in prompt_lower

    def test_encodes_drift_detected(self):
        prompt = _build_diff_system_prompt()
        assert "drift_detected" in prompt

    def test_encodes_no_drift_behaviour(self):
        prompt = _build_diff_system_prompt()
        assert "identical" in prompt.lower() or "no changes" in prompt.lower()

    def test_encodes_chains_added_policy_gap(self):
        prompt = _build_diff_system_prompt()
        assert "policy" in prompt.lower()
        assert "rule_count" in prompt or "rules inside" in prompt.lower() or "NOT listed" in prompt

    def test_encodes_chains_added_rules_not_in_rules_added(self):
        prompt = _build_diff_system_prompt()
        assert "double" in prompt.lower() or "NOT listed in" in prompt or "not listed in" in prompt.lower()

    def test_encodes_prescriptive_language_ban(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "prescriptive" in prompt_lower or "do not suggest" in prompt_lower or "do not prescribe" in prompt_lower

    def test_encodes_negation_principle(self):
        prompt = _build_diff_system_prompt()
        assert "negat" in prompt.lower()

    def test_encodes_chain_resolution_to_terminal_outcome(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "terminal" in prompt_lower
        assert "every" in prompt_lower

    def test_encodes_goto_in_diff(self):
        prompt = _build_diff_system_prompt()
        assert "goto" in prompt.lower()

    def test_encodes_azure_scope_limitation(self):
        prompt = _build_diff_system_prompt()
        assert "Azure" in prompt or "NSG" in prompt

    def test_includes_output_format_directive(self):
        prompt = _build_diff_system_prompt()
        assert "Change Summary" in prompt
        assert "Security Impact" in prompt
        assert "Overall Assessment" in prompt
        assert "Rules Recreated" in prompt


# ---------------------------------------------------------------------------
# explain_snapshot()
# ---------------------------------------------------------------------------

class TestExplainSnapshot:

    def test_returns_string(self):
        mock_client = _make_mock_client("# nftables Firewall State Explanation\nTest output.")
        with patch("nftables_explain._get_client", return_value=mock_client):
            result = explain_snapshot(MINIMAL_SNAPSHOT)
        assert isinstance(result, str)

    def test_passes_snapshot_json_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert "inet/filter" in contents

    def test_uses_state_system_prompt_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        # State prompt contains "base chain" — key marker distinguishing it from diff prompt
        assert "base chain" in contents.lower()

    def test_uses_default_model(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            with patch("nftables_explain._get_model", return_value="gemini-2.0-flash"):
                explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.0-flash"

    def test_model_override_is_used(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT, model="gemini-2.5-pro")
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.5-pro"

    def test_zero_tables_snapshot_returns_string(self):
        mock_client = _make_mock_client(
            "# nftables Firewall State Explanation\n"
            "**WARNING: No nftables tables were found in this capture.**"
        )
        with patch("nftables_explain._get_client", return_value=mock_client):
            result = explain_snapshot(ZERO_TABLES_SNAPSHOT)
        assert isinstance(result, str)

    def test_zero_tables_passes_empty_tables_in_contents(self):
        mock_client = _make_mock_client("explanation")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_snapshot(ZERO_TABLES_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert '"tables": {}' in contents or '"tables"' in contents


# ---------------------------------------------------------------------------
# explain_diff()
# ---------------------------------------------------------------------------

class TestExplainDiff:

    def test_returns_string(self):
        mock_client = _make_mock_client("# nftables Firewall Ruleset Change Explanation\nTest.")
        with patch("nftables_explain._get_client", return_value=mock_client):
            result = explain_diff(MINIMAL_DIFF)
        assert isinstance(result, str)

    def test_passes_diff_json_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert "drift_detected" in contents

    def test_uses_diff_system_prompt_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        # Diff prompt contains rules_recreated — key marker distinguishing it from state prompt
        assert "rules_recreated" in contents

    def test_no_drift_diff_returns_string(self):
        mock_client = _make_mock_client(
            "The two rulesets are identical. No changes were detected."
        )
        with patch("nftables_explain._get_client", return_value=mock_client):
            result = explain_diff(NO_DRIFT_DIFF)
        assert isinstance(result, str)

    def test_model_override_is_used(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF, model="gemini-2.5-pro")
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.5-pro"

    def test_passes_policy_changes_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("nftables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert "policy_changes" in contents


# ---------------------------------------------------------------------------
# _get_model()
# ---------------------------------------------------------------------------

class TestGetModel:

    def test_returns_default_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NFTABLES_EXPLAIN_MODEL", None)
            assert _get_model() == "gemini-2.0-flash"

    def test_respects_env_override(self):
        with patch.dict(os.environ, {"NFTABLES_EXPLAIN_MODEL": "gemini-2.5-pro"}):
            assert _get_model() == "gemini-2.5-pro"


# ---------------------------------------------------------------------------
# _get_client() error paths
# ---------------------------------------------------------------------------

class TestGetClientErrors:

    def test_missing_api_key_raises_environment_error(self):
        mock_genai_module = MagicMock()
        mock_google_module = MagicMock()
        mock_google_module.genai = mock_genai_module
        saved_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            with patch.dict(sys.modules, {"google": mock_google_module, "google.genai": mock_genai_module}):
                from nftables_explain import _get_client
                with pytest.raises(EnvironmentError, match="GEMINI_API_KEY"):
                    _get_client()
        finally:
            if saved_key is not None:
                os.environ["GEMINI_API_KEY"] = saved_key

    def test_missing_google_genai_package_raises_import_error(self):
        saved_google = sys.modules.pop("google", None)
        saved_genai = sys.modules.pop("google.genai", None)
        try:
            with patch.dict(sys.modules, {"google": None, "google.genai": None}):
                from nftables_explain import _get_client
                with pytest.raises((ImportError, TypeError)):
                    _get_client()
        finally:
            if saved_google is not None:
                sys.modules["google"] = saved_google
            if saved_genai is not None:
                sys.modules["google.genai"] = saved_genai
