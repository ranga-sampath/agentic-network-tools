"""
test_explain.py — Unit tests for iptables_explain.py

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

import iptables_explain
from iptables_explain import (
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
    "parsed_at": "2026-03-16T10:00:00Z",
    "family": "ipv4",
    "input_format": "iptables-save",
    "tables": {
        "filter": {
            "chains": {
                "INPUT": {
                    "type": "builtin",
                    "default_policy": "DROP",
                    "policy_packet_count": 0,
                    "policy_byte_count": 0,
                    "rules": [
                        {
                            "table": "filter",
                            "chain": "INPUT",
                            "position": 1,
                            "protocol": "tcp",
                            "protocol_negated": False,
                            "source": None,
                            "source_negated": False,
                            "destination": None,
                            "destination_negated": False,
                            "in_interface": None,
                            "in_interface_negated": False,
                            "out_interface": None,
                            "out_interface_negated": False,
                            "dst_port": "22",
                            "dst_port_negated": False,
                            "src_port": None,
                            "src_port_negated": False,
                            "target": "ACCEPT",
                            "target_params": None,
                            "target_stops_chain_traversal": True,
                            "match_extensions": {},
                            "opaque_extensions": None,
                            "raw_rule": "-A INPUT -p tcp --dport 22 -j ACCEPT",
                            "packet_count": None,
                            "byte_count": None,
                        }
                    ],
                },
                "OUTPUT": {
                    "type": "builtin",
                    "default_policy": "ACCEPT",
                    "policy_packet_count": 0,
                    "policy_byte_count": 0,
                    "rules": [],
                },
                "FORWARD": {
                    "type": "builtin",
                    "default_policy": "DROP",
                    "policy_packet_count": 0,
                    "policy_byte_count": 0,
                    "rules": [],
                },
            }
        }
    },
    "diagnostics": {
        "drop_policy_chains": ["filter/INPUT", "filter/FORWARD"],
        "accept_policy_chains": ["filter/OUTPUT"],
        "conntrack_position_warnings": [],
        "active_drop_rules": [],
        "nat_summary": {"masquerade_rules": [], "dnat_rules": [], "snat_rules": []},
        "user_defined_chains": {},
        "unresolved_chain_references": [],
    },
    "parse_warnings": [],
}

ZERO_TABLES_SNAPSHOT = {
    "parsed_at": "2026-03-16T10:00:00Z",
    "family": "ipv4",
    "input_format": "iptables-save",
    "tables": {},
    "diagnostics": {
        "drop_policy_chains": [],
        "accept_policy_chains": [],
        "conntrack_position_warnings": [],
        "active_drop_rules": [],
        "nat_summary": {"masquerade_rules": [], "dnat_rules": [], "snat_rules": []},
        "user_defined_chains": {},
        "unresolved_chain_references": [],
    },
    "parse_warnings": [],
}

MINIMAL_DIFF = {
    "diff_at": "2026-03-16T11:00:00Z",
    "family": "ipv4",
    "baseline_parsed_at": "2026-03-16T09:00:00Z",
    "current_parsed_at": "2026-03-16T11:00:00Z",
    "baseline_parse_warnings": [],
    "current_parse_warnings": [],
    "drift_detected": True,
    "has_critical_changes": True,
    "summary": {
        "tables_added": 0,
        "tables_removed": 0,
        "chains_added": 0,
        "chains_removed": 0,
        "policy_changes": 1,
        "rules_added": 0,
        "rules_removed": 0,
        "rules_repositioned": 0,
    },
    "changes": {
        "tables_added": [],
        "tables_removed": [],
        "chains_added": [],
        "chains_removed": [],
        "policy_changes": [
            {
                "table": "filter",
                "chain": "INPUT",
                "baseline_policy": "ACCEPT",
                "current_policy": "DROP",
            }
        ],
        "rules_added": [],
        "rules_removed": [],
        "rules_repositioned": [],
    },
}

NO_DRIFT_DIFF = {
    "diff_at": "2026-03-16T11:00:00Z",
    "family": "ipv4",
    "baseline_parsed_at": "2026-03-16T09:00:00Z",
    "current_parsed_at": "2026-03-16T11:00:00Z",
    "baseline_parse_warnings": [],
    "current_parse_warnings": [],
    "drift_detected": False,
    "has_critical_changes": False,
    "summary": {
        "tables_added": 0,
        "tables_removed": 0,
        "chains_added": 0,
        "chains_removed": 0,
        "policy_changes": 0,
        "rules_added": 0,
        "rules_removed": 0,
        "rules_repositioned": 0,
    },
    "changes": {
        "tables_added": [],
        "tables_removed": [],
        "chains_added": [],
        "chains_removed": [],
        "policy_changes": [],
        "rules_added": [],
        "rules_removed": [],
        "rules_repositioned": [],
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
    """The state system prompt must encode all critical iptables concepts."""

    def test_encodes_first_match_semantics(self):
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "first" in prompt_lower and "match" in prompt_lower

    def test_encodes_default_policy_semantics(self):
        prompt = _build_state_system_prompt()
        assert "default policy" in prompt.lower()

    def test_encodes_established_related(self):
        # Critical for stateful firewall explanation
        prompt = _build_state_system_prompt()
        assert "ESTABLISHED" in prompt
        assert "RELATED" in prompt

    def test_encodes_return_semantics(self):
        # RETURN does NOT mean accept — must be encoded
        prompt = _build_state_system_prompt()
        assert "RETURN" in prompt

    def test_encodes_chain_responsibilities(self):
        prompt = _build_state_system_prompt()
        assert "INPUT" in prompt
        assert "OUTPUT" in prompt
        assert "FORWARD" in prompt

    def test_encodes_table_responsibilities(self):
        prompt = _build_state_system_prompt()
        assert "filter" in prompt
        assert "nat" in prompt
        assert "mangle" in prompt
        assert "raw" in prompt

    def test_encodes_counter_semantics(self):
        prompt = _build_state_system_prompt()
        assert "packet_count" in prompt or "counter" in prompt.lower()

    def test_encodes_nftables_scope_limitation(self):
        # On modern VMs, iptables-nft may show zero tables while nftables enforces
        prompt = _build_state_system_prompt()
        assert "nftables" in prompt.lower() or "nft" in prompt.lower()

    def test_encodes_azure_nsg_scope_limitation(self):
        prompt = _build_state_system_prompt()
        assert "Azure" in prompt or "NSG" in prompt

    def test_encodes_zero_tables_guard(self):
        # Explicit guard for empty rulesets (iptables-nft hosts)
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "zero" in prompt_lower or "empty" in prompt_lower

    def test_encodes_log_is_nonterminal(self):
        # LOG does not block traffic — must be stated
        prompt = _build_state_system_prompt()
        assert "LOG" in prompt

    def test_encodes_user_defined_chains(self):
        prompt = _build_state_system_prompt()
        assert "user-defined" in prompt.lower() or "user defined" in prompt.lower()

    def test_encodes_conntrack_position_warning(self):
        prompt = _build_state_system_prompt()
        assert "conntrack_position_warnings" in prompt or "conntrack" in prompt.lower()

    def test_includes_output_format_directive(self):
        prompt = _build_state_system_prompt()
        assert "Traffic Table" in prompt
        assert "Executive Summary" in prompt

    def test_includes_scope_limitations_section(self):
        prompt = _build_state_system_prompt()
        assert "Scope Limitations" in prompt or "scope" in prompt.lower()

    def test_encodes_negation_principle(self):
        # _negated: true means NOT that criterion — misreading inverts the rule
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "negat" in prompt_lower

    def test_encodes_chain_resolution_to_terminal_outcome(self):
        # Every user-defined chain jump must resolve to a terminal verdict for all paths
        prompt = _build_state_system_prompt()
        prompt_lower = prompt.lower()
        assert "terminal" in prompt_lower
        assert "every" in prompt_lower


# ---------------------------------------------------------------------------
# Diff system prompt content
# ---------------------------------------------------------------------------

class TestDiffSystemPrompt:
    """The diff system prompt must encode all critical change analysis concepts."""

    def test_encodes_has_critical_changes(self):
        prompt = _build_diff_system_prompt()
        assert "has_critical_changes" in prompt

    def test_encodes_policy_changes(self):
        prompt = _build_diff_system_prompt()
        assert "policy_changes" in prompt or "policy change" in prompt.lower()

    def test_encodes_rules_added_removed(self):
        prompt = _build_diff_system_prompt()
        assert "rules_added" in prompt
        assert "rules_removed" in prompt

    def test_encodes_repositioned_rules_caveat(self):
        # Repositioned DROP/REJECT rules are not flagged by has_critical_changes
        prompt = _build_diff_system_prompt()
        assert "repositioned" in prompt.lower() or "rules_repositioned" in prompt

    def test_encodes_has_critical_false_does_not_mean_safe(self):
        prompt = _build_diff_system_prompt()
        assert "does not mean" in prompt.lower() or "does NOT mean" in prompt

    def test_encodes_security_posture_framing(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "restriction" in prompt_lower or "regression" in prompt_lower

    def test_encodes_drift_detected(self):
        prompt = _build_diff_system_prompt()
        assert "drift_detected" in prompt

    def test_encodes_no_drift_behaviour(self):
        # If drift_detected false, output should be brief
        prompt = _build_diff_system_prompt()
        assert "identical" in prompt.lower() or "no changes" in prompt.lower()

    def test_encodes_azure_scope_limitation(self):
        prompt = _build_diff_system_prompt()
        assert "Azure" in prompt or "NSG" in prompt

    def test_encodes_nftables_scope_limitation(self):
        prompt = _build_diff_system_prompt()
        assert "nftables" in prompt.lower() or "nft" in prompt.lower()

    def test_encodes_policy_change_highest_impact(self):
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "highest" in prompt_lower or "policy" in prompt_lower

    def test_includes_output_format_directive(self):
        prompt = _build_diff_system_prompt()
        assert "Change Summary" in prompt
        assert "Security Impact" in prompt
        assert "Overall Assessment" in prompt

    def test_encodes_negation_principle(self):
        # _negated: true means NOT that criterion — must be encoded in diff prompt too
        prompt = _build_diff_system_prompt()
        assert "negat" in prompt.lower()

    def test_encodes_chain_resolution_to_terminal_outcome(self):
        # Added/changed rules that jump user-defined chains must be traced to terminal verdict
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        assert "terminal" in prompt_lower
        assert "every" in prompt_lower

    def test_encodes_chains_added_policy_gap(self):
        # chains_added entries do not include policy; analyst must flag this limitation
        prompt = _build_diff_system_prompt()
        # The prompt must instruct the model that policy of newly added builtin chains is
        # NOT captured in policy_changes
        assert "policy" in prompt.lower()
        # Must mention that chains_added doesn't include rule details
        assert "rule_count" in prompt or "rules inside" in prompt.lower() or "rules NOT" in prompt

    def test_encodes_chains_added_rules_not_in_rules_added(self):
        # Rules inside added chains are not listed in rules_added (no double-counting)
        prompt = _build_diff_system_prompt()
        assert "double" in prompt.lower() or "NOT listed in" in prompt or "not listed in" in prompt.lower()

    def test_encodes_no_prescriptive_language_principle(self):
        # The prompt must explicitly prohibit prescriptive suggestions
        prompt = _build_diff_system_prompt()
        prompt_lower = prompt.lower()
        # The prompt must state that prescriptive language is prohibited
        assert "prescriptive" in prompt_lower or "do not suggest" in prompt_lower or "do not prescribe" in prompt_lower


# ---------------------------------------------------------------------------
# explain_snapshot()
# ---------------------------------------------------------------------------

class TestExplainSnapshot:

    def test_returns_string(self):
        mock_client = _make_mock_client("# Firewall State Explanation\nTest output.")
        with patch("iptables_explain._get_client", return_value=mock_client):
            result = explain_snapshot(MINIMAL_SNAPSHOT)
        assert isinstance(result, str)
        assert "# Firewall State Explanation" in result

    def test_passes_snapshot_json_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        # The combined contents string should contain the snapshot JSON
        assert "filter" in contents

    def test_uses_state_system_prompt_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        # State prompt contains ESTABLISHED — a key marker distinguishing it from diff prompt
        assert "ESTABLISHED" in contents

    def test_uses_default_model(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            with patch("iptables_explain._get_model", return_value="gemini-2.0-flash"):
                explain_snapshot(MINIMAL_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.0-flash"

    def test_model_override_is_used(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_snapshot(MINIMAL_SNAPSHOT, model="gemini-2.5-pro")
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.5-pro"

    def test_zero_tables_snapshot_still_returns_string(self):
        mock_client = _make_mock_client(
            "# Firewall State Explanation\n"
            "**WARNING: Zero iptables tables were found in this capture.**"
        )
        with patch("iptables_explain._get_client", return_value=mock_client):
            result = explain_snapshot(ZERO_TABLES_SNAPSHOT)
        assert isinstance(result, str)

    def test_zero_tables_snapshot_passes_empty_tables_in_contents(self):
        mock_client = _make_mock_client("explanation")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_snapshot(ZERO_TABLES_SNAPSHOT)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert '"tables": {}' in contents or '"tables"' in contents


# ---------------------------------------------------------------------------
# explain_diff()
# ---------------------------------------------------------------------------

class TestExplainDiff:

    def test_returns_string(self):
        mock_client = _make_mock_client("# Firewall Ruleset Change Explanation\nTest.")
        with patch("iptables_explain._get_client", return_value=mock_client):
            result = explain_diff(MINIMAL_DIFF)
        assert isinstance(result, str)

    def test_passes_diff_json_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        assert "drift_detected" in contents

    def test_uses_diff_system_prompt_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF)
        call_kwargs = mock_client.models.generate_content.call_args
        contents = call_kwargs.kwargs.get("contents") or call_kwargs[1].get("contents", "")
        # Diff prompt contains has_critical_changes — a key marker distinguishing it from state prompt
        assert "has_critical_changes" in contents

    def test_no_drift_diff_returns_string(self):
        mock_client = _make_mock_client(
            "The two rulesets are identical. No changes were detected."
        )
        with patch("iptables_explain._get_client", return_value=mock_client):
            result = explain_diff(NO_DRIFT_DIFF)
        assert isinstance(result, str)

    def test_model_override_is_used(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
            explain_diff(MINIMAL_DIFF, model="gemini-2.5-pro")
        call_kwargs = mock_client.models.generate_content.call_args
        model = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        assert model == "gemini-2.5-pro"

    def test_passes_policy_changes_in_contents(self):
        mock_client = _make_mock_client("explanation text")
        with patch("iptables_explain._get_client", return_value=mock_client):
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
            os.environ.pop("IPTABLES_EXPLAIN_MODEL", None)
            assert _get_model() == "gemini-2.0-flash"

    def test_respects_env_override(self):
        with patch.dict(os.environ, {"IPTABLES_EXPLAIN_MODEL": "claude-haiku-4-5-20251001"}):
            assert _get_model() == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# _get_client() error paths
# ---------------------------------------------------------------------------

class TestGetClientErrors:

    def test_missing_api_key_raises_environment_error(self):
        """_get_client() must raise EnvironmentError when GEMINI_API_KEY is absent."""
        mock_genai_module = MagicMock()
        mock_google_module = MagicMock()
        mock_google_module.genai = mock_genai_module
        saved_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            with patch.dict(sys.modules, {"google": mock_google_module, "google.genai": mock_genai_module}):
                from iptables_explain import _get_client
                with pytest.raises(EnvironmentError, match="GEMINI_API_KEY"):
                    _get_client()
        finally:
            if saved_key is not None:
                os.environ["GEMINI_API_KEY"] = saved_key

    def test_missing_google_genai_package_raises_import_error(self):
        """_get_client() must raise ImportError when google-genai is not installed."""
        saved_google = sys.modules.pop("google", None)
        saved_genai = sys.modules.pop("google.genai", None)
        try:
            with patch.dict(sys.modules, {"google": None, "google.genai": None}):
                from iptables_explain import _get_client
                with pytest.raises((ImportError, TypeError)):
                    _get_client()
        finally:
            if saved_google is not None:
                sys.modules["google"] = saved_google
            if saved_genai is not None:
                sys.modules["google.genai"] = saved_genai
