"""
Tests for effective_network_inspector.py — orchestrator, config, integrity, CLI.

No real az CLI calls. AzureNetworkProvider is replaced with a mock or stub.
"""
import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import effective_network_inspector as eni
from effective_network_inspector import (
    InspectorConfig,
    IntegrityError,
    _load_config_file,
    _write_artifact,
    load_snapshot,
    main,
    save_snapshot,
    validate_session_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config(tmp_path, session_id="eni_test", scope="vm", scope_target="my-vm",
            rg="my-rg", is_baseline=False, compare_baseline=None, sub=None):
    return InspectorConfig(
        session_id=session_id,
        audit_dir=str(tmp_path),
        resource_group=rg,
        scope=scope,
        scope_target=scope_target,
        subscription_id=sub,
        is_baseline=is_baseline,
        compare_baseline=compare_baseline,
    )


def _mock_provider(routes=None, nsg_rules=None, nic_names=None):
    """Build a mock AzureNetworkProvider returning canned data."""
    provider = MagicMock()
    provider.get_nic_names_for_vm.return_value = nic_names or ["nic-a"]
    provider.get_nic_names_for_vnet.return_value = nic_names or ["nic-a"]
    provider.get_effective_routes_json.return_value = json.dumps(
        {"value": routes or []}
    )
    provider.get_effective_nsg_json.return_value = json.dumps(
        {"networkSecurityGroups": [{"effectiveSecurityRules": nsg_rules or []}]}
    )
    return provider


def _minimal_snapshot(session_id="base", nic_name="nic-a"):
    return {
        "session_id": session_id,
        "scope": "vm",
        "scope_target": "my-vm",
        "resource_group": "my-rg",
        "timestamp": "2026-01-01T00:00:00Z",
        "nics": [{"nic_name": nic_name, "effective_routes": [],
                  "effective_nsg_rules": [], "error": None}],
        "parse_warnings": [],
    }


# ---------------------------------------------------------------------------
# validate_session_id
# ---------------------------------------------------------------------------

class TestValidateSessionId:

    @pytest.mark.parametrize("sid", [
        "eni_20260401_120000",
        "pre-test",
        "a",
        "A1-b_2",
        "a" * 64,
    ])
    def test_valid_formats_accepted(self, sid):
        """TC-ORCH-001: Valid session IDs pass without exception."""
        validate_session_id(sid)  # must not raise

    @pytest.mark.parametrize("sid", [
        "../evil",
        "foo/../bar",
        "foo/bar",
        "foo;bar",
        "foo bar",
        "foo&bar",
        "",
        "a" * 65,
    ])
    def test_invalid_formats_rejected(self, sid):
        """TC-ORCH-002–005: Invalid session IDs raise ValueError."""
        with pytest.raises(ValueError):
            validate_session_id(sid)


# ---------------------------------------------------------------------------
# save_snapshot / load_snapshot integrity
# ---------------------------------------------------------------------------

class TestSnapshotIntegrity:

    def test_save_creates_json_and_sha256(self, tmp_path):
        """TC-ORCH-006: Both files are created."""
        snap = _minimal_snapshot()
        save_snapshot(snap, str(tmp_path), "test-sid")
        assert (tmp_path / "test-sid_snapshot.json").exists()
        assert (tmp_path / "test-sid_snapshot.json.sha256").exists()

    def test_sha256_file_gnu_format(self, tmp_path):
        """TC-ORCH-007 / AG-3: SHA-256 file uses GNU sha256sum format (digest  filename)."""
        save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")
        sha_content = (tmp_path / "test-sid_snapshot.json.sha256").read_text()
        # Format: "<hex_digest>  <filename>\n"
        parts = sha_content.strip().split()
        assert len(parts) == 2
        digest, filename = parts
        assert re.match(r"^[0-9a-f]{64}$", digest), "Digest must be 64 hex chars"
        assert filename == "test-sid_snapshot.json"

    def test_sha256_verifiable_externally(self, tmp_path):
        """SHA-256 file can be verified with: sha256sum -c <file> from audit_dir."""
        save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")
        result = os.popen(
            f"cd {tmp_path} && sha256sum -c test-sid_snapshot.json.sha256 2>&1"
        ).read()
        assert "OK" in result

    def test_load_returns_original_data(self, tmp_path):
        """TC-ORCH-011: Round-trip: save then load returns identical dict."""
        snap = _minimal_snapshot(session_id="sid-rt")
        save_snapshot(snap, str(tmp_path), "sid-rt")
        loaded = load_snapshot(str(tmp_path), "sid-rt")
        assert loaded == snap

    def test_tampered_body_raises_integrity_error(self, tmp_path):
        """TC-ORCH-008 / TC-INT-002: Modified JSON file raises IntegrityError."""
        save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")
        json_path = tmp_path / "test-sid_snapshot.json"
        data = json_path.read_text()
        json_path.write_text(data.replace("my-rg", "tampered-rg"))
        with pytest.raises(IntegrityError, match="test-sid"):
            load_snapshot(str(tmp_path), "test-sid")

    def test_appended_byte_raises_integrity_error(self, tmp_path):
        """TC-INT-003: Single appended byte detected."""
        save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")
        json_path = tmp_path / "test-sid_snapshot.json"
        with open(json_path, "ab") as f:
            f.write(b" ")
        with pytest.raises(IntegrityError):
            load_snapshot(str(tmp_path), "test-sid")

    def test_missing_sha256_companion_raises_integrity_error(self, tmp_path):
        """TC-ORCH-009 / TC-INT-004: Missing .sha256 raises IntegrityError, not FileNotFoundError."""
        save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")
        (tmp_path / "test-sid_snapshot.json.sha256").unlink()
        with pytest.raises(IntegrityError, match="companion"):
            load_snapshot(str(tmp_path), "test-sid")

    def test_missing_snapshot_json_raises_file_not_found(self, tmp_path):
        """TC-ORCH-010: Non-existent session raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="missing-sid"):
            load_snapshot(str(tmp_path), "missing-sid")

    def test_write_artifact_oserror_has_actionable_message(self, tmp_path):
        """TC-INT-005: OSError from write produces message with session ID and path."""
        with patch("pathlib.Path.write_text", side_effect=OSError("No space left")):
            with pytest.raises(OSError, match="test-sid"):
                _write_artifact({}, str(tmp_path), "test-sid", "diff")

    def test_save_snapshot_oserror_has_actionable_message(self, tmp_path):
        with patch("pathlib.Path.write_bytes", side_effect=OSError("No space left")):
            with pytest.raises(OSError, match="test-sid"):
                save_snapshot(_minimal_snapshot(), str(tmp_path), "test-sid")


# ---------------------------------------------------------------------------
# _load_config_file
# ---------------------------------------------------------------------------

class TestLoadConfigFile:

    def _write_config(self, tmp_path, content):
        p = tmp_path / "test.env"
        p.write_text(content)
        return str(p)

    def test_all_keys_parsed(self, tmp_path):
        """TC-ORCH-012: All KEY_MAP keys are parsed correctly."""
        cfg = self._write_config(tmp_path, "\n".join([
            "RESOURCE_GROUP=my-rg",
            "SUBSCRIPTION_ID=sub-123",
            "SCOPE=vm",
            "VM_NAME=my-vm",
            "VNET_ID=/subscriptions/sub/virtualNetworks/vnet-1",
            "AUDIT_DIR=/tmp/audit",
            "SESSION_ID=pre-test",
            "IS_BASELINE=true",
            "COMPARE_BASELINE=baseline-session",
        ]))
        defaults = _load_config_file(cfg)
        assert defaults["resource_group"] == "my-rg"
        assert defaults["subscription_id"] == "sub-123"
        assert defaults["scope"] == "vm"
        assert defaults["vm_name"] == "my-vm"
        assert defaults["audit_dir"] == "/tmp/audit"
        assert defaults["session_id"] == "pre-test"
        assert defaults["is_baseline"] is True
        assert defaults["compare_baseline"] == "baseline-session"

    @pytest.mark.parametrize("val,expected", [
        ("true", True), ("True", True), ("1", True), ("yes", True),
        ("false", False), ("0", False), ("no", False),
    ])
    def test_is_baseline_variants(self, tmp_path, val, expected):
        """TC-ORCH-013: IS_BASELINE parses all truthy/falsy variants."""
        cfg = self._write_config(tmp_path, f"IS_BASELINE={val}\nRESOURCE_GROUP=rg\n")
        defaults = _load_config_file(cfg)
        assert defaults["is_baseline"] is expected

    def test_inline_comments_stripped(self, tmp_path):
        """TC-ORCH-015: Inline comments are stripped from values."""
        cfg = self._write_config(tmp_path, "RESOURCE_GROUP=my-rg  # this is a comment\n")
        defaults = _load_config_file(cfg)
        assert defaults["resource_group"] == "my-rg"

    def test_quoted_values_unquoted(self, tmp_path):
        """TC-ORCH-016: Double-quoted values have quotes stripped."""
        cfg = self._write_config(tmp_path, 'AUDIT_DIR="/path/with spaces/audit"\n')
        defaults = _load_config_file(cfg)
        assert defaults["audit_dir"] == "/path/with spaces/audit"

    def test_unknown_key_warned_to_stderr_and_ignored(self, tmp_path, capsys):
        """TC-ORCH-014: Unknown key produces warning on stderr, not stdout."""
        cfg = self._write_config(tmp_path, "UNKNOWN_KEY=value\nRESOURCE_GROUP=rg\n")
        defaults = _load_config_file(cfg)
        assert "unknown_key" not in defaults
        captured = capsys.readouterr()
        assert "UNKNOWN_KEY" in captured.err
        assert "UNKNOWN_KEY" not in captured.out

    def test_missing_file_exits_with_code_1(self, tmp_path):
        """TC-ORCH-017: Missing config file → SystemExit(1)."""
        with pytest.raises(SystemExit) as exc_info:
            _load_config_file("/nonexistent/path/config.env")
        assert exc_info.value.code == 1

    def test_blank_lines_and_comments_skipped(self, tmp_path):
        """Blank lines and comment-only lines do not produce warnings."""
        cfg = self._write_config(tmp_path,
            "# This is a header comment\n\nRESOURCE_GROUP=rg\n\n# Another comment\n")
        defaults = _load_config_file(cfg)
        assert defaults["resource_group"] == "rg"


# ---------------------------------------------------------------------------
# InspectorConfig validation
# ---------------------------------------------------------------------------

class TestInspectorConfig:

    def test_invalid_scope_rejected(self, tmp_path):
        """TC-ORCH-018: scope must be 'vm' or 'vnet'."""
        with pytest.raises(ValueError, match="scope"):
            _config(tmp_path, scope="invalid")

    def test_empty_scope_target_rejected(self, tmp_path):
        """TC-ORCH-019: empty scope_target raises ValueError."""
        with pytest.raises(ValueError, match="scope_target"):
            _config(tmp_path, scope_target="")

    def test_empty_resource_group_rejected(self, tmp_path):
        """TC-ORCH-020: empty resource_group raises ValueError."""
        with pytest.raises(ValueError, match="resource_group"):
            _config(tmp_path, rg="")

    def test_valid_config_constructed_without_error(self, tmp_path):
        cfg = _config(tmp_path)
        assert cfg.scope == "vm"
        assert cfg.scope_target == "my-vm"


# ---------------------------------------------------------------------------
# run() — pipeline orchestration
# ---------------------------------------------------------------------------

class TestRun:

    def test_baseline_mode_writes_snapshot(self, tmp_path):
        """TC-ORCH-023: --is-baseline writes snapshot.json and .sha256."""
        cfg = _config(tmp_path, is_baseline=True)
        provider = _mock_provider()
        result = eni.run(cfg, provider)
        assert result["mode"] == "baseline"
        assert (tmp_path / "eni_test_snapshot.json").exists()
        assert (tmp_path / "eni_test_snapshot.json.sha256").exists()

    def test_baseline_result_contains_session_id(self, tmp_path):
        cfg = _config(tmp_path, is_baseline=True)
        result = eni.run(cfg, _mock_provider())
        assert result["session_id"] == "eni_test"

    def test_compare_mode_produces_diff_artifact(self, tmp_path):
        """TC-ORCH-024: compare mode writes diff artifact and result contains diff."""
        # Write baseline
        base_snap = _minimal_snapshot("base-snap")
        save_snapshot(base_snap, str(tmp_path), "base-snap")

        cfg = _config(tmp_path, compare_baseline="base-snap")
        provider = _mock_provider()
        result = eni.run(cfg, provider)

        assert result["mode"] == "compare"
        assert "diff_report" in result
        assert Path(result["diff_report"]).exists()

    def test_diff_artifact_filename_format(self, tmp_path):
        """TC-ORCH-029 / AG-1: Diff file is named {baseline}_vs_{compare}_diff.json."""
        base_snap = _minimal_snapshot("base-snap")
        save_snapshot(base_snap, str(tmp_path), "base-snap")

        cfg = _config(tmp_path, session_id="compare-snap", compare_baseline="base-snap")
        eni.run(cfg, _mock_provider())

        expected = tmp_path / "base-snap_vs_compare-snap_diff.json"
        assert expected.exists(), f"Expected {expected}, got: {list(tmp_path.glob('*_diff.json'))}"

    def test_per_nic_error_isolation(self, tmp_path):
        """TC-ORCH-021: One NIC failing does not abort; partial snapshot written."""
        provider = MagicMock()
        provider.get_nic_names_for_vm.return_value = ["nic-ok", "nic-fail"]
        provider.get_effective_routes_json.side_effect = lambda name: (
            json.dumps({"value": []}) if name == "nic-ok"
            else (_ for _ in ()).throw(RuntimeError("RBAC failure"))
        )
        provider.get_effective_nsg_json.return_value = json.dumps(
            {"networkSecurityGroups": [{"effectiveSecurityRules": []}]}
        )

        cfg = _config(tmp_path, is_baseline=True)
        result = eni.run(cfg, provider)

        nics = result["snapshot"]["nics"]
        ok_nic   = next(n for n in nics if n["nic_name"] == "nic-ok")
        fail_nic = next(n for n in nics if n["nic_name"] == "nic-fail")
        assert ok_nic["error"] is None
        assert fail_nic["error"] is not None

    def test_nsg_not_queried_when_routes_fail(self, tmp_path):
        """TC-ORCH-022: NSG query skipped if routes fail for same NIC."""
        provider = MagicMock()
        provider.get_nic_names_for_vm.return_value = ["nic-fail"]
        provider.get_effective_routes_json.side_effect = RuntimeError("routes failed")

        cfg = _config(tmp_path, is_baseline=True)
        eni.run(cfg, provider)

        provider.get_effective_nsg_json.assert_not_called()

    def test_self_compare_guard_exits(self, tmp_path):
        """TC-ORCH-025: Comparing a session against itself exits with code 1."""
        base_snap = _minimal_snapshot("same-id")
        save_snapshot(base_snap, str(tmp_path), "same-id")

        cfg = _config(tmp_path, session_id="same-id", compare_baseline="same-id")
        with pytest.raises(SystemExit) as exc_info:
            eni.run(cfg, _mock_provider())
        assert exc_info.value.code == 1

    def test_bracket_mode_saves_and_diffs(self, tmp_path):
        """TC-ORCH-026: is_baseline=True AND compare_baseline set → both operations run."""
        prior_snap = _minimal_snapshot("prior-base")
        save_snapshot(prior_snap, str(tmp_path), "prior-base")

        cfg = _config(tmp_path, session_id="new-snap",
                      is_baseline=True, compare_baseline="prior-base")
        result = eni.run(cfg, _mock_provider())

        assert (tmp_path / "new-snap_snapshot.json").exists()
        assert "diff_report" in result

    def test_compare_no_drift_drift_detected_false(self, tmp_path):
        """Same data in baseline and compare → drift_detected=false in diff artifact."""
        snap = _minimal_snapshot("base-snap")
        save_snapshot(snap, str(tmp_path), "base-snap")

        cfg = _config(tmp_path, compare_baseline="base-snap")
        result = eni.run(cfg, _mock_provider())

        diff = json.loads(Path(result["diff_report"]).read_text())
        assert diff["drift_detected"] is False

    def test_skipped_nics_in_diff_artifact(self, tmp_path):
        """TC-ORCH-030 / AG-2: skipped_nics field present in diff artifact."""
        snap = _minimal_snapshot("base-snap")
        save_snapshot(snap, str(tmp_path), "base-snap")

        cfg = _config(tmp_path, compare_baseline="base-snap")
        result = eni.run(cfg, _mock_provider())

        diff = json.loads(Path(result["diff_report"]).read_text())
        assert "skipped_nics" in diff

    def test_progress_steps_baseline_only(self, tmp_path, capsys):
        """TC-ORCH-027: [1/3], [2/3], [3/3] shown; no [4/3] or [4/4]."""
        cfg = _config(tmp_path, is_baseline=True)
        eni.run(cfg, _mock_provider())
        out = capsys.readouterr().out
        assert "[1/3]" in out
        assert "[2/3]" in out
        assert "[3/3]" in out
        assert "[4/3]" not in out
        assert "[4/4]" not in out

    def test_progress_steps_compare_mode(self, tmp_path, capsys):
        """TC-ORCH-028: [1/4] through [4/4] shown in compare mode."""
        snap = _minimal_snapshot("base-snap")
        save_snapshot(snap, str(tmp_path), "base-snap")
        cfg = _config(tmp_path, compare_baseline="base-snap")
        eni.run(cfg, _mock_provider())
        out = capsys.readouterr().out
        assert "[1/4]" in out
        assert "[4/4]" in out

    def test_invalid_session_id_raises_value_error(self, tmp_path):
        """validate_session_id called before any queries."""
        cfg = _config(tmp_path, session_id="invalid/session")
        cfg.session_id = "invalid/session"  # bypass __post_init__
        with pytest.raises(ValueError):
            eni.run(cfg, _mock_provider())


# ---------------------------------------------------------------------------
# CLI (main)
# ---------------------------------------------------------------------------

class TestCLI:

    def test_scope_vm_without_vm_name_errors(self, tmp_path):
        """TC-ORCH-031: --scope vm without --vm-name exits with error."""
        with pytest.raises(SystemExit) as exc_info:
            main([
                "--scope", "vm",
                "--resource-group", "rg",
                "--is-baseline",
                "--audit-dir", str(tmp_path),
            ])
        assert exc_info.value.code != 0

    def test_scope_vnet_without_vnet_id_errors(self, tmp_path):
        """TC-ORCH-032: --scope vnet without --vnet-id exits with error."""
        with pytest.raises(SystemExit) as exc_info:
            main([
                "--scope", "vnet",
                "--resource-group", "rg",
                "--is-baseline",
                "--audit-dir", str(tmp_path),
            ])
        assert exc_info.value.code != 0

    def test_no_mode_flag_errors(self, tmp_path):
        """TC-ORCH-033: Neither --is-baseline nor --compare-baseline → error."""
        with pytest.raises(SystemExit) as exc_info:
            main([
                "--scope", "vm",
                "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--audit-dir", str(tmp_path),
            ])
        assert exc_info.value.code != 0

    def test_auto_generated_session_id_format(self, tmp_path):
        """TC-ORCH-034: Auto-generated session ID matches eni_YYYYMMDD_HHMMSS."""
        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--scope", "vm",
                "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--is-baseline",
                "--audit-dir", str(tmp_path),
            ])
        snapshots = list(tmp_path.glob("eni_*_snapshot.json"))
        assert len(snapshots) == 1
        name = snapshots[0].name.replace("_snapshot.json", "")
        assert re.match(r"^eni_\d{8}_\d{6}$", name), f"Unexpected session ID: {name}"

    def test_config_file_values_used_when_no_cli_flag(self, tmp_path):
        """TC-ORCH-035: Config file values supply defaults when CLI flags absent."""
        cfg_file = tmp_path / "test.env"
        cfg_file.write_text(
            f"RESOURCE_GROUP=config-rg\nVM_NAME=config-vm\nAUDIT_DIR={tmp_path}\n"
        )
        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--config", str(cfg_file),
                "--scope", "vm",
                "--is-baseline",
            ])
        # If config-rg was used, AzureNetworkProvider was instantiated with it
        call_kwargs = MockProvider.call_args[1]
        assert call_kwargs["resource_group"] == "config-rg"

    def test_cli_flag_overrides_config_file(self, tmp_path):
        """TC-ORCH-035: CLI flag takes precedence over config file."""
        cfg_file = tmp_path / "test.env"
        cfg_file.write_text("RESOURCE_GROUP=from-config\nVM_NAME=config-vm\n")
        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--config", str(cfg_file),
                "--scope", "vm",
                "--resource-group", "from-cli",
                "--is-baseline",
                "--audit-dir", str(tmp_path),
            ])
        call_kwargs = MockProvider.call_args[1]
        assert call_kwargs["resource_group"] == "from-cli"

    # ------------------------------------------------------------------
    # Session ID prefix normalisation (eni_ enforcement)
    # ------------------------------------------------------------------

    def test_user_session_id_without_prefix_gets_eni_prefix(self, tmp_path):
        """TC-ORCH-039: --session-id foo stores artifact as eni_foo_snapshot.json."""
        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--scope", "vm", "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--is-baseline",
                "--session-id", "pre_window_P",
                "--audit-dir", str(tmp_path),
            ])
        assert (tmp_path / "eni_pre_window_P_snapshot.json").exists()
        assert not (tmp_path / "pre_window_P_snapshot.json").exists()

    def test_user_session_id_with_prefix_not_doubled(self, tmp_path):
        """TC-ORCH-040: --session-id eni_foo stores as eni_foo (no double prefix)."""
        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--scope", "vm", "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--is-baseline",
                "--session-id", "eni_already_prefixed",
                "--audit-dir", str(tmp_path),
            ])
        assert (tmp_path / "eni_already_prefixed_snapshot.json").exists()
        assert not (tmp_path / "eni_eni_already_prefixed_snapshot.json").exists()

    def test_compare_baseline_without_prefix_resolves_eni_file(self, tmp_path):
        """TC-ORCH-041: --compare-baseline foo loads eni_foo_snapshot.json."""
        # Save baseline with eni_ prefix
        snap = _minimal_snapshot("eni_pre_window_P")
        save_snapshot(snap, str(tmp_path), "eni_pre_window_P")

        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--scope", "vm", "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--compare-baseline", "pre_window_P",  # no prefix supplied
                "--audit-dir", str(tmp_path),
            ])
        # Diff artifact should exist — baseline was found
        diffs = list(tmp_path.glob("*_diff.json"))
        assert len(diffs) == 1

    def test_compare_baseline_with_prefix_not_doubled(self, tmp_path):
        """TC-ORCH-042: --compare-baseline eni_foo loads eni_foo (no double prefix)."""
        snap = _minimal_snapshot("eni_pre_window_P")
        save_snapshot(snap, str(tmp_path), "eni_pre_window_P")

        with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
            MockProvider.return_value = _mock_provider()
            main([
                "--scope", "vm", "--vm-name", "my-vm",
                "--resource-group", "rg",
                "--compare-baseline", "eni_pre_window_P",  # prefix already present
                "--audit-dir", str(tmp_path),
            ])
        diffs = list(tmp_path.glob("*_diff.json"))
        assert len(diffs) == 1

    def test_integrity_error_exits_code_2(self, tmp_path, capsys):
        """TC-ORCH-038: Tampered baseline → SystemExit(2)."""
        snap = _minimal_snapshot("eni_base-snap")
        save_snapshot(snap, str(tmp_path), "eni_base-snap")
        (tmp_path / "eni_base-snap_snapshot.json").write_text('{"tampered": true}')

        with pytest.raises(SystemExit) as exc_info:
            with patch("effective_network_inspector.AzureNetworkProvider") as MockProvider:
                MockProvider.return_value = _mock_provider()
                main([
                    "--scope", "vm",
                    "--vm-name", "my-vm",
                    "--resource-group", "rg",
                    "--compare-baseline", "eni_base-snap",
                    "--audit-dir", str(tmp_path),
                ])
        assert exc_info.value.code == 2
