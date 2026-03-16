"""
firewall_inspector.py — VM Firewall Inspector (main orchestrator)

Captures the OS-layer firewall state (iptables/nftables) from an Azure VM,
stores it as a baseline, and diffs against a previous baseline to detect drift.

Two SSH topology cases are supported:

  Case 1 — Target VM has a public IP (direct access):
    python3 firewall_inspector.py --config config.env --is-baseline
    config.env:  TARGET_VM_IP=<public-ip>  (no BASTION_PUBLIC_IP)

  Case 2 — Target VM has only a private IP (access via bastion):
    config.env:  TARGET_VM_IP=<private-ip>  BASTION_PUBLIC_IP=<bastion-public-ip>
    If bastion and target use different SSH keys, also set BASTION_SSH_KEY_PATH.

Usage:
    python3 firewall_inspector.py --config config.env [--is-baseline | --compare-baseline SESSION_ID]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Modules in the same directory
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))
# iptables_parser lives in the sibling iptables-parser/ module
sys.path.insert(0, str(_HERE.parent / "iptables-parser"))

from framework_detector import detect_framework
from chain_classifier    import classify_diff
from iptables_diff       import diff_rulesets
from iptables_parser     import parse_iptables_save


# ---------------------------------------------------------------------------
# session_id validation
# ---------------------------------------------------------------------------

_SESSION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_session_id(session_id: str) -> None:
    """
    Raise ValueError if session_id contains characters outside [a-zA-Z0-9_-]
    or exceeds 64 characters.

    Must be called before any shell command is constructed and before any
    file path using the session_id is assembled.
    """
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError(
            f"Invalid session_id {session_id!r}. "
            f"Must match ^[a-zA-Z0-9_-]{{1,64}}$. "
            f"Use only letters, digits, underscores, and hyphens, max 64 characters."
        )


# ---------------------------------------------------------------------------
# Baseline integrity
# ---------------------------------------------------------------------------

class IntegrityError(Exception):
    """Raised when a snapshot file fails SHA-256 integrity verification."""


def _snapshot_sha256(json_bytes: bytes) -> str:
    return hashlib.sha256(json_bytes).hexdigest()


def save_snapshot(snapshot: dict, audit_dir: str, session_id: str) -> str:
    """
    Write snapshot JSON and a sha256 companion file to audit_dir.

    Returns the path to the written snapshot file.
    """
    Path(audit_dir).mkdir(parents=True, exist_ok=True)
    snap_path = Path(audit_dir) / f"{session_id}_snapshot.json"
    sha_path  = Path(audit_dir) / f"{session_id}_snapshot.json.sha256"

    json_bytes = json.dumps(snapshot, indent=2).encode("utf-8")
    sha256     = _snapshot_sha256(json_bytes)

    snap_path.write_bytes(json_bytes)
    sha_path.write_text(sha256 + "\n", encoding="utf-8")
    return str(snap_path)


def load_snapshot(audit_dir: str, session_id: str) -> dict:
    """
    Load a snapshot file and verify its SHA-256 companion.

    Raises IntegrityError if:
      - The companion .sha256 file is missing (treated as tamper evidence).
      - The computed hash does not match the stored hash.
    Raises FileNotFoundError if the snapshot JSON itself is missing.
    """
    snap_path = Path(audit_dir) / f"{session_id}_snapshot.json"
    sha_path  = Path(audit_dir) / f"{session_id}_snapshot.json.sha256"

    if not snap_path.exists():
        raise FileNotFoundError(f"Baseline snapshot not found: {snap_path}")

    if not sha_path.exists():
        raise IntegrityError(
            f"SHA-256 companion file missing for baseline {session_id}. "
            f"Expected: {sha_path}. "
            f"File may have been tampered with or was not created by this tool."
        )

    json_bytes     = snap_path.read_bytes()
    stored_sha256  = sha_path.read_text(encoding="utf-8").strip()
    computed_sha256 = _snapshot_sha256(json_bytes)

    if computed_sha256 != stored_sha256:
        raise IntegrityError(
            f"Baseline integrity check failed for {session_id}. "
            f"Stored sha256: {stored_sha256[:16]}... "
            f"Computed sha256: {computed_sha256[:16]}... "
            f"File may have been modified after capture."
        )

    return json.loads(json_bytes)


# ---------------------------------------------------------------------------
# Probe script — STATIC CONSTANT
# SESSION_ID is passed as $1 via --parameters; it is not interpolated here.
# Always collects both IPv4 and IPv6 (no family-based interpolation).
# ---------------------------------------------------------------------------

_PROBE_SCRIPT = r"""#!/bin/bash
set -euo pipefail

SESSION_ID="$1"
SSH_USER="$2"
OUT=$(mktemp /tmp/fw_XXXXXX.txt)
chmod 600 "$OUT"

collect() {
  printf '###SECTION:framework_detection###\n'
  iptables --version 2>&1          || true
  iptables-legacy --version 2>&1   || true
  nft --version 2>&1               || true
  update-alternatives --query iptables 2>&1 || true

  printf '###SECTION:iptables_ipv4###\n'
  if command -v iptables-legacy-save >/dev/null 2>&1; then
    iptables-legacy-save -c 2>&1 || printf '###UNAVAILABLE###\n'
  elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save -c 2>&1        || printf '###UNAVAILABLE###\n'
  else
    printf '###UNAVAILABLE###\n'
  fi

  printf '###SECTION:iptables_ipv6###\n'
  if command -v ip6tables-legacy-save >/dev/null 2>&1; then
    ip6tables-legacy-save -c 2>&1 || printf '###UNAVAILABLE###\n'
  elif command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save -c 2>&1        || printf '###UNAVAILABLE###\n'
  else
    printf '###UNAVAILABLE###\n'
  fi
}

collect > "$OUT" 2>&1

# Transfer ownership to the SSH user so SCP can retrieve the file.
# az vm run-command invoke runs as root; the retrieving SSH session runs as SSH_USER.
# chown failure is non-fatal — file is still readable if SSH_USER happens to be root.
chown "$SSH_USER" "$OUT" 2>/dev/null || true

printf 'PROBE_OUTPUT_PATH=%s\n' "$OUT"
printf 'PROBE_OUTPUT_BYTES=%d\n' "$(wc -c < "$OUT")"
"""

# SHA-256 of _PROBE_SCRIPT — operator can verify against HITL gate display
PROBE_SCRIPT_SHA256 = hashlib.sha256(_PROBE_SCRIPT.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Section parser
# ---------------------------------------------------------------------------

def _parse_probe_sections(text: str) -> dict[str, str]:
    """
    Split probe output into named sections using the ###SECTION:name### protocol.
    Returns dict mapping section name to content string.
    ###UNAVAILABLE### content is preserved as-is for the caller to handle.
    """
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    for line in text.splitlines():
        if line.startswith("###SECTION:") and line.endswith("###"):
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines)
            current_name  = line[len("###SECTION:"):-3]
            current_lines = []
        else:
            current_lines.append(line)

    if current_name is not None:
        sections[current_name] = "\n".join(current_lines)

    return sections


def _section_available(content: str) -> bool:
    """Return False if the section content is the ###UNAVAILABLE### marker."""
    return content.strip() != "###UNAVAILABLE###"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class InspectorConfig:
    ssh_user:             str
    target_vm_ip:         str          # public IP (Case 1) or private IP (Case 2)
    ssh_key_path:         str          # SSH key for the target VM
    session_id:           str
    audit_dir:            str
    vm_name:              str = ""     # Azure VM name; may be empty for --provider ssh
    resource_group:       str = ""     # Azure resource group; may be empty for --provider ssh
    provider:             str = "azure"        # "azure" | "ssh"
    subscription_id:      str | None = None    # Azure subscription; uses az default if omitted
    bastion_public_ip:    str | None = None    # Case 2 only
    bastion_ssh_key_path: str | None = None    # Case 2 only; defaults to ssh_key_path
    is_baseline:          bool  = False
    compare_baseline:     str | None = None    # session_id of baseline to compare
    family:               str  = "ipv4"        # "ipv4" | "ipv6" | "both"
    parse_warnings:       list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run(config: InspectorConfig, shell: Any, provider: Any) -> dict:
    """
    Full inspector pipeline:
      1. Run probe on VM
      2. Retrieve output via SCP (Case 1: direct; Case 2: via bastion)
      3. Parse sections
      4. Detect framework
      5. Parse iptables output for requested family
      6. Build snapshot
      7. If --is-baseline: save snapshot + sha256 companion
      8. If --compare-baseline: load baseline, diff, classify, save drift report
      9. Return result dict
    """
    # Validate session_id first — before any shell command or file path is constructed.
    # main() also validates, but run() must validate independently so that direct callers
    # (e.g., Ghost Agent) cannot bypass this check.
    validate_session_id(config.session_id)

    # Use vm_name when set; fall back to target_vm_ip for display (--provider ssh, no vm_name).
    target_label = config.vm_name or config.target_vm_ip

    print(f"[1/5] Running probe on {target_label} (session: {config.session_id}) ...")
    probe_info = provider.run_probe(
        vm_name=target_label,
        session_id=config.session_id,
        ssh_user=config.ssh_user,
        probe_script=_PROBE_SCRIPT,
    )
    remote_path = probe_info["probe_output_path"]
    print(f"      Probe output: {remote_path} ({probe_info['probe_output_bytes']} bytes)")

    # Retrieve output file to local temp path
    print(f"[2/5] Retrieving probe output from {config.target_vm_ip} ...")
    local_tmp: str | None = None
    try:
        fd, local_tmp = tempfile.mkstemp(suffix=".txt", prefix="fw_local_")
        os.close(fd)
        os.chmod(local_tmp, 0o600)

        provider.retrieve_probe_output(
            remote_path=remote_path,
            local_path=local_tmp,
        )

        probe_text = Path(local_tmp).read_text(encoding="utf-8", errors="replace")
    finally:
        # Clean up local temp file
        if local_tmp and Path(local_tmp).exists():
            try:
                Path(local_tmp).unlink()
            except OSError:
                pass
        # Clean up remote temp file — failure is a warning, not an abort
        try:
            ok = provider.cleanup_probe_output(remote_path=remote_path)
            if not ok:
                config.parse_warnings.append(
                    f"Remote cleanup of {remote_path} on {config.target_vm_ip} "
                    f"failed. File will be reclaimed by tmpfiles/tmpwatch (~24h TTL)."
                )
        except Exception as exc:
            config.parse_warnings.append(f"Cleanup warning: {exc}")

    print(f"[3/5] Parsing probe output ...")
    sections = _parse_probe_sections(probe_text)

    # Framework detection
    fw_section   = sections.get("framework_detection", "")
    fw_result    = detect_framework(_extract_version_strings(fw_section))
    config.parse_warnings.extend(fw_result.get("parse_warnings", []))
    print(f"      Framework: {fw_result['framework']} (confidence: {fw_result['confidence']})")

    # Parse iptables output
    print(f"[4/5] Parsing iptables rules (family: {config.family}) ...")
    parsed = {}
    families = ["ipv4", "ipv6"] if config.family == "both" else [config.family]
    for fam in families:
        section_key = f"iptables_{fam}"
        content     = sections.get(section_key, "")
        if not _section_available(content):
            config.parse_warnings.append(
                f"iptables {fam} output unavailable on {target_label}."
            )
            parsed[fam] = None
            print(f"      [{fam}] unavailable")
        else:
            parsed[fam] = parse_iptables_save(content, family=fam)
            n_tables = len(parsed[fam].get("tables", {}))
            print(f"      [{fam}] {n_tables} table(s) parsed")

    if config.parse_warnings:
        for w in config.parse_warnings:
            print(f"  [warn] {w}")

    # Build snapshot
    snapshot_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    snapshot = {
        "snapshot_at":          snapshot_at,
        "session_id":           config.session_id,
        "vm_name":              config.vm_name,
        "resource_group":       config.resource_group,
        "family":               config.family,
        "framework":            fw_result["framework"],
        "framework_confidence": fw_result["confidence"],
        "probe_script_sha256":  PROBE_SCRIPT_SHA256,
        "parse_warnings":       config.parse_warnings,
        "rulesets":             parsed,
    }

    result: dict = {"snapshot": snapshot}

    print(f"[5/5] Saving results ...")
    # Save baseline
    if config.is_baseline:
        snap_path = save_snapshot(snapshot, config.audit_dir, config.session_id)
        result["baseline_saved"] = snap_path
        result["probe_script_sha256"] = PROBE_SCRIPT_SHA256
        print(f"      Baseline saved: {snap_path}")
    elif not config.compare_baseline:
        print(f"      Snapshot captured (not saved). Use --is-baseline to save or --compare-baseline to diff.")

    # Compare to baseline
    if config.compare_baseline:
        print(f"      Comparing against baseline: {config.compare_baseline}")
        baseline = load_snapshot(config.audit_dir, config.compare_baseline)
        drift_reports: dict = {}
        for fam in families:
            b_ruleset = (baseline.get("rulesets") or {}).get(fam)
            c_ruleset = parsed.get(fam)
            if b_ruleset is None or c_ruleset is None:
                drift_reports[fam] = {
                    "error": f"Cannot diff {fam}: one or both rulesets unavailable."
                }
                continue
            diff   = diff_rulesets(b_ruleset, c_ruleset)
            diff_c = classify_diff(diff)
            drift_reports[fam] = diff_c

        drift = {
            "diff_at":           snapshot_at,
            "session_id":        config.session_id,
            "vm_name":           config.vm_name,
            "resource_group":    config.resource_group,
            "baseline_session":  config.compare_baseline,
            "probe_script_sha256": PROBE_SCRIPT_SHA256,
            "drift_by_family":   drift_reports,
        }
        drift_path = _write_artifact(drift, config.audit_dir, config.session_id, "drift")
        result["drift_report"] = drift_path
        result["drift"]        = drift
        _print_drift_summary(drift)

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_version_strings(fw_section: str) -> dict[str, str]:
    """Split framework_detection section into component version strings."""
    parts: dict[str, str] = {
        "iptables":            "",
        "iptables_legacy":     "",
        "nft":                 "",
        "update_alternatives": "",
    }
    lines = fw_section.splitlines()
    ua_lines: list[str] = []
    in_ua = False

    for line in lines:
        if line.startswith("iptables v"):
            if not parts["iptables"]:
                parts["iptables"] = line
        elif line.startswith("iptables-legacy"):
            if not parts["iptables_legacy"]:
                parts["iptables_legacy"] = line
        elif line.startswith("nftables"):
            if not parts["nft"]:
                parts["nft"] = line
        elif line.startswith("Name: iptables") or in_ua:
            in_ua = True
            ua_lines.append(line)

    if ua_lines:
        parts["update_alternatives"] = "\n".join(ua_lines)

    return parts


def _write_artifact(data: dict, audit_dir: str, session_id: str, suffix: str) -> str:
    Path(audit_dir).mkdir(parents=True, exist_ok=True)
    path = Path(audit_dir) / f"{session_id}_{suffix}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)


def _print_drift_summary(drift: dict) -> None:
    any_drift = False
    any_critical = False
    for fam, report in drift.get("drift_by_family", {}).items():
        if "error" in report:
            print(f"  [{fam}] ERROR: {report['error']}")
            continue
        d = report.get("drift_detected", False)
        c = report.get("has_critical_changes", False)
        if d:
            any_drift = True
        if c:
            any_critical = True
        s = report.get("summary", {})
        print(
            f"  [{fam}] drift={d} critical={c} "
            f"rules_added={s.get('rules_added', 0)} "
            f"rules_removed={s.get('rules_removed', 0)} "
            f"policy_changes={s.get('policy_changes', 0)}"
        )
    if not any_drift:
        print("  No drift detected.")
    elif any_critical:
        print("  CRITICAL changes detected — review drift report.")


# ---------------------------------------------------------------------------
# Config file loading
# ---------------------------------------------------------------------------

def _parse_config_value(raw: str) -> str:
    """Extract the value from a raw config.env assignment RHS.

    Handles:
    - Quoted values:   KEY="value"  or  KEY='value'
    - Inline comments: KEY="value"  # comment  (comment stripped)
    - Unquoted values: KEY=value    # comment  (comment stripped)
    - Env var expansion: KEY="${HOME}/path"  →  expanded path
    """
    raw = raw.strip()
    if raw.startswith('"'):
        end = raw.find('"', 1)
        value = raw[1:end] if end != -1 else raw[1:]
    elif raw.startswith("'"):
        end = raw.find("'", 1)
        value = raw[1:end] if end != -1 else raw[1:]
    else:
        if "#" in raw:
            raw = raw[:raw.index("#")].rstrip()
        value = raw
    return os.path.expandvars(value)


def _load_config_file(path: str) -> dict:
    """Parse a KEY=VALUE config file into argparse-compatible defaults.

    Lines starting with # and blank lines are ignored.
    Keys map to argparse dest names; values are coerced to the correct type.
    CLI flags always override values from the config file.
    """
    _KEY_MAP = {
        "VM_NAME":              ("vm_name",              str),
        "RESOURCE_GROUP":       ("resource_group",        str),
        "SUBSCRIPTION_ID":      ("subscription_id",       str),
        "TARGET_VM_IP":         ("target_vm_ip",          str),
        "TARGET_SSH_KEY_PATH":  ("target_ssh_key",        str),
        "BASTION_PUBLIC_IP":    ("bastion_public_ip",     str),
        "BASTION_SSH_KEY_PATH": ("bastion_ssh_key",       str),
        "SSH_USER":             ("ssh_user",              str),
        "AUDIT_DIR":            ("audit_dir",             str),
        "SESSION_ID":           ("session_id",            str),
        "IS_BASELINE":          ("is_baseline",           lambda v: v.strip().lower() in ("true", "1", "yes")),
        "COMPARE_BASELINE":     ("compare_baseline",      str),
        "FAMILY":               ("family",                str),
        "PROVIDER":             ("provider",              str),
    }
    defaults: dict = {}
    try:
        with open(path) as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    print(f"Warning: config.env line {lineno} skipped (no '=' found): {line!r}")
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = _parse_config_value(value)
                if key not in _KEY_MAP:
                    print(f"Warning: config.env line {lineno}: unknown key {key!r} (ignored)")
                    continue
                dest, coerce = _KEY_MAP[key]
                try:
                    defaults[dest] = coerce(value)
                except (ValueError, TypeError) as e:
                    print(f"Warning: config.env line {lineno}: cannot parse {key}={value!r}: {e}")
    except OSError as e:
        print(f"Error: cannot read config file {path!r}: {e}", file=sys.stderr)
        sys.exit(1)
    return defaults


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list | None = None) -> None:
    from providers import LocalShell, AzureProvider, SSHProvider

    if argv is None:
        argv = sys.argv[1:]

    # Pre-parse to find --config and --provider before constructing the full parser.
    # --config: lets config file values act as defaults while CLI flags override them.
    # --provider: determines which positional args are required (azure needs vm-name
    #             and resource-group; ssh does not).
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", default=None)
    pre_parser.add_argument("--provider", default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    config_defaults: dict = {}
    if pre_args.config:
        config_defaults = _load_config_file(pre_args.config)

    # Effective provider: CLI flag overrides config file, config file overrides default.
    effective_provider = pre_args.provider or config_defaults.get("provider", "azure")

    # Required flags become optional when the config file supplies the value.
    # vm_name and resource_group are also not required for --provider ssh.
    def _req(key: str) -> bool:
        if effective_provider == "ssh" and key in ("vm_name", "resource_group"):
            return False
        return key not in config_defaults

    parser = argparse.ArgumentParser(
        description=(
            "Capture and diff OS-layer firewall state from a VM.\n"
            "Supports Azure VMs (--provider azure, default) and any SSH-accessible\n"
            "Linux host such as Multipass VMs (--provider ssh)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", default=None, metavar="FILE",
        help="Path to a KEY=VALUE config file. CLI flags override config file values.",
    )
    parser.add_argument(
        "--provider", choices=["azure", "ssh"], default="azure",
        help=(
            "Target provider: 'azure' (default) uses az vm run-command invoke to run the probe; "
            "'ssh' connects directly via SSH — use for Multipass VMs, bare metal, or any "
            "SSH-accessible Linux host where az CLI is not available. "
            "(config: PROVIDER)"
        ),
    )
    parser.add_argument(
        "--vm-name", required=_req("vm_name"), default="",
        help=(
            "Azure VM name to inspect. Required for --provider azure. "
            "Optional for --provider ssh (used as a display label only). "
            "(config: VM_NAME)"
        ),
    )
    parser.add_argument(
        "--resource-group", required=_req("resource_group"), default="",
        help=(
            "Azure resource group that contains the VM. Required for --provider azure. "
            "Not used for --provider ssh. "
            "(config: RESOURCE_GROUP)"
        ),
    )
    parser.add_argument(
        "--subscription-id", default=None,
        help=(
            "Azure subscription ID. "
            "If omitted, the currently active subscription (az account set) is used. "
            "Required when your account has multiple subscriptions. "
            "Not used for --provider ssh. "
            "(config: SUBSCRIPTION_ID)"
        ),
    )
    parser.add_argument(
        "--target-vm-ip", required=_req("target_vm_ip"),
        help=(
            "IP address of the VM to inspect. "
            "Azure Case 1 (direct access): use the VM's public IP. "
            "Azure Case 2 (via bastion): use the VM's private IP. "
            "SSH provider: use the VM's IP (e.g. from 'multipass info <name>'). "
            "(config: TARGET_VM_IP)"
        ),
    )
    parser.add_argument(
        "--target-ssh-key",
        default=os.environ.get("INSPECTOR_VM_KEY", os.path.expanduser("~/.ssh/id_rsa")),
        help=(
            "Path to the SSH private key for the target VM. "
            "Defaults to $INSPECTOR_VM_KEY or ~/.ssh/id_rsa. "
            "(config: TARGET_SSH_KEY_PATH)"
        ),
    )
    parser.add_argument(
        "--bastion-public-ip", default=None,
        help=(
            "Public IP of the bastion (jump) host. "
            "Azure Case 2 only (target has no public IP). "
            "Omit for direct access (Azure Case 1 or --provider ssh). "
            "(config: BASTION_PUBLIC_IP)"
        ),
    )
    parser.add_argument(
        "--bastion-ssh-key", default=None,
        help=(
            "Path to the SSH private key for the bastion host. "
            "Case 2 only. If omitted, --target-ssh-key is used for both hops. "
            "(config: BASTION_SSH_KEY_PATH)"
        ),
    )
    parser.add_argument(
        "--ssh-user", default="azureuser",
        help=(
            "SSH username for the target VM (and bastion host when used). "
            "Default: azureuser (Azure). Use 'ubuntu' for Multipass VMs. "
            "(config: SSH_USER)"
        ),
    )
    parser.add_argument(
        "--audit-dir", default="./audit",
        help="Directory where snapshots and drift reports are written. (config: AUDIT_DIR, default: ./audit)",
    )
    parser.add_argument(
        "--session-id", default=None,
        help=(
            "Override the auto-generated session ID. "
            "Must match ^[a-zA-Z0-9_-]{1,64}$. "
            "Auto-generated format: fw_YYYYMMDD_HHMMSS. "
            "(config: SESSION_ID)"
        ),
    )
    parser.add_argument(
        "--is-baseline", action="store_true",
        help="Capture and save this snapshot as the baseline. (config: IS_BASELINE=true)",
    )
    parser.add_argument(
        "--compare-baseline", default=None, metavar="SESSION_ID",
        help="Session ID of a previously saved baseline to diff against. (config: COMPARE_BASELINE)",
    )
    parser.add_argument(
        "--family", choices=["ipv4", "ipv6", "both"], default="ipv4",
        help="Address family to inspect: ipv4 | ipv6 | both. (config: FAMILY, default: ipv4)",
    )

    parser.set_defaults(**config_defaults)
    args = parser.parse_args(argv)

    # argparse choices= only validates values parsed from argv, not set_defaults values.
    # Validate explicitly so PROVIDER=bad_value in config.env is caught here, not silently
    # misrouted to the SSHProvider branch.
    if args.provider not in ("azure", "ssh"):
        parser.error(
            f"Invalid PROVIDER value {args.provider!r}. Must be 'azure' or 'ssh'. "
            f"Check your config file or --provider flag."
        )

    # Validate: --provider azure requires vm-name and resource-group
    if args.provider == "azure":
        missing = []
        if not args.vm_name:
            missing.append("--vm-name / VM_NAME")
        if not args.resource_group:
            missing.append("--resource-group / RESOURCE_GROUP")
        if missing:
            parser.error(
                f"--provider azure requires: {', '.join(missing)}"
            )

    session_id = (
        args.session_id
        or f"fw_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    )

    # Validate session_id before constructing anything else
    validate_session_id(session_id)

    config = InspectorConfig(
        ssh_user             = args.ssh_user,
        target_vm_ip         = args.target_vm_ip,
        ssh_key_path         = args.target_ssh_key,
        session_id           = session_id,
        audit_dir            = args.audit_dir,
        vm_name              = args.vm_name,
        resource_group       = args.resource_group,
        provider             = args.provider,
        subscription_id      = args.subscription_id,
        bastion_public_ip    = args.bastion_public_ip,
        bastion_ssh_key_path = args.bastion_ssh_key,
        is_baseline          = args.is_baseline,
        compare_baseline     = args.compare_baseline,
        family               = args.family,
    )

    shell = LocalShell(audit_dir=args.audit_dir, session_id=session_id)

    if args.provider == "azure":
        provider = AzureProvider(
            shell                = shell,
            resource_group       = args.resource_group,
            subscription_id      = args.subscription_id,
            ssh_user             = args.ssh_user,
            target_vm_ip         = args.target_vm_ip,
            target_ssh_key_path  = args.target_ssh_key,
            bastion_public_ip    = args.bastion_public_ip,
            bastion_ssh_key_path = args.bastion_ssh_key,
        )
    else:  # ssh
        provider = SSHProvider(
            shell                = shell,
            ssh_user             = args.ssh_user,
            target_vm_ip         = args.target_vm_ip,
            target_ssh_key_path  = args.target_ssh_key,
            bastion_public_ip    = args.bastion_public_ip,
            bastion_ssh_key_path = args.bastion_ssh_key,
        )

    try:
        result = run(config, shell, provider)
    except IntegrityError as exc:
        print(f"[ERROR] Baseline integrity check failed: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    if "drift_report" in result:
        print(f"      Drift report: {result['drift_report']}")


if __name__ == "__main__":
    main()
