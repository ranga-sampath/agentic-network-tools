"""
effective_network_inspector.py — Effective Network Inspector

Snapshots and diffs Azure control-plane computed network state for one or more NICs:
    - Effective route table (az network nic show-effective-route-table)
    - Effective NSG evaluation (az network nic list-effective-nsg)

Two classes of failure invisible to every other Azure tool:
    BGP route withdrawal   — VirtualNetworkGateway-sourced routes disappear in the diff.
    NSG evaluation drift   — subnet NSG deny at priority 100 overrides NIC NSG allow.

This tool is Layer 0 in Ghost Agent's investigation hierarchy: the first call
for any "nothing changed but it broke" or post-incident scenario.

Usage (standalone):
    python effective_network_inspector.py --config config.env [flags]

Key flags:
    --config FILE           KEY=VALUE config file (see KEY_MAP in _load_config_file)
    --scope vm|vnet         Snapshot scope (default: vm)
    --vm-name NAME          VM name for --scope vm
    --vnet-id RESOURCE_ID   VNet resource ID for --scope vnet
    --resource-group RG     Azure resource group
    --is-baseline           Store this snapshot as baseline
    --compare-baseline SID  Session ID of baseline to diff against
    --session-id ID         Override auto-generated session ID (eni_YYYYMMDD_HHMMSS)
    --audit-dir PATH        Artifact output directory (default: ./audit)

RBAC note:
    az network nic show-effective-route-table requires
        Microsoft.Network/networkInterfaces/effectiveRouteTable/action
    az network nic list-effective-nsg requires
        Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action
    Neither is in the built-in Reader role. Network Contributor includes both.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from providers import LocalShell, AzureNetworkProvider, ProviderError, RBACError, ThrottleExhausted
from diff import extract_routes, extract_nsg_rules, compute_diff


# ---------------------------------------------------------------------------
# session_id validation
# ---------------------------------------------------------------------------

_SESSION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_session_id(session_id: str) -> None:
    """
    Raise ValueError if session_id contains characters outside [a-zA-Z0-9_-]
    or exceeds 64 characters.

    Called before any shell command or file path is constructed.
    """
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError(
            f"Invalid session_id {session_id!r}. "
            f"Must match ^[a-zA-Z0-9_-]{{1,64}}$. "
            f"Use only letters, digits, underscores, and hyphens, max 64 characters."
        )


# ---------------------------------------------------------------------------
# Snapshot integrity
# ---------------------------------------------------------------------------

class IntegrityError(Exception):
    """Raised when a snapshot file fails SHA-256 integrity verification."""


def _snapshot_sha256(json_bytes: bytes) -> str:
    return hashlib.sha256(json_bytes).hexdigest()


def save_snapshot(snapshot: dict, audit_dir: str, session_id: str) -> str:
    """
    Write snapshot JSON and SHA-256 companion file to audit_dir.

    Files written:
        {audit_dir}/{session_id}_snapshot.json
        {audit_dir}/{session_id}_snapshot.json.sha256

    Returns the path to the snapshot JSON file.
    """
    Path(audit_dir).mkdir(parents=True, exist_ok=True)
    snap_path = Path(audit_dir) / f"{session_id}_snapshot.json"
    sha_path  = Path(audit_dir) / f"{session_id}_snapshot.json.sha256"

    json_bytes = json.dumps(snapshot, indent=2).encode("utf-8")
    sha256     = _snapshot_sha256(json_bytes)

    try:
        snap_path.write_bytes(json_bytes)
        # GNU sha256sum format: "{digest}  {filename}\n" (two spaces)
        # Verifiable externally with: sha256sum -c {session_id}_snapshot.json.sha256
        sha_path.write_text(f"{sha256}  {snap_path.name}\n", encoding="utf-8")
    except OSError as e:
        raise OSError(f"Failed to write snapshot for session {session_id} to {audit_dir}: {e}") from e
    return str(snap_path)


def load_snapshot(audit_dir: str, session_id: str) -> dict:
    """
    Load a snapshot and verify its SHA-256 companion.

    Raises:
        FileNotFoundError  — snapshot JSON missing
        IntegrityError     — SHA-256 companion missing, or hash mismatch
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

    json_bytes      = snap_path.read_bytes()
    # Parse digest from first whitespace-delimited token (handles both legacy
    # plain-digest format and the GNU sha256sum "{digest}  {filename}" format)
    stored_sha256   = sha_path.read_text(encoding="utf-8").split()[0]
    computed_sha256 = _snapshot_sha256(json_bytes)

    if computed_sha256 != stored_sha256:
        raise IntegrityError(
            f"Baseline integrity check failed for {session_id}. "
            f"Stored:   {stored_sha256[:16]}... "
            f"Computed: {computed_sha256[:16]}... "
            f"File may have been modified after capture."
        )

    return json.loads(json_bytes)


def _write_artifact(data: dict, audit_dir: str, session_id: str, suffix: str) -> str:
    Path(audit_dir).mkdir(parents=True, exist_ok=True)
    path = Path(audit_dir) / f"{session_id}_{suffix}.json"
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError as e:
        raise OSError(f"Failed to write {suffix} artifact to {path}: {e}") from e
    return str(path)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class InspectorConfig:
    session_id:       str
    audit_dir:        str
    resource_group:   str
    scope:            str           # "vm" | "vnet"
    scope_target:     str           # vm_name (scope=vm) or vnet_id (scope=vnet)
    subscription_id:  str | None = None
    is_baseline:      bool = False
    compare_baseline: str | None = None
    max_workers:      int = 4       # ThreadPoolExecutor thread count (and API semaphore slots)

    def __post_init__(self) -> None:
        if self.scope not in ("vm", "vnet"):
            raise ValueError(
                f"InspectorConfig.scope must be 'vm' or 'vnet', got {self.scope!r}"
            )
        if not self.scope_target:
            raise ValueError(
                f"InspectorConfig.scope_target is required for scope={self.scope!r}. "
                f"Set --vm-name (scope=vm) or --vnet-id (scope=vnet)."
            )
        if not self.resource_group:
            raise ValueError("InspectorConfig.resource_group is required.")


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run(config: InspectorConfig, provider: AzureNetworkProvider) -> dict:
    """
    Full inspector pipeline:
      1. Validate session_id
      2. Discover NICs in scope
      3. For each NIC: get effective routes + effective NSG rules
      4. Build snapshot
      5. If --is-baseline: save snapshot + SHA-256 companion
      6. If --compare-baseline: load baseline, diff, save diff artifact
      7. Return result dict
    """
    validate_session_id(config.session_id)

    # ------------------------------------------------------------------
    # Step 1: Discover NICs
    # ------------------------------------------------------------------
    total_steps = 4 if config.compare_baseline else 3
    print(f"[1/{total_steps}] Discovering NICs (scope: {config.scope} / {config.scope_target}) ...")
    try:
        if config.scope == "vm":
            nic_names = provider.get_nic_names_for_vm(config.scope_target)
        else:
            nic_names = provider.get_nic_names_for_vnet(config.scope_target)
    except RuntimeError as exc:
        print(f"[ERROR] NIC discovery failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if not nic_names:
        print(
            f"[WARN] No NICs found for scope {config.scope}={config.scope_target}. "
            f"Snapshot will be empty.",
            file=sys.stderr,
        )
    else:
        print(f"      Found {len(nic_names)} NIC(s): {', '.join(nic_names)}")

    # ------------------------------------------------------------------
    # Step 2: Query effective state for each NIC (concurrent)
    # ------------------------------------------------------------------
    print(f"[2/{total_steps}] Querying effective network state ...")
    print(f"      (az effective-route-table can take 30–60 s per NIC; "
          f"running up to {config.max_workers} NIC queries in parallel) ...", flush=True)

    total_nics   = len(nic_names)
    progress_lock = threading.Lock()
    completed_count = [0]  # mutable counter shared across threads via list

    # Semaphore limits concurrent az CLI calls regardless of thread count.
    # A thread can be alive (processing a result) without holding a slot.
    api_semaphore = threading.Semaphore(config.max_workers)

    def _query_nic(nic_name: str) -> dict:
        entry: dict = {
            "nic_name":           nic_name,
            "effective_routes":   [],
            "effective_nsg_rules": [],
            "error":              None,
        }

        # Routes
        with api_semaphore:
            try:
                routes_json = provider.get_effective_routes_json(nic_name)
                entry["effective_routes"] = extract_routes(routes_json)
            except (ProviderError, RuntimeError) as exc:
                entry["error"] = str(exc)

        # NSG — skip if routes already failed
        if not entry["error"]:
            with api_semaphore:
                try:
                    nsg_json = provider.get_effective_nsg_json(nic_name)
                    entry["effective_nsg_rules"] = extract_nsg_rules(nsg_json)
                except (ProviderError, RuntimeError) as exc:
                    entry["error"] = str(exc)

        # Progress output — serialized so lines don't interleave
        with progress_lock:
            completed_count[0] += 1
            n = completed_count[0]

        if entry["error"]:
            print(f"      Snapshotting NIC {n}/{total_nics}: {nic_name} — ERROR",
                  file=sys.stderr)
        else:
            print(
                f"      Snapshotting NIC {n}/{total_nics}: {nic_name} "
                f"(routes: {len(entry['effective_routes'])}, "
                f"nsg_rules: {len(entry['effective_nsg_rules'])})"
            )

        return entry

    nic_entry_by_name: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
        futures = {executor.submit(_query_nic, name): name for name in nic_names}
        for future in as_completed(futures):
            nic_name = futures[future]
            try:
                nic_entry_by_name[nic_name] = future.result()
            except Exception as exc:
                # _query_nic catches all ProviderError/RuntimeError internally;
                # this safety net handles truly unexpected thread failures.
                nic_entry_by_name[nic_name] = {
                    "nic_name":            nic_name,
                    "effective_routes":    [],
                    "effective_nsg_rules": [],
                    "error":               f"Unexpected thread error: {exc}",
                }

    # Restore original NIC ordering for deterministic snapshot output
    nic_snapshots = [nic_entry_by_name[name] for name in nic_names]

    # Collect warnings from errored NIC entries
    parse_warnings = [
        f"{e['nic_name']}: {e['error']}"
        for e in nic_snapshots
        if e.get("error")
    ]
    if parse_warnings:
        for w in parse_warnings:
            print(f"  [warn] {w}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Step 3: Build snapshot
    # ------------------------------------------------------------------
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    snapshot = {
        "session_id":     config.session_id,
        "scope":          config.scope,
        "scope_target":   config.scope_target,
        "resource_group": config.resource_group,
        "timestamp":      timestamp,
        "nics":           nic_snapshots,
        "parse_warnings": parse_warnings,
    }

    result: dict = {"snapshot": snapshot}

    # ------------------------------------------------------------------
    # Step 4: Save or diff
    # ------------------------------------------------------------------
    print(f"[3/{total_steps}] Saving results ...")
    if config.is_baseline:
        snap_path = save_snapshot(snapshot, config.audit_dir, config.session_id)
        result["mode"]          = "baseline"
        result["session_id"]    = config.session_id
        result["baseline_saved"] = snap_path
        print(f"      Baseline saved: {snap_path}")
    elif not config.compare_baseline:
        print(
            f"      Snapshot captured (not saved). "
            f"Use --is-baseline to save or --compare-baseline to diff."
        )

    if config.compare_baseline:
        print(f"[4/{total_steps}] Comparing against baseline: {config.compare_baseline} ...")
        baseline = load_snapshot(config.audit_dir, config.compare_baseline)

        # Self-compare guard
        if baseline.get("session_id") == config.session_id:
            print(
                f"[ERROR] compare_baseline session_id matches the current session_id "
                f"({config.session_id}). Comparing a snapshot to itself is not valid.",
                file=sys.stderr,
            )
            sys.exit(1)

        diff = compute_diff(baseline, snapshot)
        diff_stem = f"{config.compare_baseline}_vs_{config.session_id}"
        diff_path = _write_artifact(diff, config.audit_dir, diff_stem, "diff")
        result["mode"]        = "compare"
        result["diff_report"] = diff_path
        result["diff"]        = diff
        _print_diff_summary(diff)

    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_diff_summary(diff: dict) -> None:
    drift = diff.get("drift_detected", False)
    count = diff.get("changes_count", 0)
    by_cat = diff.get("changes_by_category", {})

    if not drift:
        print("      drift_detected: false — no changes between baseline and current.")
        return

    print(f"      drift_detected: true — {count} change(s)")
    for cat, n in sorted(by_cat.items()):
        print(f"        {cat}: {n}")
    for nic_diff in diff.get("nic_diffs", []):
        nic = nic_diff["nic_name"]
        for ch in nic_diff["changes"]:
            ctype = ch["change_type"]
            cat   = ch["category"]
            if "route" in ch:
                prefix = ch["route"].get("addressPrefix", "")
                source = ch["route"].get("source", "")
                print(f"        [{nic}] {ctype} {cat}: {prefix} (source: {source})")
            elif "route_after" in ch:
                prefix = ch["route_after"].get("addressPrefix", "")
                print(f"        [{nic}] changed {cat}: {prefix}")
            elif "rule" in ch:
                rname = ch["rule"].get("name", "")
                rdir  = ch["rule"].get("direction", "")
                print(f"        [{nic}] {ctype} {cat}: {rname} ({rdir})")
            elif "rule_after" in ch:
                rname = ch["rule_after"].get("name", "")
                print(f"        [{nic}] changed {cat}: {rname}")


# ---------------------------------------------------------------------------
# Config file loading
# ---------------------------------------------------------------------------

def _parse_config_value(raw: str) -> str:
    """Extract value from config.env assignment RHS.

    Handles quoted values, inline comments, unquoted values, and ${HOME} expansion.
    Copied from firewall_inspector._parse_config_value — identical logic.
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

    Unknown keys are warned and ignored. CLI flags always override config file values.
    """
    _KEY_MAP = {
        "RESOURCE_GROUP":   ("resource_group",   str),
        "SUBSCRIPTION_ID":  ("subscription_id",  str),
        "SCOPE":            ("scope",             str),
        "VM_NAME":          ("vm_name",           str),
        "VNET_ID":          ("vnet_id",           str),
        "AUDIT_DIR":        ("audit_dir",         str),
        "SESSION_ID":       ("session_id",        str),
        "IS_BASELINE":      ("is_baseline",       lambda v: v.strip().lower() in ("true", "1", "yes")),
        "COMPARE_BASELINE": ("compare_baseline",  str),
        "MAX_WORKERS":      ("max_workers",        int),
    }
    defaults: dict = {}
    try:
        with open(path) as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    print(f"Warning: config line {lineno} skipped (no '='): {line!r}", file=sys.stderr)
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = _parse_config_value(value)
                if key not in _KEY_MAP:
                    print(f"Warning: config line {lineno}: unknown key {key!r} (ignored)", file=sys.stderr)
                    continue
                dest, coerce = _KEY_MAP[key]
                try:
                    defaults[dest] = coerce(value)
                except (ValueError, TypeError) as e:
                    print(f"Warning: config line {lineno}: cannot parse {key}={value!r}: {e}", file=sys.stderr)
    except OSError as e:
        print(f"Error: cannot read config file {path!r}: {e}", file=sys.stderr)
        sys.exit(1)
    return defaults


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    # Pre-parse to find --config before constructing the full parser
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    config_defaults: dict = {}
    if pre_args.config:
        config_defaults = _load_config_file(pre_args.config)

    def _req(key: str) -> bool:
        """True if the flag is required (not supplied by config file)."""
        return key not in config_defaults

    parser = argparse.ArgumentParser(
        description=(
            "Snapshot and diff Azure control-plane effective network state.\n"
            "Effective route table + effective NSG evaluation per NIC.\n"
            "RBAC required: Network Contributor on the resource group."
        ),
    )
    parser.add_argument(
        "--config", default=None, metavar="FILE",
        help="Path to a KEY=VALUE config file. CLI flags override config file values.",
    )
    parser.add_argument(
        "--scope", choices=["vm", "vnet"], default="vm",
        help=(
            "Snapshot scope: 'vm' (default) snapshots all NICs on the named VM; "
            "'vnet' snapshots all NICs whose subnets are in the named VNet. "
            "(config: SCOPE)"
        ),
    )
    parser.add_argument(
        "--vm-name", default="",
        help=(
            "Azure VM name. Required for --scope vm. "
            "(config: VM_NAME)"
        ),
    )
    parser.add_argument(
        "--vnet-id", default="",
        help=(
            "Full Azure resource ID of the VNet. Required for --scope vnet. "
            "Format: /subscriptions/.../resourceGroups/.../providers/"
            "Microsoft.Network/virtualNetworks/<name>. "
            "(config: VNET_ID)"
        ),
    )
    parser.add_argument(
        "--resource-group", required=_req("resource_group"), default="",
        help="Azure resource group containing the target VM or VNet. (config: RESOURCE_GROUP)",
    )
    parser.add_argument(
        "--subscription-id", default=None,
        help=(
            "Azure subscription ID. "
            "If omitted, the currently active subscription (az account set) is used. "
            "(config: SUBSCRIPTION_ID)"
        ),
    )
    parser.add_argument(
        "--audit-dir", default="./audit",
        help="Directory for snapshot and diff artifacts. (config: AUDIT_DIR, default: ./audit)",
    )
    parser.add_argument(
        "--session-id", default=None,
        help=(
            "Override the auto-generated session ID. "
            "Must match ^[a-zA-Z0-9_-]{1,64}$. "
            "Auto-generated format: eni_YYYYMMDD_HHMMSS. "
            "(config: SESSION_ID)"
        ),
    )
    parser.add_argument(
        "--is-baseline", action="store_true",
        help="Capture and save this snapshot as the baseline. (config: IS_BASELINE=true)",
    )
    parser.add_argument(
        "--compare-baseline", default=None, metavar="SESSION_ID",
        help="Session ID of a saved baseline to diff against. (config: COMPARE_BASELINE)",
    )
    parser.add_argument(
        "--max-workers", type=int, default=4, metavar="N",
        help=(
            "Maximum concurrent NIC queries (ThreadPoolExecutor threads). "
            "Also controls the API semaphore slot count. "
            "Default: 4. Reduce if hitting Azure 429 throttle errors. "
            "(config: MAX_WORKERS)"
        ),
    )

    parser.set_defaults(**config_defaults)
    args = parser.parse_args(argv)

    # Validate scope-required flags
    effective_scope = args.scope
    if effective_scope == "vm" and not args.vm_name:
        parser.error("--scope vm requires --vm-name / VM_NAME in config")
    if effective_scope == "vnet" and not args.vnet_id:
        parser.error("--scope vnet requires --vnet-id / VNET_ID in config")

    # Validate mode
    if not args.is_baseline and not args.compare_baseline:
        parser.error("One of --is-baseline or --compare-baseline SESSION_ID is required.")

    raw_sid = args.session_id or datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    session_id = raw_sid if raw_sid.startswith("eni_") else f"eni_{raw_sid}"
    validate_session_id(session_id)

    scope_target = args.vm_name if effective_scope == "vm" else args.vnet_id

    raw_compare = args.compare_baseline
    compare_baseline = (
        (raw_compare if raw_compare.startswith("eni_") else f"eni_{raw_compare}")
        if raw_compare else None
    )

    config = InspectorConfig(
        session_id       = session_id,
        audit_dir        = args.audit_dir,
        resource_group   = args.resource_group,
        scope            = effective_scope,
        scope_target     = scope_target,
        subscription_id  = args.subscription_id,
        is_baseline      = args.is_baseline,
        compare_baseline = compare_baseline,
        max_workers      = args.max_workers,
    )

    shell    = LocalShell(audit_dir=args.audit_dir, session_id=session_id)
    provider = AzureNetworkProvider(
        shell            = shell,
        resource_group   = args.resource_group,
        subscription_id  = args.subscription_id,
    )

    try:
        result = run(config, provider)
    except IntegrityError as exc:
        print(f"[ERROR] Baseline integrity check failed: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    if "diff_report" in result:
        print(f"      Diff report: {result['diff_report']}")


if __name__ == "__main__":
    main()
