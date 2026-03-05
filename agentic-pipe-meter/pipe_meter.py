"""Agentic Pipe Meter — CLI entry point and pipeline orchestrator.

Usage:
    python pipe_meter.py \\
        --source-ip 10.0.0.4 --dest-ip 10.0.0.5 --ssh-user azureuser \\
        --test-type both --storage-account mystorage --container pipe-meter-results \\
        --resource-group my-rg [--iterations 8] [--is-baseline] [--session-id ID]

Library entry point (for Ghost Agent integration):
    result = run_pipeline(config, shell, provider)
"""

import argparse
import json
import math
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

# SafeExecShell lives in the sibling agentic-safety-shell package.
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "agentic-safety-shell")
)
from safe_exec_shell import HitlDecision, SafeExecShell  # noqa: E402

from providers import AzureProvider, CloudProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class ParseError(Exception):
    """Raised when qperf or iperf2 output cannot be parsed."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    source_ip: str           # private IP — NSG check and measurement source address
    dest_ip: str             # private IP — SSH target and measurement destination
    ssh_user: str
    test_type: str           # "latency" | "throughput" | "both"
    iterations: int
    is_baseline: bool
    storage_account: str
    container: str
    resource_group: str
    session_id: str
    audit_dir: str
    # Optional infra parameters — sourced from config.env
    source_public_ip: Optional[str] = None   # SSH target for source (falls back to source_ip)
    source_vm_key_path: Optional[str] = None # -i key for source VM hops
    dest_vm_key_path: Optional[str] = None   # -i key for dest VM hops (stays on local Mac)
    subscription_id: Optional[str] = None
    location: Optional[str] = None
    vnet_name: Optional[str] = None
    subnet_name: Optional[str] = None
    source_nsg_name: Optional[str] = None
    dest_nsg_name: Optional[str] = None
    compare_baseline: bool = False  # download + compare with existing baseline


@dataclass
class PreflightResult:
    ports_open: bool
    tools_ready: bool
    actions_taken: list
    blocked_ports: list = field(default_factory=list)


@dataclass
class MeasurementRaw:
    latency_samples: list    # list[float], µs; empty if test_type=="throughput"
    throughput_samples: list # list[float], Gbps; empty if test_type=="latency"
    session_id: str


@dataclass
class ComputedStats:
    latency_p90: Optional[float]
    latency_min: Optional[float]
    latency_max: Optional[float]
    throughput_p90: Optional[float]
    throughput_min: Optional[float]
    throughput_max: Optional[float]
    is_stable: bool
    anomaly_type: Optional[str]   # "CONNECTIVITY_DROP" | "HIGH_VARIANCE" | None


@dataclass
class ComparisonResult:
    stats: ComputedStats
    baseline_p90_latency: Optional[float]
    baseline_p90_throughput: Optional[float]
    baseline_timestamp: Optional[str]
    delta_pct_latency: Optional[float]
    delta_pct_throughput: Optional[float]
    write_as_baseline: bool


@dataclass
class PipelineResult:
    status: str                   # "success" | "aborted_preflight" | "error"
    local_artifact_path: str
    blob_url: str
    session_id: str
    error_message: Optional[str]


# ---------------------------------------------------------------------------
# SSH command templates  (design §7)
# ---------------------------------------------------------------------------

_SSH_BASE_OPTS = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new"


def _make_ssh_opts(
    key_path: Optional[str] = None,
    jump_user: Optional[str] = None,
    jump_host: Optional[str] = None,
    jump_key_path: Optional[str] = None,
) -> str:
    """Return SSH option string.

    key_path      — -i flag for the final-hop connection.
    jump_user / jump_host — route through a jump host.
      * jump_key_path set: uses ProxyCommand (-W %h:%p) so both keys are used
        locally on the Mac — neither private key is forwarded to the jump host.
      * jump_key_path absent: falls back to -J (requires ssh-agent for jump hop).
    """
    opts = _SSH_BASE_OPTS
    if key_path:
        opts += f" -i {key_path}"
    if jump_user and jump_host:
        if jump_key_path:
            proxy_cmd = (
                f"ssh -i {jump_key_path}"
                f" -o StrictHostKeyChecking=accept-new"
                f" -o ConnectTimeout=15"
                f" -o BatchMode=yes"
                f" -W %h:%p {jump_user}@{jump_host}"
            )
            opts += f' -o "ProxyCommand={proxy_cmd}"'
        else:
            opts += f" -J {jump_user}@{jump_host}"
    return opts


def _S1(opts: str, user: str, dest_ip: str) -> str:
    return f'ssh {opts} {user}@{dest_ip} "lsof -ti :5001,:19765 2>/dev/null"'


def _S2(opts: str, user: str, dest_ip: str, pids: list) -> str:
    pids_str = " ".join(pids)
    return f'ssh {opts} {user}@{dest_ip} "kill {pids_str} 2>/dev/null; true"'


def _S3(opts: str, user: str, dest_ip: str, name: str) -> str:
    return f"ssh {opts} {user}@{dest_ip} \"pkill -f '{name}' 2>/dev/null; true\""


def _S4(opts: str, user: str, vm_ip: str, binary: str) -> str:
    return f'ssh {opts} {user}@{vm_ip} "which {binary}"'


def _S5(opts: str, user: str, vm_ip: str) -> str:
    return f'ssh {opts} {user}@{vm_ip} "which apt-get"'


def _S6(opts: str, user: str, vm_ip: str) -> str:
    return f'ssh {opts} {user}@{vm_ip} "sudo apt-get install -y qperf iperf"'


def _S7(opts: str, user: str, vm_ip: str) -> str:
    return f'ssh {opts} {user}@{vm_ip} "sudo yum install -y qperf iperf"'


def _S8(opts: str, user: str, dest_ip: str) -> str:
    return (
        f'ssh {opts} {user}@{dest_ip} '
        f'"nohup qperf </dev/null > /tmp/qperf_server.log 2>&1 & echo $!"'
    )


def _S9(opts: str, user: str, dest_ip: str) -> str:
    return (
        f'ssh {opts} {user}@{dest_ip} '
        f'"nohup iperf -s </dev/null > /tmp/iperf_server.log 2>&1 & echo $!"'
    )


def _S10(opts: str, user: str, source_ip: str, dest_ip: str) -> str:
    return f'ssh {opts} {user}@{source_ip} "qperf {dest_ip} -m 1024 tcp_lat"'


def _S11(opts: str, user: str, source_ip: str, dest_ip: str) -> str:
    return f'ssh {opts} {user}@{source_ip} "iperf -c {dest_ip} -P 8 -t 10"'


def _S12(opts: str, user: str, vm_ip: str) -> str:
    return f'ssh {opts} {user}@{vm_ip} "iperf -v 2>&1"'


# ---------------------------------------------------------------------------
# HITL auto-approve patterns  (design §10)
# ---------------------------------------------------------------------------

_PIPE_METER_AUTO_APPROVE_PATTERNS = [
    # ---- measurement commands (read / client) ----
    re.compile(r"^ssh\s+.*qperf\s+\S+\s+-m\s+1024\s+tcp_lat"),     # S10 latency client
    re.compile(r"^ssh\s+.*iperf\s+-c\s+\S+\s+-P\s+8"),             # S11 throughput client
    re.compile(r"^ssh\s+.*which\s+(qperf|iperf|apt-get|curl)"),      # S4, S5 tool check
    re.compile(r"^ssh\s+.*iperf\s+-v\b"),                           # S12 version check
    re.compile(r"^ssh\s+.*lsof\s+-ti"),                             # S1  stale PID check
    # ---- server lifecycle (start / teardown) ----
    re.compile(r"^ssh\s+.*nohup\s+qperf\b"),                        # S8  qperf server start
    re.compile(r"^ssh\s+.*nohup\s+iperf\s+-s\b"),                   # S9  iperf server start
    re.compile(r"^ssh\s+.*kill\s+[\d ]+2>/dev/null"),               # S2  kill by PID
    re.compile(r"^ssh\s+.*pkill\s+-f\s+"),                          # S3  pkill by name
    # ---- Azure read-only queries ----
    re.compile(r"^az\s+network\s+nic\s+(list|show)"),
    re.compile(r"^az\s+network\s+nic\s+list-effective-nsg"),
    re.compile(r"^az\s+network\s+nsg\s+show"),
    re.compile(r"^az\s+storage\s+blob\s+download"),
    re.compile(r"^az\s+storage\s+blob\s+upload"),
    # ---- blob ops routed through source VM via SSH ----
    re.compile(r"^scp\s+.*pmeter_blob_"),                                    # SCP up/down of temp files
    re.compile(r'^ssh\s+.*"rm\s+-f\s+/tmp/pmeter_blob_'),                   # SSH cleanup of temp files
    re.compile(r'^ssh\s+.*"curl\s+.*blob\.core\.windows\.net'),              # SSH: curl PUT/GET via SAS
    # ---- SAS token generation (runs locally; management plane, not firewalled) ----
    re.compile(r"^az\s+storage\s+account\s+keys\s+list"),                    # fetch account key
    re.compile(r"^az\s+storage\s+blob\s+generate-sas"),                      # compute SAS token locally
]


def _make_hitl_callback() -> Callable:
    """Return a HITL callback for SafeExecShell.

    Measurement and read-only commands are auto-approved.
    All other commands present an operator prompt.
    """
    def hitl_callback(
        command: str, reasoning: str, risk_explanation: str, tier: int
    ) -> HitlDecision:
        for pattern in _PIPE_METER_AUTO_APPROVE_PATTERNS:
            if pattern.search(command):
                return HitlDecision(action="approve")

        print("\n[HITL GATE] Command requires approval:")
        print(f"  Command:   {command}")
        print(f"  Reasoning: {reasoning}")
        if risk_explanation:
            print(f"  Risk:      {risk_explanation}")

        while True:
            try:
                answer = input("  [approve/deny]: ").strip().lower()
            except EOFError:
                # Non-interactive environment — fail closed.
                print("  (non-interactive: denying)")
                return HitlDecision(action="deny")
            if answer in ("approve", "a", "yes", "y"):
                return HitlDecision(action="approve")
            if answer in ("deny", "d", "no", "n"):
                return HitlDecision(action="deny")
            print("  Please enter 'approve' or 'deny'.")

    return hitl_callback


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _generate_session_id() -> str:
    return f"pmeter_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"


def _ip_to_blob_prefix(ip: str) -> str:
    return ip.replace(".", "_")


def _compute_p90(samples: list) -> float:
    """Return sorted(samples)[floor(0.90 * N)]. Caller guarantees len >= 1."""
    sorted_samples = sorted(samples)
    idx = math.floor(0.90 * len(sorted_samples))
    return sorted_samples[idx]


def _apply_gap_rule(samples: list) -> tuple:
    """Return (is_stable, anomaly_type).

    CONNECTIVITY_DROP takes priority over HIGH_VARIANCE.
    """
    mn = min(samples)
    mx = max(samples)
    if mn == 0.0:
        return (False, "CONNECTIVITY_DROP")
    if (mx - mn) / mn > 0.50:
        return (False, "HIGH_VARIANCE")
    return (True, None)


def _write_artifact(path: str, data: dict) -> None:
    """Write a JSON artifact to disk, creating parent directories as needed."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(path, "w") as fh:
            fh.write(json.dumps(data, indent=2, default=str))
    except OSError as e:
        raise RuntimeError(f"Failed to write artifact: {path}: {e}") from e


def _write_manifest(config: PipelineConfig) -> None:
    path = os.path.join(config.audit_dir, f"{config.session_id}_manifest.json")
    _write_artifact(path, {
        "session_id": config.session_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_ip": config.source_ip,
        "dest_ip": config.dest_ip,
        "ssh_user": config.ssh_user,
        "test_type": config.test_type,
        "iterations": config.iterations,
        "is_baseline": config.is_baseline,
        "storage_account": config.storage_account,
        "container": config.container,
        "resource_group": config.resource_group,
    })


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def parse_qperf_latency(output: str) -> float:
    """Extract latency in µs from qperf tcp_lat stdout."""
    m = re.search(r"latency\s*=\s*([\d.]+)\s*(us|µs)", output)
    if m:
        return float(m.group(1))
    m = re.search(r"latency\s*=\s*([\d.]+)\s*ms", output)
    if m:
        return float(m.group(1)) * 1000.0
    raise ParseError(
        f"Cannot parse qperf latency from output: {output[:300]!r}"
    )


def parse_iperf2_throughput(output: str) -> float:
    """Extract aggregate throughput in Gbps from iperf2 [SUM] line."""
    m = re.search(r"\[SUM\].*?([\d.]+)\s+(G|M)bits/sec", output)
    if not m:
        raise ParseError(
            f"Cannot find [SUM] line in iperf2 output: {output[:300]!r}"
        )
    value = float(m.group(1))
    unit = m.group(2)
    return value if unit == "G" else value / 1000.0


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------

def preflight_to_dict(result: PreflightResult) -> dict:
    return {
        "ports_open": result.ports_open,
        "tools_ready": result.tools_ready,
        "actions_taken": result.actions_taken,
        "blocked_ports": result.blocked_ports,
    }


def raw_to_dict(raw: MeasurementRaw) -> dict:
    return {
        "session_id": raw.session_id,
        "latency_samples_us": raw.latency_samples,
        "throughput_samples_gbps": raw.throughput_samples,
    }


def stats_to_dict(stats: ComputedStats) -> dict:
    return {
        "latency_p90": stats.latency_p90,
        "latency_min": stats.latency_min,
        "latency_max": stats.latency_max,
        "throughput_p90": stats.throughput_p90,
        "throughput_min": stats.throughput_min,
        "throughput_max": stats.throughput_max,
        "is_stable": stats.is_stable,
        "anomaly_type": stats.anomaly_type,
    }


def comparison_to_dict(result: ComparisonResult) -> dict:
    d = stats_to_dict(result.stats)
    d.update({
        "baseline_p90_latency": result.baseline_p90_latency,
        "baseline_p90_throughput": result.baseline_p90_throughput,
        "baseline_timestamp": result.baseline_timestamp,
        "delta_pct_latency": result.delta_pct_latency,
        "delta_pct_throughput": result.delta_pct_throughput,
        "write_as_baseline": result.write_as_baseline,
    })
    return d


# ---------------------------------------------------------------------------
# Artifact assembly and console output
# ---------------------------------------------------------------------------

def _assemble_artifact(
    result: ComparisonResult,
    config: PipelineConfig,
    preflight_result: PreflightResult,
) -> dict:
    """Build the final JSON artifact dict per design §3.

    Reads iteration-level data from the _raw.json intermediate artifact
    (already written by measure()) to populate the iteration_data array.
    """
    raw_path = os.path.join(config.audit_dir, f"{config.session_id}_raw.json")
    lat_samples: list = []
    thr_samples: list = []
    try:
        with open(raw_path) as fh:
            raw_data = json.load(fh)
        lat_samples = raw_data.get("latency_samples_us", [])
        thr_samples = raw_data.get("throughput_samples_gbps", [])
    except (OSError, json.JSONDecodeError):
        print(f"Warning: Could not read {raw_path} for iteration_data — artifact will have empty iteration list")

    n = max(len(lat_samples), len(thr_samples))
    iteration_data = []
    for i in range(n):
        entry: dict = {"iteration": i + 1}
        entry["latency_us"] = lat_samples[i] if i < len(lat_samples) else None
        entry["throughput_gbps"] = thr_samples[i] if i < len(thr_samples) else None
        iteration_data.append(entry)

    stats = result.stats
    baseline_found = result.baseline_timestamp is not None

    return {
        "test_metadata": {
            "session_id": config.session_id,
            "source_ip": config.source_ip,
            "destination_ip": config.dest_ip,
            "ssh_user": config.ssh_user,
            "test_type": config.test_type,
            "is_baseline": config.is_baseline,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iterations": config.iterations,
            "resource_group": config.resource_group,
            "storage_account": config.storage_account,
            "container": config.container,
        },
        "preflight": preflight_to_dict(preflight_result),
        "results": {
            "is_stable": stats.is_stable,
            "anomaly_type": stats.anomaly_type,
            "latency_p90": stats.latency_p90,
            "latency_min": stats.latency_min,
            "latency_max": stats.latency_max,
            "throughput_p90": stats.throughput_p90,
            "throughput_min": stats.throughput_min,
            "throughput_max": stats.throughput_max,
            "units": {"latency": "us", "throughput": "Gbps"},
            "iteration_data": iteration_data,
        },
        "comparison": {
            "baseline_found": baseline_found,
            "baseline_timestamp": result.baseline_timestamp,
            "baseline_latency_p90": result.baseline_p90_latency,
            "baseline_throughput_p90": result.baseline_p90_throughput,
            "delta_pct_latency": result.delta_pct_latency,
            "delta_pct_throughput": result.delta_pct_throughput,
        },
    }


def _print_console_summary(
    result: ComparisonResult,
    config: PipelineConfig,
    local_path: str,
    blob_url: str,
) -> None:
    """Print the human-readable results summary per design §12."""
    stats = result.stats
    sep = "=" * 37

    print(f"\n{sep}")
    print("=== Agentic Pipe Meter — Results ===")
    print(f"{sep}")
    print(f"Session:    {config.session_id}")
    print(f"Source:     {config.source_ip}  →  {config.dest_ip}")
    print(f"Test:       {config.test_type}  |  {config.iterations} iterations")
    print(f"Status:     SUCCESS\n")

    anomaly_tag = f"  [{stats.anomaly_type}]" if stats.anomaly_type else ""

    if config.test_type in ("latency", "both") and stats.latency_p90 is not None:
        delta_str = ""
        if result.delta_pct_latency is not None:
            direction = "slower" if result.delta_pct_latency > 0 else "faster"
            delta_str = (
                f"  ← {result.delta_pct_latency:+.1f}% vs baseline ({direction})"
            )
        print(f"Latency  (P90):  {stats.latency_p90:>8.1f} µs{delta_str}{anomaly_tag}")

    if config.test_type in ("throughput", "both") and stats.throughput_p90 is not None:
        delta_str = ""
        if result.delta_pct_throughput is not None:
            direction = "higher" if result.delta_pct_throughput > 0 else "lower"
            delta_str = (
                f"  ← {result.delta_pct_throughput:+.1f}% vs baseline ({direction})"
            )
        print(f"Throughput (P90): {stats.throughput_p90:>8.2f} Gbps{delta_str}{anomaly_tag}")

    print()
    if stats.is_stable:
        print("Stability:  STABLE")
    else:
        print(f"Stability:  UNSTABLE — {stats.anomaly_type}")

    print(f"Audit:      {local_path}")
    if blob_url:
        print(f"Blob:       {blob_url}")
    else:
        print("Blob:       (upload failed — see audit file)")
    print(f"{sep}\n")


def _print_preflight_failed(
    config: PipelineConfig,
    reason: str,
    preflight_path: str,
) -> None:
    sep = "=" * 45
    print(f"\n{sep}")
    print("=== Agentic Pipe Meter — Preflight Failed ===")
    print(f"{sep}")
    print(f"Session:    {config.session_id}")
    print(f"Reason:     {reason}")
    print(f"Audit:      {preflight_path}")
    print(f"{sep}\n")


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def validate(args: argparse.Namespace) -> PipelineConfig:
    """Validate CLI arguments and return a fully populated PipelineConfig.

    Raises ValueError with a human-readable message on the first failure.
    """
    def _check_ipv4(value: str, flag: str) -> None:
        try:
            socket.inet_aton(value)
            # inet_aton accepts some non-standard forms; also verify dotted-quad
            parts = value.split(".")
            if len(parts) != 4:
                raise OSError
        except OSError:
            raise ValueError(f"{flag}: invalid IPv4 address: {value}")

    _check_ipv4(args.source_ip, "--source-ip")
    _check_ipv4(args.dest_ip, "--dest-ip")

    if args.source_ip == args.dest_ip:
        raise ValueError("--source-ip and --dest-ip must be different")

    if args.test_type not in ("latency", "throughput", "both"):
        raise ValueError("--test-type must be one of: latency, throughput, both")

    if args.iterations < 1:
        raise ValueError("--iterations must be >= 1")

    if not args.ssh_user:
        raise ValueError("--ssh-user is required")

    if not args.storage_account:
        raise ValueError("--storage-account is required")

    if not args.container:
        raise ValueError("--container is required")

    if not args.resource_group:
        raise ValueError("--resource-group is required")

    session_id = args.session_id if args.session_id else _generate_session_id()
    audit_dir = args.audit_dir if args.audit_dir else "./audit"

    return PipelineConfig(
        source_ip=args.source_ip,
        dest_ip=args.dest_ip,
        ssh_user=args.ssh_user,
        test_type=args.test_type,
        iterations=args.iterations,
        is_baseline=args.is_baseline,
        compare_baseline=args.compare_baseline,
        storage_account=args.storage_account,
        container=args.container,
        resource_group=args.resource_group,
        session_id=session_id,
        audit_dir=audit_dir,
        source_public_ip=getattr(args, "source_public_ip", None) or None,
        source_vm_key_path=getattr(args, "source_vm_key_path", None) or None,
        dest_vm_key_path=getattr(args, "dest_vm_key_path", None) or None,
        subscription_id=getattr(args, "subscription_id", None) or None,
        location=getattr(args, "location", None) or None,
        vnet_name=getattr(args, "vnet_name", None) or None,
        subnet_name=getattr(args, "subnet_name", None) or None,
        source_nsg_name=getattr(args, "source_nsg_name", None) or None,
        dest_nsg_name=getattr(args, "dest_nsg_name", None) or None,
    )


def preflight(
    config: PipelineConfig,
    shell: SafeExecShell,
    provider: CloudProvider,
) -> PreflightResult:
    """Check NSG ports and tool availability; remediate with operator approval.

    Writes {audit_dir}/{session_id}_preflight.json on every exit path.
    """
    actions_taken: list = []
    preflight_path = os.path.join(
        config.audit_dir, f"{config.session_id}_preflight.json"
    )

    def _write_and_return(result: PreflightResult) -> PreflightResult:
        d = preflight_to_dict(result)
        d["session_id"] = config.session_id
        d["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        _write_artifact(preflight_path, d)
        return result

    # STEP 1 — NSG port check
    print(f"[preflight] Checking NSG ports (5001, 19765) between {config.source_ip} and {config.dest_ip}...")
    port_status = provider.check_nsg_ports(
        config.source_ip, config.dest_ip, [5001, 19765]
    )
    blocked = [p for p, open_ in port_status.items() if not open_]

    if blocked:
        cmds = provider.generate_port_open_commands(
            config.resource_group, config.dest_ip, blocked
        )
        print(f"\nThe following ports are blocked: {blocked}")
        print("Commands that will be run to open them:")
        for cmd in cmds:
            print(f"  {cmd}")
        print()

        for cmd in cmds:
            r = shell.execute({
                "command": cmd,
                "reasoning": "Open port for measurement",
            })
            if r["status"] == "denied":
                print(f"Port remediation declined. Ports {blocked} remain blocked.")
                return _write_and_return(
                    PreflightResult(
                        ports_open=False, tools_ready=False,
                        actions_taken=actions_taken, blocked_ports=blocked,
                    )
                )
            if r["exit_code"] != 0:
                print(f"Port open command failed: {r['output'][:200]}")
                return _write_and_return(
                    PreflightResult(
                        ports_open=False, tools_ready=False,
                        actions_taken=actions_taken, blocked_ports=blocked,
                    )
                )
        actions_taken.append(f"Opened ports {blocked} on NSG")

    # STEP 2 — Tool presence check
    source_ssh_ip = config.source_public_ip or config.source_ip
    # Direct opts for source VM (reachable via public IP).
    # ProxyCommand opts for dest VM (private IP only): both keys used locally on Mac.
    opts_src = _make_ssh_opts(config.source_vm_key_path)
    opts_dst = _make_ssh_opts(
        config.dest_vm_key_path,
        config.ssh_user, source_ssh_ip,
        config.source_vm_key_path,
    )

    print("[preflight] NSG ports OK. Checking tools on VMs...")
    for vm_priv_ip, vm_ssh_ip, opts in [
        (config.source_ip, source_ssh_ip, opts_src),
        (config.dest_ip,   config.dest_ip, opts_dst),
    ]:
        print(f"[preflight]   Checking {vm_priv_ip}...")
        qperf_r = shell.execute({
            "command": _S4(opts, config.ssh_user, vm_ssh_ip, "qperf"),
            "reasoning": "Check qperf presence",
        })
        iperf_r = shell.execute({
            "command": _S4(opts, config.ssh_user, vm_ssh_ip, "iperf"),
            "reasoning": "Check iperf presence",
        })
        qperf_ok = qperf_r["exit_code"] == 0
        iperf_ok = iperf_r["exit_code"] == 0

        # SSH failure (exit 255) → surface a helpful message
        for r_check, binary in [(qperf_r, "qperf"), (iperf_r, "iperf")]:
            if r_check["exit_code"] == 255:
                print(
                    f"SSH to {vm_ssh_ip} failed on '{binary}' check (exit 255). "
                    f"Verify ssh-agent or key in ~/.ssh/"
                )
                return _write_and_return(
                    PreflightResult(
                        ports_open=True, tools_ready=False,
                        actions_taken=actions_taken,
                    )
                )

        if not qperf_ok or not iperf_ok:
            missing = [b for b, ok in [("qperf", qperf_ok), ("iperf", iperf_ok)] if not ok]
            print(f"Missing on {vm_priv_ip}: {missing}")

            # STEP 2a — Package manager detection
            apt_r = shell.execute({
                "command": _S5(opts, config.ssh_user, vm_ssh_ip),
                "reasoning": "Detect package manager",
            })
            pkg_mgr = "apt" if apt_r["exit_code"] == 0 else "yum"
            install_cmd = (
                _S6(opts, config.ssh_user, vm_ssh_ip)
                if pkg_mgr == "apt"
                else _S7(opts, config.ssh_user, vm_ssh_ip)
            )

            # STEP 2b — Single install gate for this VM
            r = shell.execute({
                "command": install_cmd,
                "reasoning": (
                    f"Dependencies missing on {vm_priv_ip}. "
                    f"Install qperf/iperf2 via {pkg_mgr}? [Y/N]"
                ),
            })
            if r["status"] == "denied":
                print(f"Installation declined. Tools not available on {vm_priv_ip}.")
                return _write_and_return(
                    PreflightResult(
                        ports_open=True, tools_ready=False,
                        actions_taken=actions_taken,
                    )
                )
            if r["exit_code"] != 0:
                print(f"Install failed on {vm_priv_ip}: {r['output'][:200]}")
                return _write_and_return(
                    PreflightResult(
                        ports_open=True, tools_ready=False,
                        actions_taken=actions_taken,
                    )
                )
            actions_taken.append(f"Installed qperf and iperf on {vm_priv_ip}")

        # STEP 2c — iperf version check (runs regardless of whether install was needed)
        ver_r = shell.execute({
            "command": _S12(opts, config.ssh_user, vm_ssh_ip),
            "reasoning": "Verify iperf is version 2, not iperf3",
        })
        if "iperf version 2" not in ver_r["output"].lower():
            print(
                f"Error: 'iperf' on {vm_priv_ip} is not iperf2. "
                f"Output: {ver_r['output'][:100]!r}"
            )
            print(
                "  The measurement tool requires iperf2 (package: 'iperf'), not iperf3."
            )
            return _write_and_return(
                PreflightResult(
                    ports_open=True, tools_ready=False,
                    actions_taken=actions_taken,
                )
            )

    # STEP 3 — curl check on source VM (needed for SAS-based blob uploads)
    # Only required when blob ops are routed through the source VM via SSH.
    if config.source_public_ip:
        curl_r = shell.execute({
            "command": _S4(opts_src, config.ssh_user, source_ssh_ip, "curl"),
            "reasoning": "Check curl presence on source VM (required for SAS blob upload)",
        })
        if curl_r["exit_code"] != 0:
            print(
                f"[preflight] 'curl' not found on source VM {source_ssh_ip}. "
                f"curl is required for blob upload via SAS token. "
                f"Install it with: sudo apt-get install -y curl"
            )
            return _write_and_return(
                PreflightResult(
                    ports_open=True, tools_ready=False,
                    actions_taken=actions_taken,
                )
            )

    print("[preflight] Tools OK. Preflight passed.")
    return _write_and_return(
        PreflightResult(ports_open=True, tools_ready=True, actions_taken=actions_taken)
    )


def measure(config: PipelineConfig, shell: SafeExecShell) -> MeasurementRaw:
    """Run latency and/or throughput measurements; write _raw.json.

    Two fully sequential measurement loops (latency first, then throughput).
    Each loop owns its server lifecycle via try/finally.
    """
    latency_samples: list = []
    throughput_samples: list = []

    source_ssh_ip = config.source_public_ip or config.source_ip
    opts_src = _make_ssh_opts(config.source_vm_key_path)
    opts_dst = _make_ssh_opts(
        config.dest_vm_key_path,
        config.ssh_user, source_ssh_ip,
        config.source_vm_key_path,
    )

    # STEP 1 — Pre-clean: check for stale server processes on dest VM
    print(f"[measure] Checking for stale server processes on {config.dest_ip}...")
    r = shell.execute({
        "command": _S1(opts_dst, config.ssh_user, config.dest_ip),
        "reasoning": "Check for stale server processes",
    })
    pids = [ln.strip() for ln in r["output"].splitlines() if ln.strip().isdigit()]
    if pids:
        print(f"Stale process(es) found on {config.dest_ip}: PIDs {pids}")
        r2 = shell.execute({
            "command": _S2(opts_dst, config.ssh_user, config.dest_ip, pids),
            "reasoning": "Kill stale processes before test",
        })
        if r2["status"] == "denied":
            raise RuntimeError(
                f"Stale processes exist on {config.dest_ip} and kill was declined. "
                f"Cannot proceed."
            )
        if r2["exit_code"] != 0:
            raise RuntimeError(
                f"Failed to kill stale processes on {config.dest_ip}: "
                f"{r2['output'][:200]}"
            )

    # ---- LATENCY BLOCK ----
    if config.test_type in ("latency", "both"):
        qperf_pid = None
        try:
            # STEP 2a — Start qperf server
            print(f"[measure] Starting qperf server on {config.dest_ip}...")
            r = shell.execute({
                "command": _S8(opts_dst, config.ssh_user, config.dest_ip),
                "reasoning": "Start qperf server for latency test",
            })
            if r["status"] == "denied" or r["exit_code"] != 0:
                raise RuntimeError(f"qperf server start failed: {r['output'][:200]}")
            qperf_pid = r["output"].strip()
            if not qperf_pid.isdigit():
                raise RuntimeError(
                    f"qperf server returned non-integer PID: {qperf_pid!r}"
                )
            time.sleep(2)  # allow server to reach listening state

            # STEP 3a — Warm-up (result discarded, but failure is fatal)
            print("  Warming up latency (warm-up pass, ~1 s)...")
            r = shell.execute({
                "command": _S10(opts_src, config.ssh_user, source_ssh_ip, config.dest_ip),
                "reasoning": "Warm-up pass (discarded)",
            })
            if r["exit_code"] != 0:
                raise RuntimeError(
                    f"Warm-up qperf failed — server may not be ready: {r['output'][:200]}"
                )

            # STEP 4a — Recorded latency iterations
            for i in range(1, config.iterations + 1):
                print(f"  Latency iteration {i}/{config.iterations}...")
                r = shell.execute({
                    "command": _S10(
                        opts_src, config.ssh_user, source_ssh_ip, config.dest_ip
                    ),
                    "reasoning": f"Latency iteration {i}",
                })
                if r["exit_code"] != 0:
                    raise RuntimeError(
                        f"qperf client failed on iteration {i}: {r['output'][:200]}"
                    )
                latency_samples.append(parse_qperf_latency(r["output"]))

        finally:
            # STEP 5a — Kill qperf server (always runs)
            if qperf_pid and qperf_pid.isdigit():
                td = shell.execute({
                    "command": _S2(opts_dst, config.ssh_user, config.dest_ip, [qperf_pid]),
                    "reasoning": "Teardown qperf server",
                })
            else:
                td = shell.execute({
                    "command": _S3(opts_dst, config.ssh_user, config.dest_ip, "qperf"),
                    "reasoning": "Teardown qperf server (PID unknown)",
                })
            if td["status"] == "denied" or td["exit_code"] != 0:
                print(f"Warning: qperf server teardown failed — {td['output'][:100]!r}")

    # ---- THROUGHPUT BLOCK ----
    if config.test_type in ("throughput", "both"):
        iperf_pid = None
        try:
            # STEP 2b — Start iperf server
            print(f"[measure] Starting iperf server on {config.dest_ip}...")
            r = shell.execute({
                "command": _S9(opts_dst, config.ssh_user, config.dest_ip),
                "reasoning": "Start iperf server for throughput test",
            })
            if r["status"] == "denied" or r["exit_code"] != 0:
                raise RuntimeError(f"iperf server start failed: {r['output'][:200]}")
            iperf_pid = r["output"].strip()
            if not iperf_pid.isdigit():
                raise RuntimeError(
                    f"iperf server returned non-integer PID: {iperf_pid!r}"
                )
            time.sleep(2)  # allow server to reach listening state

            # STEP 3b — Warm-up (result discarded, but failure is fatal)
            print("  Warming up throughput (warm-up pass, ~10 s)...")
            r = shell.execute({
                "command": _S11(opts_src, config.ssh_user, source_ssh_ip, config.dest_ip),
                "reasoning": "Warm-up pass (discarded)",
            })
            if r["exit_code"] != 0:
                raise RuntimeError(
                    f"Warm-up iperf failed — server may not be ready: {r['output'][:200]}"
                )

            # STEP 4b — Recorded throughput iterations
            for i in range(1, config.iterations + 1):
                print(f"  Throughput iteration {i}/{config.iterations}...")
                r = shell.execute({
                    "command": _S11(
                        opts_src, config.ssh_user, source_ssh_ip, config.dest_ip
                    ),
                    "reasoning": f"Throughput iteration {i}",
                })
                if r["exit_code"] != 0:
                    raise RuntimeError(
                        f"iperf client failed on iteration {i}: {r['output'][:200]}"
                    )
                throughput_samples.append(parse_iperf2_throughput(r["output"]))

        finally:
            # STEP 5b — Kill iperf server (always runs)
            if iperf_pid and iperf_pid.isdigit():
                td = shell.execute({
                    "command": _S2(opts_dst, config.ssh_user, config.dest_ip, [iperf_pid]),
                    "reasoning": "Teardown iperf server",
                })
            else:
                td = shell.execute({
                    "command": _S3(opts_dst, config.ssh_user, config.dest_ip, "iperf -s"),
                    "reasoning": "Teardown iperf server (PID unknown)",
                })
            if td["status"] == "denied" or td["exit_code"] != 0:
                print(f"Warning: iperf server teardown failed — {td['output'][:100]!r}")

    # STEP 6 — Write artifact (outside try/finally blocks)
    raw = MeasurementRaw(latency_samples, throughput_samples, config.session_id)
    _write_artifact(
        os.path.join(config.audit_dir, f"{config.session_id}_raw.json"),
        raw_to_dict(raw),
    )
    return raw


def compute(
    raw: MeasurementRaw, test_type: str, audit_dir: str
) -> ComputedStats:
    """Compute P90, min, max, and Gap Rule from raw samples."""
    if test_type in ("latency", "both") and len(raw.latency_samples) == 0:
        raise RuntimeError("Latency samples expected but list is empty")
    if test_type in ("throughput", "both") and len(raw.throughput_samples) == 0:
        raise RuntimeError("Throughput samples expected but list is empty")

    lat_p90 = lat_min = lat_max = None
    thr_p90 = thr_min = thr_max = None
    is_stable = True
    anomaly_type = None

    if test_type in ("latency", "both"):
        lat_p90 = _compute_p90(raw.latency_samples)
        lat_min = min(raw.latency_samples)
        lat_max = max(raw.latency_samples)
        stable_lat, anom_lat = _apply_gap_rule(raw.latency_samples)
        if not stable_lat:
            is_stable = False
            anomaly_type = anom_lat

    if test_type in ("throughput", "both"):
        thr_p90 = _compute_p90(raw.throughput_samples)
        thr_min = min(raw.throughput_samples)
        thr_max = max(raw.throughput_samples)
        stable_thr, anom_thr = _apply_gap_rule(raw.throughput_samples)
        if not stable_thr:
            is_stable = False
            # CONNECTIVITY_DROP takes priority over HIGH_VARIANCE
            if anomaly_type is None or anom_thr == "CONNECTIVITY_DROP":
                anomaly_type = anom_thr

    stats = ComputedStats(
        lat_p90, lat_min, lat_max,
        thr_p90, thr_min, thr_max,
        is_stable, anomaly_type,
    )
    _write_artifact(
        os.path.join(audit_dir, f"{raw.session_id}_computed.json"),
        stats_to_dict(stats),
    )
    return stats


def compare(
    config: PipelineConfig,
    stats: ComputedStats,
    provider: CloudProvider,
) -> ComparisonResult:
    """Load baseline (if any), compute deltas, and decide whether to write baseline."""
    blob_prefix = (
        f"{_ip_to_blob_prefix(config.source_ip)}_"
        f"{_ip_to_blob_prefix(config.dest_ip)}"
    )
    baseline_blob_name = f"{blob_prefix}_baseline.json"

    baseline_bytes = None
    if config.compare_baseline:
        try:
            baseline_bytes = provider.read_blob(
                config.storage_account, config.container, baseline_blob_name
            )
            if baseline_bytes is None:
                print("Note: No baseline found for this source/dest pair. Proceeding without comparison.")
        except RuntimeError as e:
            print(f"Warning: Could not read baseline: {e}. Proceeding without comparison.")

    baseline_p90_lat = baseline_p90_thr = baseline_ts = None
    delta_lat = delta_thr = None

    if baseline_bytes:
        try:
            baseline = json.loads(baseline_bytes)
            baseline_p90_lat = baseline["results"].get("latency_p90")
            baseline_p90_thr = baseline["results"].get("throughput_p90")
            baseline_ts = baseline["test_metadata"]["timestamp"]
        except (json.JSONDecodeError, KeyError):
            print("Warning: Baseline file is malformed. Proceeding without comparison.")
            baseline_p90_lat = baseline_p90_thr = baseline_ts = None
            baseline_bytes = None

        if baseline_p90_lat is not None and baseline_p90_lat != 0.0 and stats.latency_p90 is not None:
            delta_lat = (stats.latency_p90 - baseline_p90_lat) / baseline_p90_lat * 100
        if baseline_p90_thr is not None and baseline_p90_thr != 0.0 and stats.throughput_p90 is not None:
            delta_thr = (stats.throughput_p90 - baseline_p90_thr) / baseline_p90_thr * 100

    write_as_baseline = config.is_baseline

    if config.is_baseline and baseline_bytes is not None:
        print(f"\nNote: A baseline already exists for {config.source_ip} → {config.dest_ip}")
        print(
            f"  Recorded: {baseline_ts}. "
            f"It will be overwritten (--is-baseline was set)."
        )
        # No input() prompt here. The operator's explicit --is-baseline flag is the
        # single consent for overwriting. See design §6.5 note on double-gate.

    result = ComparisonResult(
        stats, baseline_p90_lat, baseline_p90_thr, baseline_ts,
        delta_lat, delta_thr, write_as_baseline,
    )
    _write_artifact(
        os.path.join(config.audit_dir, f"{config.session_id}_comparison.json"),
        comparison_to_dict(result),
    )
    return result


def report(
    result: ComparisonResult,
    config: PipelineConfig,
    provider: CloudProvider,
    preflight_result: PreflightResult,
) -> PipelineResult:
    """Assemble and write the final artifact; upload to blob; print console summary."""
    artifact = _assemble_artifact(result, config, preflight_result)

    # Local write must succeed before any blob upload
    local_path = os.path.join(config.audit_dir, f"{config.session_id}_result.json")
    _write_artifact(local_path, artifact)  # raises RuntimeError on failure

    blob_prefix = (
        f"{_ip_to_blob_prefix(config.source_ip)}_"
        f"{_ip_to_blob_prefix(config.dest_ip)}"
    )
    blob_name = f"{blob_prefix}_{config.session_id}.json"
    blob_url = ""

    def _blob_detail(e: RuntimeError) -> str:
        """Strip the 'Blob upload failed: ' prefix providers.py adds, then clean whitespace."""
        msg = str(e).removeprefix("Blob upload failed: ").strip()
        return " ".join(msg.split())   # collapse internal newlines/spaces to one space

    try:
        blob_url = provider.write_blob(
            config.storage_account,
            config.container,
            blob_name,
            json.dumps(artifact).encode(),
        )
    except RuntimeError as e:
        print(f"Warning: Result artifact upload failed — {_blob_detail(e)}")
        print(f"  Local artifact saved at: {local_path}")

    if result.write_as_baseline:
        baseline_name = f"{blob_prefix}_baseline.json"
        try:
            provider.write_blob(
                config.storage_account,
                config.container,
                baseline_name,
                json.dumps(artifact).encode(),
            )
        except RuntimeError as e:
            print(f"Warning: Baseline upload failed — {_blob_detail(e)}")

    _print_console_summary(result, config, local_path, blob_url)

    return PipelineResult(
        status="success",
        local_artifact_path=os.path.abspath(local_path),
        blob_url=blob_url,
        session_id=config.session_id,
        error_message=None,
    )


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    config: PipelineConfig,
    shell: SafeExecShell,
    provider: CloudProvider,
) -> PipelineResult:
    """Top-level pipeline: manifest → preflight → measure → compute → compare → report."""
    try:
        _write_manifest(config)

        pre = preflight(config, shell, provider)
        if not pre.ports_open or not pre.tools_ready:
            preflight_path = os.path.join(
                config.audit_dir, f"{config.session_id}_preflight.json"
            )
            reason = (
                f"Ports {pre.blocked_ports} remain blocked."
                if not pre.ports_open
                else "Required tools (qperf/iperf) not available on one or both VMs."
            )
            _print_preflight_failed(config, reason, preflight_path)
            return PipelineResult(
                status="aborted_preflight",
                local_artifact_path=preflight_path,
                blob_url="",
                session_id=config.session_id,
                error_message=reason,
            )

        raw = measure(config, shell)
        stats = compute(raw, config.test_type, config.audit_dir)
        comparison = compare(config, stats, provider)
        return report(comparison, config, provider, pre)

    except Exception as e:
        return PipelineResult(
            status="error",
            local_artifact_path="",
            blob_url="",
            session_id=config.session_id,
            error_message=str(e),
        )


# ---------------------------------------------------------------------------
# Config file loader
# ---------------------------------------------------------------------------

def _parse_config_value(raw: str) -> str:
    """Extract the value from a raw config.env assignment RHS.

    Handles:
    - Quoted values:   KEY="value"  or  KEY='value'
    - Inline comments: KEY="value"  # comment  (comment stripped)
    - Unquoted values: KEY=value    # comment  (comment stripped)
    - Env var expansion: KEY="${HOME}/path"  →  /Users/...
    """
    raw = raw.strip()
    if raw.startswith('"'):
        end = raw.find('"', 1)
        value = raw[1:end] if end != -1 else raw[1:]
    elif raw.startswith("'"):
        end = raw.find("'", 1)
        value = raw[1:end] if end != -1 else raw[1:]
    else:
        # Unquoted — strip inline comment
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
        "SOURCE_VM_PRIVATE_IP":   ("source_ip",        str),
        "DEST_VM_PRIVATE_IP":     ("dest_ip",          str),
        "SOURCE_VM_PUBLIC_IP":    ("source_public_ip", str),
        "SSH_USER":               ("ssh_user",             str),
        "SSH_SOURCE_VM_KEY_PATH": ("source_vm_key_path",   str),
        "SSH_KEY_PATH":           ("source_vm_key_path",   str),   # Ghost Agent alias
        "SSH_DEST_VM_KEY_PATH":   ("dest_vm_key_path",     str),
        "TEST_TYPE":              ("test_type",        str),
        "RESOURCE_GROUP":         ("resource_group",   str),
        "STORAGE_ACCOUNT_NAME":   ("storage_account",  str),
        "STORAGE_CONTAINER_NAME": ("container",        str),
        "SUBSCRIPTION_ID":        ("subscription_id",  str),
        "LOCATION":               ("location",         str),
        "VNET_NAME":              ("vnet_name",        str),
        "SUBNET_NAME":            ("subnet_name",      str),
        "SOURCE_VM_NSG_NAME":     ("source_nsg_name",  str),
        "DEST_VM_NSG_NAME":       ("dest_nsg_name",    str),
        "ITERATIONS":             ("iterations",       int),
        "AUDIT_DIR":              ("audit_dir",        str),
        "SESSION_ID":             ("session_id",       str),
        "IS_BASELINE":            ("is_baseline",        lambda v: v.strip().lower() in ("true", "1", "yes")),
        "COMPARE_BASELINE":       ("compare_baseline",   lambda v: v.strip().lower() in ("true", "1", "yes")),
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
        print(f"Error: cannot read config file {path!r}: {e}")
        sys.exit(1)
    return defaults


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list) -> None:
    # Pre-parse to find --config before constructing the full parser.
    # This lets config file values act as defaults while CLI flags override them.
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    config_defaults: dict = {}
    if pre_args.config:
        config_defaults = _load_config_file(pre_args.config)

    # Required flags become optional when a config file supplies the value.
    def _req(key: str) -> bool:
        return key not in config_defaults

    parser = argparse.ArgumentParser(
        description="Agentic Pipe Meter — network latency and throughput measurement"
    )
    parser.add_argument("--config", default=None, metavar="FILE",
                        help="Path to a KEY=VALUE config file (CLI flags override)")
    parser.add_argument("--source-ip", required=_req("source_ip"), dest="source_ip",
                        help="Source VM private IP (SOURCE_VM_PRIVATE_IP)")
    parser.add_argument("--dest-ip", required=_req("dest_ip"), dest="dest_ip",
                        help="Dest VM private IP (DEST_VM_PRIVATE_IP)")
    parser.add_argument("--source-public-ip", default=None, dest="source_public_ip",
                        help="Source VM public IP for SSH (SOURCE_VM_PUBLIC_IP); falls back to --source-ip")
    parser.add_argument("--ssh-user", required=_req("ssh_user"), dest="ssh_user",
                        help="SSH username on both VMs (SSH_USER)")
    parser.add_argument("--ssh-source-vm-key-path", default=None, dest="source_vm_key_path",
                        help="Path to source VM SSH private key (SSH_SOURCE_VM_KEY_PATH)")
    parser.add_argument("--ssh-dest-vm-key-path", default=None, dest="dest_vm_key_path",
                        help="Path to dest VM SSH private key (SSH_DEST_VM_KEY_PATH)")
    parser.add_argument(
        "--test-type",
        required=_req("test_type"),
        dest="test_type",
        choices=["latency", "throughput", "both"],
    )
    parser.add_argument("--storage-account-name", required=_req("storage_account"),
                        dest="storage_account",
                        help="Azure storage account name (STORAGE_ACCOUNT_NAME)")
    parser.add_argument("--storage-container-name", required=_req("container"),
                        dest="container",
                        help="Blob container name (STORAGE_CONTAINER_NAME)")
    parser.add_argument("--resource-group", required=_req("resource_group"), dest="resource_group")
    parser.add_argument("--subscription-id", default=None, dest="subscription_id",
                        help="Azure subscription ID (SUBSCRIPTION_ID)")
    parser.add_argument("--location", default=None)
    parser.add_argument("--vnet-name", default=None, dest="vnet_name")
    parser.add_argument("--subnet-name", default=None, dest="subnet_name")
    parser.add_argument("--source-nsg-name", default=None, dest="source_nsg_name")
    parser.add_argument("--dest-nsg-name", default=None, dest="dest_nsg_name")
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--is-baseline", action="store_true", dest="is_baseline",
                        help="Write this run as the reference baseline (IS_BASELINE)")
    parser.add_argument("--compare-baseline", action="store_true", dest="compare_baseline",
                        help="Download and compare with an existing baseline (COMPARE_BASELINE)")
    parser.add_argument("--session-id", default=None, dest="session_id")
    parser.add_argument("--audit-dir", default="./audit", dest="audit_dir")

    parser.set_defaults(**config_defaults)
    args = parser.parse_args(argv)

    try:
        config = validate(args)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    shell = SafeExecShell(
        session_id=config.session_id,
        audit_dir=config.audit_dir,
        hitl_callback=_make_hitl_callback(),
        timeout_seconds=120,
    )
    provider = AzureProvider(
        shell=shell,
        resource_group=config.resource_group,
        subscription_id=config.subscription_id,
        ssh_user=config.ssh_user,
        source_public_ip=config.source_public_ip or config.source_ip,
        source_vm_key_path=config.source_vm_key_path,
    )

    result = run_pipeline(config, shell, provider)

    if result.status == "success":
        sys.exit(0)
    else:
        if result.status == "error":
            print(f"Error: {result.error_message}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
