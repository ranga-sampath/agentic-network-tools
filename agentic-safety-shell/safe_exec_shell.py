"""Safe-Exec Shell — safety boundary between the AI Brain and system commands.

Public API:
    shell = SafeExecShell(session_id, audit_dir, hitl_callback)
    response = shell.execute({"command": "ping 8.8.8.8", "reasoning": "Check connectivity"})

Four-stage pipeline: Classify -> Gate (HITL) -> Execute -> Process Output
Four-tier classification: Tier 0 (Forbidden) -> Tier 1 (Allowlist) -> Tier 2 (Azure Verbs) -> Tier 3 (Dangerous Patterns)

See architecture.md and design.md for full specification.
"""

import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLASSIFICATION_FORBIDDEN = "FORBIDDEN"
CLASSIFICATION_SAFE = "SAFE"
CLASSIFICATION_RISKY = "RISKY"

STATUS_COMPLETED = "completed"
STATUS_DENIED = "denied"
STATUS_ERROR = "error"

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_AUDIT_DIR = "./audit"
TRUNCATION_LINE_LIMIT = 200
TRUNCATION_TOKEN_ESTIMATE_LIMIT = 4000  # ~4 chars per token

# ---------------------------------------------------------------------------
# Tier 0 — Forbidden patterns
# ---------------------------------------------------------------------------

# Block device path patterns for dd detection
_BLOCK_DEVICE_RE = re.compile(
    r"/dev/(?:[shv]d[a-z]\d*|nvme\d+n\d+(?:p\d+)?|xvd[a-z]\d*|mmcblk\d+(?:p\d+)?)"
)

# Fork bomb pattern
_FORK_BOMB_RE = re.compile(r":\(\)\s*\{.*:\|:.*&.*\}\s*;?\s*:")

# Shutdown family — base commands
_SHUTDOWN_COMMANDS = frozenset({"shutdown", "reboot", "halt", "poweroff"})

# init runlevels that are forbidden
_FORBIDDEN_INIT_LEVELS = frozenset({"0", "6"})


def _is_forbidden(command_str: str, args: list[str]) -> bool:
    """Tier 0: return True if the command is catastrophic and must be blocked unconditionally."""
    if not args:
        return False

    base = os.path.basename(args[0])

    # rm -rf / or rm -rf /*
    if base == "rm":
        has_r = False
        has_f = False
        targets = []
        for a in args[1:]:
            if a.startswith("-") and not a.startswith("--"):
                if "r" in a:
                    has_r = True
                if "f" in a:
                    has_f = True
            elif a == "--recursive":
                has_r = True
            elif a == "--force":
                has_f = True
            elif not a.startswith("-"):
                targets.append(a)
        if has_r and has_f:
            for t in targets:
                normalized = t.rstrip("/")
                if normalized == "" or t == "/*":
                    # rm -rf / (normalized to empty) or rm -rf /*
                    return True

    # mkfs — any mkfs variant
    if base == "mkfs" or base.startswith("mkfs."):
        return True

    # dd to block devices
    if base == "dd":
        for a in args[1:]:
            if a.startswith("of="):
                target = a[3:]
                if _BLOCK_DEVICE_RE.match(target):
                    return True

    # Fork bomb detection on raw string
    if _FORK_BOMB_RE.search(command_str):
        return True

    # shutdown / reboot / halt / poweroff
    if base in _SHUTDOWN_COMMANDS:
        return True

    # init 0 / init 6
    if base == "init" and len(args) > 1 and args[1] in _FORBIDDEN_INIT_LEVELS:
        return True

    return False


# ---------------------------------------------------------------------------
# Tier 1 — Local command allowlist
# ---------------------------------------------------------------------------

# Commands that are always SAFE regardless of flags
_ALWAYS_SAFE = frozenset({
    "ping", "traceroute", "dig", "nslookup", "host", "whois", "mtr",
    "netstat", "ss", "lsof",
    "pcap_forensics.py",
})

# Flag-sensitive commands: each maps to a function(args) -> bool (True = RISKY)
_IFCONFIG_RISKY_FLAGS = {"up", "down", "mtu", "metric"}


def _ifconfig_is_risky(args: list[str]) -> bool:
    """ifconfig: RISKY if up/down/mtu/metric or address assignment present."""
    for a in args[1:]:
        if a in _IFCONFIG_RISKY_FLAGS:
            return True
        # Address assignment: looks like an IP address as an argument
        if re.match(r"\d+\.\d+\.\d+\.\d+", a):
            return True
    return False


_IP_RISKY_SUBCOMMANDS = frozenset({"add", "del", "set", "change", "replace", "flush"})
_IP_SAFE_SUBCOMMANDS = frozenset({"show"})


def _ip_is_risky(args: list[str]) -> bool:
    """ip: SAFE for show subcommand, RISKY for add/del/set/change/replace/flush."""
    # ip [object] [subcommand] — e.g. ip addr show, ip route add
    for a in args[1:]:
        if a in _IP_RISKY_SUBCOMMANDS:
            return True
    # Must have a show subcommand to be SAFE
    for a in args[1:]:
        if a in _IP_SAFE_SUBCOMMANDS:
            return False
    # No recognized safe subcommand -> RISKY
    return True


def _arp_is_risky(args: list[str]) -> bool:
    """arp: SAFE for -a/-n, RISKY for -d/-s."""
    for a in args[1:]:
        if a.startswith("-") and ("d" in a or "s" in a):
            return True
    return False


def _route_is_risky(args: list[str]) -> bool:
    """route: SAFE for get, RISKY for add/delete/change/flush."""
    risky = {"add", "delete", "change", "flush"}
    for a in args[1:]:
        if a in risky:
            return True
    return False


def _scutil_is_risky(args: list[str]) -> bool:
    """scutil: SAFE for --dns/--proxy/--nwi only."""
    safe_flags = {"--dns", "--proxy", "--nwi"}
    for a in args[1:]:
        if a.startswith("--") and a not in safe_flags:
            return True
    return False


def _networksetup_is_risky(args: list[str]) -> bool:
    """networksetup: SAFE for -list*/-get*, RISKY for -set*/-add*/-remove*."""
    for a in args[1:]:
        if a.startswith("-set") or a.startswith("-add") or a.startswith("-remove"):
            return True
    return False


def _tshark_is_risky(args: list[str]) -> bool:
    """tshark: SAFE only with -r flag (read from file)."""
    return "-r" not in args[1:]


def _tcpdump_is_risky(args: list[str]) -> bool:
    """tcpdump: SAFE only with -r flag (read from file)."""
    return "-r" not in args[1:]


_CURL_MUTATIVE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def _curl_is_risky(args: list[str]) -> bool:
    """curl: SAFE for GET only. RISKY if -X POST/PUT/DELETE/PATCH, -d, --data, --upload-file."""
    for i, a in enumerate(args[1:], 1):
        if a == "-d" or a == "--data" or a.startswith("--data=") or a == "--upload-file":
            return True
        if a == "-X" and i + 1 < len(args) and args[i + 1] in _CURL_MUTATIVE_METHODS:
            return True
        if a.startswith("-X") and len(a) > 2 and a[2:] in _CURL_MUTATIVE_METHODS:
            return True
    return False


# Map of flag-sensitive commands to their risk-check functions
_FLAG_SENSITIVE = {
    "ifconfig": _ifconfig_is_risky,
    "ip": _ip_is_risky,
    "arp": _arp_is_risky,
    "route": _route_is_risky,
    "scutil": _scutil_is_risky,
    "networksetup": _networksetup_is_risky,
    "tshark": _tshark_is_risky,
    "tcpdump": _tcpdump_is_risky,
    "curl": _curl_is_risky,
}


def _classify_tier1(args: list[str]) -> Optional[bool]:
    """Tier 1: Check the command allowlist.

    Returns:
        None  — command is in the allowlist and flags are safe (pass to Tier 2)
        True  — command is RISKY (not in allowlist, or risky flags)
        False is not used.
    """
    base = os.path.basename(args[0])

    # az is in the allowlist as a command family — always passes Tier 1
    if base == "az":
        return None

    # Always-safe commands
    if base in _ALWAYS_SAFE:
        return None

    # Flag-sensitive commands
    if base in _FLAG_SENSITIVE:
        if _FLAG_SENSITIVE[base](args):
            return True  # RISKY due to flags
        return None  # passes Tier 1

    # Not in allowlist at all
    return True  # RISKY


# ---------------------------------------------------------------------------
# Tier 2 — Azure CLI verb rules
# ---------------------------------------------------------------------------

_AZ_SAFE_VERBS = frozenset({"list", "show", "get", "check", "exists", "wait"})

_AZ_RISKY_VERBS = frozenset({
    "create", "delete", "update", "set", "add", "remove",
    "start", "stop", "restart", "deallocate", "move", "import", "export",
})

# Special compound commands that are safe despite containing substrings
_AZ_SAFE_SPECIAL = frozenset({
    "show-topology",
    "show-next-hop",
})


def _classify_tier2(args: list[str]) -> Optional[bool]:
    """Tier 2: Azure CLI verb-based classification.

    Returns:
        None  — not an az command (skip tier)
        True  — RISKY (mutative verb or az rest)
        False — SAFE (read-only verb)
    """
    base = os.path.basename(args[0])
    if base != "az":
        return None  # Not an az command, Tier 2 doesn't apply

    if len(args) < 2:
        return True  # bare `az` with no subcommand — RISKY

    # az rest is always RISKY
    if args[1] == "rest":
        return True

    # az login and az account show are safe
    if args[1] == "login":
        return False
    if args[1] == "account" and len(args) > 2 and args[2] == "show":
        return False

    # Find the verb — last positional arg before flags (args starting with --)
    # In `az network nsg rule list --resource-group ...`, the verb is `list`
    # Skip tokens that are values of --flag arguments (e.g. --name web-nsg).
    # Boolean flags like --created have no value — detected when the next
    # token also starts with "--".
    positional = []
    skip_next = False
    for a in args[1:]:
        if skip_next:
            if a.startswith("--"):
                # Previous flag was boolean (no value); this is a new flag
                skip_next = True
                continue
            if a.startswith("-"):
                skip_next = False
                continue
            # This token is the value of the previous flag — skip it
            skip_next = False
            continue
        if a.startswith("--"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        positional.append(a)

    # Check for special compound subcommands (e.g. show-topology)
    for p in positional:
        if p in _AZ_SAFE_SPECIAL:
            return False

    # The verb is typically the last positional argument
    if positional:
        verb = positional[-1]
        if verb in _AZ_SAFE_VERBS:
            return False
        if verb in _AZ_RISKY_VERBS:
            return True

    # Unknown verb — default RISKY
    return True


# ---------------------------------------------------------------------------
# Tier 3 — Dangerous pattern detection
# ---------------------------------------------------------------------------

_PRIVILEGE_ESCALATION_RE = re.compile(
    r"(?:^|\s|;|&&|\|\|)"  # preceded by start, space, or chain operator
    r"(?:sudo|su|doas)\b"
)

_SHELL_EVASION_PATTERNS = [
    re.compile(r"(?:^|\s)(?:bash|sh|zsh|dash|ksh)\s+-c\b"),  # bash -c / sh -c
    re.compile(r"(?:^|\s)eval\s"),                             # eval
    re.compile(r"(?:^|\s)exec\s"),                             # exec
    re.compile(r"`[^`]+`"),                                     # backtick substitution
    re.compile(r"\$\([^)]+\)"),                                 # $() substitution
]

_CHAIN_OPERATORS_RE = re.compile(r"&&|\|\||(?<!\|)\|(?!\|)|;")

_DESTRUCTIVE_COMMANDS = frozenset({
    "rm", "chmod", "chown", "kill", "killall", "pkill",
})

_REDIRECT_TO_SYSTEM_RE = re.compile(
    r">{1,2}\s*/(?:etc|usr|var|boot|sys|proc|dev|lib|sbin|bin)/"
)

_MV_TO_SYSTEM_RE = re.compile(
    r"(?:^|\s)mv\s+.*\s+/(?:etc|usr|var|boot|sys|proc|dev|lib|sbin|bin)/"
)

_TEE_TO_SYSTEM_RE = re.compile(
    r"\|\s*tee\s+/(?:etc|usr|var|boot|sys|proc|dev|lib|sbin|bin)/"
)


def _classify_tier3(command_str: str, args: list[str]) -> bool:
    """Tier 3: Dangerous pattern detection. Returns True if RISKY."""
    # Privilege escalation
    if _PRIVILEGE_ESCALATION_RE.search(command_str):
        return True

    # Shell evasion
    for pattern in _SHELL_EVASION_PATTERNS:
        if pattern.search(command_str):
            return True

    # Command chaining — if any chain operator is present, entire command is RISKY
    if _CHAIN_OPERATORS_RE.search(command_str):
        return True

    # Destructive commands anywhere in the argument list
    for a in args:
        if os.path.basename(a) in _DESTRUCTIVE_COMMANDS:
            return True

    # Redirect to system paths
    if _REDIRECT_TO_SYSTEM_RE.search(command_str):
        return True

    # mv to system paths
    if _MV_TO_SYSTEM_RE.search(command_str):
        return True

    # tee to system paths (via pipe)
    if _TEE_TO_SYSTEM_RE.search(command_str):
        return True

    # Newlines in command string — potential injection
    if "\n" in command_str:
        return True

    return False


# ---------------------------------------------------------------------------
# Main classification function (Stage 1)
# ---------------------------------------------------------------------------

def classify(command_str: str) -> tuple[str, Optional[int], str]:
    """Classify a command through the four-tier defense.

    Returns:
        (classification, tier_triggered, risk_explanation)
        classification: FORBIDDEN | SAFE | RISKY
        tier_triggered: 0-3 or None (None if SAFE)
        risk_explanation: human-readable explanation of why
    """
    command_str = command_str.strip()

    # Parse into argument vector
    try:
        args = shlex.split(command_str)
    except ValueError:
        # Malformed quoting — treat as RISKY
        return (CLASSIFICATION_RISKY, 1,
                "Command has malformed quoting and cannot be parsed safely")

    if not args:
        # This shouldn't happen (empty check is before classify), but defend
        return (CLASSIFICATION_RISKY, 1, "Empty argument list after parsing")

    # Tier 0 — Forbidden
    if _is_forbidden(command_str, args):
        return (CLASSIFICATION_FORBIDDEN, 0,
                "Catastrophic command — blocked unconditionally, no approval possible")

    # Tier 1 — Allowlist
    tier1_result = _classify_tier1(args)
    if tier1_result is True:
        base = os.path.basename(args[0])
        if base in _FLAG_SENSITIVE:
            return (CLASSIFICATION_RISKY, 1,
                    f"Command '{base}' is in the allowlist but arguments contain risky flags")
        return (CLASSIFICATION_RISKY, 1,
                f"Command '{base}' is not in the allowlist — default deny")

    # Tier 2 — Azure verb rules
    tier2_result = _classify_tier2(args)
    if tier2_result is True:
        positional = [a for a in args[1:] if not a.startswith("-")]
        verb = positional[-1] if positional else args[1] if len(args) > 1 else "unknown"
        return (CLASSIFICATION_RISKY, 2,
                f"Azure CLI verb '{verb}' is classified as mutative")
    # tier2_result is False (safe az) or None (not az) — continue

    # Tier 3 — Dangerous patterns
    if _classify_tier3(command_str, args):
        return (CLASSIFICATION_RISKY, 3,
                "Command contains a dangerous pattern (privilege escalation, "
                "shell evasion, destructive operator, or command chaining)")

    return (CLASSIFICATION_SAFE, None, "")


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

def _detect_environment(args: list[str]) -> str:
    """Determine if the command targets local or azure."""
    if args and os.path.basename(args[0]) == "az":
        return "azure"
    return "local"


# ---------------------------------------------------------------------------
# Output processing — Truncation
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def _detect_output_type(output: str) -> str:
    """Detect the format of command output."""
    stripped = output.strip()
    if not stripped:
        return "empty"

    # Binary detection: check for non-UTF-8 / control characters
    try:
        stripped.encode("utf-8")
        # Check for excessive control characters (binary marker)
        control_count = sum(1 for c in stripped[:1000]
                           if ord(c) < 32 and c not in "\n\r\t")
        if control_count > len(stripped[:1000]) * 0.1:
            return "binary"
    except UnicodeEncodeError:
        return "binary"

    # JSON array
    if stripped.startswith("["):
        try:
            json.loads(stripped)
            return "json_array"
        except (json.JSONDecodeError, RecursionError):
            pass

    # JSON object
    if stripped.startswith("{"):
        try:
            json.loads(stripped)
            return "json_object"
        except (json.JSONDecodeError, RecursionError):
            pass

    # Tabular: real CLI tables (az, netstat, ps) use 2+ spaces between columns.
    # Log streams use single spaces. Check for multi-space separators AND consistent
    # column counts across the first few lines.
    lines = stripped.split("\n")
    if len(lines) >= 3:
        multi_space_lines = 0
        col_counts = []
        for line in lines[:10]:
            if "  " in line.strip():  # 2+ consecutive spaces = column separator
                multi_space_lines += 1
                cols = len(re.split(r"\s{2,}", line.strip()))
                if cols >= 2:
                    col_counts.append(cols)
        if (multi_space_lines >= 3
                and len(col_counts) >= 3
                and len(set(col_counts)) <= 2):
            return "tabular"

    return "log_stream"


def _truncate_json_array(data: list, total_items: int) -> tuple[str, dict]:
    """Truncate a JSON array: first 3 + last 1 + message."""
    if total_items <= 4:
        return json.dumps(data, indent=2), {
            "truncation_applied": False,
            "items_total": total_items,
            "items_shown": total_items,
        }

    truncated = data[:3] + [f"[truncated: showing 4 of {total_items} items]"] + data[-1:]
    return json.dumps(truncated, indent=2), {
        "truncation_applied": True,
        "items_total": total_items,
        "items_shown": 4,
    }


def _truncate_json_object(data: dict, depth: int = 0) -> dict:
    """Truncate a JSON object: preserve top-level keys, truncate nested arrays, cap depth."""
    if depth >= 3:
        return "..."

    result = {}
    for key, value in data.items():
        if isinstance(value, list) and len(value) > 4:
            result[key] = (
                value[:3]
                + [f"[truncated: showing 4 of {len(value)} items]"]
                + value[-1:]
            )
        elif isinstance(value, dict):
            result[key] = _truncate_json_object(value, depth + 1)
        else:
            result[key] = value
    return result


def truncate_output(output: str) -> tuple[str, dict]:
    """Apply format-aware truncation. Returns (truncated_output, metadata)."""
    if not output:
        return "", {
            "truncation_applied": False,
            "total_lines": 0,
            "lines_shown": 0,
            "output_type": "empty",
        }

    output_type = _detect_output_type(output)
    lines = output.split("\n")
    total_lines = len(lines)
    total_bytes = len(output.encode("utf-8", errors="replace"))

    # Binary — replace entirely
    if output_type == "binary":
        return f"[binary output: {total_bytes} bytes, not displayed]", {
            "truncation_applied": True,
            "total_lines": total_lines,
            "lines_shown": 0,
            "total_bytes": total_bytes,
            "output_type": "binary",
        }

    # Check if under threshold
    token_estimate = _estimate_tokens(output)
    if total_lines <= TRUNCATION_LINE_LIMIT and token_estimate <= TRUNCATION_TOKEN_ESTIMATE_LIMIT:
        meta = {
            "truncation_applied": False,
            "total_lines": total_lines,
            "lines_shown": total_lines,
            "output_type": output_type,
        }
        if output_type == "json_array":
            try:
                data = json.loads(output)
                meta["items_total"] = len(data)
                meta["items_shown"] = len(data)
            except (json.JSONDecodeError, RecursionError):
                pass
        return output, meta

    # Truncate based on type
    if output_type == "json_array":
        try:
            data = json.loads(output)
            truncated_str, meta = _truncate_json_array(data, len(data))
            meta["total_lines"] = total_lines
            result_lines = truncated_str.split("\n")
            meta["lines_shown"] = len(result_lines)
            meta["total_bytes"] = total_bytes
            meta["output_type"] = "json_array"
            return truncated_str, meta
        except (json.JSONDecodeError, RecursionError):
            pass  # fall through to log_stream

    if output_type == "json_object":
        try:
            data = json.loads(output)
            truncated_data = _truncate_json_object(data)
            truncated_str = json.dumps(truncated_data, indent=2)
            result_lines = truncated_str.split("\n")
            return truncated_str, {
                "truncation_applied": True,
                "total_lines": total_lines,
                "lines_shown": len(result_lines),
                "total_bytes": total_bytes,
                "output_type": "json_object",
            }
        except (json.JSONDecodeError, RecursionError):
            pass

    if output_type == "tabular":
        # Header + first N data rows (N chosen to stay under line limit)
        n_data_rows = min(TRUNCATION_LINE_LIMIT - 1, total_lines - 1)
        shown = [lines[0]] + lines[1 : n_data_rows + 1]
        if total_lines > n_data_rows + 1:
            shown.append(f"[truncated: showing {n_data_rows} of {total_lines - 1} rows]")
        return "\n".join(shown), {
            "truncation_applied": total_lines > n_data_rows + 1,
            "total_lines": total_lines,
            "lines_shown": len(shown),
            "total_bytes": total_bytes,
            "output_type": "tabular",
        }

    # log_stream (default): first 20 + last 10
    head = lines[:20]
    tail = lines[-10:]
    omitted = total_lines - 30
    shown = head + [f"[truncated: {omitted} lines omitted]"] + tail
    return "\n".join(shown), {
        "truncation_applied": True,
        "total_lines": total_lines,
        "lines_shown": 30,
        "total_bytes": total_bytes,
        "output_type": "log_stream",
    }


# ---------------------------------------------------------------------------
# Output processing — Privacy redaction
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS = [
    # API keys
    ("api_key", re.compile(
        r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE
    ), r"\g<0>".split("=")[0] if False else None),  # placeholder — handled below

    # Passwords
    ("password", re.compile(
        r"(?:password|passwd|pwd)\s*=\s*\S+", re.IGNORECASE
    ), None),

    # Bearer tokens
    ("bearer_token", re.compile(
        r"Bearer\s+\S+", re.IGNORECASE
    ), None),

    # Connection strings (Azure-style, JDBC, ODBC)
    ("connection_string", re.compile(
        r"(?:Server|Data Source|Provider)=[^;\n]+(?:;[^;\n]+){2,}", re.IGNORECASE
    ), None),

    # Private keys (PEM)
    ("private_key", re.compile(
        r"-----BEGIN\s+\S+\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+\S+\s+PRIVATE\s+KEY-----"
    ), None),

    # Azure subscription IDs (GUID in subscription context)
    ("azure_subscription_id", re.compile(
        r'("subscriptionId"\s*:\s*")[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"',
        re.IGNORECASE
    ), None),

    # Azure storage keys
    ("storage_key", re.compile(
        r"AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}", re.IGNORECASE
    ), None),

    # SAS tokens
    ("sas_token", re.compile(
        r"\?sv=[^&\s]+(?:&[^&\s]+){3,}"
    ), None),
]


def _apply_redaction(category: str, pattern: re.Pattern, text: str) -> tuple[str, int]:
    """Apply a single redaction pattern. Returns (redacted_text, count)."""
    if category == "api_key":
        def _repl(m):
            s = m.group(0)
            sep_idx = s.find("=")
            if sep_idx == -1:
                sep_idx = s.find(":")
            if sep_idx != -1:
                return s[: sep_idx + 1] + " [REDACTED]"
            return "[REDACTED]"
        result, count = pattern.subn(_repl, text)
        return result, count

    if category == "password":
        def _repl(m):
            s = m.group(0)
            eq_idx = s.find("=")
            if eq_idx != -1:
                return s[: eq_idx + 1] + "[REDACTED]"
            return "[REDACTED]"
        result, count = pattern.subn(_repl, text)
        return result, count

    if category == "bearer_token":
        result, count = pattern.subn("Bearer [REDACTED]", text)
        return result, count

    if category == "connection_string":
        result, count = pattern.subn("[REDACTED_CONNECTION_STRING]", text)
        return result, count

    if category == "private_key":
        result, count = pattern.subn("[REDACTED_PRIVATE_KEY]", text)
        return result, count

    if category == "azure_subscription_id":
        result, count = pattern.subn(r'\1[REDACTED]"', text)
        return result, count

    if category == "storage_key":
        def _repl(m):
            s = m.group(0)
            eq_idx = s.find("=")
            if eq_idx != -1:
                return s[: eq_idx + 1] + "[REDACTED]"
            return "[REDACTED]"
        result, count = pattern.subn(_repl, text)
        return result, count

    if category == "sas_token":
        result, count = pattern.subn("[REDACTED_SAS_TOKEN]", text)
        return result, count

    return text, 0


def redact_output(text: str) -> tuple[str, dict]:
    """Apply all redaction patterns. Returns (redacted_text, metadata)."""
    total_count = 0
    categories_matched = []

    for category, pattern, _ in _REDACTION_PATTERNS:
        text, count = _apply_redaction(category, pattern, text)
        if count > 0:
            total_count += count
            categories_matched.append(category)

    return text, {
        "redactions_applied": total_count > 0,
        "redaction_count": total_count,
        "redaction_categories": categories_matched,
    }


# ---------------------------------------------------------------------------
# Output processing — Topology anonymization (opt-in)
# ---------------------------------------------------------------------------

# RFC 1918 ranges
_RFC1918_IP_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Subnet CIDRs — private ranges with /prefix
_RFC1918_SUBNET_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")/(\d{1,2})\b"
)

# Azure resource IDs
_AZURE_RESOURCE_RE = re.compile(
    r"/subscriptions/[^/\s]+(?:/resourceGroups/[^/\s]+(?:/[^/\s]+)*)"
)


class TopologyAnonymizer:
    """Session-scoped anonymizer that maps real values to consistent placeholders."""

    def __init__(self):
        self._ip_map: dict[str, str] = {}
        self._subnet_map: dict[str, str] = {}
        self._resource_map: dict[str, str] = {}
        self._ip_counter = 0
        self._subnet_counter = 0
        self._resource_counter = 0

    def _get_ip_placeholder(self, ip: str) -> str:
        if ip not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[ip] = f"[INTERNAL_IP_{self._ip_counter}]"
        return self._ip_map[ip]

    def _get_subnet_placeholder(self, subnet: str) -> str:
        if subnet not in self._subnet_map:
            self._subnet_counter += 1
            self._subnet_map[subnet] = f"[INTERNAL_SUBNET_{self._subnet_counter}]"
        return self._subnet_map[subnet]

    def _get_resource_placeholder(self, resource_id: str) -> str:
        if resource_id not in self._resource_map:
            self._resource_counter += 1
            self._resource_map[resource_id] = f"[AZURE_RESOURCE_{self._resource_counter}]"
        return self._resource_map[resource_id]

    @property
    def mappings_count(self) -> int:
        return len(self._ip_map) + len(self._subnet_map) + len(self._resource_map)

    def anonymize(self, text: str) -> str:
        """Replace internal IPs, subnets, and Azure resource IDs with placeholders."""
        # Subnets first (more specific — includes /prefix that would otherwise match IP)
        def _subnet_repl(m):
            full = f"{m.group(1)}/{m.group(2)}"
            return self._get_subnet_placeholder(full)
        text = _RFC1918_SUBNET_RE.sub(_subnet_repl, text)

        # Azure resource IDs
        def _resource_repl(m):
            return self._get_resource_placeholder(m.group(0))
        text = _AZURE_RESOURCE_RE.sub(_resource_repl, text)

        # IPs (after subnets, so /prefix versions are already replaced)
        def _ip_repl(m):
            return self._get_ip_placeholder(m.group(1))
        text = _RFC1918_IP_RE.sub(_ip_repl, text)

        return text


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

@dataclass
class AuditRecord:
    timestamp: str
    session_id: str
    sequence: int
    command: str
    reasoning: str
    status: str
    classification: str
    tier_triggered: Optional[int]
    error: Optional[str]
    action: str
    user_decision: Optional[str]
    modified_command: Optional[str]
    environment: str
    exit_code: Optional[int]
    output_summary: str
    output_truncated: bool
    redactions_applied: bool
    redaction_categories: list[str]
    duration_seconds: Optional[float]
    anonymization_applied: bool


def _write_audit_record(record: AuditRecord, audit_dir: Path, session_id: str):
    """Append one audit record to the session's JSONL file."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    filepath = audit_dir / f"shell_audit_{session_id}.jsonl"
    with open(filepath, "a") as f:
        f.write(json.dumps(asdict(record), default=str) + "\n")


# ---------------------------------------------------------------------------
# HITL decision types
# ---------------------------------------------------------------------------

@dataclass
class HitlDecision:
    action: str  # "approve", "deny", "modify"
    modified_command: Optional[str] = None


# Default HITL callback — denies everything (fail-closed)
def _default_hitl_callback(
    command: str, reasoning: str, risk_explanation: str, tier: int
) -> HitlDecision:
    return HitlDecision(action="deny")


# ---------------------------------------------------------------------------
# SafeExecShell — main class
# ---------------------------------------------------------------------------

class SafeExecShell:
    """The Safe-Exec Shell: safety boundary between the AI Brain and system commands.

    Usage:
        shell = SafeExecShell(session_id="sess_001", audit_dir="./audit")
        response = shell.execute({"command": "ping 8.8.8.8", "reasoning": "Test connectivity"})
    """

    def __init__(
        self,
        session_id: str,
        audit_dir: str = DEFAULT_AUDIT_DIR,
        hitl_callback: Optional[Callable] = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        anonymization_enabled: bool = False,
    ):
        self._session_id = session_id
        self._audit_dir = Path(audit_dir)
        self._hitl_callback = hitl_callback or _default_hitl_callback
        self._timeout = timeout_seconds
        self._anonymization_enabled = anonymization_enabled
        self._anonymizer = TopologyAnonymizer() if anonymization_enabled else None
        self._sequence = 0

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """Execute a command through the four-stage pipeline.

        Args:
            request: {"command": str, "reasoning": str}

        Returns:
            Response dict matching the Shell -> Brain contract.
        """
        self._sequence += 1
        audit_id = f"{self._session_id}_{self._sequence:03d}"

        # --- Validate request ---
        command_str = request.get("command", "")
        reasoning = request.get("reasoning", "")

        if not isinstance(command_str, str) or not command_str or not command_str.strip():
            return self._error_response(
                audit_id=audit_id,
                command_str=command_str or "",
                reasoning=reasoning,
                error_code="empty_command",
                classification=CLASSIFICATION_RISKY,
                tier_triggered=None,
                log_audit=False,  # empty commands are not logged
            )

        if "reasoning" not in request:
            return self._error_response(
                audit_id=audit_id,
                command_str=command_str,
                reasoning="",
                error_code="empty_command",
                classification=CLASSIFICATION_RISKY,
                tier_triggered=None,
                log_audit=False,
            )

        command_str = command_str.strip()

        # --- Stage 1: Classify ---
        classification, tier_triggered, risk_explanation = classify(command_str)

        # Parse for environment detection (best-effort)
        try:
            args = shlex.split(command_str)
        except ValueError:
            args = command_str.split()
        environment = _detect_environment(args) if args else "local"

        # FORBIDDEN — short-circuit before Stage 2
        if classification == CLASSIFICATION_FORBIDDEN:
            return self._error_response(
                audit_id=audit_id,
                command_str=command_str,
                reasoning=reasoning,
                error_code="forbidden_command",
                classification=CLASSIFICATION_FORBIDDEN,
                tier_triggered=0,
                log_audit=True,
                environment=environment,
            )

        # --- Stage 2: Gate (HITL) ---
        action = "auto_approved"
        user_decision = None
        modified_command = None
        executed_command = command_str

        if classification == CLASSIFICATION_RISKY:
            try:
                decision = self._hitl_callback(
                    command_str, reasoning, risk_explanation, tier_triggered
                )
            except Exception:
                # HITL mechanism failure — fail closed
                return self._denied_response(
                    audit_id=audit_id,
                    command_str=command_str,
                    reasoning=reasoning,
                    classification=classification,
                    tier_triggered=tier_triggered,
                    action="user_abandoned",
                    user_decision=None,
                    environment=environment,
                )

            if isinstance(decision, dict):
                decision = HitlDecision(
                    action=decision.get("action", "deny"),
                    modified_command=decision.get("modified_command"),
                )

            if decision.action == "deny":
                return self._denied_response(
                    audit_id=audit_id,
                    command_str=command_str,
                    reasoning=reasoning,
                    classification=classification,
                    tier_triggered=tier_triggered,
                    action="user_denied",
                    user_decision="deny",
                    environment=environment,
                )

            if decision.action == "modify" and decision.modified_command:
                modified_command = decision.modified_command.strip()
                user_decision = "modify"

                # Re-classify the modified command from Tier 0
                new_class, new_tier, new_explanation = classify(modified_command)

                if new_class == CLASSIFICATION_FORBIDDEN:
                    return self._error_response(
                        audit_id=audit_id,
                        command_str=command_str,
                        reasoning=reasoning,
                        error_code="forbidden_command",
                        classification=CLASSIFICATION_FORBIDDEN,
                        tier_triggered=0,
                        log_audit=True,
                        environment=environment,
                        modified_command=modified_command,
                    )

                if new_class == CLASSIFICATION_RISKY:
                    # Still RISKY after modification — need another HITL round
                    # For simplicity, we recursively call execute with the modified command
                    # but preserve the modification chain
                    modified_request = {"command": modified_command, "reasoning": reasoning}
                    result = self.execute(modified_request)
                    result["action"] = "user_modified"
                    result["modified_command"] = modified_command
                    return result

                # Modified command is now SAFE
                executed_command = modified_command
                action = "user_modified"
                classification = new_class
                tier_triggered = new_tier

                try:
                    args = shlex.split(executed_command)
                except ValueError:
                    args = executed_command.split()
                environment = _detect_environment(args) if args else "local"
            else:
                # Approved
                action = "user_approved"
                user_decision = "approve"

        # --- Stage 3: Execute ---
        try:
            exec_args = shlex.split(executed_command)
        except ValueError:
            exec_args = executed_command.split()

        stdout_str = ""
        stderr_str = ""
        exit_code = None
        duration = None

        try:
            start_time = time.monotonic()
            result = subprocess.run(
                exec_args,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
            )
            duration = round(time.monotonic() - start_time, 3)
            stdout_str = result.stdout
            stderr_str = result.stderr
            exit_code = result.returncode
            status = STATUS_COMPLETED
        except subprocess.TimeoutExpired:
            duration = round(time.monotonic() - start_time, 3)
            return self._timeout_response(
                audit_id=audit_id,
                command_str=command_str,
                reasoning=reasoning,
                classification=classification,
                tier_triggered=tier_triggered,
                action=action,
                user_decision=user_decision,
                modified_command=modified_command,
                environment=environment,
                duration=duration,
            )
        except FileNotFoundError:
            duration = round(time.monotonic() - start_time, 3)
            exit_code = 127
            stderr_str = f"command not found: {exec_args[0]}"
            status = STATUS_COMPLETED

        # --- Stage 4: Process output ---
        # Step 1: Truncate
        truncated_output, truncation_meta = truncate_output(stdout_str)

        # Step 2: Redact
        try:
            redacted_output, redaction_meta = redact_output(truncated_output)
            redacted_stderr, stderr_redaction = redact_output(stderr_str)
        except Exception:
            # Redaction failure — fail closed, never expose raw output
            return self._error_response(
                audit_id=audit_id,
                command_str=command_str,
                reasoning=reasoning,
                error_code="redaction_failure",
                classification=classification,
                tier_triggered=tier_triggered,
                log_audit=True,
                environment=environment,
            )

        # Step 3: Anonymize (if enabled)
        anonymization_meta = {}
        if self._anonymizer:
            redacted_output = self._anonymizer.anonymize(redacted_output)
            redacted_stderr = self._anonymizer.anonymize(redacted_stderr)
            anonymization_meta = {
                "anonymization_applied": True,
                "anonymization_mappings_count": self._anonymizer.mappings_count,
            }

        # Build output_metadata
        output_metadata = {**truncation_meta, **redaction_meta, **anonymization_meta}

        # Build response
        response = {
            "status": status,
            "classification": classification,
            "action": action,
            "output": redacted_output,
            "stderr": redacted_stderr,
            "exit_code": exit_code,
            "error": None,
            "duration_seconds": duration,
            "output_metadata": output_metadata,
            "audit_id": audit_id,
        }

        # Write audit record
        self._write_audit(
            audit_id=audit_id,
            command_str=command_str,
            reasoning=reasoning,
            status=status,
            classification=classification,
            tier_triggered=tier_triggered,
            error=None,
            action=action,
            user_decision=user_decision,
            modified_command=modified_command,
            environment=environment,
            exit_code=exit_code,
            output=redacted_output,
            output_truncated=truncation_meta.get("truncation_applied", False),
            redactions_applied=redaction_meta.get("redactions_applied", False),
            redaction_categories=redaction_meta.get("redaction_categories", []),
            duration=duration,
        )

        return response

    # --- Response builders ---

    def _error_response(
        self,
        audit_id: str,
        command_str: str,
        reasoning: str,
        error_code: str,
        classification: str,
        tier_triggered: Optional[int],
        log_audit: bool,
        environment: str = "local",
        modified_command: Optional[str] = None,
    ) -> dict[str, Any]:
        response = {
            "status": STATUS_ERROR,
            "classification": classification,
            "action": "auto_approved" if classification == CLASSIFICATION_SAFE else "auto_approved",
            "output": "",
            "stderr": "",
            "exit_code": None,
            "error": error_code,
            "duration_seconds": None,
            "output_metadata": {},
            "audit_id": audit_id,
        }

        if log_audit:
            self._write_audit(
                audit_id=audit_id,
                command_str=command_str,
                reasoning=reasoning,
                status=STATUS_ERROR,
                classification=classification,
                tier_triggered=tier_triggered,
                error=error_code,
                action="auto_approved",
                user_decision=None,
                modified_command=modified_command,
                environment=environment,
                exit_code=None,
                output="",
                output_truncated=False,
                redactions_applied=False,
                redaction_categories=[],
                duration=None,
            )

        return response

    def _denied_response(
        self,
        audit_id: str,
        command_str: str,
        reasoning: str,
        classification: str,
        tier_triggered: Optional[int],
        action: str,
        user_decision: Optional[str],
        environment: str,
    ) -> dict[str, Any]:
        response = {
            "status": STATUS_DENIED,
            "classification": classification,
            "action": action,
            "output": "",
            "stderr": "",
            "exit_code": None,
            "error": None,
            "duration_seconds": None,
            "output_metadata": {},
            "audit_id": audit_id,
        }

        self._write_audit(
            audit_id=audit_id,
            command_str=command_str,
            reasoning=reasoning,
            status=STATUS_DENIED,
            classification=classification,
            tier_triggered=tier_triggered,
            error=None,
            action=action,
            user_decision=user_decision,
            modified_command=None,
            environment=environment,
            exit_code=None,
            output="",
            output_truncated=False,
            redactions_applied=False,
            redaction_categories=[],
            duration=None,
        )

        return response

    def _timeout_response(
        self,
        audit_id: str,
        command_str: str,
        reasoning: str,
        classification: str,
        tier_triggered: Optional[int],
        action: str,
        user_decision: Optional[str],
        modified_command: Optional[str],
        environment: str,
        duration: float,
    ) -> dict[str, Any]:
        response = {
            "status": STATUS_ERROR,
            "classification": classification,
            "action": action,
            "output": "",
            "stderr": "",
            "exit_code": None,
            "error": "timeout",
            "duration_seconds": duration,
            "output_metadata": {},
            "audit_id": audit_id,
        }

        self._write_audit(
            audit_id=audit_id,
            command_str=command_str,
            reasoning=reasoning,
            status=STATUS_ERROR,
            classification=classification,
            tier_triggered=tier_triggered,
            error="timeout",
            action=action,
            user_decision=user_decision,
            modified_command=modified_command,
            environment=environment,
            exit_code=None,
            output="",
            output_truncated=False,
            redactions_applied=False,
            redaction_categories=[],
            duration=duration,
        )

        return response

    def _write_audit(
        self,
        audit_id: str,
        command_str: str,
        reasoning: str,
        status: str,
        classification: str,
        tier_triggered: Optional[int],
        error: Optional[str],
        action: str,
        user_decision: Optional[str],
        modified_command: Optional[str],
        environment: str,
        exit_code: Optional[int],
        output: str,
        output_truncated: bool,
        redactions_applied: bool,
        redaction_categories: list[str],
        duration: Optional[float],
    ):
        """Write an audit record. Failures are logged to stderr but never block execution."""
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            sequence=self._sequence,
            command=command_str,
            reasoning=reasoning,
            status=status,
            classification=classification,
            tier_triggered=tier_triggered,
            error=error,
            action=action,
            user_decision=user_decision,
            modified_command=modified_command,
            environment=environment,
            exit_code=exit_code,
            output_summary=output[:200] if output else "",
            output_truncated=output_truncated,
            redactions_applied=redactions_applied,
            redaction_categories=redaction_categories,
            duration_seconds=duration,
            anonymization_applied=self._anonymization_enabled,
        )

        try:
            _write_audit_record(record, self._audit_dir, self._session_id)
        except Exception as e:
            import sys
            print(f"WARNING: Audit log write failure: {e}", file=sys.stderr)
