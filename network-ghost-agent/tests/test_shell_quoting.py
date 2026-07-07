"""test_shell_quoting.py — path quoting in built shell commands (IMP-03).

Paths originating from the task registry and stale-file scan are interpolated
into shell commands (rm, cat). These tests assert the commands are built with
shlex-safe quoting so a path containing quotes or command substitution cannot
break out of the argument.
"""

import shlex
from unittest.mock import MagicMock

from ghost_agent import _new_session, _read_forensic_report, _run_batch_cleanup


class _CapturingShell:
    """Stub shell that records commands and returns a canned success."""

    def __init__(self, output="report body"):
        self.commands = []
        self._hitl_callback = lambda *a, **k: None
        self._output = output

    def execute(self, request):
        self.commands.append(request["command"])
        return {"status": "completed", "exit_code": 0, "output": self._output}


NASTY_NAME = 'evil"; touch pwned; echo "_forensic_report.md'


def test_read_forensic_report_quotes_path(tmp_path):
    report = tmp_path / NASTY_NAME
    report.write_text("wire evidence")
    shell = _CapturingShell()

    content = _read_forensic_report(str(report), shell, str(tmp_path))

    assert content == "report body"
    cmd = shell.commands[0]
    # The command must parse back to exactly ["cat", <path>] — one argument,
    # no injected commands.
    parsed = shlex.split(cmd)
    assert parsed[0] == "cat"
    assert parsed[1] == str(report)
    assert len(parsed) == 2


def test_read_forensic_report_plain_path_unchanged(tmp_path):
    report = tmp_path / "x_forensic_report.md"
    report.write_text("wire evidence")
    shell = _CapturingShell()

    _read_forensic_report(str(report), shell, str(tmp_path))

    assert shlex.split(shell.commands[0]) == ["cat", str(report)]


def test_batch_cleanup_quotes_stale_file_paths(tmp_path):
    nasty = str(tmp_path / 'cap$(reboot)".pcap')
    buckets = {
        "abandoned_tasks":   [],
        "needs_cleanup":     [],
        "partially_cleaned": [],
        "untracked_azure":   [],
        "stale_local_files": [{"path": nasty}, {"path": str(tmp_path / "b.pcap")}],
    }
    shell = _CapturingShell()
    state = _new_session("gemini-2.0-flash", str(tmp_path))

    _run_batch_cleanup(buckets, shell, MagicMock(), state,
                       str(tmp_path / "s.json"), location="eastus")

    rm_cmds = [c for c in shell.commands if c.startswith("rm -f ")]
    assert len(rm_cmds) == 1
    parsed = shlex.split(rm_cmds[0])
    # rm -f <path1> <path2> — each nasty path survives as ONE literal argument
    assert parsed[:2] == ["rm", "-f"]
    assert nasty in parsed
    assert len(parsed) == 4
