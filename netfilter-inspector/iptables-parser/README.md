# iptables-parser

Standalone parser, diff engine, and LLM-powered explanation for `iptables-save` output.

Parses raw `iptables-save` / `ip6tables-save` text into a structured JSON snapshot, computes rule-level diffs between two snapshots, and optionally produces a plain-English security analysis via an LLM. Designed to operate standalone or as a library consumed by the Netfilter Inspector.

**Status: Shipped — 2026-03-15.**
Tested against real Ubuntu 24.04 VMs (clean, Docker, fail2ban, CIS-hardened, log/mark/SNAT variants).

---

## Documentation

| Document | Description |
|----------|-------------|
| `docs/design.md` | Component inventory, data schemas, algorithms, error handling |
| `docs/product-requirements.md` | Users, problem statement, functional requirements |

---

## Structure

```
iptables-parser/
├── iptables_parser.py      # Public API: parse_iptables_save(); CLI: --explain / --explain-diff
├── iptables_diff.py        # Public API: diff_rulesets(); CLI: diff two parsed snapshots
├── iptables_explain.py     # LLM-powered explanation engine: explain_snapshot(), explain_diff()
├── iptables-samples/       # Real-world fixture files from live Azure and Multipass VMs
├── pyproject.toml          # Project metadata and dependencies (uv)
├── .env.example            # Environment variable reference for --explain features
├── docs/
│   ├── design.md
│   └── product-requirements.md
└── tests/                  # 108 tests: parser, diff, explain, non-functional
```

---

## Requirements

- Python 3.9+
- `pytest` (tests only)
- LLM API key set as an environment variable (for `--explain` / `--explain-diff` only — see `.env.example`)

No third-party Python packages required for the parser or diff engine. An LLM client package (e.g. `google-genai`) is required for explain features only.

---

## Installation

```bash
# From the iptables-parser directory
uv sync
```

---

## CLI usage

### Parse

```bash
# Parse an iptables-save file
python3 iptables_parser.py /etc/iptables/rules.v4

# Parse from stdin
sudo iptables-save | python3 iptables_parser.py

# Parse IPv6
sudo ip6tables-save | python3 iptables_parser.py
```

### Explain (requires LLM API key)

```bash
# Plain-English explanation of the current firewall state
sudo iptables-save | python3 iptables_parser.py --explain

# Plain-English explanation of what changed between two snapshots
python3 iptables_parser.py before.json --explain-diff after.json
```

### Diff

```bash
# Diff two parsed snapshots (no LLM)
python3 iptables_diff.py baseline.json current.json
```

---

## Running tests

```bash
# All tests (108 passed)
uv run --python 3.12 pytest tests/ -v

# Specific areas
uv run --python 3.12 pytest tests/test_fixtures.py       # fixture-level
uv run --python 3.12 pytest tests/test_field_accuracy.py # field accuracy
uv run --python 3.12 pytest tests/test_edge_cases.py     # edge cases
uv run --python 3.12 pytest tests/test_explain.py        # explain engine
```

---

## Public API

```python
from iptables_parser import parse_iptables_save
from iptables_diff import diff_rulesets
from iptables_explain import explain_snapshot, explain_diff

# Parse
snapshot = parse_iptables_save(iptables_save_text)

# Diff two snapshots
drift = diff_rulesets(baseline_snapshot, current_snapshot)

# Explain (requires LLM API key in environment)
text = explain_snapshot(snapshot)
text = explain_diff(baseline_snapshot, current_snapshot)
```

---

## Part of netfilter-inspector

This module is one component of the larger [netfilter-inspector](../README.md) system, which orchestrates iptables and nftables state capture across SSH and Azure-managed VMs and integrates with the Network Ghost Agent.
