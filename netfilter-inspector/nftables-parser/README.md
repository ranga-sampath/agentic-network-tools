# nftables-parser

Standalone parser, diff engine, and LLM-powered explanation for `nft --json list ruleset` output.

Parses the JSON output of `nft --json list ruleset` into a structured snapshot, computes rule-level diffs between two snapshots, and optionally produces a plain-English security analysis via an LLM. Designed to operate standalone or as a library consumed by the Netfilter Inspector.

**Status: Shipped — 2026-03-16.**
Tested against real Multipass VMs running nftables-native (Ubuntu 24.04).

---

## Documentation

| Document | Description |
|----------|-------------|
| `docs/design.md` | Component inventory, data schemas, algorithms, error handling |
| `docs/product-requirements.md` | Users, problem statement, functional requirements |
| `docs/test_plan.md` | Test plan |

---

## Structure

```
nftables-parser/
├── nftables_parser.py      # Public API: parse_nft_ruleset(); CLI: --explain / --explain-diff
├── nftables_diff.py        # Public API: nft_diff_rulesets(); CLI: diff two parsed snapshots
├── nftables_explain.py     # LLM-powered explanation engine: explain_snapshot(), explain_diff()
├── nftables-samples/       # Real-world fixture files (12 scenarios: clean, drop-policy, sets, NAT, etc.)
├── pyproject.toml          # Project metadata and dependencies (uv)
├── .env.example            # Environment variable reference for --explain features
├── docs/
│   ├── design.md
│   ├── product-requirements.md
│   └── test_plan.md
└── tests/                  # Parser, diff, explain, and CLI tests
```

---

## Requirements

- Python 3.9+
- `pytest` (tests only)
- `nft` with `--json` support (nftables 0.9.1+) on the target VM
- LLM API key set as an environment variable (for `--explain` / `--explain-diff` only — see `.env.example`)

No third-party Python packages required for the parser or diff engine. An LLM client package (e.g. `google-genai`) is required for explain features only.

---

## Installation

```bash
# From the nftables-parser directory
uv sync
```

---

## CLI usage

### Parse

```bash
# Parse a live nftables ruleset
sudo nft --json list ruleset | python3 nftables_parser.py

# Parse a saved nftables JSON file
python3 nftables_parser.py ruleset.json
```

### Explain (requires LLM API key)

```bash
# Plain-English explanation of the current firewall state
sudo nft --json list ruleset | python3 nftables_parser.py --explain

# Plain-English explanation of what changed between two snapshots
python3 nftables_parser.py before.json --explain-diff after.json
```

### Diff

```bash
# Diff two parsed snapshots (no LLM) — JSON output
python3 nftables_diff.py baseline.json current.json

# Diff with human-readable Markdown summary
python3 nftables_diff.py baseline.json current.json --summary
```

---

## Running tests

```bash
# All tests
uv run --python 3.12 pytest tests/ -v

# Specific areas
uv run --python 3.12 pytest tests/test_parser.py   # parser
uv run --python 3.12 pytest tests/test_diff.py     # diff engine
uv run --python 3.12 pytest tests/test_explain.py  # explain engine
uv run --python 3.12 pytest tests/test_cli.py      # CLI flags
```

---

## Public API

```python
from nftables_parser import parse_nft_ruleset
from nftables_diff import nft_diff_rulesets
from nftables_explain import explain_snapshot, explain_diff

# Parse
snapshot = parse_nft_ruleset(nft_json_text)

# Diff two snapshots
drift = nft_diff_rulesets(baseline_snapshot, current_snapshot)

# Explain (requires LLM API key in environment)
text = explain_snapshot(snapshot)
text = explain_diff(baseline_snapshot, current_snapshot)
```

---

## Part of netfilter-inspector

This module is one component of the larger [netfilter-inspector](../README.md) system, which orchestrates iptables and nftables state capture across SSH and Azure-managed VMs and integrates with the Network Ghost Agent.
