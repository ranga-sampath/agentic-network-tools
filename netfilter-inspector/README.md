# netfilter-inspector

OS-layer firewall state capture, diff, and explanation for Linux VMs.

Captures `iptables`/`ip6tables` and `nftables` ruleset snapshots from any SSH-accessible or Azure-managed Linux VM, stores them as baselines, and diffs against a previous baseline to detect configuration drift. Supports LLM-powered explanation of firewall state and diffs. Designed to operate standalone or as a tool invoked by the Network Ghost Agent.

**Status: Active development — 2026-03-18.**
Fully tested on Azure VMs (iptables-nft backend) and Multipass VMs (iptables-legacy and nftables-native).

## Documentation

| Document | Description |
|----------|-------------|
| `docs/architecture.md` | Design decisions, system boundary, component contracts |
| `iptables-parser/docs/design.md` | Parser and diff engine: schemas, algorithms, error handling |
| `iptables-parser/docs/product-requirements.md` | Users, problem statement, functional requirements |
| `firewall-inspector/docs/design.md` | Orchestrator, providers, framework detector, chain classifier |
| `firewall-inspector/docs/test_plan.md` | Test plan for firewall inspector |

## Structure

```
netfilter-inspector/
├── docs/
│   └── architecture.md             # Design decisions and system boundary
│
├── iptables-parser/                # Standalone iptables-save parser, diff, and explain engine
│   ├── iptables_parser.py          # Public API: parse_iptables_save(); optional --explain / --explain-diff
│   ├── iptables_explain.py         # LLM-powered explanation engine (Gemini); explain_snapshot(), explain_diff()
│   ├── iptables_diff.py            # Public API: diff_rulesets()
│   ├── iptables-samples/           # Real-world fixture files from live Azure and Multipass VMs
│   ├── pyproject.toml              # Project metadata and dependencies (uv)
│   ├── docs/
│   │   ├── product-requirements.md
│   │   └── design.md               # Parser + diff + explain engine design
│   └── tests/                      # 108 tests: parser, diff, explain, non-functional
│
├── nftables-parser/                # Standalone nftables JSON parser, diff, and explain engine
│   ├── nftables_parser.py          # Public API: parse_nft_ruleset()
│   ├── nftables_explain.py         # LLM-powered explanation engine (Gemini); explain_snapshot(), explain_diff()
│   ├── nftables_diff.py            # Public API: diff_rulesets()
│   ├── nftables-samples/           # Real-world fixture files from live nftables VMs
│   └── tests/                      # nftables parser and diff tests
│
└── firewall-inspector/             # Firewall state orchestrator
    ├── firewall_inspector.py       # Main pipeline: probe → retrieve → parse → diff
    ├── providers.py                # LocalShell, AzureProvider (control-plane), SSHProvider
    ├── framework_detector.py       # iptables-legacy / iptables-nft / nftables detection
    ├── chain_classifier.py         # Ephemeral/structural/user-defined chain tiers
    ├── docs/
    │   ├── design.md               # Orchestrator + providers design
    │   └── test_plan.md            # Test plan
    └── tests/                      # 141 passed, 2 skipped
```

## Module dependency

```
iptables_parser.py     (standalone — no local deps)
         ↑
iptables_diff.py       (consumes iptables_parser output format)
         ↑
iptables_explain.py    (wraps iptables_parser + iptables_diff; calls Gemini)
         ↑
chain_classifier.py    (consumes iptables_diff output format)

nftables_parser.py     (standalone — no local deps)
         ↑
nftables_diff.py       (consumes nftables_parser output format)
         ↑
nftables_explain.py    (wraps nftables_parser + nftables_diff; calls Gemini)

framework_detector.py  (standalone — no local deps)
providers.py           (standalone — no local deps)

firewall_inspector.py  (orchestrates all of the above; branches on detected framework)
         ↑
Network Ghost Agent    (calls firewall_inspector as a subprocess tool)
```

## Running tests

```bash
# All tests from the netfilter-inspector root
uv run --python 3.12 pytest iptables-parser/ firewall-inspector/
# → 249 passed, 2 skipped

# Parser + diff + explain engine only
uv run --python 3.12 pytest iptables-parser/

# Firewall inspector only (141 passed, 2 skipped)
uv run --python 3.12 pytest firewall-inspector/
```

## Requirements

- Python 3.9+
- `pytest` (tests only)
- `az` CLI with `vm run-command invoke` permission (for `--provider azure`)
- SSH key access to target VM and bastion if using two-hop topology (for `--provider ssh`)
- `sudo iptables-save` or `nft --json list ruleset` access on target VM
- `GEMINI_API_KEY` environment variable (for `--explain` / `--explain-diff` only)

No third-party Python packages required for library or inspector code. `google-genai` required for explain features only.

## Standalone usage

### Azure VM (control-plane — no SSH required)

```bash
# Capture baseline — VM name and resource group only, no IP address needed
python3 firewall-inspector/firewall_inspector.py \
    --provider azure \
    --vm-name tf-dest-vm \
    --resource-group nw-forensics-rg \
    --is-baseline

# Compare against baseline
python3 firewall-inspector/firewall_inspector.py \
    --provider azure \
    --vm-name tf-dest-vm \
    --resource-group nw-forensics-rg \
    --compare-baseline fw_20260318_095645
```

### Azure VM via bastion (two-hop SSH)

```bash
# config: PROVIDER=ssh, TARGET_VM_IP=10.0.1.5, BASTION_PUBLIC_IP=172.190.88.171
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --is-baseline
```

### Multipass / SSH VM

```bash
# config: PROVIDER=ssh, TARGET_VM_IP=192.168.2.6
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --is-baseline

python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --compare-baseline <baseline_session_id>
```

### Parser CLI — iptables (standalone, with optional explain)

```bash
# Parse an iptables-save file
python3 iptables-parser/iptables_parser.py /etc/iptables/rules.v4

# Parse from stdin
sudo iptables-save | python3 iptables-parser/iptables_parser.py

# LLM explanation of current firewall state (requires GEMINI_API_KEY)
sudo iptables-save | python3 iptables-parser/iptables_parser.py --explain

# LLM explanation of what changed between two snapshots
python3 iptables-parser/iptables_parser.py before.json --explain-diff after.json

# Diff two parsed snapshots (no LLM)
python3 iptables-parser/iptables_diff.py baseline.json current.json
```
