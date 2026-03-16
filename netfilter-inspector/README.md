# netfilter-inspector

OS-layer firewall state capture and drift detection for Linux VMs.

Captures `iptables`/`ip6tables` ruleset snapshots from any SSH-accessible Linux VM (Azure VMs, Multipass VMs, bare-metal hosts), stores them as baselines, and diffs against a previous baseline to detect configuration drift. Designed to operate standalone or as a tool invoked by the Network Ghost Agent.

**MVP status: Shipped — 2026-03-15.** End-to-end tested on Azure VMs and local Multipass VMs with iptables-legacy.

## Documentation

| Document | Description |
|----------|-------------|
| `docs/product-requirements.md` | Users, problem statement, functional requirements, constraints, out-of-scope |
| `docs/architecture.md` | Design decisions, system boundary, component contracts, intentional omissions |
| `docs/design.md` | End-to-end pipeline, artifact sequence, standalone and Ghost Agent usage |
| `iptables-parser/docs/design.md` | Parser and diff engine: schemas, algorithms, error handling, edge cases |
| `iptables-parser/docs/test_plan.md` | Test plan for parser and diff engine (57 tests) |
| `firewall-inspector/docs/design.md` | Orchestrator, providers, framework detector, chain classifier |
| `firewall-inspector/docs/test_plan.md` | Test plan for firewall inspector (123 passed, 2 skipped) |

## Structure

```
netfilter-inspector/
├── docs/
│   ├── product-requirements.md # Users, problem, functional requirements, constraints
│   ├── architecture.md         # Design decisions and system boundary
│   └── design.md               # End-to-end pipeline and usage guide
│
├── iptables-parser/            # Standalone iptables-save parser and diff engine
│   ├── iptables_parser.py      # Public API: parse_iptables_save()
│   ├── iptables_diff.py        # Public API: diff_rulesets()
│   ├── iptables-samples/       # Real-world fixture files from live VMs
│   ├── docs/
│   │   ├── product-requirements.md
│   │   ├── design.md           # Parser + diff engine design
│   │   └── test_plan.md        # Test plan (57 tests)
│   └── tests/                  # 57 tests: parser and diff engine
│
└── firewall-inspector/         # Firewall state orchestrator
    ├── firewall_inspector.py   # Main pipeline: probe → retrieve → parse → diff
    ├── providers.py            # LocalShell, AzureProvider, SSHProvider
    ├── framework_detector.py   # iptables-legacy vs iptables-nft vs nftables
    ├── chain_classifier.py     # Ephemeral/structural/user-defined tiers
    ├── config.env.example      # Config file template
    ├── multipass-config.env    # Multipass local dev config
    ├── docs/
    │   ├── design.md           # Orchestrator + providers design
    │   └── test_plan.md        # Test plan (123 passed, 2 skipped)
    ├── plans/                  # Design plans and research notes
    │   ├── vm-firewall-inspector-plan.md
    │   ├── netfilter-diff-plan.md
    │   ├── security_challenges.md
    │   └── explain-feature-design.md
    └── tests/                  # 123 passed, 2 skipped (125 total)
```

## Module dependency

```
iptables_parser.py     (standalone — no local deps)
         ↑
iptables_diff.py       (consumes iptables_parser output format)
         ↑
chain_classifier.py    (consumes iptables_diff output format)

framework_detector.py  (standalone — no local deps)
providers.py           (standalone — no local deps)

firewall_inspector.py  (orchestrates all of the above)
         ↑
Network Ghost Agent    (calls firewall_inspector as a tool)
```

## Running tests

```bash
# All tests from the netfilter-inspector root (180 passed, 2 skipped)
python3 -m pytest

# Parser + diff engine only (57 tests)
python3 -m pytest iptables-parser/

# Firewall inspector only (123 passed, 2 skipped)
python3 -m pytest firewall-inspector/
```

## Requirements

- Python 3.9+
- `pytest` (tests only)
- `az` CLI with `vm run-command invoke` permission (for `--provider azure`)
- SSH key access to target VM (and bastion if using two-hop topology)
- `known_hosts` entries for all SSH hosts before first run (`ssh-keyscan`)
- `sudo iptables-save` access on target VM

No third-party Python packages required for library code.

## Standalone usage

### Azure VM

```bash
# Capture baseline (two-hop: target has private IP, access via bastion)
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --is-baseline \
    --session-id fw_pre_change_20260315

# Compare against baseline
python3 firewall-inspector/firewall_inspector.py \
    --config config.env \
    --compare-baseline fw_pre_change_20260315 \
    --session-id fw_post_change_20260315
```

### Multipass / SSH VM

```bash
# config: PROVIDER=ssh, TARGET_VM_IP=192.168.2.6, no BASTION_PUBLIC_IP
python3 firewall-inspector/firewall_inspector.py \
    --config multipass-config.env \
    --is-baseline

python3 firewall-inspector/firewall_inspector.py \
    --config multipass-config.env \
    --compare-baseline <baseline_session_id>
```

### Parser CLI (standalone)

```bash
# Parse an iptables-save file
python3 iptables-parser/iptables_parser.py /etc/iptables/rules.v4

# Parse from stdin
sudo iptables-save | python3 iptables-parser/iptables_parser.py

# Diff two parsed snapshots
python3 iptables-parser/iptables_diff.py baseline.json current.json

# Pipe: parse live state and diff against a stored baseline
sudo iptables-save | python3 iptables-parser/iptables_parser.py | \
    python3 iptables-parser/iptables_diff.py pre_change.json -
```
