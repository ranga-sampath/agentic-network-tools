# Security Rule Inspector

**Point-in-time Azure NSG effective rule evaluator. Verdict mode or full compliance audit.**

---

## The Problem

Azure NSG evaluation for inbound traffic applies two sequential gates — the subnet NSG fires first, then the NIC NSG. The Azure portal shows each NSG's rules in isolation. It does not surface the combined verdict for a specific flow, and it does not show which gate fired the decisive rule.

Two failure patterns follow from this gap:

**Hidden denies.** A deny rule in the subnet NSG at priority 100 blocks all traffic regardless of what the NIC NSG permits. The portal shows the NIC NSG "allowing" the port — the subnet NSG deny is a separate panel, easy to miss under incident pressure.

**Forgotten rules.** NSGs accumulate rules over months of iterative changes. After 18 months, no single team member knows what every rule was added for. The portal has no compliance view that flags overly permissive rules across both gates.

---

## What This Tool Does

Queries `az network nic list-effective-nsg` — the single Azure CLI command that returns the combined subnet NSG and NIC NSG state at a given NIC — and applies the dual-gate model in pure Python.

**Verdict mode** — answers a binary question for a specific traffic flow:

- Was `10.0.1.4:5432 TCP inbound` blocked? Which gate fired?
- What was the decisive rule? What is the final ALLOW / DENY / INDETERMINATE verdict?

**Audit mode** — produces a full rule inventory and findings:

- All inbound and outbound rules across both gates, with priority order
- Shadowed rules — rules that can never fire because a higher-priority rule is a superset
- Overly permissive rules — custom ALLOW rules with wildcard source, destination, or port
- Default-only gates — NSGs present but containing no custom rules

For inbound verdict mode, `--dst-ip` may be omitted. The tool derives it from the VM's own NIC private IP — which is always the correct destination for inbound traffic evaluated at a NIC.

---

## Quick Start

```bash
# Inbound verdict — was TCP/5432 from 10.0.1.4 blocked?
python security_rule_inspector.py \
  --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg \
  --src-ip 10.0.1.4 \
  --dst-port 5432 \
  --proto tcp \
  --direction inbound

# Full compliance audit
python security_rule_inspector.py \
  --vm-name tf-dest-vm \
  --resource-group nw-forensics-rg
```

---

## CLI Reference

```
security_rule_inspector.py
  --vm-name         VM_NAME             (required)
  --resource-group  RG_NAME             (required)

  Verdict mode (all five, or four with --dst-ip omitted for inbound):
  --src-ip          SOURCE_IP
  --dst-ip          DESTINATION_IP      (inbound: omit to derive from NIC)
  --dst-port        PORT                (1–65535)
  --proto           tcp | udp | icmp | *
  --direction       inbound | outbound

  Optional:
  --nic-name        NIC_NAME            override primary NIC resolution
  --subscription-id SUBSCRIPTION_ID    uses az default if absent
  --session-id      ID                 nsg_ prefix always enforced
  --audit-dir       PATH               artifact dir (default: ./audit)
```

**Mode selection:**
- All five traffic flags → verdict mode
- Four flags with `--dst-ip` absent and `--direction inbound` → verdict mode (dst_ip derived from NIC)
- No traffic flags → audit mode
- Any other partial combination → exit 2

---

## Outputs

### Verdict artifact
```
audit/{session_id}_verdict.json
```

```json
{
  "mode": "verdict",
  "traffic": { "src_ip": "10.0.1.4", "dst_ip": "10.0.1.5", "dst_port": 5432, ... },
  "gate_order": ["subnet", "nic"],
  "gate1": { "gate": "subnet", "verdict": "DENY", "decisive_rule": {...} },
  "gate2": { "gate": "nic",    "verdict": null, "evaluated": false, "skip_reason": "PRIOR_GATE_DENY" },
  "final_verdict": "DENY",
  "shadowed_rules": [],
  "unresolvable_rules": [],
  "parse_warnings": []
}
```

### Audit artifact
```
audit/{session_id}_audit.json
```

Includes full rule inventory across both gates and both directions, plus `findings.shadowed_rules`, `findings.permissive_rules`, and `findings.default_only_gates`.

### Raw artifact (both modes)
```
audit/{session_id}_raw.json   ← verbatim az CLI output
```

---

## Verdict values

| Verdict | Meaning |
|---|---|
| `ALLOW` | Both gates allow — traffic would be permitted |
| `DENY` | A gate fired a deny rule — traffic is blocked |
| `INDETERMINATE` | A rule with an unresolvable service tag or ASG matched before a decisive CIDR rule — the tool cannot determine the verdict without service tag expansion |

---

## RBAC Requirements

| Permission | Required for |
|---|---|
| `Microsoft.Compute/virtualMachines/read` | NIC name resolution via `az vm show` |
| `Microsoft.Network/networkInterfaces/read` | Private IP resolution via `az network nic show` |
| `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | `az network nic list-effective-nsg` |

All three are included in `Network Contributor`. The built-in `Reader` role does not include the `effectiveNetworkSecurityGroups/action` permission.

---

## Ghost Agent Integration

This tool is the backend for the `inspect_nsg` tool in Ghost Agent. Ghost Agent calls it as a subprocess with either a full traffic tuple (verdict mode) or VM name only (audit mode), reads the JSON artifact, and returns the verdict or findings to its reasoning loop.

```
inspect_nsg  ←→  security_rule_inspector.py
```

Ghost Agent demo use cases U and V exercise this tool:
- **Use Case U ("The Hidden Gate")** — Subnet NSG deny at Gate 1, NIC NSG shows all ALLOW
- **Use Case V ("The Open Doorway")** — Audit surfaces forgotten allow-all rule after 18 months of drift

---

## Module Structure

```
security-rule-inspector/
├── security_rule_inspector.py   ← CLI entry point + pipeline orchestration
├── nsg_engine.py                ← Pure dual-gate evaluation engine (no I/O)
├── nsg_preprocessor.py          ← Normalises raw az CLI JSON to gate/rule objects
├── providers.py                 ← Azure CLI boundary (NIC name, NIC IP, effective NSG)
├── fixtures/                    ← 10 JSON fixtures for unit and integration tests
├── docs/
│   ├── product-requirements.md
│   ├── architecture.md
│   ├── design.md
│   └── test_plan.md
└── tests/
    ├── test_nsg_engine.py        ← pure engine unit tests
    ├── test_nsg_preprocessor.py  ← preprocessor unit tests
    ├── test_providers.py         ← provider unit tests
    ├── test_cli.py               ← mode detection, validation, session ID tests
    ├── test_integration.py       ← end-to-end pipeline tests (mocked provider)
    ├── test_adversarial.py       ← malformed input, edge case, and adversarial tests
    ├── test_handler.py           ← Ghost Agent handler interface tests
    └── conftest.py
```

---

## Running Tests

```bash
python3.12 -m pytest tests/ -v
```

All tests run without Azure credentials. `AzureNSGProvider` is replaced with mocks throughout.
