# Audit Trail — ghost_20260224_065616
_Generated: 2026-02-24T06:57:12.642089+00:00_

## Hypotheses Log
| ID | Description | State | Denials |
|---|---|---|---|
| H1 | A custom route table is redirecting traffic from tf-source-vm. | CONFIRMED | 0 |
| H2 | An NSG rule is blocking traffic despite the first-level team's check. | REFUTED | 0 |
| H3 | A firewall or other network appliance is blocking traffic between the VMs. | REFUTED | 0 |

## Command Evidence
| Audit ID | Context | Command | Classification | Action | Exit Code | Outcome |
|---|---|---|---|---|---|---|
| — | [CLOUD] | `az network vnet subnet show --resource-group nw-forensics-rg` | SAFE | auto_approved | 0 | completed |
| — | [CLOUD] | `az network route-table route list --resource-group nw-forens` | SAFE | auto_approved | 0 | completed |
| — | [CLOUD] | `az vm show --resource-group nw-forensics-rg --name tf-source` | SAFE | auto_approved | 0 | completed |
| — | [CLOUD] | `az network nic show-effective-route-table --resource-group n` | RISKY | user_approved | 0 | completed |
| — | [CLOUD] | `az network route-table route list --resource-group nw-forens` | SAFE | auto_approved | 3 | completed |

_[LOCAL] = engineer's machine context. [CLOUD] = Azure control/data plane._

## Integrity Statement
All evidence cited by audit_id from append-only JSONL files:
- Shell audit:    audit/shell_audit_ghost_20260224_065616.jsonl
- Task registry:  audit/orchestrator_tasks_*.jsonl
Raw command output is retained in the JSONL audit trail; only summaries appear here.