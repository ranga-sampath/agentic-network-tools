#!/usr/bin/env bash
# =============================================================================
# Use Case Q — "The Rule Nobody Checked": Setup
#
# Context: P1 customer escalation. Application-to-database connections on
# TCP port 5432 (PostgreSQL) stopped working at 14:32 UTC. The customer is
# adamant: "We did not change anything." The on-call engineer checked the
# NIC-level NSG on tf-dest-vm and confirmed port 5432 is in the Allow rules.
# Simultaneously, ping latency to the VM has spiked from 2ms to 50ms+.
#
# This setup injects TWO independent faults:
#
# Fault 1 — Azure NSG high-priority DENY for the database port:
#   Adds a priority-100 DENY rule for TCP port 5432 to tf-dest-vm-nsg.
#   In Azure NSG evaluation, INBOUND traffic hits subnet NSG rules first,
#   then NIC NSG rules. A deny at priority 100 overrides every allow rule
#   at higher priority numbers, regardless of where the allow is defined.
#   The on-call engineer only checked the NIC NSG allow list — which still
#   shows port 5432 as allowed. The effective evaluation result tells the
#   complete story that no single NSG resource query can show.
#
# Fault 2 — OS-level tc netem latency on SOURCE VM (SSH exempt):
#   Adds 50ms artificial delay to all non-SSH traffic from tf-source-vm.
#   This is the source of the spike in application latency. It has nothing
#   to do with the TCP 5432 connectivity failure — two separate faults
#   with two different root causes, reported together by the customer.
#   Ghost Agent must identify them independently and not conflate them.
#
# Why this is a WOW scenario:
#   Every engineer learns to check NSG rules. "Port 5432 is allowed" ends
#   most investigations. But the EFFECTIVE NSG evaluation — the combined
#   result of subnet NSG evaluated first, then NIC NSG — can show a deny
#   that no individual NSG resource query surfaces. Ghost Agent uses
#   detect_effective_network_drift to diff the current effective state
#   against the morning baseline, finds the priority-100 DENY in seconds,
#   and then separately identifies the OS-level latency injection. The
#   customer claim "we changed nothing" is disproven by cryptographic
#   evidence: a SHA-256 verified diff of effective network state.
#
# Detection path (Ghost Agent):
#   1. detect_effective_network_drift(compare_session_id=eni_pre_escalation_Q)
#      → drift_detected=true, security_rule_change, priority-100 DENY TCP 5432
#   2. Ghost Agent surfaces the specific rule and its priority
#   3. pipe_meter(test_type="latency") → HIGH_VARIANCE or elevated RTT
#   4. az vm run-command tc qdisc show on source VM → netem delay found
#   5. RCA: two independent faults, separate remediations
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

# Paths
ENI_SCRIPT="${SCRIPT_DIR}/../../../effective-network-inspector/effective_network_inspector.py"
ENI_AUDIT_DIR="${SCRIPT_DIR}/../../audit"
BASELINE_SESSION_ID="eni_pre_escalation_Q"
NSG_RULE_NAME="ghost-demo-subnet-block-5432"
DB_PORT="5432"
LATENCY="50ms"

echo ""
echo "==================================================="
echo "  Use Case Q — Setup: The Rule Nobody Checked"
echo "  Capturing last-known-good baseline, then injecting:"
echo "  Fault 1:  NSG DENY TCP ${DB_PORT} at priority 100 on ${DEST_VM_NSG_NAME}"
echo "  Fault 2:  tc netem delay ${LATENCY} on ${SOURCE_VM_NAME} (SSH exempt)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Pre-requisite: Capture the last-known-good effective network baseline
# Simulates a morning baseline capture by the ops team at the start of shift.
# ---------------------------------------------------------------------------
echo "  [0/3] Capturing last-known-good effective network baseline ..."
echo "        Session ID: ${BASELINE_SESSION_ID}"
echo "        (az effective-route-table can take 30-60s per NIC)"
echo ""
mkdir -p "${ENI_AUDIT_DIR}"
python3 "${ENI_SCRIPT}" \
  --resource-group   "${RESOURCE_GROUP}" \
  --subscription-id  "${SUBSCRIPTION_ID}" \
  --scope            vm \
  --vm-name          "${DEST_VM_NAME}" \
  --audit-dir        "${ENI_AUDIT_DIR}" \
  --session-id       "${BASELINE_SESSION_ID}" \
  --is-baseline
echo "  [OK] Baseline saved: ${BASELINE_SESSION_ID}"
echo ""

# ---------------------------------------------------------------------------
# Fault 1: High-priority NSG DENY for the database port
# Priority 100 fires before any allow rules at higher priority numbers.
# The on-call engineer checking "port 5432 allowed" in the NIC NSG is
# looking at only half the picture. The effective evaluation includes this.
# ---------------------------------------------------------------------------
echo "  [1/3] Injecting NSG DENY TCP ${DB_PORT} at priority 100 on ${DEST_VM_NSG_NAME} ..."
echo "        Rule: ${NSG_RULE_NAME} — simulating a subnet NSG rule addition"
az network nsg rule create \
  --resource-group  "${RESOURCE_GROUP}" \
  --nsg-name        "${DEST_VM_NSG_NAME}" \
  --name            "${NSG_RULE_NAME}" \
  --priority        100 \
  --direction       Inbound \
  --access          Deny \
  --protocol        Tcp \
  --destination-port-ranges "${DB_PORT}" \
  --description     "DEMO: subnet-NSG trap — TCP ${DB_PORT} deny at priority 100, overrides all NIC NSG allows" \
  --output none
echo "  [OK] NSG rule ${NSG_RULE_NAME} created (priority 100 DENY TCP ${DB_PORT})"
echo "       NIC NSG still shows port ${DB_PORT} as allowed — the on-call check missed this."

# ---------------------------------------------------------------------------
# Fault 2: tc netem latency on SOURCE VM (SSH exempt via prio filter)
# An independent fault injected separately from the NSG change.
# ---------------------------------------------------------------------------
echo "  [2/3] Injecting tc netem delay ${LATENCY} on ${SOURCE_VM_NAME} (SSH exempt) ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name           "${SOURCE_VM_NAME}" \
  --command-id     RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    tc qdisc del dev \$IFACE root 2>/dev/null || true
    tc qdisc add dev \$IFACE root handle 1: prio bands 3
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem delay ${LATENCY}
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo '[OK] prio+netem applied: SSH exempt, all other traffic delay=${LATENCY}'
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv
echo "  [OK] OS-level netem delay ${LATENCY} injected on ${SOURCE_VM_NAME} (invisible to Azure)"

echo ""
echo "==================================================="
echo "  FAULTS ACTIVE:"
echo "  Fault 1: NSG DENY TCP ${DB_PORT} at priority 100 on ${DEST_VM_NSG_NAME}"
echo "           NIC NSG allow rule for port ${DB_PORT} still visible — misleading."
echo "           Effective NSG evaluation: DENY fires first (lower priority number wins)."
echo "  Fault 2: tc netem delay ${LATENCY} on ${SOURCE_VM_NAME}"
echo "           Completely separate from the connectivity failure. Not an NSG issue."
echo ""
echo "  LAST-KNOWN-GOOD BASELINE: ${BASELINE_SESSION_ID}"
echo "  (stored in ${ENI_AUDIT_DIR})"
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. detect_effective_network_drift(compare_session_id=eni_pre_escalation_Q)"
echo "     → drift_detected=true, security_rule_change (TCP ${DB_PORT} DENY at priority 100)"
echo "     KEY MOMENT: Customer said 'nothing changed.' The diff proves otherwise."
echo "     KEY INSIGHT: NIC NSG shows port ${DB_PORT} allowed — only effective NSG shows the deny."
echo "  2. pipe_meter or latency test → elevated RTT from source to dest"
echo "  3. tc qdisc show on source VM → netem delay ${LATENCY} found"
echo "  4. Two root causes identified independently. Customer claim disproven."
echo "==================================================="
echo ""
