#!/usr/bin/env bash
# =============================================================================
# Use Case P — "The Rollback That Wasn't": Setup
#
# Context: Change management window CR-2026-0401 for infrastructure patching
# just closed. The lead engineer emailed the team: "All changes applied and
# verified. Rollback complete." Ninety minutes later, customers escalate.
#
# This setup injects TWO faults that simulate what a sloppy rollback leaves
# behind:
#
# Fault 1 — Azure NSG deny rule NOT removed (the incomplete rollback):
#   Adds a priority-150 DENY rule for TCP port 8080 to tf-dest-vm-nsg.
#   This represents a change made during the window that was supposed to be
#   temporary but was never removed — invisible to anyone who only checks
#   the NIC NSG summary in the portal (which shows "8080: Allowed from the
#   later allow rule" but the priority-150 deny fires first).
#
# Fault 2 — Forgotten OS-level diagnostic rule from the window:
#   A field engineer ran 'iptables -I INPUT 1 -p tcp --dport 5001 -j DROP'
#   during the window to isolate a separate service, forgot to remove it.
#   No trace in Azure — invisible to every Azure control-plane tool.
#
# Why this is a WOW scenario:
#   The rollback email says "complete." The Azure portal shows "allowed."
#   The on-call engineer has spent 45 minutes cycling through NSG audits
#   and getting "looks fine" from every tool. The Ghost Agent compares the
#   current effective network state against the pre-window baseline — a
#   SHA-256 verified snapshot taken before the window opened — and in one
#   tool call produces cryptographic proof that the rollback claim is false.
#   Then it finds the forgotten OS-level rule on the second pass.
#
# IMPORTANT: This setup captures the pre-window baseline BEFORE injecting
# faults. The baseline session ID is printed at the end. Use it in the prompt.
#
# Detection path (Ghost Agent):
#   1. detect_effective_network_drift(compare_session_id=eni_pre_window_P)
#      → drift_detected=true, security_rule_change, new DENY for TCP 8080
#   2. pipe_meter(test_type="connectivity") → CONNECTIVITY_DROP
#   3. detect_config_drift(provider=azure) or run_shell_cmd iptables -L
#      → finds forgotten DROP rule for port 5001
#   4. RCA: two artifacts from the window; rollback email was incorrect
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

# Paths
ENI_SCRIPT="${SCRIPT_DIR}/../../../effective-network-inspector/effective_network_inspector.py"
ENI_AUDIT_DIR="${SCRIPT_DIR}/../../audit"
BASELINE_SESSION_ID="eni_pre_window_P"
NSG_RULE_NAME="ghost-demo-rollback-block-8080"
BLOCKED_PORT="8080"

echo ""
echo "==================================================="
echo "  Use Case P — Setup: The Rollback That Wasn't"
echo "  Capturing pre-window baseline, then injecting:"
echo "  Fault 1:  NSG DENY TCP ${BLOCKED_PORT} on ${DEST_VM_NSG_NAME} (not rolled back)"
echo "  Fault 2:  iptables DROP TCP 5001 on ${DEST_VM_NAME} (forgotten diagnostic)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Pre-requisite: Capture the pre-window effective network baseline
# This snapshot is the forensic reference. The Ghost Agent will compare
# post-fault state against it to prove the rollback is incomplete.
# ---------------------------------------------------------------------------
echo "  [0/3] Capturing pre-window effective network baseline ..."
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
echo "  [OK] Pre-window baseline saved: ${BASELINE_SESSION_ID}"
echo ""

# ---------------------------------------------------------------------------
# Fault 1: NSG DENY rule — the change that was never rolled back
# Priority 150: fires before the default-allow rules at priority 65000.
# ---------------------------------------------------------------------------
echo "  [1/3] Injecting NSG DENY TCP ${BLOCKED_PORT} on ${DEST_VM_NSG_NAME} ..."
echo "        Rule: ${NSG_RULE_NAME}, priority 150, direction Inbound"
az network nsg rule create \
  --resource-group  "${RESOURCE_GROUP}" \
  --nsg-name        "${DEST_VM_NSG_NAME}" \
  --name            "${NSG_RULE_NAME}" \
  --priority        150 \
  --direction       Inbound \
  --access          Deny \
  --protocol        Tcp \
  --destination-port-ranges "${BLOCKED_PORT}" \
  --description     "DEMO: rollback-incomplete fault — TCP ${BLOCKED_PORT} deny left behind from CR-2026-0401" \
  --output none
echo "  [OK] NSG rule ${NSG_RULE_NAME} created (priority 150 DENY TCP ${BLOCKED_PORT})"

# ---------------------------------------------------------------------------
# Fault 2: Forgotten iptables DROP — the field engineer's diagnostic rule
# ---------------------------------------------------------------------------
echo "  [2/3] Injecting forgotten iptables DROP for TCP 5001 on ${DEST_VM_NAME} ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name           "${DEST_VM_NAME}" \
  --command-id     RunShellScript \
  --scripts "
    iptables -D INPUT -p tcp --dport 5001 -j DROP 2>/dev/null || true
    iptables -I INPUT 1 -p tcp --dport 5001 -j DROP
    echo '[OK] iptables DROP inserted for TCP 5001 — simulating forgotten diagnostic rule'
    iptables -L INPUT -n -v --line-numbers | head -8
  " \
  --query "value[0].message" -o tsv
echo "  [OK] OS-level iptables DROP injected for TCP 5001 (invisible to Azure portal)"

echo ""
echo "==================================================="
echo "  FAULTS ACTIVE:"
echo "  Fault 1: NSG deny for TCP ${BLOCKED_PORT} on ${DEST_VM_NSG_NAME}"
echo "           Azure portal shows 'port ${BLOCKED_PORT} allowed' via a lower-priority rule."
echo "           Effective state shows priority-150 DENY fires first."
echo "  Fault 2: iptables DROP for TCP 5001 on ${DEST_VM_NAME}"
echo "           Completely invisible to all Azure control-plane tools."
echo ""
echo "  PRE-WINDOW BASELINE: ${BASELINE_SESSION_ID}"
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
echo "  1. detect_effective_network_drift(compare_session_id=eni_pre_window_P)"
echo "     → drift_detected=true, security_rule_change (TCP ${BLOCKED_PORT} deny added)"
echo "     KEY MOMENT: SHA-256 verified baseline proves rollback claim is false."
echo "  2. pipe_meter or connectivity test → confirms TCP ${BLOCKED_PORT} unreachable"
echo "  3. detect_config_drift or iptables audit → finds TCP 5001 DROP on OS layer"
echo "  4. Two independent artifacts from the window. Rollback was not complete."
echo "==================================================="
echo ""
