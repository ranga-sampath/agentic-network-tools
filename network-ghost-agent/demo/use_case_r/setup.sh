#!/usr/bin/env bash
# =============================================================================
# Use Case R — "The 60-Second Sign-Off"
# Scenario : A maintenance window just closed. The change owner needs a
#            machine-readable certificate that the window made ZERO effective
#            network changes so the CAB can sign off without a manual audit.
#            Separately, the observability team reports that Prometheus metrics
#            scrapes from tf-dest-vm on TCP 9090 have been failing — a
#            pre-existing OS-level fault that predates the window.
# Setup    : (1) Inject pre-existing iptables DROP on TCP 9090 on dest VM
#            (2) Capture ENI baseline AFTER fault injection (so the "window"
#                comparison will produce drift_detected: false — no Azure
#                network state changed during the window itself)
# WOW moment: drift_detected: false is an explicit, cryptographic negative
#             confirmation. Combined with a SHA-256 verified baseline, it
#             proves the window touched nothing — zero manual audit needed.
#             detect_config_drift then surfaces the pre-existing OS rule as
#             a separate finding.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

ENI_SCRIPT="${SCRIPT_DIR}/../../../effective-network-inspector/effective_network_inspector.py"
AUDIT_DIR="${SCRIPT_DIR}/../../audit"
SESSION_ID="eni_pre_window_R"

echo "======================================================================"
echo " Use Case R — The 60-Second Sign-Off"
echo " Resource group  : ${RESOURCE_GROUP}"
echo " Destination VM  : ${DEST_VM_NAME}"
echo " Subscription ID : ${SUBSCRIPTION_ID}"
echo "======================================================================"
echo ""

# ── [1/3] Inject pre-existing OS-level block: iptables DROP TCP 9090 ─────────
# This simulates a Prometheus metrics scrape failure that already existed
# BEFORE the maintenance window opened. It is not an Azure network change —
# it lives in the guest OS firewall — so ENI drift detection will not flag it.
# detect_config_drift (iptables inspector) will find it as a separate finding.
echo "[1/3] Injecting pre-existing iptables DROP TCP 9090 on ${DEST_VM_NAME} ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name "${DEST_VM_NAME}" \
  --command-id RunShellScript \
  --scripts "
    # Idempotent: only add if not already present
    if ! sudo iptables -C INPUT -p tcp --dport 9090 -j DROP 2>/dev/null; then
      sudo iptables -I INPUT -p tcp --dport 9090 -j DROP
      echo 'Rule added: DROP TCP 9090'
    else
      echo 'Rule already present (idempotent)'
    fi
  " \
  --output table
echo ""

# ── [2/3] Capture ENI baseline AFTER fault injection ────────────────────────
# The baseline is captured NOW — after the OS rule is in place but before any
# "window" activity. Since we will make NO Azure network changes during the
# "window," the compare run will produce drift_detected: false.
# The baseline snapshot is SHA-256 verified by the inspector automatically.
echo "[2/3] Capturing ENI baseline (session: ${SESSION_ID}) ..."
python3 "${ENI_SCRIPT}" \
  --resource-group  "${RESOURCE_GROUP}" \
  --subscription-id "${SUBSCRIPTION_ID}" \
  --scope           vm \
  --vm-name         "${DEST_VM_NAME}" \
  --session-id      "${SESSION_ID}" \
  --is-baseline \
  --audit-dir       "${AUDIT_DIR}"
echo ""

# ── [3/3] Presenter notes ────────────────────────────────────────────────────
echo "======================================================================"
echo " PRESENTER NOTES"
echo "======================================================================"
echo ""
echo " Faults injected:"
echo "   - iptables DROP TCP 9090 on ${DEST_VM_NAME} (pre-existing OS rule)"
echo "   - NO Azure NSG or route changes made (window made zero changes)"
echo ""
echo " Baseline captured: ${SESSION_ID}"
echo "   File: ${AUDIT_DIR}/eni_${SESSION_ID}_snapshot.json"
echo ""
echo " Demo flow:"
echo "   1. Paste PROMPT.txt into the Ghost Agent."
echo "   2. Ghost Agent calls detect_effective_network_drift:"
echo "        baseline=eni_pre_window_R, compare=<current>"
echo "        → drift_detected: false (no Azure state changed)"
echo "   3. Ghost Agent calls detect_config_drift (iptables):"
echo "        → finds DROP TCP 9090 on ${DEST_VM_NAME}"
echo "   4. Ghost Agent presents the drift_detected: false result as"
echo "      a machine-readable change management sign-off certificate,"
echo "      then explains the pre-existing OS rule as a separate finding."
echo ""
echo " WOW moment: the negative confirmation is explicit and cryptographic."
echo "   The CAB gets a SHA-256 verified artifact proving the window was"
echo "   clean — in seconds, not hours of manual review."
echo "======================================================================"
