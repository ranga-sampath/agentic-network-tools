#!/usr/bin/env bash
# =============================================================================
# Use Case N — "The Hardening Surprise": Setup
#
# Scenario:
#   A newly provisioned tf-dest-vm is unreachable after the security team ran
#   a CIS hardening script overnight. Azure NSG shows all necessary ports are
#   open. The change window baseline was captured before the script ran.
#
# Fault injected (two steps):
#   Step 1 — Capture pre-hardening baseline via firewall_inspector.py.
#   Step 2 — Flip INPUT chain policy from ACCEPT to DROP (the highest-impact
#             single change in iptables — every unmatched packet is now silently
#             dropped). SSH ACCEPT is inserted first to prevent lockout.
#
# Detection path (Ghost Agent):
#   1. NSG audit → SSH, app ports ALLOWED (control-plane shows nothing wrong)
#   2. detect_config_drift(compare_session_id=<baseline>, explain=True)
#      → diffs current state against pre-hardening baseline
#      → --explain-diff flags: "INPUT policy ACCEPT → DROP — all unmatched
#        traffic silently dropped; effective posture: default-deny"
#   KEY MOMENT: One line in the diff output explains total VM unreachability.
#
# Teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
FI_PATH="${REPO_ROOT}/netfilter-inspector/firewall-inspector/firewall_inspector.py"
AUDIT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/audit"
BASELINE_ID_FILE="${SCRIPT_DIR}/.baseline_session_id"

echo ""
echo "==================================================="
echo "  Use Case N — Setup: The Hardening Surprise"
echo "  Step 1: Capture pre-hardening baseline"
echo "  Step 2: Flip INPUT policy ACCEPT → DROP"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Idempotency guard — prevent re-running without teardown first.
# If the fault is already injected, the baseline would capture the faulted
# state (INPUT policy=DROP), making the diff empty and the demo useless.
# ---------------------------------------------------------------------------
if [[ -f "$BASELINE_ID_FILE" ]]; then
  echo "[ERROR] Baseline already captured (session: $(cat "$BASELINE_ID_FILE"))."
  echo "        Run teardown.sh first before re-running setup."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Capture pre-hardening baseline
# ---------------------------------------------------------------------------
echo "  [1/2] Capturing pre-hardening baseline on $DEST_VM_NAME ..."

TMP_CONFIG=$(mktemp /tmp/fw_baseline_XXXXXX.env)
cat > "$TMP_CONFIG" <<EOF
PROVIDER=azure
VM_NAME=${FW_VM_NAME:-$DEST_VM_NAME}
RESOURCE_GROUP=${RESOURCE_GROUP}
AUDIT_DIR=${AUDIT_DIR}
FAMILY=both
SSH_USER=${SSH_USER:-azureuser}
EOF

BASELINE_OUTPUT=$(python3 "$FI_PATH" --config "$TMP_CONFIG" --is-baseline 2>&1)
echo "$BASELINE_OUTPUT"
rm -f "$TMP_CONFIG"

# Extract session_id from "Baseline saved: /path/.../SESSION_ID_snapshot.json"
SNAP_PATH=$(echo "$BASELINE_OUTPUT" | grep "Baseline saved:" | awk '{print $NF}')
BASELINE_SESSION_ID=$(basename "$SNAP_PATH" "_snapshot.json")

if [[ -z "$BASELINE_SESSION_ID" ]]; then
  echo "[ERROR] Could not extract baseline session_id from firewall_inspector output."
  echo "        Ensure Azure credentials are active and $DEST_VM_NAME is running."
  exit 1
fi

echo "$BASELINE_SESSION_ID" > "$BASELINE_ID_FILE"
echo ""
echo "  [OK] Baseline captured: session_id = $BASELINE_SESSION_ID"
echo "       Stored in: $BASELINE_ID_FILE"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Flip INPUT policy to DROP (CIS hardening simulation)
# ---------------------------------------------------------------------------
echo "  [2/2] Flipping INPUT policy ACCEPT → DROP on $DEST_VM_NAME ..."
echo "        (inserting SSH ACCEPT rule first to prevent lockout)"
echo "        (az vm run-command in progress — typically 30–60 s) ..."

az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Remove any previously injected demo rules to ensure idempotency
    iptables -D INPUT -s 168.63.129.16 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

    # Position 1: Azure Wire Server (168.63.129.16) — explicit ACCEPT.
    # The Wire Server is the Azure infrastructure endpoint the VM agent uses
    # to receive run-commands and deliver results. This is a new inbound
    # connection on each poll cycle, so ESTABLISHED,RELATED alone is not
    # sufficient after an INPUT DROP policy flip. Azure hardening docs
    # require this rule for VMs with strict iptables policies.
    iptables -I INPUT 1 -s 168.63.129.16 -j ACCEPT

    # Position 2: ESTABLISHED,RELATED — keeps return traffic for all
    # outbound connections alive (SSH sessions, outbound HTTPS, etc.)
    iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Position 3: SSH — explicit permit for new SSH connections
    iptables -I INPUT 3 -p tcp --dport 22 -j ACCEPT

    # Flip INPUT policy to DROP (the CIS hardening action)
    iptables -P INPUT DROP

    echo '[OK] INPUT policy set to DROP'
    echo '     Rule 1: 168.63.129.16 ACCEPT    (Azure Wire Server — run-command delivery)'
    echo '     Rule 2: ESTABLISHED,RELATED ACCEPT (return traffic for outbound connections)'
    echo '     Rule 3: TCP port 22 ACCEPT        (SSH access preserved)'
    echo ''
    echo 'Current INPUT chain:'
    iptables -L INPUT -n -v --line-numbers | head -10
  " \
  --query "value[0].message" -o tsv

# Write PROMPT.txt with the actual session_id embedded
cat > "${SCRIPT_DIR}/PROMPT.txt" <<EOF
tf-dest-vm is unreachable after the security team ran CIS hardening scripts last night. SSH and application services are timing out. The Azure NSG on tf-dest-vm shows all required ports are open and no changes were made to it. A firewall baseline was captured before the hardening window with session ID: ${BASELINE_SESSION_ID}. Investigate what the hardening script changed at the OS firewall layer and what impact it has on traffic in resource group nw-forensics-rg.
EOF

echo ""
echo "==================================================="
echo "  Both steps complete."
echo "  Baseline session ID: $BASELINE_SESSION_ID"
echo "  INPUT policy:        DROP (was ACCEPT)"
echo "  Azure NSG:           ports still shown as ALLOWED"
echo "==================================================="
echo ""
echo "  PROMPT (also written to PROMPT.txt):"
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: uv run --python 3.12 python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. NSG audit → required ports ALLOWED (misleading)"
echo "  2. detect_config_drift(compare_session_id=$BASELINE_SESSION_ID, explain=True)"
echo "     → diffs current state vs pre-hardening baseline"
echo "  3. --explain-diff flags:"
echo "       INPUT policy changed: ACCEPT → DROP  ← the critical finding"
echo "       3 new rules: Wire Server ACCEPT, ESTABLISHED,RELATED ACCEPT, SSH ACCEPT"
echo "       All unmatched traffic now silently dropped"
echo "  KEY MOMENT: Policy flip = maximum blast radius. One line explains everything."
echo "  NOTE: Wire Server (168.63.129.16) + ESTABLISHED,RELATED rules mirror real"
echo "        CIS hardening. Azure VMs REQUIRE these for management plane connectivity."
echo "==================================================="
echo ""
