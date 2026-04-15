#!/usr/bin/env bash
# =============================================================================
# Use Case T — "The Phantom Firewall": Teardown
#
# Restores:
#   - Disassociates ghost-demo-t-rt from subnet (restores prior table or none)
#   - Deletes ghost-demo-t-rt and its routes
#   - Removes the iptables OUTPUT DROP port 80 rule from SOURCE_VM_NAME
#   - Removes baseline session ID file
#
# Safe to run even if setup was partial.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STATE_FILE="/tmp/ghost-demo-t.env"

echo ""
echo "=== Use Case T — Teardown: The Phantom Firewall ==="
echo ""

# Always source config.env for SSH variables (not stored in state file)
source "${SCRIPT_DIR}/../config.env"

if [[ -f "$STATE_FILE" ]]; then
  source "$STATE_FILE"
  echo "  Using state from $STATE_FILE"
  echo "  RT: $RT_NAME | Source VM: $SOURCE_VM_NAME | Prior RT: ${PREV_RT:-none}"
else
  RT_NAME="ghost-demo-t-rt"
  PREV_RT=""
  echo "  State file not found — using defaults"
fi

# ---------------------------------------------------------------------------
# Step 1: Disassociate route table from subnet
# ---------------------------------------------------------------------------
echo "  [1/3] Restoring subnet $SUBNET_NAME route table association ..."
CURRENT_RT_ID=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --query "routeTable.id" -o tsv 2>/dev/null || echo "")

if [[ -z "$CURRENT_RT_ID" ]]; then
  echo "  [SKIP] No route table currently on $SUBNET_NAME"
else
  if [[ -n "${PREV_RT:-}" ]]; then
    az network vnet subnet update \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --name "$SUBNET_NAME" \
      --route-table "$PREV_RT" \
      --output none
    echo "  [OK] Subnet $SUBNET_NAME restored to prior route table"
  else
    az network vnet subnet update \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --name "$SUBNET_NAME" \
      --remove routeTable \
      --output none
    echo "  [OK] Route table disassociated from $SUBNET_NAME"
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Delete the demo route table
# ---------------------------------------------------------------------------
echo "  [2/3] Deleting route table $RT_NAME ..."
EXISTING_RT=$(az network route-table show \
  --name "$RT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RT" ]]; then
  az network route-table delete \
    --name "$RT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --output none
  echo "  [OK] Route table $RT_NAME deleted"
else
  echo "  [SKIP] $RT_NAME not found — already deleted?"
fi

# ---------------------------------------------------------------------------
# Step 3: Remove iptables OUTPUT DROP port 80 rule from SOURCE_VM_NAME
# Uses SSH directly (faster, no VM agent dependency).
# Route table is already disassociated in Step 1, so SSH connectivity is normal.
# ---------------------------------------------------------------------------
if [[ -n "${SOURCE_VM_NAME:-}" && -n "${SOURCE_VM_PUBLIC_IP:-}" && -n "${SSH_SOURCE_VM_KEY_PATH:-}" ]]; then
  echo "  [3/3] Removing iptables OUTPUT DROP port 80 from $SOURCE_VM_NAME ..."
  ssh -i "$SSH_SOURCE_VM_KEY_PATH" \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=15 \
      -o BatchMode=yes \
      "${SSH_USER}@${SOURCE_VM_PUBLIC_IP}" \
      "sudo iptables -C OUTPUT -p tcp --dport 80 -j DROP 2>/dev/null && sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP && echo '[OK] OUTPUT DROP port 80 rule removed' || echo '[SKIP] OUTPUT DROP port 80 rule not found (already removed?)';\
       echo 'Current OUTPUT chain:'; sudo iptables -L OUTPUT -n --line-numbers | head -8" || true
else
  echo "  [SKIP] SSH vars not set — skipping iptables cleanup"
  echo "         Manual cleanup on $SOURCE_VM_NAME:"
  echo "         sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP"
fi

# ---------------------------------------------------------------------------
# Clean up local artifacts
# ---------------------------------------------------------------------------
rm -f "$STATE_FILE"
echo "  [OK] State file removed"

echo ""
echo "  Teardown complete."
echo "  - Route table $RT_NAME deleted, subnet $SUBNET_NAME restored"
echo "  - iptables OUTPUT DROP port 80 removed from $SOURCE_VM_NAME"
echo "  - External connectivity from $SOURCE_VM_NAME is normal again"
echo ""
