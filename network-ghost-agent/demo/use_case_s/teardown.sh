#!/usr/bin/env bash
# =============================================================================
# Use Case S — "The Accidental Blackhole": Teardown
#
# Restores:
#   - Disassociates ghost-demo-s-rt from the subnet (restores prior table or none)
#   - Deletes ghost-demo-s-rt and its routes
#
# Safe to run even if setup was partial (each step checks current state).
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STATE_FILE="/tmp/ghost-demo-s.env"

echo ""
echo "=== Use Case S — Teardown: The Accidental Blackhole ==="
echo ""

if [[ -f "$STATE_FILE" ]]; then
  source "$STATE_FILE"
  echo "  Using state from $STATE_FILE"
  echo "  RT: $RT_NAME | Subnet: $SUBNET_NAME | Prior RT: ${PREV_RT:-none}"
else
  source "${SCRIPT_DIR}/../config.env"
  RT_NAME="ghost-demo-s-rt"
  PREV_RT=""
  echo "  State file not found — using defaults (RT=$RT_NAME, no prior table)"
fi

# ---------------------------------------------------------------------------
# Step 1: Disassociate route table from subnet
# ---------------------------------------------------------------------------
echo "  [1/2] Restoring subnet $SUBNET_NAME route table association ..."
CURRENT_RT_ID=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --query "routeTable.id" -o tsv 2>/dev/null || echo "")

if [[ -z "$CURRENT_RT_ID" ]]; then
  echo "  [SKIP] No route table currently on $SUBNET_NAME — nothing to disassociate"
else
  if [[ -n "${PREV_RT:-}" ]]; then
    # Restore the previous route table
    az network vnet subnet update \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --name "$SUBNET_NAME" \
      --route-table "$PREV_RT" \
      --output none
    echo "  [OK] Subnet $SUBNET_NAME restored to prior route table"
  else
    # Remove route table — no prior table existed
    az network vnet subnet update \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --name "$SUBNET_NAME" \
      --remove routeTable \
      --output none
    echo "  [OK] Route table disassociated from $SUBNET_NAME (no prior table)"
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Delete the demo route table (routes are deleted automatically)
# ---------------------------------------------------------------------------
echo "  [2/2] Deleting route table $RT_NAME ..."
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

rm -f "$STATE_FILE"
echo "  [OK] State file removed"
echo ""
echo "  Teardown complete. Subnet $SUBNET_NAME restored. tf-source-vm → tf-dest-vm routing is normal."
echo ""
