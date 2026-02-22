#!/usr/bin/env bash
# =============================================================================
# Use Case F — Teardown: Restore nwlogs080613 to its original state
#
# Restores:
#   - defaultAction back to Allow (or whatever it was before setup)
#   - Removes the VNet network rule we added (if we added it)
#   - Subnet endpoints are left as-is (they were empty before setup,
#     and setup left them empty — no change needed)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STATE_FILE="/tmp/ghost-demo-f.env"

echo ""
echo "=== Use Case F — Teardown ==="

# Source state file written by setup.sh
if [[ -f "$STATE_FILE" ]]; then
  source "$STATE_FILE"
  echo "  Using state from $STATE_FILE"
  echo "  SA: $DEMO_SA | prevDefaultAction: $PREV_DEFAULT_ACTION | ruleAdded: $RULE_ALREADY_EXISTED"
else
  # Fallback: source config and assume defaults
  source "${SCRIPT_DIR}/../config.env"
  DEMO_SA="$STORAGE_ACCOUNT_NAME"
  PREV_DEFAULT_ACTION="Allow"
  RULE_ALREADY_EXISTED="false"
  SUBNET_ID=$(az network vnet subnet show \
    -g "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" \
    --query "id" -o tsv 2>/dev/null || echo "")
  echo "  State file not found — using defaults (SA=$DEMO_SA, restore to Allow)"
fi

# ---------------------------------------------------------------------------
# Step 1: Restore defaultAction on the storage account
# ---------------------------------------------------------------------------
CURRENT_ACTION=$(az storage account show \
  --name "$DEMO_SA" \
  --resource-group "$RESOURCE_GROUP" \
  --query "networkRuleSet.defaultAction" -o tsv 2>/dev/null || echo "unknown")

if [[ "$CURRENT_ACTION" == "$PREV_DEFAULT_ACTION" ]]; then
  echo "  [SKIP] defaultAction already '$PREV_DEFAULT_ACTION' — no change needed"
else
  az storage account update \
    --name "$DEMO_SA" \
    --resource-group "$RESOURCE_GROUP" \
    --default-action "$PREV_DEFAULT_ACTION" \
    --output none
  echo "  [OK] $DEMO_SA defaultAction restored to '$PREV_DEFAULT_ACTION'"
fi

# ---------------------------------------------------------------------------
# Step 2: Remove the VNet network rule we added (if we added it)
# ---------------------------------------------------------------------------
if [[ "$RULE_ALREADY_EXISTED" == "false" ]] && [[ -n "${SUBNET_ID:-}" ]]; then
  EXISTING_RULE=$(az storage account network-rule list \
    --account-name "$DEMO_SA" \
    --resource-group "$RESOURCE_GROUP" \
    --query "virtualNetworkRules[?virtualNetworkResourceId=='${SUBNET_ID}'].virtualNetworkResourceId" \
    -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING_RULE" ]]; then
    az storage account network-rule remove \
      --account-name "$DEMO_SA" \
      --resource-group "$RESOURCE_GROUP" \
      --subnet "$SUBNET_ID" \
      --output none
    echo "  [OK] VNet network rule removed from $DEMO_SA"
  else
    echo "  [SKIP] VNet rule not found (already removed?)"
  fi
else
  echo "  [SKIP] VNet rule was pre-existing — leaving in place"
fi

# ---------------------------------------------------------------------------
# Step 3: Subnet endpoints — no action needed
# setup.sh left them as [] (same as before), so there is nothing to restore
# ---------------------------------------------------------------------------
echo "  [SKIP] Subnet service endpoints — no change needed (were empty before setup)"

# Clean up state file
rm -f "$STATE_FILE"
echo "  [OK] State file $STATE_FILE removed"
echo "  Teardown complete. nwlogs080613 is accessible again."
echo "  Use Cases B and C can now be run."
