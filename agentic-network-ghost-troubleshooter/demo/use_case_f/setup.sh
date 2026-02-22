#!/usr/bin/env bash
# =============================================================================
# Use Case F — "The Silent Gatekeeper": Setup
#
# Configures the EXISTING capture storage account (nwlogs080613) with a VNet
# firewall rule and sets defaultAction=Deny, then removes the Microsoft.Storage
# service endpoint from the subnet — introducing the mismatch:
#
#   Storage firewall : defaultAction=Deny + VNet rule for forensics-vnet/default ✓
#   Subnet endpoints : []  (no Microsoft.Storage)                                ✗
#
# Without the service endpoint, VM traffic goes to the storage PUBLIC endpoint
# and is rejected by defaultAction: Deny — even though the VNet rule is present.
#
# There is no new storage account. The demo uses nwlogs080613 so the agent
# investigates the same account used for captures, without the ambiguity of a
# separate demo SA appearing in the prompt.
#
# IMPORTANT: nwlogs080613 is locked down while this fault is active.
#   - Run teardown.sh before running Use Cases B or C.
#   - Run ghost_agent WITHOUT --storage-account for this demo.
#
# Audience: VP of Engineering
# Duration: ~12 minutes (pure control-plane, no captures needed)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

DEMO_SA="$STORAGE_ACCOUNT_NAME"   # nwlogs080613 — existing account, no new SA
STATE_FILE="/tmp/ghost-demo-f.env"

echo ""
echo "==================================================="
echo "  Use Case F — Setup: Service endpoint mismatch"
echo "  Storage account: $DEMO_SA (existing — no new account created)"
echo "  VNet: $VNET_NAME / Subnet: $SUBNET_NAME"
echo "  Fault: VNet firewall rule present; subnet endpoint removed"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Save current state of nwlogs080613 for teardown
# ---------------------------------------------------------------------------
echo "  [1/5] Saving current state of $DEMO_SA..."
PREV_DEFAULT_ACTION=$(az storage account show \
  --name "$DEMO_SA" \
  --resource-group "$RESOURCE_GROUP" \
  --query "networkRuleSet.defaultAction" -o tsv 2>/dev/null || echo "Allow")
echo "       Current defaultAction: $PREV_DEFAULT_ACTION"

# ---------------------------------------------------------------------------
# Step 2: Temporarily add Microsoft.Storage endpoint to subnet
# Required by Azure before a VNet network rule can reference this subnet
# ---------------------------------------------------------------------------
echo "  [2/5] Adding Microsoft.Storage endpoint to subnet (required for VNet rule)..."
CURRENT_ENDPOINTS=$(az network vnet subnet show \
  -g "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" \
  --query "serviceEndpoints[].service" -o tsv 2>/dev/null || echo "")

ENDPOINT_WAS_PRESENT="false"
if echo "$CURRENT_ENDPOINTS" | grep -q "Microsoft.Storage"; then
  echo "       Microsoft.Storage endpoint already present."
  ENDPOINT_WAS_PRESENT="true"
else
  az network vnet subnet update \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "$VNET_NAME" \
    --name "$SUBNET_NAME" \
    --service-endpoints Microsoft.Storage \
    --output none
  echo "       [OK] Microsoft.Storage endpoint added temporarily"
fi

# ---------------------------------------------------------------------------
# Step 3: Add VNet network rule for subnet → nwlogs080613
# This is the "correct" config the storage firewall expects
# ---------------------------------------------------------------------------
echo "  [3/5] Adding VNet network rule to $DEMO_SA..."
SUBNET_ID=$(az network vnet subnet show \
  -g "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" \
  --query "id" -o tsv 2>/dev/null)

EXISTING_RULE=$(az storage account network-rule list \
  --account-name "$DEMO_SA" \
  --resource-group "$RESOURCE_GROUP" \
  --query "virtualNetworkRules[?virtualNetworkResourceId=='${SUBNET_ID}'].virtualNetworkResourceId" \
  -o tsv 2>/dev/null || echo "")

RULE_ALREADY_EXISTED="false"
if [[ -n "$EXISTING_RULE" ]]; then
  echo "       VNet rule for subnet already exists — skipping."
  RULE_ALREADY_EXISTED="true"
else
  az storage account network-rule add \
    --account-name "$DEMO_SA" \
    --resource-group "$RESOURCE_GROUP" \
    --subnet "$SUBNET_ID" \
    --output none
  echo "       [OK] VNet rule added: subnet '$SUBNET_NAME' → $DEMO_SA"
fi

# ---------------------------------------------------------------------------
# Step 4: Set defaultAction=Deny on nwlogs080613
# Only VNet-authenticated traffic (via service endpoint) is allowed
# ---------------------------------------------------------------------------
echo "  [4/5] Setting defaultAction=Deny on $DEMO_SA..."
az storage account update \
  --name "$DEMO_SA" \
  --resource-group "$RESOURCE_GROUP" \
  --default-action Deny \
  --bypass AzureServices \
  --output none
echo "       [OK] Storage firewall: defaultAction=Deny, bypass=AzureServices"

# ---------------------------------------------------------------------------
# Phase B — Introduce the fault: remove the Microsoft.Storage endpoint
# This recreates the accident: subnet maintenance removed the Storage endpoint
# while adding an Azure SQL endpoint
# ---------------------------------------------------------------------------
echo "  [5/5] Introducing fault: removing Microsoft.Storage service endpoint..."
az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --service-endpoints '[]' \
  --output none
echo "       [OK] Microsoft.Storage service endpoint removed from subnet"

# ---------------------------------------------------------------------------
# Save state for teardown
# ---------------------------------------------------------------------------
cat > "$STATE_FILE" <<EOF
DEMO_SA=${DEMO_SA}
RESOURCE_GROUP=${RESOURCE_GROUP}
VNET_NAME=${VNET_NAME}
SUBNET_NAME=${SUBNET_NAME}
SUBNET_ID=${SUBNET_ID}
PREV_DEFAULT_ACTION=${PREV_DEFAULT_ACTION}
RULE_ALREADY_EXISTED=${RULE_ALREADY_EXISTED}
ENDPOINT_WAS_PRESENT=${ENDPOINT_WAS_PRESENT}
EOF
echo "       State saved to $STATE_FILE"

echo ""
echo "  [OK] Fault injected. Current state:"
echo "       $DEMO_SA firewall : defaultAction=Deny, VNet rule for $SUBNET_NAME ✓"
echo "       Subnet endpoints  : [] (no Microsoft.Storage)                       ✗"
echo "       Effect            : VM traffic → public endpoint → rejected by Deny"
echo ""
echo "  ⚠  WARNING: $DEMO_SA is locked down. Do NOT run Use Cases B or C until"
echo "     teardown.sh is run."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run ghost_agent WITHOUT --storage-account (nwlogs080613 is locked):"
echo "    uv run --python 3.12 python ghost_agent.py \\"
echo "      --resource-group nw-forensics-rg \\"
echo "      --location eastus"
echo ""
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE:"
echo "  The agent will:"
echo "  1. Check NSG → clean. Check routes → clean."
echo "  2. Query storage account firewall: defaultAction=Deny, VNet rule present"
echo "  3. Query subnet service endpoints: empty list"
echo "  4. Correlate: VNet rule requires endpoint; subnet has none → public path → rejected"
echo "  Key commands to watch:"
echo "    az storage account show --query networkRuleSet"
echo "    az network vnet subnet show --query serviceEndpoints"
echo "==================================================="
