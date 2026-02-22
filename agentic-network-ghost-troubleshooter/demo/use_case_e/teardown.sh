#!/usr/bin/env bash
# =============================================================================
# Use Case E — Teardown: Disassociate route table, delete it, stop listener
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

ROUTE_TABLE_NAME="ghost-demo-blackhole-rt"
HTTP_PORT=8080

echo ""
echo "=== Use Case E — Teardown ==="

# ---------------------------------------------------------------------------
# Step 1: Disassociate route table from subnet
# ---------------------------------------------------------------------------
CURRENT_RT=$(az network vnet subnet show \
               -g "$RESOURCE_GROUP" \
               --vnet-name "$VNET_NAME" \
               --name "$SUBNET_NAME" \
               --query "routeTable.id" -o tsv 2>/dev/null || echo "")

if [[ "$CURRENT_RT" == *"$ROUTE_TABLE_NAME"* ]]; then
  # --route-table "" fails: Azure CLI constructs an ARM ID with an empty name.
  # az rest GET returns raw ARM JSON (properties nested correctly for PUT).
  # Strip routeTable from properties and PUT back.
  SUBNET_RESOURCE_ID=$(az network vnet subnet show \
    -g "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" \
    --query "id" -o tsv)
  PATCHED_BODY=$(az rest \
    --method GET \
    --url "${SUBNET_RESOURCE_ID}?api-version=2023-11-01" | python3 -c "
import sys, json
subnet = json.load(sys.stdin)
subnet.get('properties', {}).pop('routeTable', None)
print(json.dumps(subnet))
")
  az rest \
    --method PUT \
    --url "${SUBNET_RESOURCE_ID}?api-version=2023-11-01" \
    --headers "Content-Type=application/json" \
    --body "$PATCHED_BODY" \
    --output none
  echo "  [OK] Route table disassociated from subnet '$SUBNET_NAME'"
else
  echo "  [SKIP] Route table not associated with subnet (already removed?)"
fi

# ---------------------------------------------------------------------------
# Step 2: Delete the route table
# ---------------------------------------------------------------------------
EXISTING_RT=$(az network route-table show \
               -g "$RESOURCE_GROUP" \
               --name "$ROUTE_TABLE_NAME" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RT" ]]; then
  az network route-table delete \
    --resource-group "$RESOURCE_GROUP" \
    --name "$ROUTE_TABLE_NAME"
  echo "  [OK] Route table '$ROUTE_TABLE_NAME' deleted"
else
  echo "  [SKIP] Route table '$ROUTE_TABLE_NAME' not found (already deleted?)"
fi

# ---------------------------------------------------------------------------
# Step 3: Stop HTTP listener on dest-vm
# ---------------------------------------------------------------------------
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "fuser -k ${HTTP_PORT}/tcp 2>/dev/null && echo 'Listener stopped' || echo 'No listener found'" \
  --output none

echo "  [OK] HTTP listener stopped on dest-vm:${HTTP_PORT}"

# ---------------------------------------------------------------------------
# Step 4: Verify subnet has no route table
# ---------------------------------------------------------------------------
FINAL_RT=$(az network vnet subnet show \
             -g "$RESOURCE_GROUP" \
             --vnet-name "$VNET_NAME" \
             --name "$SUBNET_NAME" \
             --query "routeTable" -o tsv 2>/dev/null || echo "")

if [[ -z "$FINAL_RT" ]] || [[ "$FINAL_RT" == "None" ]]; then
  echo "  [OK] Subnet '$SUBNET_NAME' confirmed: no route table associated"
else
  echo "  [WARN] Subnet still shows a route table: $FINAL_RT"
fi

echo "  Teardown complete."
