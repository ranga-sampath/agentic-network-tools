#!/usr/bin/env bash
# =============================================================================
# Use Case U — "The Hidden Gate": Teardown
# Disassociates subnet NSG, deletes it, stops the PostgreSQL mock listener.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

SUBNET_NSG_NAME="ghost-demo-subnet-nsg"
PGSQL_PORT=5432

echo ""
echo "=== Use Case U — Teardown: The Hidden Gate ==="

# ---------------------------------------------------------------------------
# Step 1: Disassociate subnet NSG from the subnet
# az network vnet subnet update --network-security-group "" constructs an ARM
# ID with an empty name and fails silently. Use az rest + PUT to null the field.
# ---------------------------------------------------------------------------
CURRENT_NSG=$(az network vnet subnet show \
               -g "$RESOURCE_GROUP" \
               --vnet-name "$VNET_NAME" \
               --name "$SUBNET_NAME" \
               --query "networkSecurityGroup.id" -o tsv 2>/dev/null || echo "")

if [[ "$CURRENT_NSG" == *"$SUBNET_NSG_NAME"* ]]; then
  SUBNET_RESOURCE_ID=$(az network vnet subnet show \
    -g "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" \
    --query "id" -o tsv)
  PATCHED_BODY=$(az rest \
    --method GET \
    --url "${SUBNET_RESOURCE_ID}?api-version=2023-11-01" | python3 -c "
import sys, json
subnet = json.load(sys.stdin)
subnet.get('properties', {}).pop('networkSecurityGroup', None)
print(json.dumps(subnet))
")
  az rest \
    --method PUT \
    --url "${SUBNET_RESOURCE_ID}?api-version=2023-11-01" \
    --headers "Content-Type=application/json" \
    --body "$PATCHED_BODY" \
    --output none
  echo "  [OK] Subnet NSG disassociated from subnet '$SUBNET_NAME'"
else
  echo "  [SKIP] Subnet NSG not associated with subnet (already removed?)"
fi

# ---------------------------------------------------------------------------
# Step 2: Delete the subnet NSG
# ---------------------------------------------------------------------------
EXISTING_NSG=$(az network nsg show \
               -g "$RESOURCE_GROUP" \
               --name "$SUBNET_NSG_NAME" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_NSG" ]]; then
  az network nsg delete \
    --resource-group "$RESOURCE_GROUP" \
    --name "$SUBNET_NSG_NAME"
  echo "  [OK] NSG '$SUBNET_NSG_NAME' deleted"
else
  echo "  [SKIP] NSG '$SUBNET_NSG_NAME' not found (already deleted?)"
fi

# ---------------------------------------------------------------------------
# Step 3: Stop the PostgreSQL mock listener on dest-vm
# ---------------------------------------------------------------------------
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${PGSQL_PORT}/tcp 2>/dev/null && echo 'PostgreSQL mock stopped' || echo 'No listener on port ${PGSQL_PORT}'
  " \
  --output none
echo "  [OK] PostgreSQL mock stopped on dest-vm:${PGSQL_PORT}"

# ---------------------------------------------------------------------------
# Step 4: Verify subnet has no NSG associated
# ---------------------------------------------------------------------------
FINAL_NSG=$(az network vnet subnet show \
              -g "$RESOURCE_GROUP" \
              --vnet-name "$VNET_NAME" \
              --name "$SUBNET_NAME" \
              --query "networkSecurityGroup" -o tsv 2>/dev/null || echo "")

if [[ -z "$FINAL_NSG" ]] || [[ "$FINAL_NSG" == "None" ]]; then
  echo "  [OK] Subnet '$SUBNET_NAME' confirmed: no NSG associated"
else
  echo "  [WARN] Subnet still shows an NSG: $FINAL_NSG"
fi

echo "  Teardown complete."
