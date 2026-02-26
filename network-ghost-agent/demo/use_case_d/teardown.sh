#!/usr/bin/env bash
# =============================================================================
# Use Case D — Teardown: Remove both NSG deny rules and stop listeners
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

POSTGRES_RULE="ghost-demo-block-postgres"
REDIS_RULE="ghost-demo-block-redis"
POSTGRES_PORT=5432
REDIS_PORT=6379

echo ""
echo "=== Use Case D — Teardown ==="

# Remove PostgreSQL NSG rule
EXISTING_PG=$(az network nsg rule show \
               -g "$RESOURCE_GROUP" \
               --nsg-name "$DEST_VM_NSG_NAME" \
               --name "$POSTGRES_RULE" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_PG" ]]; then
  az network nsg rule delete \
    -g "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$POSTGRES_RULE"
  echo "  [OK] NSG rule '$POSTGRES_RULE' deleted"
else
  echo "  [SKIP] NSG rule '$POSTGRES_RULE' not found (already deleted?)"
fi

# Remove Redis NSG rule
EXISTING_RD=$(az network nsg rule show \
               -g "$RESOURCE_GROUP" \
               --nsg-name "$DEST_VM_NSG_NAME" \
               --name "$REDIS_RULE" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RD" ]]; then
  az network nsg rule delete \
    -g "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$REDIS_RULE"
  echo "  [OK] NSG rule '$REDIS_RULE' deleted"
else
  echo "  [SKIP] NSG rule '$REDIS_RULE' not found (already deleted?)"
fi

# Stop service listeners on dest-vm
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${POSTGRES_PORT}/tcp 2>/dev/null && echo 'PostgreSQL listener stopped' || echo 'No PostgreSQL listener found'
    fuser -k ${REDIS_PORT}/tcp 2>/dev/null && echo 'Redis listener stopped' || echo 'No Redis listener found'
  " \
  --output none

echo "  [OK] Service listeners stopped on dest-vm (ports $POSTGRES_PORT, $REDIS_PORT)"
echo "  Teardown complete."
