#!/usr/bin/env bash
# =============================================================================
# Use Case A — Teardown: Remove the NSG deny rule and stop HTTP listener
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RULE_NAME="ghost-demo-block-${DEMO_BLOCKED_PORT}"

echo ""
echo "=== Use Case A — Teardown ==="

# Remove NSG rule
EXISTING=$(az network nsg rule show \
             -g "$RESOURCE_GROUP" \
             --nsg-name "$DEST_VM_NSG_NAME" \
             --name "$RULE_NAME" \
             --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
  az network nsg rule delete \
    -g "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$RULE_NAME"
  echo "  [OK] NSG rule '$RULE_NAME' deleted"
else
  echo "  [SKIP] NSG rule '$RULE_NAME' not found (already deleted?)"
fi

# Stop the HTTP listener on dest-vm
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "fuser -k ${DEMO_BLOCKED_PORT}/tcp 2>/dev/null && echo 'Listener stopped' || echo 'No listener found'" \
  --output none

echo "  [OK] HTTP listener stopped on dest-vm:${DEMO_BLOCKED_PORT}"
echo "  Teardown complete."
