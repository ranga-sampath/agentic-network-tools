#!/usr/bin/env bash
# =============================================================================
# Use Case V — "The Open Doorway": Teardown
# Removes the planted RDP allow rule from the dest VM's NIC NSG.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RDP_RULE_NAME="ghost-demo-temp-rdp-access"

echo ""
echo "=== Use Case V — Teardown: The Open Doorway ==="

EXISTING_RULE=$(az network nsg rule show \
                  -g "$RESOURCE_GROUP" \
                  --nsg-name "$DEST_VM_NSG_NAME" \
                  --name "$RDP_RULE_NAME" \
                  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RULE" ]]; then
  az network nsg rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$RDP_RULE_NAME"
  echo "  [OK] Rule '$RDP_RULE_NAME' deleted from $DEST_VM_NSG_NAME"
else
  echo "  [SKIP] Rule '$RDP_RULE_NAME' not found (already removed?)"
fi

echo "  Teardown complete. NSG restored to pre-demo state."
echo ""
