#!/usr/bin/env bash
# =============================================================================
# Use Case P — "The Rollback That Wasn't": Teardown
# Removes the NSG deny rule and the iptables DROP from the dest VM.
# Safe to run multiple times (idempotent).
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

NSG_RULE_NAME="ghost-demo-rollback-block-8080"

echo ""
echo "=== Use Case P — Teardown: The Rollback That Wasn't ==="

echo "  [1/2] Removing NSG deny rule ${NSG_RULE_NAME} from ${DEST_VM_NSG_NAME} ..."
if az network nsg rule show \
     --resource-group "${RESOURCE_GROUP}" \
     --nsg-name       "${DEST_VM_NSG_NAME}" \
     --name           "${NSG_RULE_NAME}" \
     --output none 2>/dev/null; then
  az network nsg rule delete \
    --resource-group "${RESOURCE_GROUP}" \
    --nsg-name       "${DEST_VM_NSG_NAME}" \
    --name           "${NSG_RULE_NAME}"
  echo "  [OK] NSG rule ${NSG_RULE_NAME} removed — TCP 8080 deny cleared"
else
  echo "  [SKIP] NSG rule ${NSG_RULE_NAME} not found (already removed?)"
fi

echo "  [2/2] Removing iptables DROP for TCP 5001 from ${DEST_VM_NAME} ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name           "${DEST_VM_NAME}" \
  --command-id     RunShellScript \
  --scripts "
    if iptables -C INPUT -p tcp --dport 5001 -j DROP 2>/dev/null; then
      iptables -D INPUT -p tcp --dport 5001 -j DROP
      echo '[OK] iptables DROP for TCP 5001 removed'
    else
      echo '[SKIP] No iptables DROP rule for TCP 5001 found (already removed?)'
    fi
    iptables -L INPUT -n --line-numbers | head -6
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  Teardown complete. TCP 8080 NSG deny removed; iptables DROP removed."
echo "  Note: pre-window baseline pre_window_P remains in ./audit/ for reference."
echo ""
