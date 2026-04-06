#!/usr/bin/env bash
# =============================================================================
# Use Case Q — "The Rule Nobody Checked": Teardown
# Removes the NSG deny rule from dest VM and tc netem from source VM.
# Safe to run multiple times (idempotent).
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

NSG_RULE_NAME="ghost-demo-subnet-block-5432"

echo ""
echo "=== Use Case Q — Teardown: The Rule Nobody Checked ==="

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
  echo "  [OK] NSG rule ${NSG_RULE_NAME} removed — TCP 5432 deny cleared"
else
  echo "  [SKIP] NSG rule ${NSG_RULE_NAME} not found (already removed?)"
fi

echo "  [2/2] Removing tc netem from ${SOURCE_VM_NAME} ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name           "${SOURCE_VM_NAME}" \
  --command-id     RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    if tc qdisc show dev \$IFACE | grep -qE 'prio|netem'; then
      tc qdisc del dev \$IFACE root
      echo '[OK] root qdisc removed from \$IFACE — clean link restored'
    else
      echo '[SKIP] No fault qdisc found (already removed?)'
    fi
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  Teardown complete. TCP 5432 deny removed; netem delay cleared."
echo "  Note: baseline pre_escalation_Q remains in ./audit/ for reference."
echo ""
