#!/usr/bin/env bash
# =============================================================================
# Use Case L — "The Double Lock": Teardown
# Removes the NSG deny rule and tc netem from dest VM.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

NSG_RULE_NAME="ghost-demo-l-block-iperf"

echo ""
echo "=== Use Case L — Teardown: The Double Lock ==="

echo "  [1/2] Removing NSG DENY rule from $DEST_VM_NSG_NAME ..."
EXISTING=$(az network nsg rule show \
             -g "$RESOURCE_GROUP" \
             --nsg-name "$DEST_VM_NSG_NAME" \
             --name "$NSG_RULE_NAME" \
             --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
  az network nsg rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$NSG_RULE_NAME"
  echo "       [OK] NSG rule '$NSG_RULE_NAME' deleted"
else
  echo "       [SKIP] NSG rule '$NSG_RULE_NAME' not found (already removed?)"
fi

echo "  [2/2] Removing tc netem from $DEST_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    if tc qdisc show dev \$IFACE | grep -qE 'prio|netem|tbf'; then
      tc qdisc del dev \$IFACE root
      echo \"[OK] root qdisc removed from \$IFACE — clean link restored\"
    else
      echo \"[SKIP] No fault qdisc found on \$IFACE (already removed?)\"
    fi
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo "  Teardown complete. NSG rule deleted, tc netem removed from dest VM."
echo ""
