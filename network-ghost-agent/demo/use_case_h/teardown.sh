#!/usr/bin/env bash
# =============================================================================
# Use Case H — "Latency Landmine": Teardown
# Removes the tc netem qdisc from the source VM, restoring normal latency.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

echo ""
echo "=== Use Case H — Teardown: Latency Landmine ==="

az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    if tc qdisc show dev \$IFACE | grep -qE 'prio|netem|tbf'; then
      tc qdisc del dev \$IFACE root
      echo \"[OK] root qdisc removed from \$IFACE — normal latency restored\"
    else
      echo \"[SKIP] No fault qdisc found on \$IFACE (already removed?)\"
    fi
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo "  Teardown complete. Latency restored to sub-millisecond VNet baseline."
echo ""
