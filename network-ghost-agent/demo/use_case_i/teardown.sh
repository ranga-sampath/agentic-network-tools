#!/usr/bin/env bash
# =============================================================================
# Use Case I — "Packet Grinder": Teardown
# Removes the tc netem qdisc from the source VM, restoring clean links.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

echo ""
echo "=== Use Case I — Teardown: Packet Grinder ==="

az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
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

echo "  Teardown complete. Packet loss, latency, and corruption cleared."
echo ""
