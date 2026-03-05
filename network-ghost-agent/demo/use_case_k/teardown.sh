#!/usr/bin/env bash
# =============================================================================
# Use Case K — "The Bandwidth Thief": Teardown
# Removes tc tbf from source VM and iptables ICMP rule from dest VM.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

echo ""
echo "=== Use Case K — Teardown: The Bandwidth Thief ==="

echo "  [1/2] Removing tc tbf from $SOURCE_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    if tc qdisc show dev \$IFACE | grep -qE 'prio|netem|tbf'; then
      tc qdisc del dev \$IFACE root
      echo \"[OK] root qdisc removed from \$IFACE — full throughput restored\"
    else
      echo \"[SKIP] No fault qdisc found on \$IFACE (already removed?)\"
    fi
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo "  [2/2] Removing iptables ICMP DROP from $DEST_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    if iptables -C INPUT -p icmp -j DROP 2>/dev/null; then
      iptables -D INPUT -p icmp -j DROP
      echo \"[OK] iptables ICMP DROP rule removed — ping restored\"
    else
      echo \"[SKIP] No iptables ICMP DROP rule found (already removed?)\"
    fi
    iptables -L INPUT -n --line-numbers | head -6
  " \
  --query "value[0].message" -o tsv

echo "  Teardown complete. Throughput and ping restored."
echo ""
