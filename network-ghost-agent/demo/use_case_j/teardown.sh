#!/usr/bin/env bash
# =============================================================================
# Use Case J — "The Shadow Firewall": Teardown
# Removes the iptables DROP rule from dest VM and tc netem from source VM.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

echo ""
echo "=== Use Case J — Teardown: The Shadow Firewall ==="

echo "  [1/2] Removing iptables DROP rule from $DEST_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    if iptables -C INPUT -p tcp --dport 5001 -j DROP 2>/dev/null; then
      iptables -D INPUT -p tcp --dport 5001 -j DROP
      echo \"[OK] iptables DROP rule removed for TCP port 5001\"
    else
      echo \"[SKIP] No iptables DROP rule found for port 5001 (already removed?)\"
    fi
    iptables -L INPUT -n --line-numbers | head -6
  " \
  --query "value[0].message" -o tsv

echo "  [2/2] Removing tc netem from $SOURCE_VM_NAME ..."
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

echo "  Teardown complete. Both faults removed."
echo ""
