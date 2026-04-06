#!/usr/bin/env bash
# =============================================================================
# Use Case R — "The 60-Second Sign-Off": Teardown
# Removes the pre-existing iptables DROP TCP 9090 from tf-dest-vm.
# Idempotent — safe to run multiple times or if setup was partial.
# =============================================================================
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-nw-forensics-rg}"
DEST_VM_NAME="${DEST_VM_NAME:-tf-dest-vm}"

echo "======================================================================"
echo " Use Case R — Teardown"
echo " Resource group : ${RESOURCE_GROUP}"
echo " Destination VM : ${DEST_VM_NAME}"
echo "======================================================================"
echo ""

# ── [1/1] Remove iptables DROP TCP 9090 from dest VM ─────────────────────────
echo "[1/1] Removing iptables DROP TCP 9090 from ${DEST_VM_NAME} ..."
az vm run-command invoke \
  --resource-group "${RESOURCE_GROUP}" \
  --name "${DEST_VM_NAME}" \
  --command-id RunShellScript \
  --scripts "
    if sudo iptables -C INPUT -p tcp --dport 9090 -j DROP 2>/dev/null; then
      sudo iptables -D INPUT -p tcp --dport 9090 -j DROP
      echo 'Rule removed: DROP TCP 9090'
    else
      echo 'Rule not present — nothing to remove (idempotent)'
    fi
  " \
  --output table
echo ""

echo "Teardown complete."
