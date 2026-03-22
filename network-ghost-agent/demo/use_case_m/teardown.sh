#!/usr/bin/env bash
# =============================================================================
# Use Case M — "The Banned Guest": Teardown
# Removes the f2b-sshd chain and INPUT jump rule from tf-dest-vm.
# Safe to run even if setup was partial.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

echo ""
echo "=== Use Case M — Teardown: The Banned Guest ==="
echo ""

echo "  [1/1] Removing f2b-sshd chain from $DEST_VM_NAME ..."
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Remove INPUT jump rule first (chain cannot be deleted while referenced)
    iptables -D INPUT -j f2b-sshd 2>/dev/null \
      && echo '[OK] INPUT → f2b-sshd jump rule removed' \
      || echo '[SKIP] INPUT jump rule not found (already removed?)'

    # Flush and delete the chain
    iptables -F f2b-sshd 2>/dev/null || true
    iptables -X f2b-sshd 2>/dev/null \
      && echo '[OK] f2b-sshd chain deleted' \
      || echo '[SKIP] f2b-sshd chain not found (already removed?)'

    echo '[OK] Firewall state restored'
    iptables -L INPUT -n --line-numbers | head -8
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  Teardown complete. f2b-sshd chain removed from $DEST_VM_NAME."
echo ""
