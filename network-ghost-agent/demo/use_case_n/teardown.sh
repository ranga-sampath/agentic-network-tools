#!/usr/bin/env bash
# =============================================================================
# Use Case N — "The Hardening Surprise": Teardown
# Restores INPUT policy to ACCEPT and removes the injected SSH ACCEPT rule.
# Safe to run even if setup was partial.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

BASELINE_ID_FILE="${SCRIPT_DIR}/.baseline_session_id"

echo ""
echo "=== Use Case N — Teardown: The Hardening Surprise ==="
echo ""

echo "  [1/2] Restoring INPUT policy to ACCEPT on $DEST_VM_NAME ..."
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Restore default INPUT policy first — must happen before rule removal
    # so the VM is not briefly in default-deny without any ACCEPT rules
    iptables -P INPUT ACCEPT
    echo '[OK] INPUT policy restored to ACCEPT'

    # Remove the Azure Wire Server rule inserted by setup
    if iptables -C INPUT -s 168.63.129.16 -j ACCEPT 2>/dev/null; then
      iptables -D INPUT -s 168.63.129.16 -j ACCEPT
      echo '[OK] Wire Server (168.63.129.16) ACCEPT rule removed'
    else
      echo '[SKIP] Wire Server rule not found (already removed?)'
    fi

    # Remove the ESTABLISHED,RELATED guard rule inserted by setup
    if iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
      iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      echo '[OK] ESTABLISHED,RELATED ACCEPT rule removed'
    else
      echo '[SKIP] ESTABLISHED,RELATED rule not found (already removed?)'
    fi

    # Remove the SSH ACCEPT guard rule inserted by setup
    if iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
      iptables -D INPUT -p tcp --dport 22 -j ACCEPT
      echo '[OK] SSH ACCEPT guard rule removed'
    else
      echo '[SKIP] SSH ACCEPT guard rule not found (already removed?)'
    fi

    echo ''
    echo 'Current INPUT chain:'
    iptables -L INPUT -n --line-numbers | head -8
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [2/2] Cleaning up baseline session ID file ..."
if [[ -f "$BASELINE_ID_FILE" ]]; then
  BASELINE_SESSION_ID=$(cat "$BASELINE_ID_FILE")
  rm -f "$BASELINE_ID_FILE"
  echo "  [OK] Removed $BASELINE_ID_FILE (was: $BASELINE_SESSION_ID)"
  echo "       Note: snapshot artifacts remain in audit/ for post-demo review."
else
  echo "  [SKIP] No baseline ID file found at $BASELINE_ID_FILE"
fi

echo ""
echo "  Teardown complete. INPUT policy restored to ACCEPT on $DEST_VM_NAME."
echo ""
