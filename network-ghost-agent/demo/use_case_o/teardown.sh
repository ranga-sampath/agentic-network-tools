#!/usr/bin/env bash
# =============================================================================
# Use Case O — "The Docker Coup": Teardown
# Removes Docker-style chains injected by setup (or stops/starts Docker to
# restore clean state). Safe to run even if setup was partial.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

BASELINE_ID_FILE="${SCRIPT_DIR}/.baseline_session_id"

echo ""
echo "=== Use Case O — Teardown: The Docker Coup ==="
echo ""

echo "  [1/2] Removing Docker-style chains from $DEST_VM_NAME ..."
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    if systemctl is-active --quiet docker 2>/dev/null; then
      echo '[docker] Docker daemon is running — stopping (removes its chains) ...'
      systemctl stop docker
      sleep 2
      echo '[OK] Docker stopped — chains removed by daemon'
    else
      echo '[docker] Docker not running as a service — removing chains manually ...'
    fi

    # Flush and delete all Docker chains regardless of path (idempotent cleanup)
    for chain in DOCKER DOCKER-USER DOCKER-ISOLATION-STAGE-1 DOCKER-ISOLATION-STAGE-2; do
      iptables -F \$chain 2>/dev/null || true
      iptables -X \$chain 2>/dev/null || true
    done
    iptables -t nat -F DOCKER 2>/dev/null || true
    iptables -t nat -X DOCKER 2>/dev/null || true

    echo '[OK] Docker chains cleared'
    echo 'FORWARD chain (should have no DOCKER references):'
    iptables -L FORWARD -n --line-numbers | head -6
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
echo "  Teardown complete. Docker chains removed from $DEST_VM_NAME."
echo ""
