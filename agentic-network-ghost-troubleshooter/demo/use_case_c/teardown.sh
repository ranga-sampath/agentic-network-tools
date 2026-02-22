#!/usr/bin/env bash
# =============================================================================
# Use Case C — Teardown
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

HTTP_PORT=7070

echo ""
echo "=== Use Case C — Teardown ==="

echo "  Stopping server on dest-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${HTTP_PORT}/tcp 2>/dev/null && echo 'Server stopped' || echo 'Not running'
    rm -rf /tmp/demo-uc-c
  " \
  --output none
echo "  [OK] Server stopped"

echo "  Stopping generator on source-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    pkill -f demo_uc_c_gen.sh 2>/dev/null && echo 'Generator stopped' || echo 'Not running'
    rm -f /tmp/demo_uc_c_gen.sh /tmp/demo_uc_c.log
  " \
  --output none
echo "  [OK] Generator stopped"
echo "  Teardown complete."
