#!/usr/bin/env bash
# =============================================================================
# Use Case B — Teardown: Stop traffic generators and HTTP server
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

HTTP_PORT=8080

echo ""
echo "=== Use Case B — Teardown ==="

# Stop HTTP server on dest-vm
echo "  Stopping HTTP server on dest-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "fuser -k ${HTTP_PORT}/tcp 2>/dev/null && echo 'HTTP server stopped' || echo 'No server found'" \
  --output none
echo "  [OK] HTTP server stopped"

# Stop traffic generator on source-vm
echo "  Stopping traffic generator on source-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    pkill -f demo_traffic_gen.sh 2>/dev/null && echo 'Traffic generator stopped' || echo 'No generator found'
    rm -f /tmp/demo_traffic_gen.sh /tmp/demo_traffic.log /tmp/demo_http.log
  " \
  --output none
echo "  [OK] Traffic generator stopped"
echo "  Teardown complete."
