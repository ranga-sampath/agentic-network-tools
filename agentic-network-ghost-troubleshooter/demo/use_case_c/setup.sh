#!/usr/bin/env bash
# =============================================================================
# Use Case C — "Show Me Both Sides": Setup
#
# Generates sustained, asymmetric traffic between the two VMs.
# The key characteristic: source-vm generates more traffic than dest-vm
# acknowledges on time — creating conditions for TCP retransmissions and
# slightly different packet counts at each end. This is what a dual-end
# capture will surface: small asymmetric differences between what was
# sent and what was received, exactly replicating intermittent drop scenarios.
#
# The setup also generates a DNS query pattern to the Azure-provided resolver
# (168.63.129.16) to add multi-protocol forensic data to both captures.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

HTTP_PORT=7070     # Different port from UC-B to avoid conflict
DURATION=900       # 15 minutes — long enough for a dual capture during the demo

echo ""
echo "==================================================="
echo "  Use Case C — Setup: Sustained asymmetric traffic"
echo "  Source: $SOURCE_VM_NAME ($SOURCE_VM_PRIVATE_IP)"
echo "  Dest:   $DEST_VM_NAME ($DEST_VM_PRIVATE_IP)"
echo "  Duration: ${DURATION}s"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Dest VM — HTTP server + a slow endpoint to create backpressure
# ---------------------------------------------------------------------------
echo "  [1/3] Starting HTTP server on dest-vm (port $HTTP_PORT)..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${HTTP_PORT}/tcp 2>/dev/null || true
    mkdir -p /tmp/demo-uc-c

    # Simple server with a /slow endpoint that sleeps briefly (creates backpressure)
    cat > /tmp/demo-uc-c/server.py <<'PYSERVER'
import http.server, time, random

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/slow':
            time.sleep(random.uniform(0.05, 0.15))  # 50-150ms think time
            body = b'slow response'
        else:
            body = b'OK'
        self.send_response(200)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass  # suppress per-request logging

import socketserver
with socketserver.TCPServer(('0.0.0.0', ${HTTP_PORT}), Handler) as srv:
    srv.serve_forever()
PYSERVER

    nohup bash -c 'timeout ${DURATION} python3 /tmp/demo-uc-c/server.py > /tmp/demo-uc-c/server.log 2>&1' &
    disown
    sleep 2
    ss -tlnp | grep ${HTTP_PORT} && echo 'Server started OK' || echo 'WARNING: server not listening'
  " \
  --output none
echo "     HTTP server with /slow endpoint ready on dest-vm:${HTTP_PORT}"

# ---------------------------------------------------------------------------
# Step 2: Source VM — High-frequency mixed traffic generator
# Sends fast requests and slow requests in a ratio to create retransmissions
# ---------------------------------------------------------------------------
echo "  [2/3] Starting traffic generator on source-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    cat > /tmp/demo_uc_c_gen.sh <<'TRAFFIC'
#!/usr/bin/env bash
DEST_IP=\"${DEST_VM_PRIVATE_IP}\"
PORT=${HTTP_PORT}
END_TIME=\$(( \$(date +%s) + ${DURATION} ))
echo \"Dual-end traffic generator started. PID=\$\$\" > /tmp/demo_uc_c.log

BATCH=0
while [[ \$(date +%s) -lt \$END_TIME ]]; do
  BATCH=\$(( BATCH + 1 ))
  echo \"Batch \$BATCH at \$(date)\" >> /tmp/demo_uc_c.log

  # Fast requests (should complete without retransmission)
  for i in \$(seq 1 5); do
    curl -s --max-time 2 http://\${DEST_IP}:\${PORT}/ -o /dev/null &
  done

  # Slow request (may cause TCP retransmission due to /slow backpressure)
  curl -s --max-time 5 http://\${DEST_IP}:\${PORT}/slow -o /dev/null &

  # DNS queries toward Azure resolver (adds DNS traffic to both captures)
  dig +short +time=2 www.microsoft.com @168.63.129.16 >> /tmp/demo_uc_c.log 2>&1 || true
  dig +short +time=2 portal.azure.com @168.63.129.16 >> /tmp/demo_uc_c.log 2>&1 || true

  wait  # wait for parallel curls before next batch
  sleep 1
done

echo 'Generator finished.' >> /tmp/demo_uc_c.log
TRAFFIC
    chmod +x /tmp/demo_uc_c_gen.sh
    nohup /tmp/demo_uc_c_gen.sh &
    disown
    sleep 3
    head -3 /tmp/demo_uc_c.log 2>/dev/null || echo 'Log not yet written'
  " \
  --output none
echo "     Traffic generator started on source-vm"

# ---------------------------------------------------------------------------
# Step 3: Verify both sides are active
# ---------------------------------------------------------------------------
echo "  [3/3] Verifying traffic..."
sleep 6
SRC_LOG=$(az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "wc -l /tmp/demo_uc_c.log 2>/dev/null && tail -3 /tmp/demo_uc_c.log" \
  --query "value[0].message" -o tsv 2>/dev/null || echo "Not ready yet")

echo ""
echo "  Source traffic log: $SRC_LOG"
echo ""
echo "  [OK] Setup complete. Sustained traffic running for ~${DURATION}s."
echo "       You can start the demo now. The capture window needs 30-60 seconds"
echo "       of active traffic — the generator ensures continuous coverage."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "==================================================="
echo "  NOTE FOR PRESENTER:"
echo "  When ghost_agent asks for capture parameters, let it decide."
echo "  When it asks to capture on BOTH VMs (dual-end), approve both HITL gates."
echo "  The comparison report will show asymmetric TCP stats between source & dest."
echo "==================================================="
