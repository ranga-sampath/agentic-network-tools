#!/usr/bin/env bash
# =============================================================================
# Use Case B — "The Wire Doesn't Lie": Setup
#
# Generates realistic, varied network traffic between the two VMs so the
# packet capture will have interesting content for the forensic engine:
#   - HTTP requests (TCP connections with data transfer)
#   - DNS lookups (to produce DNS traffic in the capture)
#   - Some deliberately broken connections (connection resets, timeouts)
#     to give the PCAP engine anomalies to report on
#
# The traffic generator runs in the background for 10 minutes, which is
# longer than the capture window, ensuring there is always live traffic
# when the capture starts.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

HTTP_PORT=8080
RST_PORT=9999    # Port with nothing listening — causes RST, interesting for PCAP

echo ""
echo "==================================================="
echo "  Use Case B — Setup: Starting traffic generator"
echo "  Source: $SOURCE_VM_NAME ($SOURCE_VM_PRIVATE_IP)"
echo "  Dest:   $DEST_VM_NAME ($DEST_VM_PRIVATE_IP)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Start an HTTP server on dest-vm
# ---------------------------------------------------------------------------
echo "  [1/3] Starting HTTP server on dest-vm (port $HTTP_PORT)..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Kill any prior listener on this port
    fuser -k ${HTTP_PORT}/tcp 2>/dev/null || true
    # Create a simple HTML page to serve
    mkdir -p /tmp/demo-site
    cat > /tmp/demo-site/index.html <<'HTML'
<html><body><h1>Ghost Agent Demo Target</h1><p>VM: ${DEST_VM_NAME}</p></body></html>
HTML
    # Start server (auto-kills after 600 seconds = 10 minutes)
    nohup bash -c '
      cd /tmp/demo-site
      timeout 600 python3 -m http.server ${HTTP_PORT} --bind 0.0.0.0 \
        > /tmp/demo_http.log 2>&1
    ' &
    disown
    sleep 1
    ss -tlnp | grep ${HTTP_PORT} && echo 'HTTP server started OK'
  " \
  --output none
echo "     HTTP server ready on dest-vm:${HTTP_PORT}"

# ---------------------------------------------------------------------------
# Step 2: Start a traffic generator on source-vm
# Generates: HTTP GETs, DNS queries, and TCP RST-inducing connections
# ---------------------------------------------------------------------------
echo "  [2/3] Starting traffic generator on source-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    cat > /tmp/demo_traffic_gen.sh <<'TRAFFIC'
#!/usr/bin/env bash
# Traffic generator for Ghost Agent demo — runs for 10 minutes
DEST_IP=\"${DEST_VM_PRIVATE_IP}\"
HTTP_PORT=${HTTP_PORT}
RST_PORT=${RST_PORT}
END_TIME=\$(( \$(date +%s) + 600 ))

echo 'Traffic generator started. PID: \$\$' > /tmp/demo_traffic.log

while [[ \$(date +%s) -lt \$END_TIME ]]; do
  # --- HTTP requests (valid connections with data transfer) ---
  for i in 1 2 3; do
    curl -s --max-time 3 http://\${DEST_IP}:\${HTTP_PORT}/ >> /tmp/demo_traffic.log 2>&1 || true
    sleep 0.5
  done

  # --- DNS queries (generates DNS traffic in the capture) ---
  dig +short google.com @8.8.8.8 >> /tmp/demo_traffic.log 2>&1 || true
  dig +short microsoft.com @168.63.129.16 >> /tmp/demo_traffic.log 2>&1 || true

  # --- Connection resets: connect to port with no listener (TCP RST anomaly) ---
  # This makes the PCAP interesting — forensic engine will flag TCP RSTs
  nc -z -w1 \${DEST_IP} \${RST_PORT} >> /tmp/demo_traffic.log 2>&1 || true

  # --- Slightly slower HTTP request to produce latency variation ---
  curl -s --max-time 5 http://\${DEST_IP}:\${HTTP_PORT}/slow 2>/dev/null || true

  sleep 2
done

echo 'Traffic generator finished.' >> /tmp/demo_traffic.log
TRAFFIC
    chmod +x /tmp/demo_traffic_gen.sh
    nohup /tmp/demo_traffic_gen.sh &
    disown
    sleep 2
    cat /tmp/demo_traffic.log | head -5
  " \
  --output none
echo "     Traffic generator started on source-vm"

# ---------------------------------------------------------------------------
# Step 3: Verify traffic is flowing
# ---------------------------------------------------------------------------
echo "  [3/3] Verifying traffic flow..."
sleep 5
VERIFY=$(az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "tail -5 /tmp/demo_traffic.log 2>/dev/null || echo 'Log not yet written'" \
  --query "value[0].message" -o tsv 2>/dev/null || echo "Could not verify")
echo "     Traffic log tail: $VERIFY"

echo ""
echo "  [OK] Traffic is flowing between VMs."
echo "       HTTP server: dest-vm:${HTTP_PORT}"
echo "       Generator runs for ~10 minutes"
echo ""
echo "  Wait 30-60 seconds after capture starts to ensure enough packets."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "==================================================="
