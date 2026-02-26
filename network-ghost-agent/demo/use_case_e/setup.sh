#!/usr/bin/env bash
# =============================================================================
# Use Case E — "The Phantom Route": Setup
#
# Creates a User Defined Route (UDR) with a /32 host route for the destination
# VM's IP (10.0.1.5) pointing to a non-existent Virtual Appliance (10.0.1.100).
# The route table is associated with the default subnet — this activates a
# "black hole" that silently discards all traffic to dest-vm.
#
# NSG is deliberately left CLEAN so the agent must pivot from NSG investigation
# to route table analysis. This demonstrates the escalation ladder and the
# ability to investigate beyond the most obvious failure layer.
#
# IMPORTANT: Azure DOES apply UDRs to intra-subnet traffic when a /32 host
# route overrides the system VnetLocal route. Effective routes on source-vm's
# NIC will show the custom /32 winning over the system route.
#
# Audience: Senior Network Architect
# Duration: ~15 minutes (includes optional PCAP on dest-vm showing silence)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

ROUTE_TABLE_NAME="ghost-demo-blackhole-rt"
ROUTE_NAME="ghost-demo-nva-redirect"
DEST_HOST_ROUTE="${DEST_VM_PRIVATE_IP}/32"
NVA_IP="10.0.1.100"    # Non-existent NVA — planned but never provisioned
HTTP_PORT=8080

echo ""
echo "==================================================="
echo "  Use Case E — Setup: UDR black hole"
echo "  Route table:   $ROUTE_TABLE_NAME"
echo "  Route:         $ROUTE_NAME"
echo "  Prefix:        $DEST_HOST_ROUTE → VirtualAppliance → $NVA_IP"
echo "  Subnet:        $VNET_NAME/$SUBNET_NAME"
echo "  Effect:        All traffic to dest-vm silently black-holed"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Start a listener on dest-vm (proves service is UP — H3/H4 refuted)
# The agent can confirm the service exists; the silence is in the network path.
# ---------------------------------------------------------------------------
echo "  [1/4] Starting HTTP listener on dest-vm (port $HTTP_PORT)..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${HTTP_PORT}/tcp 2>/dev/null || true
    nohup bash -c '
      timeout 1800 python3 -m http.server ${HTTP_PORT} --bind 0.0.0.0 \
        > /tmp/demo_uce_http.log 2>&1
    ' &
    disown
    sleep 1
    ss -tlnp | grep ${HTTP_PORT} && echo 'Listener started OK' || echo 'WARNING: listener not started'
  " \
  --output none
echo "     HTTP listener started on dest-vm:${HTTP_PORT}"

# ---------------------------------------------------------------------------
# Step 2: Create route table (idempotent)
# ---------------------------------------------------------------------------
echo "  [2/4] Creating route table $ROUTE_TABLE_NAME..."
EXISTING_RT=$(az network route-table show \
               -g "$RESOURCE_GROUP" \
               --name "$ROUTE_TABLE_NAME" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RT" ]]; then
  echo "     Route table '$ROUTE_TABLE_NAME' already exists — skipping creation."
else
  az network route-table create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$ROUTE_TABLE_NAME" \
    --location "$LOCATION" \
    --output none
  echo "     [OK] Route table created: $ROUTE_TABLE_NAME"
fi

# ---------------------------------------------------------------------------
# Step 3: Add the black-hole /32 host route
# ---------------------------------------------------------------------------
echo "  [3/4] Adding UDR black-hole route..."
EXISTING_ROUTE=$(az network route-table route show \
                  -g "$RESOURCE_GROUP" \
                  --route-table-name "$ROUTE_TABLE_NAME" \
                  --name "$ROUTE_NAME" \
                  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_ROUTE" ]]; then
  echo "     Route '$ROUTE_NAME' already exists — skipping creation."
else
  az network route-table route create \
    --resource-group "$RESOURCE_GROUP" \
    --route-table-name "$ROUTE_TABLE_NAME" \
    --name "$ROUTE_NAME" \
    --address-prefix "$DEST_HOST_ROUTE" \
    --next-hop-type VirtualAppliance \
    --next-hop-ip-address "$NVA_IP" \
    --output none
  echo "     [OK] Route created: $DEST_HOST_ROUTE → VirtualAppliance → $NVA_IP"
fi

# ---------------------------------------------------------------------------
# Step 4: Associate route table with the subnet (this activates the black hole)
# ---------------------------------------------------------------------------
echo "  [4/4] Associating route table with subnet $SUBNET_NAME..."
CURRENT_RT=$(az network vnet subnet show \
               -g "$RESOURCE_GROUP" \
               --vnet-name "$VNET_NAME" \
               --name "$SUBNET_NAME" \
               --query "routeTable.id" -o tsv 2>/dev/null || echo "")

if [[ "$CURRENT_RT" == *"$ROUTE_TABLE_NAME"* ]]; then
  echo "     Route table already associated with subnet — skipping."
else
  az network vnet subnet update \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "$VNET_NAME" \
    --name "$SUBNET_NAME" \
    --route-table "$ROUTE_TABLE_NAME" \
    --output none
  echo "     [OK] Route table '$ROUTE_TABLE_NAME' associated with subnet '$SUBNET_NAME'"
fi

echo ""
echo "  [OK] Black hole route is active."
echo "       $DEST_HOST_ROUTE → VirtualAppliance → $NVA_IP (non-existent)"
echo "       NSG is clean — packet drop happens at routing layer."
echo ""
echo "  Allow ~60 seconds for effective route table to update on source-vm NIC."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Then run ghost_agent.py and type the prompt above."
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE:"
echo "  The agent will:"
echo "  1. Check NSG rules → finds all ALLOW → H1 REFUTED"
echo "  2. Pivot to route tables → finds '$ROUTE_TABLE_NAME'"
echo "  3. List routes → finds $ROUTE_NAME ($DEST_HOST_ROUTE → $NVA_IP)"
echo "  4. Check effective routes on source-vm NIC → confirms /32 is active"
echo "  5. Optionally run a PCAP on dest-vm → shows zero incoming packets"
echo "  Key command to watch: az network nic show-effective-route-table"
echo "==================================================="
