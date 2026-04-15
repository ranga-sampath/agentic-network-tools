#!/usr/bin/env bash
# =============================================================================
# Use Case S — "The Accidental Blackhole": Setup
#
# Scenario:
#   The network team attached a new route table to the VNet default subnet as
#   part of a security hardening exercise. The intended goal was to route
#   specific traffic through an NVA, but the admin accidentally left the
#   next-hop as None on a /32 route for tf-dest-vm's private IP. Every packet
#   from tf-source-vm destined for tf-dest-vm now hits a User-defined blackhole
#   and is silently discarded by Azure at the routing layer.
#
# Fault injected:
#   - Route table "ghost-demo-s-rt" created in RESOURCE_GROUP
#   - Route: DEST_VM_PRIVATE_IP/32 → nextHopType=None
#   - Route table associated with SUBNET_NAME
#   - NSG is intentionally NOT touched — the mismatch is the point
#
# Detection path (Ghost Agent):
#   1. NSG audit → no deny rules on either VM NIC (routing fault is invisible here)
#   2. effective_route_inspector(vm_name=SOURCE_VM_NAME, dst_ip=DEST_VM_PRIVATE_IP)
#      → result: WINNER
#      → winning_route: DEST_VM_PRIVATE_IP/32 [User] → None
#      → anomaly_warnings: BLACKHOLE_WARNING
#   3. Pre-completion checklist closes:
#        (a) Symptom: silent drops from tf-source-vm to tf-dest-vm
#        (b) Mechanism: User /32 route with nextHopType=None on winning route
#        (c) Mechanism alone is sufficient to produce silent drops
#        (d) Audit ID: rt_<session_id> verdict artifact
#   Recommended action: remove or correct the blackhole route in ghost-demo-s-rt.
#
# KEY MOMENT: Investigation terminates at step 2. No packet capture needed.
# The route table name, prefix, and source tier are all in the verdict.
#
# Audience: VP of Engineering, Senior Network Engineers
# Duration: ~8 minutes (pure Azure control-plane, no captures)
#
# Teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RT_NAME="ghost-demo-s-rt"
ROUTE_NAME="blackhole-dest-vm"
STATE_FILE="/tmp/ghost-demo-s.env"

echo ""
echo "==================================================="
echo "  Use Case S — Setup: The Accidental Blackhole"
echo "  Route table : $RT_NAME"
echo "  Fault        : $DEST_VM_PRIVATE_IP/32 → None (blackhole)"
echo "  Subnet       : $SUBNET_NAME in $VNET_NAME"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Idempotency guard — prevent re-running without teardown first
# ---------------------------------------------------------------------------
if [[ -f "$STATE_FILE" ]]; then
  echo "[ERROR] State file exists at $STATE_FILE."
  echo "        Run teardown.sh before re-running setup."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create route table
# ---------------------------------------------------------------------------
echo "  [1/3] Creating route table $RT_NAME ..."
EXISTING_RT=$(az network route-table show \
  --name "$RT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RT" ]]; then
  echo "       [WARN] $RT_NAME already exists — will reuse."
else
  az network route-table create \
    --name "$RT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none
  echo "       [OK] Route table created: $RT_NAME"
fi

# ---------------------------------------------------------------------------
# Step 2: Add blackhole route for tf-dest-vm
# ---------------------------------------------------------------------------
echo "  [2/3] Adding blackhole route $DEST_VM_PRIVATE_IP/32 → None ..."
az network route-table route create \
  --name "$ROUTE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --route-table-name "$RT_NAME" \
  --address-prefix "${DEST_VM_PRIVATE_IP}/32" \
  --next-hop-type None \
  --output none
echo "       [OK] Route: $DEST_VM_PRIVATE_IP/32 → None (Azure will silently drop all traffic)"

# ---------------------------------------------------------------------------
# Step 3: Associate route table with the subnet
# Save any pre-existing association for teardown restoration
# ---------------------------------------------------------------------------
echo "  [3/3] Associating $RT_NAME with subnet $SUBNET_NAME ..."
PREV_RT=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --query "routeTable.id" -o tsv 2>/dev/null || echo "")

az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --route-table "$RT_NAME" \
  --output none
echo "       [OK] $RT_NAME associated with $SUBNET_NAME"
echo "       [INFO] Prior route table: ${PREV_RT:-none}"

# ---------------------------------------------------------------------------
# Save state for teardown
# ---------------------------------------------------------------------------
cat > "$STATE_FILE" <<EOF
RT_NAME=${RT_NAME}
ROUTE_NAME=${ROUTE_NAME}
RESOURCE_GROUP=${RESOURCE_GROUP}
VNET_NAME=${VNET_NAME}
SUBNET_NAME=${SUBNET_NAME}
DEST_VM_PRIVATE_IP=${DEST_VM_PRIVATE_IP}
PREV_RT=${PREV_RT}
EOF
echo "       State saved to $STATE_FILE"

echo ""
echo "  [OK] Fault injected. Current state:"
echo "       $DEST_VM_PRIVATE_IP/32 → None (User UDR wins over all system routes)"
echo "       NSG                    : unchanged — no deny rules (misleading clean)"
echo "       Subnet association     : $RT_NAME → $SUBNET_NAME active"
echo ""
echo "==================================================="
echo "  PROMPT (also written to PROMPT.txt):"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: uv run --python 3.12 python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. NSG audit: tf-source-vm NIC → no deny. tf-dest-vm NIC → no deny."
echo "     (No Azure API call can detect this fault — the route table is the source of truth.)"
echo "  2. effective_route_inspector(vm_name=tf-source-vm, dst_ip=$DEST_VM_PRIVATE_IP)"
echo "       result         : WINNER"
echo "       winning_route  : $DEST_VM_PRIVATE_IP/32 [User] → None"
echo "       anomaly_warnings: BLACKHOLE_WARNING"
echo "     Azure route selection: User /32 (tier 1) beats Default VnetLocal /24 (tier 3)."
echo "     The very specificity of the route makes it win — and makes it a silent drop."
echo "  3. Pre-completion checklist:"
echo "       Symptom   : Silent drop from tf-source-vm to tf-dest-vm"
echo "       Mechanism : nextHopType=None on the winning User /32 route"
echo "       Audit ID  : rt_<session_id> in audit/"
echo "     Recommended action: Remove route $ROUTE_NAME from $RT_NAME,"
echo "     or correct its next-hop to a valid NVA or VnetLocal type."
echo "  KEY MOMENT: The investigation terminates at step 2 — no capture needed."
echo "  All evidence is in the Azure control-plane routing state."
echo "==================================================="
echo ""
