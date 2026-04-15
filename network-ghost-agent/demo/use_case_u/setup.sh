#!/usr/bin/env bash
# =============================================================================
# Use Case U — "The Hidden Gate": Setup
#
# The operator is blocked on port 5432 (PostgreSQL) and checks the NIC NSG
# in the Azure portal. The NIC NSG looks clean — AllowVnetInBound at priority
# 65000 should let the traffic through. But the connection still times out.
#
# The fault lives one layer earlier: a subnet NSG with a Deny rule at priority
# 200 for port 5432. For inbound traffic, Azure evaluates the SUBNET NSG first.
# The deny fires at Gate 1; the NIC NSG (Gate 2) is never reached.
#
# inspect_nsg in verdict mode shows:
#   final_verdict: DENY
#   decisive_rule: ghost-demo-block-pgsql (priority 200, subnet NSG, gate1)
#   gate2: not evaluated (Gate 1 denied)
#
# This is the moment that resets the engineer's mental model: "check the portal
# NIC NSG" is not the same as "check the effective inbound evaluation."
#
# Audience: Senior network engineers and cloud architects
# Duration: ~10 minutes
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

SUBNET_NSG_NAME="ghost-demo-subnet-nsg"
SUBNET_NSG_RULE_NAME="ghost-demo-block-pgsql"
PGSQL_PORT=5432

echo ""
echo "==================================================="
echo "  Use Case U — Setup: The Hidden Gate"
echo "  Subnet NSG:    $SUBNET_NSG_NAME"
echo "  Rule:          $SUBNET_NSG_RULE_NAME (Deny Tcp:$PGSQL_PORT from 10.0.1.0/24, priority 200)"
echo "  Subnet:        $VNET_NAME/$SUBNET_NAME"
echo "  Effect:        Inbound port $PGSQL_PORT blocked at Gate 1 (subnet NSG)"
echo "                 NIC NSG (Gate 2) is never evaluated — appears clean"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Start a TCP mock listener on port 5432 on dest-vm
# Proves the service is UP — the block is in the network path, not the app.
# ---------------------------------------------------------------------------
echo "  [1/4] Starting PostgreSQL mock listener on dest-vm (port $PGSQL_PORT)..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    fuser -k ${PGSQL_PORT}/tcp 2>/dev/null || true
    nohup python3 -c \"
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', ${PGSQL_PORT}))
s.listen(10)
while True:
    try: c, _ = s.accept(); c.close()
    except: pass
\" > /tmp/pgsql_mock.log 2>&1 &
    disown
    sleep 1
    ss -tlnp | grep ${PGSQL_PORT} && echo 'PostgreSQL mock listening OK' || echo 'WARNING: port not listening'
  " \
  --output none
echo "     PostgreSQL mock started on dest-vm:${PGSQL_PORT}"

# ---------------------------------------------------------------------------
# Step 2: Create the subnet NSG (idempotent)
# ---------------------------------------------------------------------------
echo "  [2/4] Creating subnet NSG $SUBNET_NSG_NAME..."
EXISTING_NSG=$(az network nsg show \
                 -g "$RESOURCE_GROUP" \
                 --name "$SUBNET_NSG_NAME" \
                 --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_NSG" ]]; then
  echo "     NSG '$SUBNET_NSG_NAME' already exists — skipping creation."
else
  az network nsg create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$SUBNET_NSG_NAME" \
    --location "$LOCATION" \
    --output none
  echo "     [OK] NSG created: $SUBNET_NSG_NAME"
fi

# ---------------------------------------------------------------------------
# Step 3: Add the Deny rule for port 5432
# Priority 200 — wins before the implicit AllowVnetInBound at 65000 on the
# NIC NSG. The subnet NSG has no AllowVnetInBound override so this rule is
# the first match for Tcp:5432 from the VNet.
# ---------------------------------------------------------------------------
echo "  [3/4] Adding Deny rule '$SUBNET_NSG_RULE_NAME' for port $PGSQL_PORT..."
EXISTING_RULE=$(az network nsg rule show \
                  -g "$RESOURCE_GROUP" \
                  --nsg-name "$SUBNET_NSG_NAME" \
                  --name "$SUBNET_NSG_RULE_NAME" \
                  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RULE" ]]; then
  echo "     Rule '$SUBNET_NSG_RULE_NAME' already exists — skipping creation."
else
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$SUBNET_NSG_NAME" \
    --name "$SUBNET_NSG_RULE_NAME" \
    --priority 200 \
    --direction Inbound \
    --access Deny \
    --protocol Tcp \
    --source-address-prefixes "10.0.1.0/24" \
    --source-port-ranges "*" \
    --destination-address-prefixes "*" \
    --destination-port-ranges "$PGSQL_PORT" \
    --output none
  echo "     [OK] Rule created: Deny Tcp:$PGSQL_PORT from 10.0.1.0/24 (priority 200)"
fi

# ---------------------------------------------------------------------------
# Step 4: Associate the subnet NSG with the default subnet
# This activates Gate 1 — inbound traffic now passes through subnet NSG first.
# ---------------------------------------------------------------------------
echo "  [4/4] Associating subnet NSG with subnet $SUBNET_NAME..."
CURRENT_NSG=$(az network vnet subnet show \
                -g "$RESOURCE_GROUP" \
                --vnet-name "$VNET_NAME" \
                --name "$SUBNET_NAME" \
                --query "networkSecurityGroup.id" -o tsv 2>/dev/null || echo "")

if [[ "$CURRENT_NSG" == *"$SUBNET_NSG_NAME"* ]]; then
  echo "     NSG already associated with subnet — skipping."
else
  az network vnet subnet update \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "$VNET_NAME" \
    --name "$SUBNET_NAME" \
    --network-security-group "$SUBNET_NSG_NAME" \
    --output none
  echo "     [OK] NSG '$SUBNET_NSG_NAME' associated with subnet '$SUBNET_NAME'"
fi

echo ""
echo "  [OK] Hidden Gate is active."
echo "       Subnet NSG:  $SUBNET_NSG_NAME"
echo "       Rule:        $SUBNET_NSG_RULE_NAME — Deny Tcp:$PGSQL_PORT, priority 200"
echo "       NIC NSG:     $DEST_VM_NSG_NAME — AllowVnetInBound visible in portal (irrelevant)"
echo "       Service:     PostgreSQL mock running on dest-vm:$PGSQL_PORT"
echo ""
echo "  Allow ~30 seconds for subnet NSG effective rules to propagate."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE:"
echo "  The agent will:"
echo "  1. Recognise a specific connectivity failure with a known traffic tuple"
echo "  2. Call inspect_nsg in verdict mode (src IP, dest VM, port 5432, Tcp, Inbound)"
echo "  3. Receive final_verdict: DENY — decisive_rule in gate1 (subnet NSG)"
echo "  4. Gate 2 (NIC NSG) absent from result — never evaluated"
echo "  KEY MOMENT: The on-call engineer checked the NIC NSG in the portal."
echo "              It showed AllowVnetInBound. Correct — and irrelevant."
echo "              Inbound evaluation hits the subnet NSG first."
echo "  Key fields to watch: decisive_rule.gate, decisive_rule.nsg_name"
echo "==================================================="
