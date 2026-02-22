#!/usr/bin/env bash
# =============================================================================
# Use Case A — "The Invisible Wall": Setup
#
# Adds an NSG deny rule that silently blocks TCP port 8080 inbound to the
# destination VM. This creates the symptom: source-vm can ping dest-vm fine
# (L3 works) but cannot establish a TCP connection on port 8080.
#
# Ghost Agent will need to form hypotheses, rule out alternatives, and find
# this exact rule by querying the Azure NSG API.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RULE_NAME="ghost-demo-block-${DEMO_BLOCKED_PORT}"
PRIORITY=150    # High priority (lower number = higher precedence in Azure NSGs)

echo ""
echo "==================================================="
echo "  Use Case A — Setup: Adding NSG deny rule"
echo "  NSG:      $DEST_VM_NSG_NAME"
echo "  Rule:     $RULE_NAME (priority $PRIORITY)"
echo "  Blocking: TCP inbound port $DEMO_BLOCKED_PORT to dest VM"
echo "==================================================="
echo ""

# Check the rule doesn't already exist
EXISTING=$(az network nsg rule show \
             -g "$RESOURCE_GROUP" \
             --nsg-name "$DEST_VM_NSG_NAME" \
             --name "$RULE_NAME" \
             --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
  echo "  Rule '$RULE_NAME' already exists — skipping creation."
  echo "  Run teardown.sh first if you want to recreate it."
  exit 0
fi

# Start a simple HTTP listener on dest-vm so port 8080 is actually open
# on the OS — this makes the NSG block the only thing stopping traffic.
# The listener exits after 30 minutes automatically.
echo "  Starting HTTP listener on dest-vm port $DEMO_BLOCKED_PORT..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Kill any prior listener on this port
    fuser -k ${DEMO_BLOCKED_PORT}/tcp 2>/dev/null || true
    # Start a simple Python HTTP server in background (auto-kills after 30m)
    nohup bash -c '
      timeout 1800 python3 -m http.server ${DEMO_BLOCKED_PORT} \
        --bind 0.0.0.0 \
        > /tmp/demo_http_${DEMO_BLOCKED_PORT}.log 2>&1
    ' &
    disown
    sleep 1
    ss -tlnp | grep ${DEMO_BLOCKED_PORT} && echo 'Listener started OK' || echo 'WARNING: listener may not have started'
  " \
  --output none

echo "  HTTP listener started on dest-vm:${DEMO_BLOCKED_PORT}"

# Add the NSG deny rule
echo "  Adding NSG deny rule..."
az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$DEST_VM_NSG_NAME" \
  --name "$RULE_NAME" \
  --priority "$PRIORITY" \
  --direction Inbound \
  --access Deny \
  --protocol Tcp \
  --source-address-prefixes '*' \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges "$DEMO_BLOCKED_PORT" \
  --description "Ghost Agent demo: intentional block on port $DEMO_BLOCKED_PORT" \
  --output none

echo ""
echo "  [OK] NSG deny rule created: $RULE_NAME"
echo "       Priority: $PRIORITY | Direction: Inbound | Port: $DEMO_BLOCKED_PORT | Action: Deny"
echo ""
echo "  Allow ~30 seconds for the NSG rule to propagate before running the demo."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Then run ghost_agent.py and type the prompt above."
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
