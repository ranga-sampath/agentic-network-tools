#!/usr/bin/env bash
# =============================================================================
# Use Case T — Intermediate fix: remove Fault 1 (route table), leave Fault 2.
#
# Run this between Phase 1 and Phase 2 of the demo:
#   Phase 1: agent finds routing blackhole (ghost-demo-t-rt, 0.0.0.0/0 → None)
#   [run this script to simulate the operator applying the recommended fix]
#   Phase 2: agent finds iptables OUTPUT DROP port 80 (Fault 2 still active)
#
# What this does:
#   - Disassociates ghost-demo-t-rt from the subnet (routing restored)
#   - Leaves the iptables OUTPUT DROP port 80 rule on tf-source-vm intact
#
# After this script:
#   - HTTPS to internet: working (default Internet route wins)
#   - apt update (HTTP port 80): still hanging (iptables DROP port 80 active)
#   - Run ghost agent with PROMPT2.txt for Phase 2
#
# Full teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

STATE_FILE="/tmp/ghost-demo-t.env"
RT_NAME="ghost-demo-t-rt"

echo ""
echo "==================================================="
echo "  Use Case T — Fix Fault 1: Remove route table"
echo "  Fault 2 (iptables OUTPUT DROP port 80) remains."
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Disassociate the route table from the subnet
# ---------------------------------------------------------------------------
echo "  Disassociating $RT_NAME from subnet $SUBNET_NAME ..."
CURRENT_RT=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --query "routeTable.id" -o tsv 2>/dev/null || echo "")

if [[ -z "$CURRENT_RT" ]]; then
  echo "  [SKIP] No route table currently on $SUBNET_NAME — already removed?"
else
  az network vnet subnet update \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "$VNET_NAME" \
    --name "$SUBNET_NAME" \
    --remove routeTable \
    --output none
  echo "  [OK] Route table disassociated. Default Internet route now active."
fi

echo ""
echo "  State after fix:"
echo "    Routing (0.0.0.0/0)  : Internet [Default] — restored"
echo "    iptables OUTPUT DROP  : port 80 still active on $SOURCE_VM_NAME"
echo ""
echo "  HTTPS to internet    : working"
echo "  apt update (port 80) : still hanging"
echo ""
echo "  Run Phase 2 with PROMPT2.txt:"
echo "  uv run --python 3.12 python ghost_agent.py --config demo/config.env"
cat "${SCRIPT_DIR}/PROMPT2.txt"
echo ""
