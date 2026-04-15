#!/usr/bin/env bash
# =============================================================================
# Use Case V — "The Open Doorway": Setup
#
# Simulates an overly permissive NSG rule that accumulated over 18 months of
# production operation. An engineer added a "temporary" rule to allow RDP
# (TCP 3389) from the internet (0.0.0.0/0) for a troubleshooting session and
# never removed it. The VM is Linux — no RDP service is running — but the NSG
# rule represents an open attack surface and is an immediate compliance finding.
#
# No specific flow to test: the operator wants a full picture, not a verdict
# on one connection. Ghost Agent must recognize this as an audit-mode request
# and call inspect_nsg without src/dst/port/proto/direction arguments.
#
# inspect_nsg in audit mode returns:
#   mode: audit
#   effective_rules: full list of all inbound and outbound rules at both gates
#     → ghost-demo-temp-rdp-access (priority 500, Allow Tcp:3389 from *)
#     → AllowVnetInBound (priority 65000, Allow * from VirtualNetwork)
#     → DenyAllInBound (priority 65500, Deny * from *)
#
# The Brain reads the rule list, identifies the ghost-demo-temp-rdp-access
# rule as anomalous (0.0.0.0/0 source, production VM, non-standard port),
# and surfaces it as the primary finding with a recommended remediation.
#
# Audience: Senior network engineers and security architects
# Duration: ~8 minutes
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RDP_RULE_NAME="ghost-demo-temp-rdp-access"
RDP_PORT=3389

echo ""
echo "==================================================="
echo "  Use Case V — Setup: The Open Doorway"
echo "  NSG:   $DEST_VM_NSG_NAME"
echo "  Rule:  $RDP_RULE_NAME"
echo "         Allow Tcp:$RDP_PORT from 0.0.0.0/0, priority 500"
echo "  Note:  Linux VM — no RDP service running"
echo "         Rule is a compliance finding, not a functional path"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Add the "forgotten" RDP allow rule to the dest VM's NIC NSG (idempotent)
# Priority 500 — sits above the default rules, below typical app rules.
# This mimics a rule added during an incident and never cleaned up.
# ---------------------------------------------------------------------------
echo "  [1/1] Adding '$RDP_RULE_NAME' to $DEST_VM_NSG_NAME..."
EXISTING_RULE=$(az network nsg rule show \
                  -g "$RESOURCE_GROUP" \
                  --nsg-name "$DEST_VM_NSG_NAME" \
                  --name "$RDP_RULE_NAME" \
                  --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RULE" ]]; then
  echo "     Rule '$RDP_RULE_NAME' already exists — skipping creation."
else
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$RDP_RULE_NAME" \
    --priority 500 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --source-address-prefixes "*" \
    --source-port-ranges "*" \
    --destination-address-prefixes "*" \
    --destination-port-ranges "$RDP_PORT" \
    --output none
  echo "     [OK] Rule created: Allow Tcp:$RDP_PORT from * (priority 500)"
fi

echo ""
echo "  [OK] Open doorway planted in $DEST_VM_NSG_NAME."
echo "       NSG now has a rule permitting TCP 3389 from the internet."
echo "       VM is Linux — no RDP service is running."
echo "       Rule will not be found by anyone checking application ports."
echo "       It only surfaces in a full effective rule audit."
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
echo "  1. Recognise a security posture question — no specific flow to evaluate"
echo "  2. Call inspect_nsg in audit mode (vm_name + resource_group only)"
echo "  3. Receive full effective rule inventory for both NSG gates"
echo "  4. Surface '$RDP_RULE_NAME': Allow Tcp:3389 from * — open to the internet"
echo "  5. Flag AllowVnetInBound (65000) as broad and candidate for scoping"
echo "  KEY MOMENT: The rule is on a Linux VM. Nothing is listening on 3389."
echo "              No monitoring alert ever fires. No connectivity test trips over it."
echo "              It only surfaces in a full effective rule audit."
echo "  Key field to watch: effective_rules[].source_address_prefix for '*'"
echo "==================================================="
