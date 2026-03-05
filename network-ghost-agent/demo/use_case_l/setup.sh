#!/usr/bin/env bash
# =============================================================================
# Use Case L — "The Double Lock": Setup
#
# Injects TWO independent faults — BOTH on the DEST VM, but at different
# layers of the network stack.
#
# Fault 1 — Control plane (NSG):
#   Adds a DENY rule for TCP port 5001 inbound on tf-dest-vm NSG at
#   priority 200. This immediately blocks all iperf connections.
#   Ghost Agent will find this via az network nsg rule list.
#
# Fault 2 — Data plane (tc netem on DEST VM):
#   Adds tc netem delay 80ms + loss 8% on all non-SSH outbound traffic
#   from tf-dest-vm. This is the HIDDEN fault — even if the NSG rule is
#   removed, performance will still be severely degraded.
#   Ghost Agent finds this via az vm run-command tc qdisc show on dest VM.
#
# Why this is a WOW scenario:
#   (1) Engineer finds the NSG deny rule and says "I found it!" — but
#       removing it alone doesn't fix the problem (latency still broken).
#   (2) BOTH faults are on the SAME VM but at different layers:
#         NSG = Azure control plane (az network nsg rule list)
#         tc netem = OS data plane (az vm run-command tc qdisc show)
#   (3) Previous tc netem demos (G/H/I) put tc on the SOURCE VM.
#       Here it's on the DEST VM — so checking source VM would find nothing.
#       Agent must check BOTH VMs as the system prompt instructs.
#   (4) The prompt explicitly warns "there may be more than one issue" —
#       a good agent must not stop at the first finding.
#
# Detection path:
#   1. run_pipe_meter → CONNECTIVITY_DROP (NSG blocks iperf port 5001)
#   2. NSG audit on dest VM → finds DENY rule at priority 200 (Fault 1)
#   3. tc qdisc show on DEST VM → finds netem delay+loss (Fault 2)
#      (Previous demos checked SOURCE VM — this tests if agent checks BOTH)
#   4. tc qdisc show on SOURCE VM → clean (no fault there)
#   5. Report: TWO independent findings on dest VM, different remediations
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

NSG_RULE_NAME="ghost-demo-l-block-iperf"
NSG_PRIORITY=200
DELAY="80ms"
LOSS="8%"

echo ""
echo "==================================================="
echo "  Use Case L — Setup: The Double Lock"
echo "  Fault 1:  NSG DENY TCP 5001 on $DEST_VM_NSG_NAME (priority $NSG_PRIORITY)"
echo "  Fault 2:  tc netem delay $DELAY loss $LOSS on $DEST_VM_NAME (SSH exempt)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Fault 1: NSG DENY rule on DEST VM NSG
# ---------------------------------------------------------------------------
echo "  [1/2] Adding NSG DENY rule for port 5001 on $DEST_VM_NSG_NAME ..."

EXISTING=$(az network nsg rule show \
             -g "$RESOURCE_GROUP" \
             --nsg-name "$DEST_VM_NSG_NAME" \
             --name "$NSG_RULE_NAME" \
             --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
  echo "       Rule '$NSG_RULE_NAME' already exists — skipping creation."
else
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$NSG_RULE_NAME" \
    --priority "$NSG_PRIORITY" \
    --direction Inbound \
    --access Deny \
    --protocol Tcp \
    --source-address-prefixes '*' \
    --source-port-ranges '*' \
    --destination-address-prefixes '*' \
    --destination-port-ranges "5001" \
    --description "Ghost Agent demo L: intentional block on iperf port 5001" \
    --output none
  echo "       [OK] NSG rule created: $NSG_RULE_NAME (priority $NSG_PRIORITY, Deny TCP 5001)"
fi

# ---------------------------------------------------------------------------
# Fault 2: tc netem delay+loss on DEST VM (SSH exempt via prio filter)
# ---------------------------------------------------------------------------
echo "  [2/2] Injecting tc netem delay+loss on $DEST_VM_NAME (SSH port 22 exempt) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    tc qdisc del dev \$IFACE root 2>/dev/null || true
    # prio root: 3 bands. Band 1 = bypass (SSH). Band 3 = through netem.
    tc qdisc add dev \$IFACE root handle 1: prio bands 3
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem delay ${DELAY} loss ${LOSS}
    # SSH exempt
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through netem)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+netem applied on \$IFACE: SSH exempt, data traffic delay=${DELAY} loss=${LOSS}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Both faults injected on $DEST_VM_NAME:"
echo "       Fault 1: NSG Deny TCP 5001 inbound (priority 200)"
echo "                Immediately breaks iperf connectivity."
echo "       Fault 2: tc netem delay=${DELAY} loss=${LOSS} on dest VM (SSH exempt)"
echo "                Hidden performance fault — survives even if NSG rule is removed."
echo "                Note: previous demos had tc on SOURCE VM; here it's on DEST VM."
echo ""
echo "  Allow ~30 seconds for NSG rule to propagate."
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
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. pipe_meter → CONNECTIVITY_DROP (NSG blocks TCP 5001)"
echo "  2. NSG audit on dest VM → finds DENY rule at priority 200 (Fault 1)"
echo "  3. tc qdisc show on DEST VM → finds netem delay=${DELAY} loss=${LOSS} (Fault 2)"
echo "  4. tc qdisc show on SOURCE VM → clean (teaches: always check BOTH VMs)"
echo "  KEY MOMENT: Agent finds BOTH faults and reports them independently."
echo "  POST-DEMO STORY: If you removed only the NSG rule, latency would still be"
echo "  broken. You need BOTH fixes. This is the 'maintenance window' trap."
echo "==================================================="
