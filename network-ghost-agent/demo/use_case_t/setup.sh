#!/usr/bin/env bash
# =============================================================================
# Use Case T — "The Phantom Firewall": Setup
#
# Scenario:
#   The security team set up a route table routing all egress through an NVA
#   for compliance monitoring. The NVA was later decommissioned during a cost
#   review but the UDR was never updated. tf-source-vm now forwards all
#   internet-bound traffic to a phantom IP (10.0.0.253) that no VM answers.
#
#   Separately, an iptables OUTPUT DROP rule for port 80 was left on
#   tf-source-vm by a penetration tester who forgot to clean up. This is an
#   independent fault — even if the NVA route is fixed, HTTP remains broken.
#
# Two independent faults:
#   Fault 1 (routing layer):
#     Route table "ghost-demo-t-rt" with 0.0.0.0/0 → VirtualAppliance 10.0.0.253
#     Associated with SUBNET_NAME. All internet traffic silently dropped.
#     effective_route_inspector → WINNER + NVA_WARNING (phantom NVA: 10.0.0.253)
#
#   Fault 2 (OS layer):
#     iptables -A OUTPUT -p tcp --dport 80 -j DROP on SOURCE_VM_NAME
#     Detected via detect_config_drift(is_baseline=True) — the blocking_rules
#     field surfaces explicit DROP rules in the current state without needing
#     a prior baseline comparison.
#
# Detection path (Ghost Agent):
#   1. NSG audit → no outbound deny rules
#   2. effective_route_inspector(vm_name=SOURCE_VM_NAME, dst_ip="8.8.8.8")
#      → WINNER: 0.0.0.0/0 [User] → VirtualAppliance 10.0.0.253 + NVA_WARNING
#   3. Agent verifies NVA at 10.0.0.253:
#      az network nic list --query ... → not found. Phantom confirmed.
#   4. detect_config_drift(is_baseline=True, vm_name=SOURCE_VM_NAME)
#      → blocking_rules contains: OUTPUT DROP --dport 80
#      Agent identifies port 80 block from blocking_rules without a prior diff.
#   5. Pre-completion checklist:
#      Symptom (HTTPS + all internet) : Mechanism = phantom NVA, all traffic dropped
#      Symptom (HTTP specifically)     : Mechanism = iptables OUTPUT DROP port 80
#      Both must be remediated — fixing one is not sufficient.
#
# KEY MOMENT: The two-phase structure demonstrates that fault investigation is
# iterative. Phase 1 closes correctly — the routing fault is the right answer at
# that point. Phase 2 opens because the residual symptom (apt still fails after
# routing is fixed) carries a different fault signature (selective port block),
# which drives the agent naturally to the OS layer without any prompting.
#
# Audience: Senior Network Engineers, Security team
# Duration: ~15 minutes across two prompts
#
# Demo flow:
#   1. ./setup.sh                        — inject both faults
#   2. Ghost Agent + PROMPT.txt          — Phase 1: finds routing blackhole
#   3. ./fix_fault1.sh                   — simulate operator applying the fix
#   4. Ghost Agent + PROMPT2.txt         — Phase 2: finds iptables port 80
#   5. ./teardown.sh                     — full cleanup
#
# Teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RT_NAME="ghost-demo-t-rt"
ROUTE_NAME="all-egress-to-nva"
# Derive phantom NVA IP from DEST_VM_PRIVATE_IP: same subnet, .253 address.
# Must be within the VNet address space so Azure preserves VirtualAppliance
# nextHopType in the effective route table. An out-of-VNet IP causes Azure to
# reflect the route as None instead, suppressing NVA_WARNING.
PHANTOM_NVA_IP="$(echo "$DEST_VM_PRIVATE_IP" | sed 's/\.[0-9]*$/.253/')"
STATE_FILE="/tmp/ghost-demo-t.env"

echo ""
echo "==================================================="
echo "  Use Case T — Setup: The Phantom Firewall"
echo "  Fault 1: 0.0.0.0/0 → VirtualAppliance $PHANTOM_NVA_IP (phantom NVA)"
echo "  Fault 2: iptables OUTPUT DROP port 80 on $SOURCE_VM_NAME"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Idempotency guard
# ---------------------------------------------------------------------------
if [[ -f "$STATE_FILE" ]]; then
  echo "[ERROR] State file exists at $STATE_FILE."
  echo "        Run teardown.sh before re-running setup."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create route table with phantom NVA route
# ---------------------------------------------------------------------------
echo "  [1/3] Creating route table $RT_NAME with phantom NVA route ..."
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

echo "       Adding route: 0.0.0.0/0 → VirtualAppliance $PHANTOM_NVA_IP ..."
az network route-table route create \
  --name "$ROUTE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --route-table-name "$RT_NAME" \
  --address-prefix "0.0.0.0/0" \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address "$PHANTOM_NVA_IP" \
  --output none
echo "       [OK] Route: 0.0.0.0/0 → VirtualAppliance $PHANTOM_NVA_IP (phantom — no VM here)"

# ---------------------------------------------------------------------------
# Step 2: Inject iptables OUTPUT DROP for port 80 on SOURCE_VM_NAME
# Uses SSH directly (faster, no VM agent dependency).
# MUST run BEFORE associating the route table — once 0.0.0.0/0 UDR is active,
# egress SSH connectivity to the VM may be disrupted.
# ---------------------------------------------------------------------------
echo "  [2/3] Injecting iptables OUTPUT DROP port 80 on $SOURCE_VM_NAME ..."

ssh -i "$SSH_SOURCE_VM_KEY_PATH" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=15 \
    -o BatchMode=yes \
    "${SSH_USER}@${SOURCE_VM_PUBLIC_IP}" \
    "sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP 2>/dev/null || true; sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP && echo '[OK] OUTPUT DROP rule added for port 80' && sudo iptables -L OUTPUT -n --line-numbers | head -10"

echo "       [OK] iptables OUTPUT DROP port 80 active on $SOURCE_VM_NAME"

# ---------------------------------------------------------------------------
# Step 3: Associate route table with the subnet
# Route table association activates Fault 1. Done last so Wire Server
# connectivity is intact for the run-command above.
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
PHANTOM_NVA_IP=${PHANTOM_NVA_IP}
RESOURCE_GROUP=${RESOURCE_GROUP}
VNET_NAME=${VNET_NAME}
SUBNET_NAME=${SUBNET_NAME}
SOURCE_VM_NAME=${SOURCE_VM_NAME}
PREV_RT=${PREV_RT}
EOF

echo ""
echo "==================================================="
echo "  Both faults active."
echo "  Phantom NVA IP      : $PHANTOM_NVA_IP (no VM at this address)"
echo "  iptables OUTPUT DROP: port 80 on $SOURCE_VM_NAME"
echo "==================================================="
echo ""
echo "  PROMPT (also written to PROMPT.txt):"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: uv run --python 3.12 python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — two-phase investigation:"
echo ""
echo "  PHASE 1 (PROMPT.txt) — routing layer:"
echo "  1. NSG audit → no outbound deny rules (routing fault invisible to NSG)"
echo "  2. effective_route_inspector(vm_name=$SOURCE_VM_NAME, dst_ip='8.8.8.8')"
echo "       result          : WINNER"
echo "       winning_route   : 0.0.0.0/0 [User] → None"
echo "       anomaly_warnings: BLACKHOLE_WARNING"
echo "     Fault 1 confirmed: all internet traffic silently dropped at routing layer."
echo "  3. Recommended action: remove ghost-demo-t-rt from subnet."
echo "     Phase 1 closes correctly here — routing is the complete answer at this point."
echo ""
echo "  [PRESENTER] Run ./fix_fault1.sh to simulate the operator applying the fix."
echo "  HTTPS now works. apt update still hangs. Type PROMPT2.txt into the agent."
echo ""
echo "  PHASE 2 (PROMPT2.txt) — OS layer:"
echo "  1. effective_route_inspector(vm_name=$SOURCE_VM_NAME, dst_ip='8.8.8.8')"
echo "       result: WINNER → Internet [Default] — routing is now clean."
echo "  2. Fault-class reasoning fires: HTTPS works, apt (HTTP port 80) fails."
echo "     Selective block on one protocol → OS-layer DROP rule is the signature."
echo "  3. detect_config_drift(is_baseline=True, vm_name=$SOURCE_VM_NAME, provider=ssh)"
echo "       blocking_rules: [{chain: OUTPUT, protocol: tcp, dst_port: 80, target: DROP}]"
echo "     Fault 2 confirmed: iptables OUTPUT DROP port 80 blocks apt independently."
echo "     WHY provider=ssh: Azure Wire Server (168.63.129.16) uses port 80 for run-command"
echo "     delivery. The OUTPUT DROP --dport 80 rule blocks Wire Server, causing provider=azure"
echo "     to time out. SSH connects on port 22 — unaffected by port-selective output rules."
echo "  4. Recommended action: iptables -D OUTPUT -p tcp --dport 80 -j DROP."
echo ""
echo "  KEY MOMENT: Phase 2 is driven entirely by the changed symptom — the agent"
echo "  reaches the OS layer through reasoning, not prescription. The symptom pattern"
echo "  (HTTPS passes, HTTP fails) is unambiguous: selective port block, OS layer."
echo "  The provider=ssh choice is also driven by reasoning: the fault being investigated"
echo "  is a port 80 output block, which would defeat the Azure run-command mechanism."
echo "==================================================="
echo ""
