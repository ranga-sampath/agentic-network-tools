#!/usr/bin/env bash
# =============================================================================
# Use Case K — "The Bandwidth Thief": Setup
#
# Injects TWO independent OS-level faults — both invisible to Azure control
# plane. Neither appears in NSG rules or route tables.
#
# Fault 1 — tc tbf (token bucket filter) on SOURCE VM:
#   Throttles ALL non-SSH outbound traffic to 5 Mbps. This creates a STABLE,
#   consistent throughput ceiling — iperf always measures ~5 Mbps.
#   pipe_meter will return is_stable=True (no HIGH_VARIANCE) but with an
#   absolute throughput of ~0.005 Gbps — anomalously low for Azure VNet
#   (expected 2+ Gbps on accelerated networking VMs).
#   Ghost Agent must reason from absolute value, not anomaly type.
#
# Fault 2 — iptables ICMP DROP on DEST VM:
#   Drops all incoming ICMP (ping) requests. Ping from source to dest fails.
#   This is an OS-level iptables rule — invisible to Azure NSG audit.
#   It is a RED HERRING for the "slow transfers" symptom: ICMP has nothing
#   to do with TCP throughput. Ghost Agent must correctly identify this as
#   a separate, independent fault — not the cause of slow file copies.
#
# Why this is a WOW scenario:
#   (1) Azure control plane shows nothing wrong — NSG clean, routes fine.
#   (2) pipe_meter says is_stable=True — no anomaly type fires.
#       Ghost Agent must reason: "5 Mbps is not a valid Azure VNet throughput."
#   (3) Two symptoms (slow transfers + failing ping) have two DIFFERENT root
#       causes that must be reported independently. A naive agent conflates them.
#   (4) Both fixes require OS-level intervention (tc + iptables), not Azure API.
#
# Detection path:
#   1. NSG check → clean (ICMP not blocked at Azure level)
#   2. run_pipe_meter(test_type="throughput") → is_stable=True, ~0.005 Gbps
#   3. Absolute-value reasoning → 5 Mbps << Azure VNet baseline
#   4. az vm run-command tc qdisc show on SOURCE VM → tbf found (Fault 1)
#   5. az vm run-command iptables -L INPUT on DEST VM → ICMP DROP found (Fault 2)
#   6. Report: two independent root causes, different remediations
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

RATE="5mbit"

echo ""
echo "==================================================="
echo "  Use Case K — Setup: The Bandwidth Thief"
echo "  Fault 1:  tc tbf rate $RATE on $SOURCE_VM_NAME (SSH exempt)"
echo "  Fault 2:  iptables ICMP DROP on $DEST_VM_NAME"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Fault 1: tc tbf rate throttle on SOURCE VM (SSH exempt via prio filter)
# ---------------------------------------------------------------------------
echo "  [1/2] Injecting tc tbf ${RATE} throttle on $SOURCE_VM_NAME (SSH port 22 exempt) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    tc qdisc del dev \$IFACE root 2>/dev/null || true
    # prio root: 3 bands. Band 1 = bypass (SSH). Band 3 = through tbf.
    tc qdisc add dev \$IFACE root handle 1: prio bands 3
    tc qdisc add dev \$IFACE parent 1:3 handle 30: tbf rate ${RATE} burst 20kb latency 400ms
    # SSH exempt
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through tbf)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+tbf applied on \$IFACE: SSH exempt, all other traffic rate=${RATE}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

# ---------------------------------------------------------------------------
# Fault 2: iptables ICMP DROP on DEST VM
# ---------------------------------------------------------------------------
echo "  [2/2] Injecting iptables ICMP DROP on $DEST_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Remove any existing demo rule to avoid duplicates
    iptables -D INPUT -p icmp -j DROP 2>/dev/null || true
    # Insert ICMP drop at position 1
    iptables -I INPUT 1 -p icmp -j DROP
    echo \"[OK] iptables DROP rule inserted for ICMP\"
    iptables -L INPUT -n -v --line-numbers | head -6
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Both faults injected:"
echo "       Fault 1: tc tbf rate ${RATE} on $SOURCE_VM_NAME — stable throttle on all data traffic"
echo "                pipe_meter will show is_stable=True but throughput ≈ ${RATE} (5x below baseline)."
echo "                NSG audit shows clean — completely invisible to Azure control plane."
echo "       Fault 2: iptables ICMP DROP on $DEST_VM_NAME — ping fails"
echo "                This is a RED HERRING. Unrelated to TCP throughput."
echo "                Ghost Agent must report BOTH as separate independent findings."
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
echo "  1. NSG check → clean (ICMP not blocked at Azure level)"
echo "  2. pipe_meter throughput → is_stable=True, ~0.005 Gbps (5 Mbps)"
echo "  3. Absolute value reasoning: 5 Mbps << Azure VNet multi-Gbps baseline"
echo "  4. tc qdisc show on source VM → tbf rate=${RATE} found (Fault 1)"
echo "  5. iptables -L INPUT on dest VM → ICMP DROP found (Fault 2)"
echo "  KEY MOMENT: Ghost Agent correctly separates two independent OS-level faults."
echo "==================================================="
