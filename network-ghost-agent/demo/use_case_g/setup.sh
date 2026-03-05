#!/usr/bin/env bash
# =============================================================================
# Use Case G — "Bandwidth Heist": Setup
#
# Injects 50% random packet loss on the source VM's primary NIC via tc netem.
# 50% loss on a TCP connection forces constant retransmits; effective throughput
# collapses and becomes highly variable across iterations — producing a
# HIGH_VARIANCE or CONNECTIVITY_DROP anomaly in Agentic Pipe Meter.
#
# Why source VM, not dest VM:
#   iperf sends data FROM source TO dest. Throttling dest egress only affects
#   tiny ACK packets (< 20 Mbps). To throttle the data path, tc must be on
#   the sender (source VM) egress.
#
# Ghost Agent will:
#   1. Call run_pipe_meter(test_type="throughput") → HIGH_VARIANCE or CONNECTIVITY_DROP
#   2. Rule out NSG and routing hypotheses (both clean)
#   3. Find the active tc netem rule on source VM via az vm run-command
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

LOSS="20%"

echo ""
echo "==================================================="
echo "  Use Case G — Setup: Bandwidth Heist"
echo "  Target VM:  $SOURCE_VM_NAME  ($SOURCE_VM_PRIVATE_IP)"
echo "  Fault:      tc netem loss $LOSS"
echo "==================================================="
echo ""

echo "  Injecting tc netem $LOSS packet loss on $SOURCE_VM_NAME (SSH port 22 exempt) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    # Clear any existing root qdisc first
    tc qdisc del dev \$IFACE root 2>/dev/null || true
    # prio root: 3 bands.  Band 1 = bypass (SSH).  Band 3 = through netem.
    tc qdisc add dev \$IFACE root handle 1: prio bands 3
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem loss ${LOSS}
    # SSH exempt: both destination and source port 22 go to band 1 (no netem)
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through netem)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+netem applied on \$IFACE: SSH exempt, all other traffic loss=${LOSS}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Packet loss fault injected: 20% of outbound packets dropped"
echo "       TCP retransmits cause variable throughput degradation."
echo "       NSG rules unchanged — fault is OS-level, invisible to control plane."
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
