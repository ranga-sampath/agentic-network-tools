#!/usr/bin/env bash
# =============================================================================
# Use Case I — "Packet Grinder": Setup
#
# Injects a combined tc netem rule on the source VM: 10% random packet loss +
# 10ms base latency + 2% packet corruption. This simulates a severely degraded
# physical link. Loss causes TCP retransmits (variable throughput); corruption
# forces TCP checksum failures and additional retransmits. Together they produce
# HIGH_VARIANCE or CONNECTIVITY_DROP anomalies in both latency and throughput.
#
# Why source VM, not dest VM:
#   iperf/qperf measurements are driven FROM source TO dest. Faults on source
#   egress directly affect the measured data path.
#
# Ghost Agent will:
#   1. Call run_pipe_meter(test_type="both") → HIGH_VARIANCE / CONNECTIVITY_DROP
#   2. Rule out NSG (no deny rules) and routing (no custom routes)
#   3. Discover the tc netem rule on source VM via az vm run-command
#   4. Identify the combined loss + corruption pattern as the root cause
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

LOSS="10%"
DELAY="10ms"
CORRUPT="2%"

echo ""
echo "==================================================="
echo "  Use Case I — Setup: Packet Grinder"
echo "  Target VM:  $SOURCE_VM_NAME  ($SOURCE_VM_PRIVATE_IP)"
echo "  Fault:      tc netem loss $LOSS delay $DELAY corrupt $CORRUPT"
echo "==================================================="
echo ""

echo "  Injecting tc netem packet-loss fault on $SOURCE_VM_NAME (SSH port 22 exempt) ..."
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
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem loss ${LOSS} delay ${DELAY} corrupt ${CORRUPT}
    # SSH exempt: both destination and source port 22 go to band 1 (no netem)
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through netem)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+netem applied on \$IFACE: SSH exempt, data traffic loss=${LOSS} delay=${DELAY} corrupt=${CORRUPT}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Packet fault injected:"
echo "       - $LOSS random packet loss (causes TCP retransmits, variable throughput)"
echo "       - $DELAY base latency (raises qperf tcp_lat baseline)"
echo "       - $CORRUPT packet corruption (triggers checksum failures + more retransmits)"
echo "       NSG and routing unchanged — simulates a degraded physical link."
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
