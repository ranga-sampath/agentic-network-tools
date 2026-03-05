#!/usr/bin/env bash
# =============================================================================
# Use Case J — "The Shadow Firewall": Setup
#
# Injects TWO independent faults:
#
# Fault 1 — OS-level firewall on DEST VM (iptables):
#   Adds an iptables DROP rule for TCP port 5001 inbound on tf-dest-vm.
#   Azure NSG still shows port 5001 allowed — the block is invisible to
#   all Azure control-plane tools. The only way to find it:
#     (a) packet capture shows SYNs arriving at dest with no SYN-ACK, or
#     (b) az vm run-command invoke iptables -L INPUT
#
# Fault 2 — OS-level latency on SOURCE VM (tc netem):
#   Adds 30ms delay on all non-SSH outbound traffic from source VM.
#   This appears as a secondary latency finding once connectivity is restored.
#
# Why this is a WOW scenario:
#   Engineers learn early to check NSG rules. "Port 5001 is open" looks like
#   proof the network is fine. But iptables is a completely separate OS-level
#   firewall stack that Azure control plane knows nothing about.
#   Ghost Agent must cross the Azure→OS boundary, use packet capture as
#   forensic evidence that packets ARE arriving (ruling out NSG/routing),
#   and then inspect the OS firewall directly.
#
# Detection path (no system prompt changes needed — LLM reasons from evidence):
#   1. run_pipe_meter → CONNECTIVITY_DROP
#   2. NSG audit → port 5001 allowed (misleading)
#   3. capture_traffic on dest VM → SYNs arrive but no SYN-ACK → OS drop
#   4. az vm run-command invoke iptables -L INPUT → finds DROP rule
#   5. az vm run-command invoke tc qdisc show on source → finds netem delay
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

DELAY="30ms"

echo ""
echo "==================================================="
echo "  Use Case J — Setup: The Shadow Firewall"
echo "  Fault 1:  iptables DROP port 5001 on $DEST_VM_NAME"
echo "  Fault 2:  tc netem delay $DELAY on $SOURCE_VM_NAME (SSH exempt)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Fault 1: iptables DROP rule on DEST VM
# ---------------------------------------------------------------------------
echo "  [1/2] Injecting iptables DROP rule on $DEST_VM_NAME ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Remove any existing demo rule to avoid duplicates
    iptables -D INPUT -p tcp --dport 5001 -j DROP 2>/dev/null || true
    # Insert at position 1 (highest priority) — blocks iperf before any app sees it
    iptables -I INPUT 1 -p tcp --dport 5001 -j DROP
    echo \"[OK] iptables DROP rule inserted for TCP port 5001\"
    iptables -L INPUT -n -v --line-numbers | head -8
  " \
  --query "value[0].message" -o tsv

# ---------------------------------------------------------------------------
# Fault 2: tc netem delay on SOURCE VM (SSH exempt via prio filter)
# ---------------------------------------------------------------------------
echo "  [2/2] Injecting tc netem delay on $SOURCE_VM_NAME (SSH port 22 exempt) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SOURCE_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    IFACE=\$(ip route show default | awk '{print \$5}' | head -1)
    tc qdisc del dev \$IFACE root 2>/dev/null || true
    # prio root: 3 bands. Band 1 = bypass (SSH). Band 3 = through netem.
    tc qdisc add dev \$IFACE root handle 1: prio bands 3
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem delay ${DELAY}
    # SSH exempt
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through netem)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+netem applied on \$IFACE: SSH exempt, all other traffic delay=${DELAY}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Both faults injected:"
echo "       Fault 1: iptables DROP port 5001 on $DEST_VM_NAME"
echo "                Azure NSG still shows port 5001 allowed — invisible to control plane."
echo "       Fault 2: tc netem delay ${DELAY} on $SOURCE_VM_NAME (SSH exempt)"
echo "                Adds latency once connectivity issue is resolved."
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
echo "  1. pipe_meter → CONNECTIVITY_DROP"
echo "  2. NSG audit → port 5001 ALLOWED (misleading clean result)"
echo "  3. Packet capture on dest VM → SYNs arrive, NO SYN-ACK (OS-level drop)"
echo "  4. az vm run-command iptables -L INPUT → DROP rule found"
echo "  5. az vm run-command tc qdisc show on source → netem delay found"
echo "  KEY MOMENT: Ghost Agent crosses Azure→OS boundary using PCAP evidence."
echo "==================================================="
