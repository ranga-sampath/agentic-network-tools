#!/usr/bin/env bash
# =============================================================================
# Use Case H — "Latency Landmine": Setup
#
# Injects tc netem with 100ms base delay AND 10% packet loss on the source
# VM's primary NIC (SSH port 22 exempt).
#
# Why delay + loss (not pure jitter):
#   qperf tcp_lat sends probes serially and reports the AVERAGE latency over
#   a ~2-second window.  Per-packet jitter averages out across ~20 probes,
#   so pure jitter produces stable iteration values → is_stable=True, no
#   anomaly.  Adding 10% loss means ~2 probes per iteration trigger TCP
#   retransmit timeouts (RTO ≈ 200-300 ms).  Retransmit count follows
#   Poisson(λ≈2), so iteration averages range from ~50ms (0 retransmits) to
#   ~100ms+ (6+ retransmits) — well above the 50% spread threshold →
#   HIGH_VARIANCE fires reliably.
#
# Why source VM, not dest VM:
#   qperf probes travel FROM source TO dest; delay/loss on source egress
#   is directly reflected in RTT measurements.
#
# Ghost Agent will:
#   1. Call run_pipe_meter(test_type="latency") → HIGH_VARIANCE on latency
#   2. Rule out NSG and routing hypotheses (both clean)
#   3. Find the active tc netem rule on source VM via az vm run-command
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

DELAY="100ms"
LOSS="10%"

echo ""
echo "==================================================="
echo "  Use Case H — Setup: Latency Landmine"
echo "  Target VM:  $SOURCE_VM_NAME  ($SOURCE_VM_PRIVATE_IP)"
echo "  Fault:      tc netem delay $DELAY loss $LOSS"
echo "==================================================="
echo ""

echo "  Injecting tc netem delay+loss fault on $SOURCE_VM_NAME (SSH port 22 exempt) ..."
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
    tc qdisc add dev \$IFACE parent 1:3 handle 30: netem delay ${DELAY} loss ${LOSS}
    # SSH exempt: both destination and source port 22 go to band 1 (no netem)
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip dport 22 0xffff flowid 1:1
    tc filter add dev \$IFACE parent 1: pref 10 protocol ip u32 match ip sport 22 0xffff flowid 1:1
    # Everything else → band 3 (through netem)
    tc filter add dev \$IFACE parent 1: pref 100 protocol ip u32 match u32 0 0 flowid 1:3
    echo \"[OK] prio+netem applied on \$IFACE: SSH exempt, data traffic delay=${DELAY} loss=${LOSS}\"
    tc qdisc show dev \$IFACE
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [OK] Latency fault injected: 100ms delay + 10% loss on outbound data packets."
echo "       TCP retransmit timeouts cause per-iteration latency variance → HIGH_VARIANCE."
echo "       NSG rules and routing unchanged — invisible to control-plane audits."
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
