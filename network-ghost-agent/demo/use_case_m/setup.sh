#!/usr/bin/env bash
# =============================================================================
# Use Case M — "The Banned Guest": Setup
#
# Scenario:
#   A partner service at IP 203.0.113.47 (RFC5737 TEST-NET-3) cannot connect
#   to tf-dest-vm on port 22. Azure NSG shows SSH inbound allowed. The portal
#   shows the VM healthy. Nothing in Azure explains the failure.
#
# Fault injected:
#   Simulates an active fail2ban ban by creating the f2b-sshd chain and
#   inserting a REJECT rule for the partner IP, then jumping to it from INPUT.
#   This is structurally identical to what fail2ban creates at runtime.
#
# Detection path (Ghost Agent):
#   1. NSG audit → SSH port 22 allowed (control-plane shows nothing wrong)
#   2. detect_config_drift(is_baseline=True, explain=True) → captures live
#      iptables state and runs --explain
#   3. --explain surfaces: f2b-sshd chain recognised as fail2ban chain,
#      active /32 ban on 203.0.113.47, RETURN → falls to DROP policy
#   KEY MOMENT: OS-layer explanation that Azure has no visibility into.
#
# Teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

BANNED_IP="203.0.113.47"   # RFC5737 TEST-NET-3 — safe for demos/docs

echo ""
echo "==================================================="
echo "  Use Case M — Setup: The Banned Guest"
echo "  Fault: fail2ban-style ban on $DEST_VM_NAME"
echo "  Banned IP: $BANNED_IP (RFC5737 TEST-NET-3)"
echo "==================================================="
echo ""

echo "  [1/1] Injecting fail2ban-style f2b-sshd chain on $DEST_VM_NAME ..."
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Remove any existing demo chain to avoid duplicates
    iptables -D INPUT -j f2b-sshd 2>/dev/null || true
    iptables -F f2b-sshd          2>/dev/null || true
    iptables -X f2b-sshd          2>/dev/null || true

    # Create f2b-sshd chain — mirrors what fail2ban creates at runtime
    iptables -N f2b-sshd

    # Insert ban: REJECT for the partner IP
    iptables -A f2b-sshd -s ${BANNED_IP}/32 -j REJECT --reject-with icmp-port-unreachable

    # RETURN at end of chain — unmatched packets fall back to INPUT policy (ACCEPT)
    iptables -A f2b-sshd -j RETURN

    # Jump to f2b-sshd from INPUT — no port filter, matches real fail2ban behaviour.
    # fail2ban sends all INPUT traffic through the ban chain; the chain itself
    # contains source-IP rules, so only the banned IP is affected.
    iptables -I INPUT 1 -j f2b-sshd

    echo '[OK] f2b-sshd chain created with active ban'
    iptables -L f2b-sshd -n -v --line-numbers
  " \
  --query "value[0].message" -o tsv

echo ""
echo "==================================================="
echo "  Fault injected."
echo "  Azure NSG: SSH (port 22) ALLOWED on $DEST_VM_NAME"
echo "  OS layer:  $BANNED_IP/32 REJECTED via f2b-sshd"
echo "==================================================="
echo ""
echo "  WHAT TO TELL THE AUDIENCE:"
echo "  Our partner service at $BANNED_IP cannot SSH into"
echo "  $DEST_VM_NAME. Azure shows port 22 is open. The VM"
echo "  is healthy. No recent NSG changes. Investigate."
echo ""
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: uv run --python 3.12 python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. NSG audit → port 22 ALLOWED (misleading clean result)"
echo "  2. detect_config_drift(is_baseline=True, explain=True)"
echo "     → captures live iptables state, runs --explain"
echo "  3. --explain output surfaces:"
echo "       f2b-sshd recognised as fail2ban chain"
echo "       1 active ban: $BANNED_IP/32 → REJECT"
echo "       RETURN → falls to INPUT DROP policy"
echo "  KEY MOMENT: Azure blind spot closed by OS-layer explain."
echo "==================================================="
echo ""
