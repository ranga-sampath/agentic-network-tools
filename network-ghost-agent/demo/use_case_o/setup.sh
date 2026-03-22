#!/usr/bin/env bash
# =============================================================================
# Use Case O — "The Docker Coup": Setup
#
# Scenario:
#   Services on tf-dest-vm stop routing correctly after the platform team
#   upgraded and restarted the Docker daemon. Azure NSG is unchanged. The
#   change window baseline was captured before the daemon restart.
#
# Fault injected (two steps):
#   Step 1 — Flush Docker iptables chains (simulate pre-restart clean state),
#             then capture the baseline.
#   Step 2 — Restart Docker daemon, which rewrites its full chain set:
#             DOCKER, DOCKER-USER, DOCKER-ISOLATION-STAGE-1/2 in FILTER,
#             DOCKER and MASQUERADE rules in NAT. 12+ rules added.
#
# If Docker is not installed on the VM, the script falls back to manually
# injecting representative Docker-style chains for the demo.
#
# Detection path (Ghost Agent):
#   1. NSG audit → unchanged (control-plane blind to Docker chains)
#   2. detect_config_drift(compare_session_id=<baseline>, explain=True)
#      → diffs current state vs pre-Docker baseline
#      → --explain-diff surfaces new DOCKER-* chains, flags
#        DOCKER-ISOLATION-STAGE-2 drops inter-bridge traffic
#   KEY MOMENT: Daemon restart silently rewrites OS firewall — invisible from
#               Azure control plane, visible via --explain-diff.
#
# Teardown: ./teardown.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
FI_PATH="${REPO_ROOT}/netfilter-inspector/firewall-inspector/firewall_inspector.py"
AUDIT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/audit"
BASELINE_ID_FILE="${SCRIPT_DIR}/.baseline_session_id"

echo ""
echo "==================================================="
echo "  Use Case O — Setup: The Docker Coup"
echo "  Step 1: Flush Docker chains + capture baseline"
echo "  Step 2: Restart Docker (or inject Docker-style chains)"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Idempotency guard — prevent re-running without teardown first.
# If re-run while Docker chains are already present, the baseline would
# capture the faulted state, making the diff empty and the demo useless.
# ---------------------------------------------------------------------------
if [[ -f "$BASELINE_ID_FILE" ]]; then
  echo "[ERROR] Baseline already captured (session: $(cat "$BASELINE_ID_FILE"))."
  echo "        Run teardown.sh first before re-running setup."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Flush Docker chains to simulate pre-restart state, then baseline
# Note: This temporarily stops Docker networking on $DEST_VM_NAME.
#       Ensure no production containers are relying on Docker networking
#       before running this script.
# ---------------------------------------------------------------------------
echo "  [1/2] Stopping Docker and capturing clean baseline on $DEST_VM_NAME ..."
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Stop Docker daemon first — prevents it from recreating chains during cleanup.
    # If we only flush chains while Docker is running it recreates them within seconds,
    # making the baseline dirty (race condition).
    if systemctl is-active --quiet docker 2>/dev/null; then
      echo '[docker] Docker daemon is running — stopping before baseline ...'
      systemctl stop docker
      sleep 2
      echo '[docker] Daemon stopped'
    else
      echo '[docker] Docker daemon not active as a service — no stop needed'
    fi

    # Flush any remaining chains (defensive — docker stop should remove them)
    for chain in DOCKER DOCKER-USER DOCKER-ISOLATION-STAGE-1 DOCKER-ISOLATION-STAGE-2; do
      iptables -F \$chain 2>/dev/null || true
      iptables -X \$chain 2>/dev/null || true
    done
    iptables -t nat -F DOCKER 2>/dev/null || true
    iptables -t nat -X DOCKER 2>/dev/null || true

    echo '[OK] Docker chains cleared — clean state ready for baseline'
    echo 'FORWARD chain (should have no DOCKER references):'
    iptables -L FORWARD -n --line-numbers | head -6
  " \
  --query "value[0].message" -o tsv

echo ""
echo "  [1/2] Capturing baseline in clean (Docker stopped) state ..."

TMP_CONFIG=$(mktemp /tmp/fw_baseline_XXXXXX.env)
cat > "$TMP_CONFIG" <<EOF
PROVIDER=azure
VM_NAME=${FW_VM_NAME:-$DEST_VM_NAME}
RESOURCE_GROUP=${RESOURCE_GROUP}
AUDIT_DIR=${AUDIT_DIR}
FAMILY=both
SSH_USER=${SSH_USER:-azureuser}
EOF

BASELINE_OUTPUT=$(python3 "$FI_PATH" --config "$TMP_CONFIG" --is-baseline 2>&1)
echo "$BASELINE_OUTPUT"
rm -f "$TMP_CONFIG"

SNAP_PATH=$(echo "$BASELINE_OUTPUT" | grep "Baseline saved:" | awk '{print $NF}')
BASELINE_SESSION_ID=$(basename "$SNAP_PATH" "_snapshot.json")

if [[ -z "$BASELINE_SESSION_ID" ]]; then
  echo "[ERROR] Could not extract baseline session_id. Check Azure credentials and VM state."
  exit 1
fi

echo "$BASELINE_SESSION_ID" > "$BASELINE_ID_FILE"
echo ""
echo "  [OK] Baseline captured: session_id = $BASELINE_SESSION_ID"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Restart Docker daemon (or inject Docker-style chains if not installed)
# ---------------------------------------------------------------------------
echo "  [2/2] Starting Docker daemon on $DEST_VM_NAME (adds chains to iptables) ..."
echo "        (or injecting representative Docker chains if Docker not installed)"
echo "        (az vm run-command in progress — typically 30–60 s) ..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    if systemctl is-active --quiet docker 2>/dev/null; then
      echo '[docker] Docker daemon is active — restarting to re-inject chains ...'
      systemctl restart docker
      sleep 5  # Give Docker time to add all its chains
      echo '[OK] Docker daemon restarted'
      echo 'FORWARD chain (Docker chains now present):'
      iptables -L FORWARD -n --line-numbers | head -12
      echo 'User-defined chains:'
      iptables -L -n | grep '^Chain DOCKER' | head -6

    else
      echo '[docker] Docker not running as a service — injecting representative Docker-style chains ...'

      # filter table: create chains
      iptables -N DOCKER                   2>/dev/null || true
      iptables -N DOCKER-USER              2>/dev/null || true
      iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
      iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true

      # filter table: FORWARD rules
      iptables -I FORWARD 1 -j DOCKER-USER
      iptables -I FORWARD 2 -j DOCKER-ISOLATION-STAGE-1
      iptables -A FORWARD -j DOCKER
      iptables -A FORWARD -j ACCEPT

      # filter table: chain contents
      iptables -A DOCKER-ISOLATION-STAGE-1 -j DOCKER-ISOLATION-STAGE-2
      iptables -A DOCKER-ISOLATION-STAGE-1 -j RETURN
      iptables -A DOCKER-ISOLATION-STAGE-2 -j DROP
      iptables -A DOCKER-ISOLATION-STAGE-2 -j RETURN
      iptables -A DOCKER-USER -j RETURN

      # nat table: create chain and rules
      iptables -t nat -N DOCKER 2>/dev/null || true
      iptables -t nat -A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE
      iptables -t nat -A DOCKER -j RETURN

      echo '[OK] Docker-style chains injected (filter + nat tables)'
      echo 'FORWARD chain:'
      iptables -L FORWARD -n --line-numbers | head -12
      echo 'User-defined chains:'
      iptables -L -n | grep '^Chain DOCKER' | head -6
    fi
  " \
  --query "value[0].message" -o tsv

# Write PROMPT.txt with actual session_id embedded
cat > "${SCRIPT_DIR}/PROMPT.txt" <<EOF
Services on tf-dest-vm stopped routing correctly after the platform team upgraded and restarted the Docker daemon earlier today. Container networking appears broken and some inter-service calls are failing. The Azure NSG is unchanged. A firewall baseline was captured before the Docker daemon restart with session ID: ${BASELINE_SESSION_ID}. Investigate what changed at the OS firewall layer and what the traffic impact is, in resource group nw-forensics-rg.
EOF

echo ""
echo "==================================================="
echo "  Both steps complete."
echo "  Baseline session ID: $BASELINE_SESSION_ID"
echo "  Docker chains:       injected (DOCKER, DOCKER-USER,"
echo "                       DOCKER-ISOLATION-STAGE-1/2)"
echo "  Azure NSG:           unchanged"
echo "==================================================="
echo ""
echo "  PROMPT (also written to PROMPT.txt):"
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Run: uv run --python 3.12 python ghost_agent.py --config demo/config.env"
echo "  Then type the prompt above."
echo "==================================================="
echo ""
echo "  PRESENTER NOTE — expected investigation path:"
echo "  1. NSG audit → unchanged (control-plane blind to Docker chains)"
echo "  2. detect_config_drift(compare_session_id=$BASELINE_SESSION_ID, explain=True)"
echo "     → diffs current vs pre-Docker baseline"
echo "  3. --explain-diff surfaces:"
echo "       4 new user-defined chains (DOCKER, DOCKER-USER,"
echo "         DOCKER-ISOLATION-STAGE-1, DOCKER-ISOLATION-STAGE-2)"
echo "       6 new FORWARD rules + 4 NAT rules"
echo "       DOCKER-ISOLATION-STAGE-2 drops inter-bridge traffic"
echo "  KEY MOMENT: Daemon restart silently rewrites iptables —"
echo "              invisible from Azure, visible via explain-diff."
echo "==================================================="
echo ""
