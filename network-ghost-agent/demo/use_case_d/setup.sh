#!/usr/bin/env bash
# =============================================================================
# Use Case D — "The Two-Headed Hydra": Setup
#
# Creates TWO independent NSG deny rules on the destination VM's NSG:
#   - ghost-demo-block-postgres  (priority 110)  blocks TCP port 5432
#   - ghost-demo-block-redis     (priority 150)  blocks TCP port 6379
#
# Different priorities simulate two engineers making changes at different times
# during a maintenance window. Ghost Agent must form 4 simultaneous hypotheses
# and confirm two independent misconfigurations, ruling out VNet-level routing
# and service availability issues.
#
# Audience: Senior Network Product Manager
# Duration: ~10 minutes (pure control-plane, no captures needed)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

POSTGRES_RULE="ghost-demo-block-postgres"
REDIS_RULE="ghost-demo-block-redis"
POSTGRES_PORT=5432
REDIS_PORT=6379
POSTGRES_PRIORITY=110
REDIS_PRIORITY=150

echo ""
echo "==================================================="
echo "  Use Case D — Setup: Dual NSG misconfiguration"
echo "  NSG:           $DEST_VM_NSG_NAME"
echo "  Rule 1:        $POSTGRES_RULE (priority $POSTGRES_PRIORITY, port $POSTGRES_PORT)"
echo "  Rule 2:        $REDIS_RULE (priority $REDIS_PRIORITY, port $REDIS_PORT)"
echo "  Effect:        PostgreSQL AND Redis both blocked from source VM"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Start service listeners on dest-vm (PostgreSQL + Redis simulation)
# Services must be listening so the agent can confirm H4 is FALSE (services up)
# ---------------------------------------------------------------------------
echo "  [1/3] Starting service listeners on dest-vm..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEST_VM_NAME" \
  --command-id RunShellScript \
  --scripts "
    # Kill any prior listeners on these ports
    fuser -k ${POSTGRES_PORT}/tcp 2>/dev/null || true
    fuser -k ${REDIS_PORT}/tcp 2>/dev/null || true

    # PostgreSQL simulator: accepts connections, responds with a minimal banner
    # Uses socat to listen on 5432 and echo a fake Postgres startup message
    which socat >/dev/null 2>&1 || apt-get install -y socat >/dev/null 2>&1 || true

    # Fallback: Python socket server that accepts and immediately closes (service is UP)
    nohup bash -c '
      timeout 1800 python3 - <<PYEOF
import socket, threading, time

def serve(port, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", port))
    s.listen(5)
    s.settimeout(1800)
    print(f\"{label} listener started on :{port}\", flush=True)
    deadline = time.time() + 1800
    while time.time() < deadline:
        try:
            conn, _ = s.accept()
            conn.send(f\"{label} ready\".encode())
            conn.close()
        except OSError:
            break
    s.close()

t1 = threading.Thread(target=serve, args=(${POSTGRES_PORT}, \"PostgreSQL\"), daemon=True)
t2 = threading.Thread(target=serve, args=(${REDIS_PORT}, \"Redis\"), daemon=True)
t1.start()
t2.start()
t1.join()
PYEOF
    ' &
    disown
    sleep 2
    ss -tlnp | grep -E \"${POSTGRES_PORT}|${REDIS_PORT}\" && echo 'Both listeners started OK' || echo 'WARNING: one or both listeners may not have started'
  " \
  --output none
echo "     Service listeners started on dest-vm (ports $POSTGRES_PORT, $REDIS_PORT)"

# ---------------------------------------------------------------------------
# Step 2: Create the two NSG deny rules (idempotent)
# ---------------------------------------------------------------------------
echo "  [2/3] Creating NSG deny rules..."

# PostgreSQL rule (priority 110 — simulates Engineer A's change)
EXISTING_PG=$(az network nsg rule show \
               -g "$RESOURCE_GROUP" \
               --nsg-name "$DEST_VM_NSG_NAME" \
               --name "$POSTGRES_RULE" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_PG" ]]; then
  echo "     Rule '$POSTGRES_RULE' already exists — skipping."
else
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$POSTGRES_RULE" \
    --priority "$POSTGRES_PRIORITY" \
    --direction Inbound \
    --access Deny \
    --protocol Tcp \
    --source-address-prefixes '*' \
    --source-port-ranges '*' \
    --destination-address-prefixes '*' \
    --destination-port-ranges "$POSTGRES_PORT" \
    --description "Ghost Agent demo: intentional block on PostgreSQL port $POSTGRES_PORT (Engineer A)" \
    --output none
  echo "     [OK] NSG rule created: $POSTGRES_RULE (priority $POSTGRES_PRIORITY)"
fi

# Redis rule (priority 150 — simulates Engineer B's change, different time)
EXISTING_RD=$(az network nsg rule show \
               -g "$RESOURCE_GROUP" \
               --nsg-name "$DEST_VM_NSG_NAME" \
               --name "$REDIS_RULE" \
               --query "name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_RD" ]]; then
  echo "     Rule '$REDIS_RULE' already exists — skipping."
else
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$DEST_VM_NSG_NAME" \
    --name "$REDIS_RULE" \
    --priority "$REDIS_PRIORITY" \
    --direction Inbound \
    --access Deny \
    --protocol Tcp \
    --source-address-prefixes '*' \
    --source-port-ranges '*' \
    --destination-address-prefixes '*' \
    --destination-port-ranges "$REDIS_PORT" \
    --description "Ghost Agent demo: intentional block on Redis port $REDIS_PORT (Engineer B)" \
    --output none
  echo "     [OK] NSG rule created: $REDIS_RULE (priority $REDIS_PRIORITY)"
fi

# ---------------------------------------------------------------------------
# Step 3: Confirm state
# ---------------------------------------------------------------------------
echo "  [3/3] Verifying NSG rules..."
az network nsg rule list \
  -g "$RESOURCE_GROUP" \
  --nsg-name "$DEST_VM_NSG_NAME" \
  --query "[?starts_with(name,'ghost-demo')].{Rule:name,Priority:priority,Access:access,Port:destinationPortRange}" \
  -o table 2>/dev/null || true

echo ""
echo "  [OK] Dual NSG misconfiguration in place."
echo "       Priority 110: $POSTGRES_RULE → Deny TCP $POSTGRES_PORT"
echo "       Priority 150: $REDIS_RULE → Deny TCP $REDIS_PORT"
echo ""
echo "  Allow ~30 seconds for NSG rules to propagate before running the demo."
echo ""
echo "==================================================="
echo "  WHAT TO TELL THE AUDIENCE:"
echo "==================================================="
cat "${SCRIPT_DIR}/PROMPT.txt"
echo ""
echo "  Then run ghost_agent.py and type the prompt above."
echo "  See demo/README.md for the full presenter's guide."
echo "==================================================="
