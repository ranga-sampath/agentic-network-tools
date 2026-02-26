#!/usr/bin/env bash
# =============================================================================
# 00_prereqs.sh — Validate all prerequisites before running any demo use case
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

PASS=0; FAIL=0
ok()   { echo "  [OK]  $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; }

echo ""
echo "==================================================="
echo "  Ghost Agent Demo — Prerequisite Check"
echo "==================================================="
echo ""

# ---------------------------------------------------------------------------
# 1. config.env — required fields
# ---------------------------------------------------------------------------
echo "--- 1. config.env fields ---"
REQUIRED_VARS=(
  SUBSCRIPTION_ID RESOURCE_GROUP LOCATION
  VNET_NAME SUBNET_NAME
  SOURCE_VM_NAME SOURCE_VM_PUBLIC_IP SOURCE_VM_PRIVATE_IP
  DEST_VM_NAME DEST_VM_PRIVATE_IP
  DEST_VM_NSG_NAME
  STORAGE_ACCOUNT_NAME STORAGE_CONTAINER_NAME
  GEMINI_API_KEY
)
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    fail "$var is empty in config.env"
  else
    ok "$var is set"
  fi
done

# ---------------------------------------------------------------------------
# 2. az CLI login and correct subscription
# ---------------------------------------------------------------------------
echo ""
echo "--- 2. Azure CLI ---"
if ! az account show --query id -o tsv &>/dev/null; then
  fail "Not logged in to Azure CLI. Run: az login"
else
  CURRENT_SUB=$(az account show --query id -o tsv)
  if [[ "$CURRENT_SUB" != "$SUBSCRIPTION_ID" ]]; then
    warn "Active subscription ($CURRENT_SUB) differs from config ($SUBSCRIPTION_ID)"
    warn "Run: az account set --subscription $SUBSCRIPTION_ID"
  else
    ok "Azure CLI logged in, correct subscription"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Resource group exists
# ---------------------------------------------------------------------------
echo ""
echo "--- 3. Resource group ---"
if az group show -n "$RESOURCE_GROUP" --query id -o tsv &>/dev/null; then
  ok "Resource group '$RESOURCE_GROUP' exists"
else
  fail "Resource group '$RESOURCE_GROUP' not found"
fi

# ---------------------------------------------------------------------------
# 4. VMs exist and are running
# ---------------------------------------------------------------------------
echo ""
echo "--- 4. Virtual machines ---"
for VM in "$SOURCE_VM_NAME" "$DEST_VM_NAME"; do
  STATE=$(az vm show -g "$RESOURCE_GROUP" -n "$VM" \
            --query "powerState" -d -o tsv 2>/dev/null || echo "NOT_FOUND")
  if [[ "$STATE" == "VM running" ]]; then
    ok "VM '$VM' is running"
  elif [[ "$STATE" == "NOT_FOUND" ]]; then
    fail "VM '$VM' not found in resource group"
  else
    warn "VM '$VM' state: $STATE (expected 'VM running')"
  fi
done

# ---------------------------------------------------------------------------
# 5. Azure Network Watcher enabled in the region
# ---------------------------------------------------------------------------
echo ""
echo "--- 5. Azure Network Watcher ---"
# Network Watcher lives in NetworkWatcherRG with name NetworkWatcher_{location}
NW_STATE=$(az network watcher list \
             --query "[?location=='${LOCATION}'].provisioningState" \
             -o tsv 2>/dev/null || echo "")
if [[ "$NW_STATE" == "Succeeded" ]]; then
  ok "Network Watcher enabled in '$LOCATION'"
else
  fail "Network Watcher not found in '$LOCATION'. Enable with:"
  echo "       az network watcher configure --locations $LOCATION --enabled true -g NetworkWatcherRG"
fi

# Network Watcher extension on VMs
echo ""
echo "--- 5b. NetworkWatcherAgentLinux on VMs ---"
for VM in "$SOURCE_VM_NAME" "$DEST_VM_NAME"; do
  EXT=$(az vm extension show \
          -g "$RESOURCE_GROUP" --vm-name "$VM" \
          --name NetworkWatcherAgentLinux \
          --query "provisioningState" -o tsv 2>/dev/null || echo "NOT_FOUND")
  if [[ "$EXT" == "Succeeded" ]]; then
    ok "NetworkWatcherAgentLinux on '$VM'"
  else
    fail "NetworkWatcherAgentLinux missing on '$VM'. Install with:"
    echo "       az vm extension set -g $RESOURCE_GROUP --vm-name $VM \\"
    echo "         --name NetworkWatcherAgentLinux \\"
    echo "         --publisher Microsoft.Azure.NetworkWatcher --no-wait"
  fi
done

# ---------------------------------------------------------------------------
# 6. Storage account and container
# ---------------------------------------------------------------------------
echo ""
echo "--- 6. Storage ---"
SA_STATE=$(az storage account show \
             -n "$STORAGE_ACCOUNT_NAME" -g "$RESOURCE_GROUP" \
             --query "provisioningState" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [[ "$SA_STATE" == "Succeeded" ]]; then
  ok "Storage account '$STORAGE_ACCOUNT_NAME' exists"
else
  fail "Storage account '$STORAGE_ACCOUNT_NAME' not found"
fi

CONTAINER_EXISTS=$(az storage container exists \
                     --name "$STORAGE_CONTAINER_NAME" \
                     --account-name "$STORAGE_ACCOUNT_NAME" \
                     --auth-mode login \
                     --query "exists" -o tsv 2>/dev/null || echo "false")
if [[ "$CONTAINER_EXISTS" == "true" ]]; then
  ok "Storage container '$STORAGE_CONTAINER_NAME' exists"
else
  fail "Storage container '$STORAGE_CONTAINER_NAME' not found. Create with:"
  echo "       az storage container create -n $STORAGE_CONTAINER_NAME \\"
  echo "         --account-name $STORAGE_ACCOUNT_NAME --auth-mode login"
fi

# ---------------------------------------------------------------------------
# 7. GEMINI_API_KEY
# ---------------------------------------------------------------------------
echo ""
echo "--- 7. Gemini API key ---"
if [[ -n "${GEMINI_API_KEY:-}" ]]; then
  ok "GEMINI_API_KEY is set (${#GEMINI_API_KEY} chars)"
else
  fail "GEMINI_API_KEY is empty. Set it in config.env."
fi

# ---------------------------------------------------------------------------
# 8. Python and ghost_agent.py dependencies
# ---------------------------------------------------------------------------
echo ""
echo "--- 8. Python environment ---"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
if ! command -v "$PYTHON_BIN" &>/dev/null; then
  # Try uv python
  if command -v uv &>/dev/null; then
    ok "uv available — will run via: uv run --python 3.12 ghost_agent.py"
    PYTHON_BIN="uv_run"
  else
    fail "python3.12 not found and uv not available"
  fi
else
  ok "Python: $($PYTHON_BIN --version)"
fi

# Check google-genai is importable
if [[ "$PYTHON_BIN" != "uv_run" ]]; then
  if "$PYTHON_BIN" -c "import google.genai" 2>/dev/null; then
    ok "google-genai importable"
  else
    warn "google-genai not importable — run: uv sync (or pip install google-genai)"
  fi
fi

# ---------------------------------------------------------------------------
# 9. SSH key
# ---------------------------------------------------------------------------
echo ""
echo "--- 9. SSH key ---"
if [[ -f "$SSH_KEY_PATH" ]]; then
  PERMS=$(stat -f "%OLp" "$SSH_KEY_PATH" 2>/dev/null || stat -c "%a" "$SSH_KEY_PATH" 2>/dev/null)
  if [[ "$PERMS" == "400" || "$PERMS" == "600" ]]; then
    ok "SSH key found at $SSH_KEY_PATH (permissions: $PERMS)"
  else
    warn "SSH key found but permissions are $PERMS (recommend 400). Run: chmod 400 $SSH_KEY_PATH"
    PASS=$((PASS + 1))
  fi
else
  fail "SSH key not found at $SSH_KEY_PATH"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==================================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "==================================================="
if [[ $FAIL -gt 0 ]]; then
  echo "  Fix the failures above before running demos."
  exit 1
else
  echo "  All checks passed. Ready to run demos."
  exit 0
fi
