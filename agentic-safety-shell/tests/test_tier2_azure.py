"""Section 3 — Tier 2: Azure CLI Verb Rules.

Tests T2.01–T2.36. All P1 (SHOULD PASS).
"""

import pytest

from safe_exec_shell import CLASSIFICATION_RISKY, CLASSIFICATION_SAFE, classify


# ---------------------------------------------------------------------------
# T2.01–T2.11: Safe verbs (read-only)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("az vm list", id="T2.01"),
    pytest.param("az network nsg show --name web-nsg --resource-group prod-rg", id="T2.02"),
    pytest.param("az keyvault secret get --name dbpass --vault-name myvault", id="T2.03"),
    pytest.param("az network dns record-set check --name test --zone-name example.com", id="T2.04"),
    pytest.param("az group exists --name prod-rg", id="T2.05"),
    pytest.param("az vm wait --created --name web-01 --resource-group prod-rg", id="T2.06"),
    pytest.param("az network watcher show-topology --resource-group prod-rg", id="T2.07"),
    pytest.param("az network watcher show-next-hop --vm web-01 --resource-group prod-rg --dest-ip 10.0.0.5", id="T2.08"),
    pytest.param("az network watcher flow-log list --nsg web-nsg --resource-group prod-rg", id="T2.09"),
    pytest.param("az login", id="T2.10"),
    pytest.param("az account show", id="T2.11"),
])
def test_az_safe_verbs(command):
    classification, _, _ = classify(command)
    assert classification == CLASSIFICATION_SAFE, (
        f"Expected SAFE for '{command}', got {classification}"
    )


# ---------------------------------------------------------------------------
# T2.20–T2.36: Risky verbs (mutative)
# ---------------------------------------------------------------------------

@pytest.mark.p1
@pytest.mark.parametrize("command", [
    pytest.param("az vm create --name test-vm --resource-group dev-rg --image UbuntuLTS", id="T2.20"),
    pytest.param("az group delete --name dev-rg --yes", id="T2.21"),
    pytest.param("az vm update --name web-01 --resource-group prod-rg --set tags.env=staging", id="T2.22"),
    pytest.param("az network nsg rule set --name allow-ssh --nsg-name web-nsg --resource-group prod-rg", id="T2.23"),
    pytest.param("az network vnet subnet add --name backend --vnet-name main-vnet --resource-group prod-rg", id="T2.24"),
    pytest.param("az network nsg rule remove --name allow-ssh --nsg-name web-nsg --resource-group prod-rg", id="T2.25"),
    pytest.param("az vm start --name web-01 --resource-group prod-rg", id="T2.26"),
    pytest.param("az vm stop --resource-group prod --name web-01", id="T2.27"),
    pytest.param("az vm restart --name web-01 --resource-group prod-rg", id="T2.28"),
    pytest.param("az vm deallocate --name web-01 --resource-group prod-rg", id="T2.29"),
    pytest.param("az resource move --ids /subscriptions/abc/resourceGroups/src --destination-group dest", id="T2.30"),
    pytest.param("az network dns zone import --name example.com --resource-group dns-rg --file-name zone.txt", id="T2.31"),
    pytest.param("az network dns zone export --name example.com --resource-group dns-rg", id="T2.32"),
    pytest.param("az rest --method POST --url https://management.azure.com/foo", id="T2.33"),
    pytest.param("az rest --method GET --url https://management.azure.com/foo", id="T2.34"),
    pytest.param("az network watcher packet-capture create --vm web-01 --resource-group prod-rg", id="T2.35"),
    pytest.param("az network watcher flow-log create --nsg web-nsg --resource-group prod-rg", id="T2.36"),
])
def test_az_risky_verbs(command):
    classification, _, _ = classify(command)
    assert classification == CLASSIFICATION_RISKY, (
        f"Expected RISKY for '{command}', got {classification}"
    )
