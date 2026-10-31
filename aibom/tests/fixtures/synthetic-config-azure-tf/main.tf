resource "azurerm_key_vault" "vault" {
  name                = "vault"
  location            = "eastus"
  resource_group_name = "rg"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

resource "azurerm_storage_account" "logs" {
  name                     = "logsstore"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_linux_web_app" "app" {
  name                = "app"
  resource_group_name = "rg"
  location            = "eastus"
  service_plan_id     = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan"
  https_only          = true

  site_config {}
}
