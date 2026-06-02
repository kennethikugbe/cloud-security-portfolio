# Stage 4, Task 1: Azure Key Vault & Managed Identity
# ISO 27001: A.10.1 (Cryptographic controls), A.8.5 (Secure authentication)

data "azurerm_client_config" "current" {}

locals {
  kv_name = "${var.prefix}-kv-${random_id.suffix.hex}"
}

resource "azurerm_key_vault" "main" {
  name                        = local.kv_name
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  enable_rbac_authorization   = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = [var.allowed_ssh_cidr]
    virtual_network_subnet_ids = [azurerm_subnet.main.id]
  }

  tags = {
    Environment = "SecurityLab"
    ISO27001    = "A.10.1,A.8.20"
  }
}

resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_user_assigned_identity" "vm" {
  name                = "${var.prefix}-vm-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = "SecurityLab"
    ISO27001    = "A.8.5"
  }
}

resource "azurerm_role_assignment" "vm_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.vm.principal_id
}

resource "azurerm_key_vault_secret" "ssh_public_key" {
  name         = "azure-lab-ssh-public-key"
  value        = file(pathexpand("~/.ssh/id_rsa_azure_lab.pub"))
  key_vault_id = azurerm_key_vault.main.id

  tags = {
    Purpose  = "VM-SSH-Authentication"
    ISO27001 = "A.10.1"
  }

  depends_on = [azurerm_role_assignment.kv_admin]
}
