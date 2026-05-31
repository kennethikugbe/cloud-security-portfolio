locals {
  sanitized_prefix = substr(lower(replace(var.prefix, "-", "")), 0, 14)
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location

  tags = {
    Environment = "SecurityLab"
    Owner       = "Kenneth"
    ManagedBy   = "Terraform"
    Purpose     = "CloudSecurityTraining"
    ISO27001    = "A.5.9,A.8.9"
  }
}

resource "azurerm_storage_account" "tfstate" {
  name                     = "${local.sanitized_prefix}tf${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
  }

  tags = {
    Purpose     = "TerraformRemoteState"
    Sensitivity = "High"
    ISO27001    = "A.12.3,A.10.1"
  }
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "terraform-state"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}
