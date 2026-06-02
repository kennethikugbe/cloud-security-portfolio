output "resource_group_name" {
  description = "Name of the created resource group"
  value       = azurerm_resource_group.main.name
}

output "storage_account_name" {
  description = "Globally unique storage account name for Terraform state"
  value       = azurerm_storage_account.tfstate.name
}

output "storage_container_name" {
  description = "Blob container name for state files"
  value       = azurerm_storage_container.tfstate.name
}

output "vm_public_ip_address" {
  description = "Public IP address of the Linux VM (Phase 3)"
  value       = length(azurerm_public_ip.main) > 0 ? azurerm_public_ip.main.ip_address : null
}

output "ssh_connection_string" {
  description = "SSH command to connect to the hardened VM (Phase 3)"
  value       = length(azurerm_public_ip.main) > 0 ? "ssh -i ~/.ssh/id_rsa_azure_lab ${var.admin_username}@${azurerm_public_ip.main.ip_address}" : null
}

# Stage 4 Outputs: Key Vault & Managed Identity
output "key_vault_name" {
  description = "Name of the Azure Key Vault (globally unique)"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "HTTPS endpoint for Key Vault API access"
  value       = azurerm_key_vault.main.vault_uri
}

output "managed_identity_id" {
  description = "Resource ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.vm.id
}

output "managed_identity_principal_id" {
  description = "Principal ID for RBAC role assignments"
  value       = azurerm_user_assigned_identity.vm.principal_id
}

output "managed_identity_client_id" {
  description = "Client ID for application authentication (no secrets needed)"
  value       = azurerm_user_assigned_identity.vm.client_id
}
