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
