variable "prefix" {
  description = "Prefix for all Azure resources. Lowercase alphanumeric and hyphens only."
  type        = string
  default     = "kenneth-lab"
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "eastus"
}

variable "allowed_ssh_cidr" {
  description = "Public IP CIDR allowed for SSH inbound (format: x.x.x.x/32)"
  type        = string
}

variable "admin_username" {
  description = "Admin username for Linux VMs"
  type        = string
  default     = "kennethadmin"
}
