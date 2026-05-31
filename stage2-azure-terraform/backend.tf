terraform {
  backend "azurerm" {
    # All configuration injected dynamically by init-backend.sh
    # from terraform.tfstate outputs. Zero hardcoded identifiers.
  }
}
