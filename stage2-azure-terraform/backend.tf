terraform {
  backend "azurerm" {
    resource_group_name  = "kenneth-tfstate-rg"
    storage_account_name = "kennethlabtffbpct9wt"
    container_name       = "terraform-state"
    key                  = "stage2.tfstate"
    use_azuread_auth     = true
  }
}
