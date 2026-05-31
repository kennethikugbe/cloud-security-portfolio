#!/bin/bash
# Dynamic Terraform backend initialization
# Extracts resource identifiers from terraform.tfstate via jq
# Fallback: reads directly from resources[] if outputs{} is empty
# Zero hardcoded Azure identifiers. Kenneth - Cloud Security Apprentice

set -euo pipefail

STATE_FILE="${INIT_STATE_FILE:-terraform.tfstate}"

if [[ ! -f "$STATE_FILE" ]]; then
  printf '%s\n' "[!] State file not found: $STATE_FILE" >&2
  printf '%s\n' "    Run 'terraform apply' first to create the bootstrap resources." >&2
  exit 1
fi

printf '%s\n' "[*] Reading state file: $STATE_FILE"

# --- Extraction strategy: outputs first, resources as fallback ---
RG_NAME=$(jq -r '.outputs.resource_group_name.value // empty' "$STATE_FILE")
SA_NAME=$(jq -r '.outputs.storage_account_name.value // empty' "$STATE_FILE")

# If outputs are empty (common after failed migration attempts), extract from resources
if [[ -z "$RG_NAME" ]]; then
  printf '%s\n' "[*] Outputs empty. Extracting Resource Group from resources[]..."
  RG_NAME=$(jq -r '.resources[] | select(.type == "azurerm_resource_group" and .name == "main") | .instances[0].attributes.name' "$STATE_FILE")
fi

if [[ -z "$SA_NAME" ]]; then
  printf '%s\n' "[*] Outputs empty. Extracting Storage Account from resources[]..."
  SA_NAME=$(jq -r '.resources[] | select(.type == "azurerm_storage_account" and .name == "tfstate") | .instances[0].attributes.name' "$STATE_FILE")
fi

if [[ -z "$RG_NAME" || "$RG_NAME" == "null" ]]; then
  printf '%s\n' "[!] Failed to extract resource_group_name from state" >&2
  exit 1
fi

if [[ -z "$SA_NAME" || "$SA_NAME" == "null" ]]; then
  printf '%s\n' "[!] Failed to extract storage_account_name from state" >&2
  exit 1
fi

printf '%s\n' "[*] Resource Group:  $RG_NAME"
printf '%s\n' "[*] Storage Account: $SA_NAME"

# Clean up any stale hardcoded backend config
rm -f backend.hcl

printf '%s\n' "[*] Initializing Terraform backend with dynamic configuration..."

terraform init \
  -backend-config="resource_group_name=$RG_NAME" \
  -backend-config="storage_account_name=$SA_NAME" \
  -backend-config="container_name=terraform-state" \
  -backend-config="key=stage2.tfstate" \
  -backend-config="use_azuread_auth=true" \
  "$@"
