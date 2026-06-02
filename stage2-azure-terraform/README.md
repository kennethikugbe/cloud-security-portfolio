# Stage 2 & 4: Infrastructure as Code — Azure Security Baseline

## Author
Kenneth | Cloud Security & DevSecOps Engineer | ISO 27001 Lead Auditor

## Overview
Production-grade Terraform automation for deploying a hardened Azure environment with encrypted remote state, network segmentation, CIS-hardened compute via cloud-init, and Azure-native secrets management through Key Vault and Managed Identities.

**Operational Note:** All Azure resources were deployed live across multiple regions during development, then destroyed via cost governance after code validation. The Terraform definitions remain production-ready and deployable on any non-Free-Tier subscription.

## Repository Structure

| File | Purpose | ISO 27001 |
|------|---------|-----------|
| `providers.tf` | AzureRM provider, version pinning, `skip_provider_registration` | A.8.9 |
| `variables.tf` | Reusable parameterized inputs | A.8.9 |
| `main.tf` | Resource Group, encrypted Storage Account for state | A.5.9, A.10.1, A.12.3 |
| `network.tf` | VNet (10.0.0.0/16), subnet (10.0.1.0/24), NSG, public IP, NIC | A.8.20 |
| `compute.tf` | Ubuntu 22.04 VM with SSH key auth, cloud-init CIS hardening | A.8.1, A.8.5 |
| `keyvault.tf` | **Key Vault (RBAC, soft-delete, purge protection), Managed Identity, secret storage** | **A.10.1, A.8.5** |
| `cloud-init.yaml` | First-boot automation: UFW, SSH hardening, fail2ban | A.8.1 |
| `outputs.tf` | Exported identifiers for downstream automation | A.8.9 |
| `backend.tf` | Azure Blob backend configuration (CLI-bootstrapped) | A.10.1, A.12.3 |
| `init-backend.sh` | Dynamic backend initialization from `terraform.tfstate` via `jq` | A.8.9 |
| `.gitignore` | Excludes local state, plan files, backend configs | A.8.1 |

## Architecture Decisions

| Decision | Rationale | ISO 27001 |
|----------|-----------|-----------|
| Separate backend RG (`kenneth-tfstate-rg`) | Prevents `terraform destroy` from destroying its own state storage | A.12.3, A.10.1 |
| Dynamic backend init (`init-backend.sh`) | Zero hardcoded Azure identifiers in repository | A.8.9 |
| Remote state backend (Azure Blob) | Eliminates local plaintext state; SSE encrypted at rest | A.10.1, A.12.3 |
| Provider version pinning | Reproducible, auditable builds | A.8.9 |
| TLS 1.2 minimum / HTTPS-only | Prevents downgrade attacks on storage API | A.8.21 |
| Resource Group tagging | Asset inventory, ownership traceability | A.5.9 |
| NSG: SSH locked to engineer public IP | Least-privilege network access | A.8.20, A.8.5 |
| cloud-init hardening | Immutable first-boot security baseline | A.8.1, A.8.5 |
| `disable_password_authentication = true` | Enforces key-based auth | A.8.5 |
| **Key Vault RBAC authorization** | **Modern authorization model; audit-friendly access logging** | **A.10.1** |
| **Soft-delete + purge protection** | **Prevents accidental or ransomware-driven secret destruction** | **A.10.1, A.12.3** |
| **Network ACLs default deny** | **Key Vault accessible only from lab subnet + engineer public IP** | **A.8.20** |
| **User-assigned Managed Identity** | **Workload authentication without service principal secrets in code** | **A.8.5** |
| **SSH key in Key Vault** | **Centralized secret lifecycle; no keys committed to repositories** | **A.10.1** |

## Deployment Workflow

### Phase 1: Bootstrap Backend Storage (Azure CLI)
```bash
az group create --name kenneth-tfstate-rg --location eastus --tags Purpose=TfBackend Owner=Kenneth
az storage account create --name <UNIQUE> --resource-group kenneth-tfstate-rg --location eastus --sku Standard_LRS --min-tls-version TLS1_2 --allow-blob-public-access false
az storage container create --name terraform-state --account-name <UNIQUE> --auth-mode login
