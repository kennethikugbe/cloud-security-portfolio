# Stage 2: Infrastructure as Code — Azure Security Baseline

## Author
Kenneth | Cloud Security & DevSecOps Engineer | ISO 27001 Lead Auditor

## Files
| File | Purpose |
|------|---------|
| `providers.tf` | Provider declaration and version pinning |
| `variables.tf` | Parameterized inputs for reuse |
| `main.tf` | Resource Group + encrypted Storage Account for remote state |
| `outputs.tf` | Exported identifiers for downstream automation |
| `backend.tf` | Empty backend block (config injected by init-backend.sh) |
| `init-backend.sh` | Dynamic backend initialization from terraform.tfstate |
| `.gitignore` | Excludes state files, cache, plan files |
| `network.tf` | Virtual Network, Subnet, NSG, Public IP, NIC (Phase 3) |
| `compute.tf` | Hardened Linux VM with SSH key auth + cloud-init (Phase 3) |
| `cloud-init.yaml` | CIS-hardening bootstrap applied at first boot |

## Deployment
```bash
# Phase 1: Bootstrap
terraform init
terraform plan -out bootstrap.plan -var="allowed_ssh_cidr=<YOUR_IP>/32"
terraform apply bootstrap.plan

# Phase 2: Migrate state
./init-backend.sh -migrate-state

# Phase 3: Deploy network + VM
terraform plan -out phase3.plan -var="allowed_ssh_cidr=<YOUR_IP>/32"
terraform apply phase3.plan
