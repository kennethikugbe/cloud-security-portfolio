# Stage 3: DevSecOps Engineering — Container Security

## Author
Kenneth | Cloud Security & DevSecOps Engineer | ISO 27001 Lead Auditor

## Overview
Hardened container image for security auditing with automated vulnerability scanning via Trivy. Demonstrates container-level least privilege, minimal attack surface, and scan-to-remediate workflow.

## Files
| File | Purpose |
|------|---------|
| `Dockerfile` | Hardened image: Ubuntu 22.04, non-root user, minimal packages, explicit CVE patching |
| `scripts/container_audit.sh` | Container-native security audit (no systemd dependencies) |
| `.dockerignore` | Prevents secrets and build artifacts from entering image layers |
| `trivy-report.sarif` | SARIF vulnerability report (zero HIGH/CRITICAL findings) |

## Security Controls
| Control | Implementation | ISO 27001 |
|---------|---------------|-----------|
| Non-root execution | `USER auditor` (UID 10001) | A.8.1 |
| Minimal packages | `--no-install-recommends` + explicit package list | A.8.9 |
| CVE patching | `apt-get upgrade -y` + `autoremove` + `clean` | A.8.8 |
| Vulnerability scanning | Trivy HIGH/CRITICAL with `--exit-code 1` | A.8.8 |
| SARIF evidence | `--format sarif --output trivy-report.sarif` | A.5.35 |
| Build context hygiene | `.dockerignore` excludes `.git`, `*.tfstate`, `.ssh` | A.8.1 |

## Scan Results
