# Cloud Security & DevSecOps Engineering Portfolio

**Author:** Kenneth | Cloud Security Engineer | DevSecOps Engineer | ISO 27001:2022 Lead Auditor

This repository documents a systematic, hands-on apprenticeship in Cloud Security Engineering and DevSecOps. Every tool, script, and infrastructure definition was built from scratch, executed in real environments, and committed with operational notes—including failures, recoveries, and architectural decisions.

> **Governance + Engineering:** This portfolio demonstrates the rare intersection of ISO 27001 control framework expertise and infrastructure-as-code automation. Security is not an afterthought; it is embedded in the build pipeline, the network architecture, and the compliance evidence.

---

## Repository Roadmap

| Stage | Focus | Status | Key Deliverables |
|-------|-------|--------|----------------|
| **1 — Linux Security Automation** | Bash scripting, CIS hardening, network scanning, Python compliance parsing | **Complete** | `host_audit.sh`, `host_hardening_audit_v2.sh`, `network_scanner.sh`, `generate_risk_register.py` |
| **2 — Infrastructure as Code (Azure)** | Terraform, remote state, network segmentation, cloud-init, VM hardening | **Complete** | Resource Group, VNet, NSG, encrypted remote backend, dynamic `init-backend.sh`, cloud-init YAML |
| **3 — DevSecOps & Container Security** | Docker hardening, Trivy scanning, GitHub Actions CI/CD, SAST/DAST gates | **Next** | Hardened container, security pipeline, automated compliance reports |
| **4 — Secure Cloud Architecture** | Azure security services, Key Vault, private endpoints, managed identities, Defender for Cloud | **Planned** | Hardened multi-tier architecture with ISO 27001 control mapping |
| **5 — Detection & Response** | Wazuh, MITRE ATT&CK mapping, incident response runbooks, log analysis | **Planned** | SIEM deployment, threat modelling, IR playbook |
| **6 — Capstone** | Integrated fictional company scenario: audit + infrastructure + pipeline + IR | **Planned** | End-to-end portfolio piece for hiring manager review |

---

## What Makes This Portfolio Different

| Typical Tutorial Portfolio | This Repository |
|---------------------------|-----------------|
| Copy-paste scripts from Medium articles | Every script written from scratch; debugged live against real system behavior |
| Green checkmarks only | Documents real failures: `sed` file truncation, Azure provider race-conditions, SKU capacity restrictions, DNS propagation delays |
| Theory without control mapping | Every resource and script mapped to ISO 27001:2022 controls (A.5.9, A.8.1, A.8.5, A.8.9, A.8.20, A.10.1, A.12.3) |
| Click-ops in cloud console | Zero portal clicks; 100% Terraform with version pinning, remote state, and automated backend initialization |
| Single environment | Cross-environment awareness: local Linux VM → Azure cloud → containerized CI/CD |

---

## Repository Structure

