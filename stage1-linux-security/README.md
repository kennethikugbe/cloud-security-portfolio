# Stage 1: Linux Host Security & Hardening Automation

## Author
Kenneth | Cloud Security & DevSecOps Engineer | ISO 27001 Lead Auditor

## Overview
Production-ready security automation built from scratch on an Ubuntu VM. This directory contains four independent tools that form a complete host assessment and compliance evidence pipeline.

## Tools

### 1. `host_audit.sh`
Generates ISO 27001-aligned Markdown audit reports covering:
- Privileged user enumeration (A.5.18)
- Network exposure mapping (A.8.1)
- Failed authentication analysis (A.8.5)
- World-writable file detection

### 2. `host_hardening_audit.sh` (v1 — Archived)
Initial CIS benchmark audit with audit/remediate/apply modes. Deprecated after a live incident where `sed` in-place editing silently failed and truncated `/etc/ssh/sshd_config`. Retained as incident evidence and lesson documentation.

### 3. `host_hardening_audit_v2.sh` (Production)
Bulletproof audit and remediation:
- Audits via `sshd -T` (effective running configuration)
- Remediates via `/etc/ssh/sshd_config.d/99-hardening.conf` drop-in overrides
- Validates with `sshd -t` before restart
- Three modes: audit, remediate, apply

### 4. `network_scanner.sh`
Attack surface discovery:
- `nmap` top-1000 cross-referenced with `sudo ss` process ownership
- UFW rule validation per service
- Risk ranking: HIGH (listening+no-rule), LOW (allowed)
- Shadow listener detection for services outside scan range

### 5. `generate_risk_register.py`
Python compliance automation:
- Parses all Markdown reports into an ISO 27001-style risk register CSV
- Maps CIS references to ISO 27001:2022 controls
- `--latest` flag ingests only current state per report type
- Global sequential Entry IDs for audit traceability
- Skips PASS findings; registers only gaps and risks

## Incident & Lessons Learned

| Version | Incident | Root Cause | Fix |
|---------|----------|------------|-----|
| v1 | `sshd_config` truncated to 15 bytes | `sed` returns 0 on zero matches; no `sshd -t` validation; no backup | v2: `sshd -T` auditing, `sshd_config.d` drop-ins, `sshd -t` pre-restart |
| Python v1 | Duplicate Entry IDs | Counter scoped per-parser function | v1.1: Global counter reference across all parsers |

## Compliance Mapping
| Tool | Framework | Controls |
|------|-----------|----------|
| host_audit.sh | ISO 27001:2022 | A.5.18, A.8.1, A.8.5 |
| host_hardening_audit_v2.sh | CIS Ubuntu Benchmark | 3.5.x, 5.2.x |
| network_scanner.sh | ISO 27001:2022 | A.8.20, A.8.21, A.8.9 |
| generate_risk_register.py | ISO 27001:2022 | A.5.28, A.5.35 (Risk assessment) |

## Usage
```bash
./scripts/host_audit.sh
./scripts/host_hardening_audit_v2.sh
./scripts/network_scanner.sh
python3 scripts/generate_risk_register.py --latest

