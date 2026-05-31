#!/bin/bash
# Stage 1, Task 1: Host Security Audit
# Kenneth - Cloud Security Apprentice
# Generates a Markdown audit report for Linux host review

set -euo pipefail

# --- Configuration ---
REPORT_DIR="$HOME/security-lab/stage1/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/audit_${TIMESTAMP}.md"
HOSTNAME=$(hostname)
OS_INFO=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown")

mkdir -p "$REPORT_DIR"

# --- Functions ---

write_header() {
  cat << EOL > "$REPORT_FILE"
# Host Security Audit Report

| Field | Value |
|-------|-------|
| **Host** | ${HOSTNAME} |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **OS** | ${OS_INFO} |
| **Auditor** | Kenneth |

> This report was generated automatically by a custom audit script.
> Mapped to ISO 27001 controls: A.5.18 (Information security roles), A.8.1 (User endpoint devices), A.8.5 (Secure authentication).

---
EOL
}

audit_system() {
  printf '%s\n' "" "## 1. System Information" "" >> "$REPORT_FILE"
  printf '%s\n' "- **Kernel:** $(uname -r)" >> "$REPORT_FILE"
  printf '%s\n' "- **Uptime:** $(uptime -p 2>/dev/null || uptime)" >> "$REPORT_FILE"
  printf '%s\n' "- **Active Sessions:** $(who | wc -l)" >> "$REPORT_FILE"
}

audit_users() {
  printf '%s\n' "" "## 2. Privileged User Audit" "" >> "$REPORT_FILE"

  printf '%s\n' "### Users with UID 0 (root access)" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE" || true
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '\n' >> "$REPORT_FILE"

  printf '%s\n' "### Sudo Group Members" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  getent group sudo 2>/dev/null | cut -d: -f4 >> "$REPORT_FILE" || printf '%s\n' "N/A" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '\n' >> "$REPORT_FILE"
}

audit_network() {
  printf '%s\n' "" "## 3. Network Exposure" "" >> "$REPORT_FILE"
  printf '%s\n' "### Listening Ports (TCP/UDP)" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  ss -tulnp 2>/dev/null >> "$REPORT_FILE" || netstat -tulnp 2>/dev/null >> "$REPORT_FILE" || printf '%s\n' "ss/netstat unavailable" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '\n' >> "$REPORT_FILE"
}

audit_logins() {
  printf '%s\n' "" "## 4. Failed Authentication (SSH, last 24h)" "" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  if command -v journalctl &> /dev/null; then
    journalctl _COMM=sshd --since "24 hours ago" 2>/dev/null | grep "Failed password" >> "$REPORT_FILE" || printf '%s\n' "No failures logged or insufficient permissions." >> "$REPORT_FILE"
  else
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -n 20 >> "$REPORT_FILE" || printf '%s\n' "Auth log not accessible." >> "$REPORT_FILE"
  fi
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '\n' >> "$REPORT_FILE"
}

audit_files() {
  printf '%s\n' "" "## 5. File Permission Risks" "" >> "$REPORT_FILE"
  printf '%s\n' "### World-Writable Files in /etc, /tmp, /var/tmp" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
  find /etc /tmp /var/tmp -xdev -type f -perm -002 2>/dev/null >> "$REPORT_FILE" || true
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '\n' >> "$REPORT_FILE"
  printf '%s\n' "> **Risk Note:** World-writable files in /etc indicate configuration tampering risk (ISO 27001 A.8.1)." >> "$REPORT_FILE"
}

# --- Main Execution ---
echo "[*] Starting host audit on ${HOSTNAME}..."
write_header
audit_system
audit_users
audit_network
audit_logins
audit_files

echo "[+] Audit complete."
echo "[*] Report location: ${REPORT_FILE}"
echo "---"
echo "[*] Preview (first 25 lines):"
head -n 25 "$REPORT_FILE"
