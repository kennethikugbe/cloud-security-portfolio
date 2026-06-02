#!/bin/bash
# Stage 3, Task 1: Container Security Audit
# Kenneth - Cloud Security & DevSecOps Apprentice
# Designed for non-root execution inside minimal containers

set -euo pipefail

REPORT_DIR="/app/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/container_audit_${TIMESTAMP}.md"

mkdir -p "$REPORT_DIR"

write_header() {
  cat << EOL > "$REPORT_FILE"
# Container Security Audit Report

| Field | Value |
|-------|-------|
| **Container Hostname** | $(hostname) |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Running As** | $(id -un) (UID: $(id -u), GID: $(id -g)) |
| **Image** | ${IMAGE_NAME:-unknown} |
| **Auditor** | Kenneth |

> Executed inside a hardened container environment.
> Mapped to ISO 27001:2022: A.8.1 (User endpoint devices), A.8.9 (Configuration management).

---
EOL
}

audit_user_context() {
  printf '%s\n' "" "## 1. User Context & Privileges" "" >> "$REPORT_FILE"
  printf '%s\n' "- **UID:** $(id -u)" >> "$REPORT_FILE"
  printf '%s\n' "- **GID:** $(id -g)" >> "$REPORT_FILE"
  printf '%s\n' "- **Groups:** $(id -Gn)" >> "$REPORT_FILE"
  printf '%s\n' "- **Home:** $HOME" >> "$REPORT_FILE"
  if [[ "$(id -u)" -eq 0 ]]; then
    printf '%s\n' "- **WARNING:** Running as root inside container." >> "$REPORT_FILE"
  else
    printf '%s\n' "- **PASS:** Running as non-root user." >> "$REPORT_FILE"
  fi
}

audit_processes() {
  printf '%s\n' "" "## 2. Running Processes" "" '```' >> "$REPORT_FILE"
  ps aux 2>/dev/null | tail -n +2 | head -n 20 >> "$REPORT_FILE" || printf '%s\n' "ps unavailable" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
}

audit_network() {
  printf '%s\n' "" "## 3. Network Exposure (Container)" "" '```' >> "$REPORT_FILE"
  ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || printf '%s\n' "No listening sockets detected" >> "$REPORT_FILE"
  printf '%s\n' '```' >> "$REPORT_FILE"
}

audit_file_perms() {
  printf '%s\n' "" "## 4. World-Writable Files in /etc, /tmp, /var/tmp" "" '```' >> "$REPORT_FILE"
  find /etc /tmp /var/tmp -xdev -type f -perm -002 2>/dev/null >> "$REPORT_FILE" || true
  printf '%s\n' '```' >> "$REPORT_FILE"
  printf '%s\n' "" "> **Note:** World-writable files in /etc indicate container image build errors." >> "$REPORT_FILE"
}

audit_packages() {
  printf '%s\n' "" "## 5. Security-Relevant Packages" "" "| Package | Version |" >> "$REPORT_FILE"
  printf '%s\n' "|---------|---------|" >> "$REPORT_FILE"
  dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | grep -iE "ssh|ssl|crypt|passw|sudo|auth" | while IFS=$'\t' read -r pkg ver; do
    printf '| %s | %s |\n' "$pkg" "$ver" >> "$REPORT_FILE"
  done || true
}

main() {
  echo "[*] Starting container security audit..."
  write_header
  audit_user_context
  audit_processes
  audit_network
  audit_file_perms
  audit_packages
  printf '%s\n' "" "---" "" "[*] Audit complete. Report: ${REPORT_FILE}" >> "$REPORT_FILE"
  echo "[+] Report written to: $REPORT_FILE"
  cat "$REPORT_FILE"
}

main "$@"
