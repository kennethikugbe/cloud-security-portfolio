#!/bin/bash
# Stage 1, Task 2 (v2): Bulletproof Host Hardening Audit
# Audits via sshd -T (effective config). Remediates via drop-in overrides.
# Kenneth - Cloud Security Apprentice

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/hardening_audit_v2_${TIMESTAMP}.md"
REMEDIATE_SCRIPT="$REPORT_DIR/remediate_v2_${TIMESTAMP}.sh"
MODE="audit"

HARDENING_CONF="/etc/ssh/sshd_config.d/99-hardening.conf"
BANNER_FILE="/etc/ssh/banner"

usage() {
  printf '%s\n' "Usage: $0 [-a] [-r] [--apply]"
  printf '%s\n' "  -a    Audit only (default)"
  printf '%s\n' "  -r    Generate remediation script for manual review"
  printf '%s\n' "  --apply  Apply fixes via drop-in overrides (console access recommended)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a) MODE="audit"; shift ;;
    -r) MODE="remediate"; shift ;;
    --apply) MODE="apply"; shift ;;
    -h|--help) usage ;;
    *) printf '%s\n' "Unknown option: $1"; usage ;;
  esac
done

mkdir -p "$REPORT_DIR"

write_header() {
  cat << EOL > "$REPORT_FILE"
# Host Hardening Audit Report (v2)

| Field | Value |
|-------|-------|
| **Host** | $(hostname) |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Mode** | ${MODE} |
| **Auditor** | Kenneth |

> Audits effective running configuration via \`sshd -T\`.
> Remediates via drop-in overrides in \`${HARDENING_CONF}\`.
> **WARNING:** Drop-in sets PasswordAuthentication=no. Ensure console/VM access.

---
EOL
}

write_results_header() {
  printf '%s\n' "" "## Audit Results" "" "| Check | Status | Finding | CIS Ref |" "|-------|--------|---------|---------|" >> "$REPORT_FILE"
}

append_result() {
  printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4" >> "$REPORT_FILE"
}

# --- Effective config reader (reads compiled-in defaults + files + drop-ins) ---
get_sshd_val() {
  local key="$1"
  local result
  result=$(sudo sshd -T 2>/dev/null | grep -iE "^${key}\s+" | head -n 1 | awk '{print $2}' || true)
  if [[ -z "$result" ]]; then
    printf '%s\n' "UNKNOWN"
  else
    printf '%s\n' "$result"
  fi
}

# --- Checks ---

check_firewall() {
  local status="FAIL" finding=""
  if command -v ufw &>/dev/null; then
    local ufw_out
    ufw_out=$(sudo ufw status verbose 2>/dev/null || sudo ufw status verbose 2>/dev/null || echo "")
    if printf '%s\n' "$ufw_out" | grep -qi "status: active"; then
      if printf '%s\n' "$ufw_out" | grep -qi "default: deny (incoming)"; then
        status="PASS"
        finding="UFW active with default deny incoming."
      else
        status="WARN"
        finding="UFW active but default incoming not deny."
      fi
    else
      finding="UFW installed but inactive."
    fi
  else
    finding="UFW not installed."
  fi
  append_result "Firewall Active" "$status" "$finding" "CIS 3.5"
}

check_ssh_root() {
  local val
  val=$(get_sshd_val "permitrootlogin")
  local status="PASS" finding="PermitRootLogin=${val}"
  if [[ "$val" == "yes" || "$val" == "prohibit-password" || "$val" == "without-password" ]]; then
    status="FAIL"
    finding="PermitRootLogin=${val} (should be no)."
  elif [[ "$val" == "UNKNOWN" ]]; then
    status="FAIL"
    finding="Unable to read effective config."
  fi
  append_result "SSH Root Login" "$status" "$finding" "CIS 5.2.9"
}

check_ssh_password() {
  local val
  val=$(get_sshd_val "passwordauthentication")
  local status="PASS" finding="PasswordAuthentication=${val}"
  if [[ "$val" == "yes" ]]; then
    status="WARN"
    finding="PasswordAuthentication=yes. Key-based auth recommended for production."
  elif [[ "$val" == "UNKNOWN" ]]; then
    status="INFO"
    finding="Unable to verify."
  fi
  append_result "SSH Password Auth" "$status" "$finding" "CIS 5.2.11"
}

check_ssh_maxauth() {
  local val
  val=$(get_sshd_val "maxauthtries")
  local status="PASS" finding="MaxAuthTries=${val}"
  if [[ "$val" == "UNKNOWN" ]]; then
    status="FAIL"
    finding="Unable to read effective config."
  elif ! [[ "$val" =~ ^[0-9]+$ ]]; then
    status="FAIL"
    finding="Non-numeric value: ${val}"
  elif [[ "$val" -gt 4 ]]; then
    status="FAIL"
    finding="MaxAuthTries=${val} (should be <= 4)."
  fi
  append_result "SSH MaxAuthTries" "$status" "$finding" "CIS 5.2.6"
}

check_ssh_x11() {
  local val
  val=$(get_sshd_val "x11forwarding")
  local status="PASS" finding="X11Forwarding=${val}"
  if [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="X11Forwarding=${val} (should be no)."
  fi
  append_result "SSH X11 Forwarding" "$status" "$finding" "CIS 5.2.6"
}

check_ssh_protocol() {
  local val
  val=$(get_sshd_val "protocol")
  # sshd -T on modern OpenSSH does not output Protocol (v2 is implicit)
  local status="PASS" finding="Protocol=${val}"
  if [[ "$val" == "1" ]]; then
    status="FAIL"
    finding="Protocol=1 (should be 2)."
  elif [[ "$val" == "UNKNOWN" ]]; then
    status="INFO"
    finding="Protocol not reported (modern default is 2, acceptable)."
  fi
  append_result "SSH Protocol" "$status" "$finding" "CIS 5.2.3"
}

check_ssh_alive_interval() {
  local val
  val=$(get_sshd_val "clientaliveinterval")
  local status="PASS" finding="ClientAliveInterval=${val}"
  if [[ "$val" == "UNKNOWN" ]]; then
    status="FAIL"
    finding="Unable to read effective config."
  elif ! [[ "$val" =~ ^[0-9]+$ ]]; then
    status="FAIL"
    finding="Non-numeric value: ${val}"
  elif [[ "$val" -eq 0 || "$val" -gt 300 ]]; then
    status="FAIL"
    finding="ClientAliveInterval=${val} (should be 1-300)."
  fi
  append_result "SSH Alive Interval" "$status" "$finding" "CIS 5.2.13"
}

check_ssh_alive_count() {
  local val
  val=$(get_sshd_val "clientalivecountmax")
  local status="PASS" finding="ClientAliveCountMax=${val}"
  if [[ "$val" == "UNKNOWN" ]]; then
    status="FAIL"
    finding="Unable to read effective config."
  elif ! [[ "$val" =~ ^[0-9]+$ ]]; then
    status="FAIL"
    finding="Non-numeric value: ${val}"
  elif [[ "$val" -gt 3 ]]; then
    status="FAIL"
    finding="ClientAliveCountMax=${val} (should be <= 3)."
  fi
  append_result "SSH Alive Count" "$status" "$finding" "CIS 5.2.13"
}

check_ssh_hostbased() {
  local val
  val=$(get_sshd_val "hostbasedauthentication")
  local status="PASS" finding="HostbasedAuthentication=${val}"
  if [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="HostbasedAuthentication=${val} (should be no)."
  fi
  append_result "SSH HostbasedAuth" "$status" "$finding" "CIS 5.2.7"
}

check_ssh_empty_password() {
  local val
  val=$(get_sshd_val "permitemptypasswords")
  local status="PASS" finding="PermitEmptyPasswords=${val}"
  if [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="PermitEmptyPasswords=${val} (should be no)."
  fi
  append_result "SSH Empty Passwords" "$status" "$finding" "CIS 5.2.10"
}

check_ssh_banner() {
  local val
  val=$(get_sshd_val "banner")
  local status="PASS" finding="Banner=${val}"
  if [[ "$val" == "none" || "$val" == "UNKNOWN" ]]; then
    status="WARN"
    finding="Banner not set (recommended for legal/audit logging)."
  fi
  append_result "SSH Banner" "$status" "$finding" "CIS 5.2.15"
}

# --- Remediation generators ---

write_firewall_remediation() {
  {
    printf '%s\n' ""
    printf '%s\n' "# --- Firewall Remediation ---"
    printf '%s\n' "sudo ufw default deny incoming"
    printf '%s\n' "sudo ufw default allow outgoing"
    printf '%s\n' "sudo ufw allow ssh"
    printf '%s\n' "sudo ufw --force enable"
  } >> "$REMEDIATE_SCRIPT"
}

write_ssh_remediation() {
  {
    printf '%s\n' ""
    printf '%s\n' "# --- SSH Hardening Remediation ---"
    printf '%s\n' "# Writes drop-in overrides instead of editing main sshd_config"
    printf '%s\n' "sudo mkdir -p /etc/ssh/sshd_config.d"
    printf '%s\n' "{"
    printf '%s\n' "  echo '# Auto-generated SSH hardening - Kenneth'"
    printf '%s\n' "  echo 'PermitRootLogin no'"
    printf '%s\n' "  echo 'PasswordAuthentication no'"
    printf '%s\n' "  echo 'MaxAuthTries 4'"
    printf '%s\n' "  echo 'ClientAliveInterval 300'"
    printf '%s\n' "  echo 'ClientAliveCountMax 3'"
    printf '%s\n' "  echo 'X11Forwarding no'"
    printf '%s\n' "  echo 'HostbasedAuthentication no'"
    printf '%s\n' "  echo 'PermitEmptyPasswords no'"
    printf '%s\n' "  echo \"Banner ${BANNER_FILE}\""
    printf '%s\n' "} | sudo tee ${HARDENING_CONF} >/dev/null"
    printf '%s\n' ""
    printf '%s\n' "printf '%%s\\n' 'Authorized use only. All activity is monitored.' | sudo tee ${BANNER_FILE} >/dev/null"
    printf '%s\n' ""
    printf '%s\n' "# Validate before restart"
    printf '%s\n' "sudo sshd -t"
    printf '%s\n' "sudo systemctl restart ssh"
  } >> "$REMEDIATE_SCRIPT"
}

apply_remediation() {
  printf '%s\n' "[!] APPLYING hardening via drop-in overrides..."

  # --- Firewall ---
  if command -v ufw &>/dev/null; then
    sudo ufw default deny incoming 2>/dev/null || true
    sudo ufw default allow outgoing 2>/dev/null || true
    sudo ufw allow ssh 2>/dev/null || true
    sudo ufw --force enable 2>/dev/null || true
    printf '%s\n' "[+] Firewall configured."
  fi

  # --- SSH: write drop-in config (SAFE) ---
  sudo mkdir -p /etc/ssh/sshd_config.d
  {
    printf '%s\n' "# Auto-generated SSH hardening - Kenneth"
    printf '%s\n' "PermitRootLogin no"
    printf '%s\n' "PasswordAuthentication no"
    printf '%s\n' "MaxAuthTries 4"
    printf '%s\n' "ClientAliveInterval 300"
    printf '%s\n' "ClientAliveCountMax 3"
    printf '%s\n' "X11Forwarding no"
    printf '%s\n' "HostbasedAuthentication no"
    printf '%s\n' "PermitEmptyPasswords no"
    printf '%s\n' "Banner ${BANNER_FILE}"
  } | sudo tee "$HARDENING_CONF" >/dev/null

  printf '%s\n' 'Authorized use only. All activity is monitored.' | sudo tee "$BANNER_FILE" >/dev/null

  printf '%s\n' "[*] Validating SSH configuration..."
  sudo sshd -t
  printf '%s\n' "[+] SSH config valid."

  printf '%s\n' "[*] Restarting SSH service..."
  sudo systemctl restart ssh
  printf '%s\n' "[+] SSH restarted successfully."
}

main() {
  write_header
  write_results_header

  check_firewall
  check_ssh_root
  check_ssh_password
  check_ssh_maxauth
  check_ssh_x11
  check_ssh_protocol
  check_ssh_alive_interval
  check_ssh_alive_count
  check_ssh_hostbased
  check_ssh_empty_password
  check_ssh_banner

  printf '%s\n' "" "---" "" "Audit complete. Report: ${REPORT_FILE}" >> "$REPORT_FILE"

  printf '%s\n' "[*] Audit complete."
  printf '%s\n' "[*] Report: $REPORT_FILE"

  if [[ "$MODE" == "remediate" || "$MODE" == "apply" ]]; then
    {
      printf '%s\n' "#!/bin/bash"
      printf '%s\n' "# Auto-generated remediation script (v2)"
      printf '%s\n' "# Generated: $(date)"
      printf '%s\n' "# Uses drop-in overrides instead of in-place file editing"
      printf '%s\n' ""
    } > "$REMEDIATE_SCRIPT"

    write_firewall_remediation
    write_ssh_remediation

    chmod +x "$REMEDIATE_SCRIPT"
    printf '%s\n' "[*] Remediation script: $REMEDIATE_SCRIPT"

    if [[ "$MODE" == "apply" ]]; then
      apply_remediation
      printf '%s\n' "[+] Remediation applied. Run audit again to verify."
    fi
  fi
}

main "$@"
