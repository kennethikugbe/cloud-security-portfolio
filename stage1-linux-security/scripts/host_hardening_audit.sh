#!/bin/bash
# Stage 1, Task 2: Host Hardening Audit
# Evaluates SSH and firewall config against CIS benchmarks
# Kenneth - Cloud Security Apprentice

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/hardening_audit_${TIMESTAMP}.md"
REMEDIATE_SCRIPT="$REPORT_DIR/remediate_${TIMESTAMP}.sh"
MODE="audit"

usage() {
  printf '%s\n' "Usage: $0 [-a] [-r] [--apply]"
  printf '%s\n' "  -a    Audit only (default)"
  printf '%s\n' "  -r    Generate remediation script for manual review"
  printf '%s\n' "  --apply  Apply fixes directly (DANGEROUS: only use with console access)"
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

if [[ "$MODE" == "remediate" || "$MODE" == "apply" ]]; then
  {
    printf '%s\n' "#!/bin/bash"
    printf '%s\n' "# Auto-generated remediation script"
    printf '%s\n' "# Generated: $(date)"
    printf '%s\n' "# WARNING: Review before executing. Ensure console/VM access before running."
    printf '%s\n' ""
    printf '%s\n' "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)"
    printf '%s\n' ""
  } > "$REMEDIATE_SCRIPT"
fi

write_header() {
  cat << EOL > "$REPORT_FILE"
# Host Hardening Audit Report

| Field | Value |
|-------|-------|
| **Host** | $(hostname) |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Mode** | ${MODE} |
| **Auditor** | Kenneth |

> Evaluates host configuration against CIS Ubuntu Linux Benchmark controls.
> **WARNING:** Applying SSH hardening without key-based auth configured may lock you out.

---
EOL
}

write_results_header() {
  printf '%s\n' "" "## Audit Results" "" "| Check | Status | Finding | CIS Ref |" "|-------|--------|---------|---------|" >> "$REPORT_FILE"
}

append_result() {
  printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4" >> "$REPORT_FILE"
}

get_ssh_val() {
  local key="$1"
  local result
  result=$(grep -iE "^\s*${key}\s+" /etc/ssh/sshd_config 2>/dev/null | tail -n 1 | awk '{$1=""; print substr($0,2)}' || true)
  if [[ -z "$result" ]]; then
    printf '%s\n' "NOTSET"
  else
    printf '%s\n' "$result"
  fi
}

check_firewall() {
  local status="FAIL" finding=""
  
  if command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      status="PASS"
      finding="UFW is active."
      if ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; then
        finding="$finding Default deny incoming: yes."
      else
        status="FAIL"
        finding="$finding Default deny incoming: NO."
      fi
    else
      finding="UFW installed but inactive."
    fi
  else
    finding="UFW not installed."
    if command -v iptables &>/dev/null; then
      finding="$finding iptables present (manual review required)."
    fi
  fi
  
  append_result "Firewall Active" "$status" "$finding" "CIS 3.5"
  
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    {
      printf '%s\n' "" "# --- Firewall Remediation ---"
      printf '%s\n' "sudo apt-get update -qq"
      printf '%s\n' "sudo apt-get install -y ufw"
      printf '%s\n' "sudo ufw default deny incoming"
      printf '%s\n' "sudo ufw default allow outgoing"
      printf '%s\n' "sudo ufw allow ssh # CRITICAL: ensure console access first"
      printf '%s\n' "sudo ufw --force enable"
    } >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_root() {
  local val=$(get_ssh_val "PermitRootLogin")
  local status="PASS" finding="PermitRootLogin=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="FAIL"
    finding="Not explicitly set (modern default is prohibit-password, but explicit 'no' is recommended for CIS)."
  elif [[ "$val" == "yes" ]]; then
    status="FAIL"
    finding="PermitRootLogin=yes. Root login via SSH is permitted."
  fi
  append_result "SSH Root Login" "$status" "$finding" "CIS 5.2.9"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_password() {
  local val=$(get_ssh_val "PasswordAuthentication")
  local status="INFO" finding="PasswordAuthentication=${val}"
  if [[ "$val" == "yes" ]]; then
    status="WARN"
    finding="PasswordAuthentication=yes. Key-based auth is recommended for production."
  elif [[ "$val" == "no" ]]; then
    status="PASS"
    finding="PasswordAuthentication=no. Key-based auth enforced."
  elif [[ "$val" == "NOTSET" ]]; then
    status="WARN"
    finding="Not explicitly set (may default to yes)."
  fi
  append_result "SSH Password Auth" "$status" "$finding" "CIS 5.2.11"
  if [[ "$val" == "yes" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    {
      printf '%s\n' "# WARNING: Only disable password auth if key-based auth is configured and tested."
      printf '%s\n' "# sudo sed -i 's/^#*\\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
    } >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_maxauth() {
  local val=$(get_ssh_val "MaxAuthTries")
  local status="PASS" finding="MaxAuthTries=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="FAIL"
    finding="Not set (defaults to 6, should be <= 4)."
  elif [[ "$val" =~ ^[0-9]+$ ]]; then
    if [[ "$val" -gt 4 ]]; then
      status="FAIL"
      finding="MaxAuthTries=${val} (should be <= 4)."
    fi
  else
    status="FAIL"
    finding="Non-numeric value: ${val}"
  fi
  append_result "SSH MaxAuthTries" "$status" "$finding" "CIS 5.2.6"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config || printf '%s\\n' 'MaxAuthTries 4' | sudo tee -a /etc/ssh/sshd_config >/dev/null" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_x11() {
  local val=$(get_ssh_val "X11Forwarding")
  local status="PASS" finding="X11Forwarding=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="INFO"
    finding="Not explicitly set (modern default is no)."
  elif [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="X11Forwarding=${val} (should be no)."
  fi
  append_result "SSH X11 Forwarding" "$status" "$finding" "CIS 5.2.6"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_protocol() {
  local val=$(get_ssh_val "Protocol")
  local status="PASS" finding="Protocol=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="INFO"
    finding="Not explicitly set (modern SSH defaults to 2)."
  elif [[ "$val" != "2" ]]; then
    status="FAIL"
    finding="Protocol=${val} (should be 2)."
  fi
  append_result "SSH Protocol" "$status" "$finding" "CIS 5.2.3"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*Protocol.*/Protocol 2/' /etc/ssh/sshd_config || printf '%s\\n' 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config >/dev/null" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_alive_interval() {
  local val=$(get_ssh_val "ClientAliveInterval")
  local status="PASS" finding="ClientAliveInterval=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="FAIL"
    finding="Not set (should be 1-300 seconds)."
  elif [[ "$val" =~ ^[0-9]+$ ]]; then
    if [[ "$val" -eq 0 || "$val" -gt 300 ]]; then
      status="FAIL"
      finding="ClientAliveInterval=${val} (should be 1-300)."
    fi
  else
    status="FAIL"
    finding="Non-numeric value: ${val}"
  fi
  append_result "SSH Alive Interval" "$status" "$finding" "CIS 5.2.13"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || printf '%s\\n' 'ClientAliveInterval 300' | sudo tee -a /etc/ssh/sshd_config >/dev/null" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_alive_count() {
  local val=$(get_ssh_val "ClientAliveCountMax")
  local status="PASS" finding="ClientAliveCountMax=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="FAIL"
    finding="Not set (should be <= 3)."
  elif [[ "$val" =~ ^[0-9]+$ ]]; then
    if [[ "$val" -gt 3 ]]; then
      status="FAIL"
      finding="ClientAliveCountMax=${val} (should be <= 3)."
    fi
  else
    status="FAIL"
    finding="Non-numeric value: ${val}"
  fi
  append_result "SSH Alive Count" "$status" "$finding" "CIS 5.2.13"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config || printf '%s\\n' 'ClientAliveCountMax 3' | sudo tee -a /etc/ssh/sshd_config >/dev/null" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_hostbased() {
  local val=$(get_ssh_val "HostbasedAuthentication")
  local status="PASS" finding="HostbasedAuthentication=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="INFO"
    finding="Not explicitly set (modern default is no)."
  elif [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="HostbasedAuthentication=${val} (should be no)."
  fi
  append_result "SSH HostbasedAuth" "$status" "$finding" "CIS 5.2.7"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_empty_password() {
  local val=$(get_ssh_val "PermitEmptyPasswords")
  local status="PASS" finding="PermitEmptyPasswords=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="INFO"
    finding="Not explicitly set (modern default is no)."
  elif [[ "$val" != "no" ]]; then
    status="FAIL"
    finding="PermitEmptyPasswords=${val} (should be no)."
  fi
  append_result "SSH Empty Passwords" "$status" "$finding" "CIS 5.2.10"
  if [[ "$status" == "FAIL" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "sudo sed -i 's/^#*\\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config" >> "$REMEDIATE_SCRIPT"
  fi
}

check_ssh_banner() {
  local val=$(get_ssh_val "Banner")
  local status="PASS" finding="Banner=${val}"
  if [[ "$val" == "NOTSET" ]]; then
    status="WARN"
    finding="Banner not set (recommended for legal/audit logging)."
  fi
  append_result "SSH Banner" "$status" "$finding" "CIS 5.2.15"
  if [[ "$status" == "WARN" && ( "$MODE" == "remediate" || "$MODE" == "apply" ) ]]; then
    printf '%s\n' "printf '%s\\n' 'Authorized use only. All activity is monitored.' | sudo tee /etc/ssh/banner >/dev/null" >> "$REMEDIATE_SCRIPT"
    printf '%s\n' "sudo sed -i 's/^#*\\s*Banner.*/Banner \\/etc\\/ssh\\/banner/' /etc/ssh/sshd_config || printf '%s\\n' 'Banner /etc/ssh/banner' | sudo tee -a /etc/ssh/sshd_config >/dev/null" >> "$REMEDIATE_SCRIPT"
  fi
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
      printf '%s\n' ""
      printf '%s\n' "# Restart SSH service to apply changes"
      printf '%s\n' "sudo systemctl restart sshd 2>/dev/null || sudo service ssh restart"
    } >> "$REMEDIATE_SCRIPT"
    chmod +x "$REMEDIATE_SCRIPT"
    printf '%s\n' "[*] Remediation script: $REMEDIATE_SCRIPT"
    
    if [[ "$MODE" == "apply" ]]; then
      printf '%s\n' "[!] APPLY MODE: Executing remediation script..."
      bash "$REMEDIATE_SCRIPT"
      printf '%s\n' "[+] Remediation applied."
    fi
  fi
}

main "$@"
