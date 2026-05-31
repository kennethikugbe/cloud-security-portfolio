#!/bin/bash
# Stage 1, Task 3: Network Security Scanner
# Cross-references nmap, process listeners, and firewall rules
# Kenneth - Cloud Security Apprentice

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/network_scan_${TIMESTAMP}.md"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$REPORT_DIR"

# --- Header ---
cat << EOL > "$REPORT_FILE"
# Network Security Scan Report

| Field | Value |
|-------|-------|
| **Host** | $(hostname) |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Auditor** | Kenneth |

> Cross-references listening services (nmap), process ownership (ss), and firewall rules (ufw).
> Mapped to ISO 27001:2022: A.8.20 (Information security in networks), A.8.21 (Security of network services), A.8.9 (Configuration management).

---
EOL

printf '%s\n' "" "## Risk-Ranked Service Exposure" "" \
"| Port | Protocol | Service (nmap) | Process (ss) | UFW State | Risk | Finding |" \
"|------|----------|----------------|--------------|-----------|------|---------|" >> "$REPORT_FILE"

echo "[*] Running nmap TCP scan (top 1000 ports)..."
nmap -sT --top-ports 1000 -oG "$TMP_DIR/nmap.grep" localhost >/dev/null 2>&1 || true

echo "[*] Collecting process listeners..."
ss -tulnp > "$TMP_DIR/ss.txt" 2>/dev/null || netstat -tulnp > "$TMP_DIR/ss.txt" 2>/dev/null || true

echo "[*] Collecting firewall state..."
sudo ufw status verbose > "$TMP_DIR/ufw.txt" 2>/dev/null || ufw status verbose > "$TMP_DIR/ufw.txt" 2>/dev/null || printf '%s\n' "UFW unavailable" > "$TMP_DIR/ufw.txt"

# Parse nmap open ports
parse_nmap() {
  grep "Ports:" "$TMP_DIR/nmap.grep" 2>/dev/null | sed 's/.*Ports: //' | tr ',' '\n' | while read -r segment; do
    port=$(printf '%s\n' "$segment" | awk -F/ '{print $1}' | tr -d ' ')
    state=$(printf '%s\n' "$segment" | awk -F/ '{print $2}')
    proto=$(printf '%s\n' "$segment" | awk -F/ '{print $3}')
    service=$(printf '%s\n' "$segment" | awk -F/ '{print $5}')
    if [[ "$state" == "open" && "$port" =~ ^[0-9]+$ ]]; then
      printf '%s\t%s\t%s\n' "$port" "$proto" "$service"
    fi
  done
}

parse_nmap | sort -t$'\t' -k1,1n > "$TMP_DIR/ports.txt"

# Parse ss listeners
parse_ss() {
  grep LISTEN "$TMP_DIR/ss.txt" 2>/dev/null | while read -r line; do
    proto=$(printf '%s\n' "$line" | awk '{print $1}')
    local_addr=$(printf '%s\n' "$line" | awk '{print $5}')
    port=$(printf '%s\n' "$local_addr" | awk -F: '{print $NF}')
    process=$(printf '%s\n' "$line" | grep -o 'users:(("[^"]*"' | head -1 | sed 's/users:(("//' | sed 's/"$//' || echo "Unknown")
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s\t%s\t%s\n' "$port" "$proto" "$process"
    fi
  done
}

parse_ss | sort -t$'\t' -k1,1n > "$TMP_DIR/processes.txt"

# Cross-reference and risk-rank
while IFS=$'\t' read -r port proto service; do
  process=$(awk -F'\t' -v p="$port" '$1==p {print $3}' "$TMP_DIR/processes.txt" | head -n 1 || echo "Unknown")
  
  # Check UFW
  if grep -qE "^${port}/${proto}" "$TMP_DIR/ufw.txt" 2>/dev/null; then
    if grep -E "^${port}/${proto}" "$TMP_DIR/ufw.txt" | grep -qi "ALLOW"; then
      ufw_state="ALLOW"
    elif grep -E "^${port}/${proto}" "$TMP_DIR/ufw.txt" | grep -qi "DENY"; then
      ufw_state="DENY"
    else
      ufw_state="RULE"
    fi
  else
    ufw_state="NO_RULE"
  fi
  
  # Risk scoring
  if [[ "$ufw_state" == "ALLOW" ]]; then
    risk="LOW"; finding="Service listening and explicitly allowed."
  elif [[ "$ufw_state" == "DENY" ]]; then
    risk="INFO"; finding="Listening but blocked by firewall."
  elif [[ "$ufw_state" == "NO_RULE" ]]; then
    risk="HIGH"; finding="Listening with NO explicit firewall rule. Vulnerable to default-policy bypass."
  else
    risk="MEDIUM"; finding="Ambiguous firewall state."
  fi
  
  printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$port" "$proto" "$service" "$process" "$ufw_state" "$risk" "$finding" >> "$REPORT_FILE"
done < "$TMP_DIR/ports.txt"

# Check for shadow listeners (ss shows them, nmap missed them)
printf '%s\n' "" "### Shadow Listeners (Outside nmap Top 1000)" "" \
"| Port | Protocol | Process | Risk |" \
"|------|----------|---------|------|" >> "$REPORT_FILE"

while IFS=$'\t' read -r port proto process; do
  if ! awk -F'\t' -v p="$port" '$1==p {found=1} END {exit !found}' "$TMP_DIR/ports.txt"; then
    printf '| %s | %s | %s | HIGH (missed by standard scan) |\n' "$port" "$proto" "$process" >> "$REPORT_FILE"
  fi
done < "$TMP_DIR/processes.txt"

# Summary
open_count=$(wc -l < "$TMP_DIR/ports.txt" | tr -d ' ')
high_count=$(grep -c "HIGH" "$REPORT_FILE" || echo 0)

printf '%s\n' "" "---" "" "## Summary" "" \
"- **Open Services Found:** ${open_count}" \
"- **High-Risk Exposures:** ${high_count}" \
"" \
"> **Recommendation:** All HIGH-risk services require explicit UFW rules or binding to localhost. " \
"Shadow listeners should be manually reviewed and either documented or removed." >> "$REPORT_FILE"

printf '%s\n' "[+] Scan complete. Report: $REPORT_FILE"
printf '%s\n' "---"
head -n 35 "$REPORT_FILE"
