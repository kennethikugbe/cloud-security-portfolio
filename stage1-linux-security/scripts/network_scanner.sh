#!/bin/bash
# Stage 1, Task 3: Network Security Scanner (v1.1)
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
sudo nmap -sT --top-ports 1000 -oG "$TMP_DIR/nmap.grep" localhost >/dev/null 2>&1 || nmap -sT --top-ports 1000 -oG "$TMP_DIR/nmap.grep" localhost >/dev/null 2>&1 || true

echo "[*] Collecting process listeners (sudo required for root-owned processes)..."
sudo ss -tulnp > "$TMP_DIR/ss.txt" 2>/dev/null || ss -tulnp > "$TMP_DIR/ss.txt" 2>/dev/null || true

echo "[*] Collecting firewall state..."
sudo ufw status verbose > "$TMP_DIR/ufw.txt" 2>/dev/null || ufw status verbose > "$TMP_DIR/ufw.txt" 2>/dev/null || printf '%s\n' "UFW unavailable" > "$TMP_DIR/ufw.txt"

# Parse nmap open ports
parse_nmap() {
  grep "Ports:" "$TMP_DIR/nmap.grep" 2>/dev/null | sed 's/.*Ports: //' | tr ',' '\n' | while read -r segment; do
    segment=$(echo "$segment" | sed 's/^ *//')
    [[ -z "$segment" ]] && continue
    port=$(echo "$segment" | awk -F/ '{print $1}' | tr -d ' ')
    state=$(echo "$segment" | awk -F/ '{print $2}' | tr -d ' ')
    proto=$(echo "$segment" | awk -F/ '{print $3}' | tr -d ' ')
    service=$(echo "$segment" | awk -F/ '{print $5}' | tr -d ' ')
    if [[ "$state" == "open" && "$port" =~ ^[0-9]+$ ]]; then
      printf '%s\t%s\t%s\n' "$port" "$proto" "$service"
    fi
  done
}

parse_nmap | sort -t$'\t' -k1,1n > "$TMP_DIR/ports.txt"

# Parse ss listeners - deduplicate by port+protocol
parse_ss() {
  grep LISTEN "$TMP_DIR/ss.txt" 2>/dev/null | while read -r line; do
    proto=$(echo "$line" | awk '{print $1}')
    local_addr=$(echo "$line" | awk '{print $5}')
    # Robust port extraction: handles IPv6, interface scopes like %lo
    port=$(echo "$local_addr" | sed 's/.*://' | sed 's/%.*//')
    
    # Extract process name from users:((..."column"
    process=$(echo "$line" | grep -o 'users:(("[^"]*"' | head -1 | sed 's/users:(("//; s/"$//' || echo "Unknown")
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s\t%s\t%s\n' "$port" "$proto" "$process"
    fi
  done | sort -t$'\t' -k1,1 -k2,2 | awk -F'\t' '!seen[$1"\t"$2]++'
}

parse_ss > "$TMP_DIR/processes.txt"

# Cross-reference and risk-rank
while IFS=$'\t' read -r port proto service; do
  [[ -z "$port" ]] && continue
  process=$(awk -F'\t' -v p="$port" -v pr="$proto" '$1==p && $2==pr {print $3; exit}' "$TMP_DIR/processes.txt" || echo "Unknown")
  [[ -z "$process" ]] && process="Unknown"
  
  # Check UFW
  ufw_match=$(grep -E "^${port}/${proto}" "$TMP_DIR/ufw.txt" 2>/dev/null | head -1 || true)
  if echo "$ufw_match" | grep -qi "ALLOW"; then
    ufw_state="ALLOW"
  elif echo "$ufw_match" | grep -qi "DENY"; then
    ufw_state="DENY"
  elif [[ -n "$ufw_match" ]]; then
    ufw_state="RULE"
  else
    ufw_state="NO_RULE"
  fi
  
  # Risk scoring
  if [[ "$ufw_state" == "ALLOW" ]]; then
    risk="LOW"; finding="Listening and explicitly allowed."
  elif [[ "$ufw_state" == "DENY" ]]; then
    risk="INFO"; finding="Listening but blocked by firewall."
  elif [[ "$ufw_state" == "NO_RULE" ]]; then
    risk="HIGH"; finding="Listening with NO explicit firewall rule. Vulnerable to default-policy bypass."
  else
    risk="MEDIUM"; finding="Ambiguous firewall state."
  fi
  
  printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$port" "$proto" "$service" "$process" "$ufw_state" "$risk" "$finding" >> "$REPORT_FILE"
done < "$TMP_DIR/ports.txt"

# Shadow listeners: ss shows them, nmap missed (outside top 1000 or localhost-only)
printf '%s\n' "" "### Shadow Listeners (Outside nmap Top 1000 or Localhost-Only)" "" \
"| Port | Protocol | Process | Risk |" \
"|------|----------|---------|------|" >> "$REPORT_FILE"

while IFS=$'\t' read -r port proto process; do
  [[ -z "$port" ]] && continue
  if ! awk -F'\t' -v p="$port" -v pr="$proto" '$1==p && $2==pr {found=1} END {exit !found}' "$TMP_DIR/ports.txt" 2>/dev/null; then
    printf '| %s | %s | %s | HIGH (missed by standard scan or localhost-only) |\n' "$port" "$proto" "$process" >> "$REPORT_FILE"
  fi
done < "$TMP_DIR/processes.txt"

# Summary
open_count=$(grep -c '^[0-9]' "$TMP_DIR/ports.txt" 2>/dev/null || echo 0)
high_count=$(grep -c "HIGH" "$REPORT_FILE" || echo 0)

printf '%s\n' "" "---" "" "## Summary" "" \
"- **Open Services Found:** ${open_count}" \
"- **High-Risk Exposures:** ${high_count}" \
"" \
"> **Recommendation:** All HIGH-risk services require explicit UFW rules or binding to localhost. " \
"Shadow listeners should be reviewed — localhost-only services (e.g., systemd-resolved) are typically acceptable." >> "$REPORT_FILE"

printf '%s\n' "[+] Scan complete. Report: $REPORT_FILE"
printf '%s\n' "---"
head -n 40 "$REPORT_FILE"
