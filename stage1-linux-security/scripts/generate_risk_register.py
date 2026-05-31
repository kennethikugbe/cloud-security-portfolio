#!/usr/bin/env python3
"""
Stage 1, Task 4 (v1.1): ISO 27001 Risk Register Generator
Parses Markdown audit reports and generates a CSV risk register.
Kenneth - Cloud Security Apprentice
"""

import argparse
import csv
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import namedtuple, defaultdict

# --- ISO 27001:2022 Control Mapping ---
CIS_TO_ISO_MAPPING = {
    "CIS 3.5": "A.8.20 (Information security in networks)",
    "CIS 5.2.3": "A.8.5 (Secure authentication)",
    "CIS 5.2.6": "A.8.5 (Secure authentication)",
    "CIS 5.2.7": "A.8.5 (Secure authentication)",
    "CIS 5.2.9": "A.5.18 (Information security roles), A.8.1",
    "CIS 5.2.10": "A.8.1 (User endpoint devices)",
    "CIS 5.2.11": "A.8.5 (Secure authentication)",
    "CIS 5.2.13": "A.8.1, A.5.28",
    "CIS 5.2.15": "A.5.18",
}

RISK_TO_ISO_MAPPING = {
    "HIGH": "A.8.20, A.8.21",
    "MEDIUM": "A.8.20",
    "LOW": "A.8.9 (Configuration management)",
}

RiskEntry = namedtuple("RiskEntry", [
    "entry_id", "date", "source_report", "finding_category",
    "finding_description", "risk_level", "status",
    "iso_control", "recommended_action", "evidence_location", "owner"
])

def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse Markdown audit reports into an ISO 27001 risk register CSV."
    )
    parser.add_argument(
        "--reports-dir", "-i",
        default="../reports",
        help="Directory containing Markdown audit reports"
    )
    parser.add_argument(
        "--output", "-o",
        default="../reports/risk_register.csv",
        help="Output CSV file path"
    )
    parser.add_argument(
        "--latest", "-l",
        action="store_true",
        help="Only ingest the most recent report of each type"
    )
    return parser.parse_args()

def extract_report_metadata(content, filename):
    """Extract host, date, and auditor from report header."""
    host_match = re.search(r'\*\*Host\*\*\s*\|\s*([^\n|]+)', content)
    date_match = re.search(r'\*\*Date\*\*\s*\|\s*([^\n|]+)', content)
    host = host_match.group(1).strip() if host_match else "Unknown"
    date_str = date_match.group(1).strip() if date_match else datetime.now().isoformat()
    return host, date_str

def get_report_type(content, filename):
    """Classify report by content signature."""
    if "Host Hardening Audit Report (v2)" in content:
        return "hardening_v2"
    elif "Network Security Scan Report" in content:
        return "network_scan"
    elif "Host Security Audit Report" in content:
        return "host_audit"
    return None

def parse_hardening_audit(content, filename, host, date_str, global_counter):
    """Parse host_hardening_audit_v2 reports."""
    entries = []
    table_pattern = re.compile(
        r'\|\s*([^|]+?)\s*\|\s*(PASS|FAIL|WARN|INFO)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|',
        re.MULTILINE
    )
    for match in table_pattern.finditer(content):
        check = match.group(1).strip()
        status = match.group(2).strip()
        finding = match.group(3).strip()
        cis_ref = match.group(4).strip()

        if status == "PASS":
            continue

        risk_level = "HIGH" if status == "FAIL" else ("MEDIUM" if status == "WARN" else "LOW")
        iso_control = CIS_TO_ISO_MAPPING.get(cis_ref, "A.8.1 (General)")
        action = f"Remediate {check}: {finding}. Apply via sshd_config.d or UFW."
        if "PasswordAuthentication" in check:
            action = "Deploy SSH key-based authentication before enforcing PasswordAuthentication=no."

        global_counter[0] += 1
        entry = RiskEntry(
            entry_id=f"SEC-{datetime.now().strftime('%Y%m%d')}-{global_counter[0]:03d}",
            date=date_str,
            source_report=filename,
            finding_category="SSH/Host Hardening",
            finding_description=f"[{check}] {finding}",
            risk_level=risk_level,
            status="Open",
            iso_control=iso_control,
            recommended_action=action,
            evidence_location=f"reports/{filename}",
            owner="Cloud Security Engineer"
        )
        entries.append(entry)
    return entries

def parse_network_scan(content, filename, host, date_str, global_counter):
    """Parse network_scan reports."""
    entries = []
    # Parse main exposure table
    table_pattern = re.compile(
        r'\|\s*(\d+)\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(\w+)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)\s*\|\s*([^|]+?)\s*\|',
        re.MULTILINE
    )
    for match in table_pattern.finditer(content):
        port = match.group(1).strip()
        proto = match.group(2).strip()
        service = match.group(3).strip()
        process = match.group(4).strip()
        ufw_state = match.group(5).strip()
        risk = match.group(6).strip()
        finding = match.group(7).strip()

        if risk in ("LOW", "INFO"):
            continue

        iso_control = RISK_TO_ISO_MAPPING.get(risk, "A.8.20")
        action = f"Review service {process} on {port}/{proto}. "
        if ufw_state == "NO_RULE":
            action += "Add explicit UFW rule or bind to localhost."
        elif process == "cupsd":
            action += "Remove CUPS if not required: sudo apt-get remove --purge cups."

        global_counter[0] += 1
        entry = RiskEntry(
            entry_id=f"SEC-{datetime.now().strftime('%Y%m%d')}-{global_counter[0]:03d}",
            date=date_str,
            source_report=filename,
            finding_category="Network Exposure",
            finding_description=f"Port {port}/{proto} ({service}/{process}): {finding}",
            risk_level=risk,
            status="Open",
            iso_control=iso_control,
            recommended_action=action,
            evidence_location=f"reports/{filename}",
            owner="Cloud Security Engineer"
        )
        entries.append(entry)

    # Parse shadow listeners (skipping localhost-only known services)
    shadow_pattern = re.compile(
        r'\|\s*(\d+)\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*\|\s*HIGH\s*\([^)]+\)\s*\|',
        re.MULTILINE
    )
    for match in shadow_pattern.finditer(content):
        port = match.group(1).strip()
        proto = match.group(2).strip()
        process = match.group(3).strip()

        if process == "systemd-resolve" or process == "systemd-resolved":
            continue

        global_counter[0] += 1
        entry = RiskEntry(
            entry_id=f"SEC-{datetime.now().strftime('%Y%m%d')}-{global_counter[0]:03d}",
            date=date_str,
            source_report=filename,
            finding_category="Shadow Listener",
            finding_description=f"Port {port}/{proto} ({process}): Not detected by nmap top-1000.",
            risk_level="MEDIUM",
            status="Open",
            iso_control="A.8.20, A.8.21",
            recommended_action=f"Investigate {process} necessity. Document or remove.",
            evidence_location=f"reports/{filename}",
            owner="Cloud Security Engineer"
        )
        entries.append(entry)

    return entries

def parse_host_audit(content, filename, host, date_str, global_counter):
    """Parse host_audit reports for permission risks and failed logins."""
    entries = []
    if "World-Writable Files" in content:
        global_counter[0] += 1
        entry = RiskEntry(
            entry_id=f"SEC-{datetime.now().strftime('%Y%m%d')}-{global_counter[0]:03d}",
            date=date_str,
            source_report=filename,
            finding_category="File Permissions",
            finding_description="World-writable files detected in /etc, /tmp, or /var/tmp.",
            risk_level="MEDIUM",
            status="Open",
            iso_control="A.8.1 (User endpoint devices), A.5.28",
            recommended_action="Review and remove world-writable permissions from configuration directories.",
            evidence_location=f"reports/{filename}",
            owner="Cloud Security Engineer"
        )
        entries.append(entry)
    return entries

def classify_and_parse(filepath, global_counter):
    """Route the report to the correct parser."""
    content = filepath.read_text(encoding='utf-8')
    filename = filepath.name
    host, date_str = extract_report_metadata(content, filename)

    rtype = get_report_type(content, filename)
    if rtype == "hardening_v2":
        return parse_hardening_audit(content, filename, host, date_str, global_counter)
    elif rtype == "network_scan":
        return parse_network_scan(content, filename, host, date_str, global_counter)
    elif rtype == "host_audit":
        return parse_host_audit(content, filename, host, date_str, global_counter)
    else:
        print(f"[!] Unknown report type, skipping: {filename}", file=sys.stderr)
        return []

def select_latest_reports(report_paths):
    """Keep only the most recent report per report type."""
    by_type = defaultdict(list)
    for p in report_paths:
        content = p.read_text(encoding='utf-8')
        rtype = get_report_type(content, p.name)
        if rtype:
            by_type[rtype].append(p)
    selected = []
    for rtype, paths in by_type.items():
        # Sort by modification time, keep latest
        latest = max(paths, key=lambda p: p.stat().st_mtime)
        selected.append(latest)
        print(f"[*] Latest {rtype}: {latest.name}")
    return selected

def write_csv(entries, output_path):
    if not entries:
        print("[!] No risk entries found.", file=sys.stderr)
        sys.exit(1)

    fieldnames = [
        "Entry ID", "Date", "Source Report", "Finding Category",
        "Finding Description", "Risk Level", "Status",
        "ISO 27001:2022 Control", "Recommended Action",
        "Evidence Location", "Owner"
    ]

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "Entry ID": e.entry_id,
                "Date": e.date,
                "Source Report": e.source_report,
                "Finding Category": e.finding_category,
                "Finding Description": e.finding_description,
                "Risk Level": e.risk_level,
                "Status": e.status,
                "ISO 27001:2022 Control": e.iso_control,
                "Recommended Action": e.recommended_action,
                "Evidence Location": e.evidence_location,
                "Owner": e.owner,
            })
    print(f"[+] Risk register written: {output_path}")
    print(f"    Total entries: {len(entries)}")

def main():
    args = parse_args()
    reports_dir = Path(args.reports_dir).resolve()
    output_path = Path(args.output).resolve()

    if not reports_dir.exists():
        print(f"[!] Reports directory not found: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    all_reports = sorted(reports_dir.glob("*.md"))
    if args.latest:
        reports_to_parse = select_latest_reports(all_reports)
    else:
        reports_to_parse = all_reports

    global_counter = [0]  # mutable integer reference across parsers
    all_entries = []

    for report in reports_to_parse:
        print(f"[*] Parsing: {report.name}")
        entries = classify_and_parse(report, global_counter)
        all_entries.extend(entries)

    write_csv(all_entries, output_path)

    print("\n--- Preview (first 5 entries) ---")
    for e in all_entries[:5]:
        print(f"{e.entry_id} | {e.risk_level} | {e.finding_description[:60]}...")

if __name__ == "__main__":
    main()
