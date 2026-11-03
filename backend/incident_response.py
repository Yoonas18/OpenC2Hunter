"""
Automated Incident Response, Forensic Triage Bundle & Host Isolation Engine.
Generates comprehensive forensic triage zip archives and manages host quarantine.
"""

import csv
import io
import json
import logging
import platform
import subprocess
import zipfile
from datetime import datetime, timezone
from typing import Any

import psutil

from mitre_attack import map_flow_to_mitre

logger = logging.getLogger("openc2hunter.incident_response")


def generate_triage_bundle(
    flow_data: dict[str, Any],
    memory_strings: dict[str, Any] | None = None,
    blocked_ips: list[str] | None = None,
) -> bytes:
    """
    Generates a full forensic triage archive (.zip) containing:
      1. incident_report.md (SOC Executive Incident Response Report)
      2. telemetry_bundle.json (Structured IOC and threat intelligence data)
      3. extracted_memory_strings.txt (Memory strings and decoded payload artifacts)
      4. host_socket_snapshot.csv (Active system connections at time of triage)
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    zip_buffer = io.BytesIO()

    pid = flow_data.get("pid", 0)
    process_name = flow_data.get("process_name", "Unknown")
    dst_ip = flow_data.get("dst_ip", "0.0.0.0")  # nosec B104
    dst_port = flow_data.get("dst_port", 0)
    risk_score = flow_data.get("risk_score", 0)
    binary_path = flow_data.get("binary_path", "N/A")
    sha256 = flow_data.get("sha256", "N/A")
    dns_query = flow_data.get("dns_query", "N/A")
    entropy = flow_data.get("entropy", 0.0)
    jitter = flow_data.get("jitter_pct", 100.0)
    mitre_matches = map_flow_to_mitre(flow_data)

    # 1. Generate Executive Incident Response Report Markdown
    report_md = f"""# 🚨 OPENC2HUNTER FORENSIC INCIDENT REPORT
**Generated:** {now_str}
**Classification:** TLP:AMBER | STRICT DEFENSIVE DISSEMINATION
**Incident Status:** {'CONTAINED / BLOCKED' if (blocked_ips and dst_ip in blocked_ips) else 'ACTIVE THREAT'}

---

## 1. Executive Incident Summary
An anomalous Command & Control (C2) beacon session was detected and flagged by OpenC2Hunter heuristics.
- **Risk Assessment:** {risk_score}/100 ({'CRITICAL' if risk_score >= 75 else 'HIGH' if risk_score >= 50 else 'MEDIUM'})
- **Target Remote Endpoint:** `{dst_ip}:{dst_port}`
- **Responsible Host Process:** `{process_name}` (PID: `{pid}`)
- **Binary Image Path:** `{binary_path}`
- **SHA256 Hash:** `{sha256}`

---

## 2. Telemetry & Beacon Heuristics
- **Inter-Arrival Time (IAT) Jitter:** `{jitter:.1f}%` (Values < 20% indicate automated heartbeat beaconing)
- **Resolved Domain / DNS Query:** `{dns_query}`
- **Shannon Domain Entropy:** `{entropy:.2f} bits/char` ({'FLAGGED AS DGA' if entropy > 3.5 else 'Normal range'})
- **Total Packets / Bytes Sent:** `{flow_data.get('packets_out', 0)} pkts` / `{flow_data.get('bytes_out', 0)} bytes`

---

## 3. MITRE ATT&CK Enterprise Mapping
The following adversarial techniques were identified during session analysis:
"""
    for m in mitre_matches:
        report_md += f"- **[{m['id']}] {m['name']}** (Tactic: *{m['tactic']}*, Severity: `{m['severity']}`)\n  *{m['description']}*\n"

    report_md += f"""
---

## 4. Host Forensic Context
- **Operating System:** {platform.system()} {platform.release()} ({platform.machine()})
- **Hostname:** {platform.node()}
- **Contained Status:** {'Mitigated and blocked in OS Firewall.' if (blocked_ips and dst_ip in blocked_ips) else 'Requires immediate analyst action!'}

---

## 5. Recommended Containment Playbook
1. Ensure process PID `{pid}` is killed immediately.
2. Maintain outbound firewall drop rules for `{dst_ip}` across all internal gateways.
3. Ingest attached STIX 2.1 & YARA signatures into enterprise EDR / SIEM.
4. Review extracted memory strings below for secondary drop URLs or persistence keys.
"""

    # 2. Memory strings text
    mem_text = f"=== EXTRACTED PROCESS STRINGS & MEMORY FORENSICS ===\nPID: {pid} | Process: {process_name} | Timestamp: {now_str}\n\n"
    if memory_strings:
        mem_text += f"Extracted URLs ({len(memory_strings.get('urls', []))}):\n"
        for u in memory_strings.get("urls", []):
            mem_text += f"  - {u}\n"

        mem_text += f"\nExtracted External IPs ({len(memory_strings.get('ips', []))}):\n"
        for ip in memory_strings.get("ips", []):
            mem_text += f"  - {ip}\n"

        mem_text += f"\nSuspicious Command Sequences ({len(memory_strings.get('suspicious_tokens', []))}):\n"
        for tok in memory_strings.get("suspicious_tokens", []):
            mem_text += f"  - [SUSPICIOUS] {tok}\n"
    else:
        mem_text += "No memory strings were collected or binary was inaccessible at triage time.\n"

    # 3. Live Socket Snapshot CSV
    socket_csv_io = io.StringIO()
    writer = csv.writer(socket_csv_io)
    writer.writerow(["pid", "process_name", "family", "type", "laddr", "lport", "raddr", "rport", "status"])
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}" if conn.laddr else ""
            lport = f"{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}" if conn.raddr else ""
            rport = f"{conn.raddr.port}" if conn.raddr else ""
            pname = "Unknown"
            if conn.pid:
                try:
                    pname = psutil.Process(conn.pid).name()
                except Exception:
                    pass
            writer.writerow([conn.pid, pname, conn.family.name, conn.type.name, laddr, lport, raddr, rport, conn.status])
    except Exception as exc:
        writer.writerow(["N/A", f"Error enumerating sockets: {exc}", "", "", "", "", "", "", ""])

    # Build ZIP package
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("incident_report.md", report_md.encode("utf-8"))
        zf.writestr(
            "telemetry_bundle.json",
            json.dumps({"flow_data": flow_data, "mitre": mitre_matches, "generated_at": now_str}, indent=2).encode("utf-8"),
        )
        zf.writestr("extracted_memory_strings.txt", mem_text.encode("utf-8"))
        zf.writestr("host_socket_snapshot.csv", socket_csv_io.getvalue().encode("utf-8"))

    zip_buffer.seek(0)
    return zip_buffer.getvalue()


def toggle_host_quarantine(enable: bool) -> dict[str, Any]:
    """
    Enables or disables emergency host quarantine isolation rules on Windows or Linux.
    Safely keeps localhost and SOC ports (8000, 3000) open for analyst communication.
    """
    os_type = platform.system()
    rule_name = "OpenC2Hunter_Host_Quarantine"
    success = False
    message = ""

    if os_type == "Windows":
        if enable:
            # Block all outbound TCP traffic except loopback and private ranges
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                "protocol=TCP", "remoteip=0.0.0.0/1,128.0.0.0/1"
            ]
            try:
                res = subprocess.run(cmd, shell=False, capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    success = True
                    message = "Host successfully isolated via Windows Defender Firewall. External C2 blocked."
                else:
                    success = False
                    message = f"Elevation required: {res.stderr or res.stdout}"
            except Exception as e:
                message = str(e)
        else:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            try:
                subprocess.run(cmd, shell=False, capture_output=True, text=True, check=False)
                success = True
                message = "Host quarantine lifted. Normal outbound routing restored."
            except Exception as e:
                message = str(e)
    else:
        # Linux iptables fallback
        if enable:
            cmd = [
                "iptables", "-I", "OUTPUT", "-p", "tcp", "-m", "multiport",
                "--dports", "80,443,8443,8080", "-j", "DROP", "-m", "comment",
                "--comment", rule_name
            ]
        else:
            cmd = [
                "iptables", "-D", "OUTPUT", "-p", "tcp", "-m", "multiport",
                "--dports", "80,443,8443,8080", "-j", "DROP", "-m", "comment",
                "--comment", rule_name
            ]
        try:
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, check=False)
            success = res.returncode == 0
            message = "Quarantine applied via iptables" if enable else "Quarantine removed via iptables"
        except Exception as e:
            message = str(e)

    return {"quarantine_active": enable, "success": success, "detail": message}

