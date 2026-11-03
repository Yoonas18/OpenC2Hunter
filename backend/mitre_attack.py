"""
MITRE ATT&CK Enterprise Matrix Mapper for OpenC2Hunter.
Maps network telemetry, DGA anomalies, C2 beacon timing, canary decoy probes,
and process memory strings to official MITRE ATT&CK Enterprise Techniques.
"""

from typing import Any

MITRE_TECHNIQUES = {
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS) to blend in with normal network traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "severity": "HIGH",
    },
    "T1568.002": {
        "id": "T1568.002",
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "description": "Adversaries use DGAs to dynamically resolve domain names for C2 fallback, exhibiting high Shannon entropy.",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
        "severity": "CRITICAL",
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries steal and transmit data over existing C2 communications channels back to attacker infrastructure.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "severity": "HIGH",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries abuse interpreters such as PowerShell, Python, cmd.exe, or bash to execute commands and implants.",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "severity": "HIGH",
    },
    "T1090.003": {
        "id": "T1090.003",
        "name": "Proxy: Multi-hop Proxy (Tor / Anonymization)",
        "tactic": "Command and Control",
        "description": "Adversaries route traffic through onion routing networks (Tor) or multiple proxies to mask true origin IP.",
        "url": "https://attack.mitre.org/techniques/T1090/003/",
        "severity": "MEDIUM",
    },
    "T1573.002": {
        "id": "T1573.002",
        "name": "Encrypted Channel: Asymmetric Cryptography",
        "tactic": "Command and Control",
        "description": "Adversaries employ asymmetric cryptography or custom TLS profiles with low session jitter to secure C2.",
        "url": "https://attack.mitre.org/techniques/T1573/002/",
        "severity": "HIGH",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries enumerate internal network services and trigger canary decoy traps on unmapped ports.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "severity": "CRITICAL",
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection / Suspicious Memory Strings",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": "Adversaries inject malicious code or maintain remote command strings inside running process memory.",
        "url": "https://attack.mitre.org/techniques/T1055/",
        "severity": "CRITICAL",
    },
}


def map_flow_to_mitre(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Evaluates a flow dictionary and returns all matching MITRE ATT&CK techniques.
    """
    matches = []
    matched_ids = set()

    dst_port = flow.get("dst_port", 0)
    jitter = flow.get("jitter_pct", 100.0)
    entropy = flow.get("entropy", 0.0)
    proc_name = (flow.get("process_name") or "").lower()
    osint_tags = flow.get("osint_tags") or []
    bytes_out = flow.get("bytes_out", 0)

    # 1. Web protocol C2 (HTTP/HTTPS ports with beaconing)
    if dst_port in (80, 443, 8000, 8080, 8443, 8888, 9001):
        if jitter < 25.0:
            matched_ids.add("T1071.001")
            matched_ids.add("T1573.002")

    # 2. DGA anomaly
    if entropy > 3.5 or flow.get("is_dga"):
        matched_ids.add("T1568.002")

    # 3. High outbound exfil volume over regular connection
    if bytes_out > 500000 and jitter < 30.0:
        matched_ids.add("T1041")

    # 4. Command/Scripting process
    if any(p in proc_name for p in ("python", "powershell", "cmd.exe", "pwsh", "bash", "wscript", "cscript")):
        matched_ids.add("T1059")

    # 5. Tor / Proxy tags from OSINT
    if any(t in str(osint_tags).lower() for t in ("tor", "proxy", "vpn", "anonymizer")):
        matched_ids.add("T1090.003")

    # Format return list
    for tid in matched_ids:
        if tid in MITRE_TECHNIQUES:
            matches.append(MITRE_TECHNIQUES[tid])

    return matches


def get_mitre_summary(flows: list[dict[str, Any]], canary_alerts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """
    Aggregates MITRE coverage and hit counts across all monitored flows and honeytraps.
    """
    technique_counts: dict[str, int] = {k: 0 for k in MITRE_TECHNIQUES}
    tactics_affected: dict[str, int] = {}

    for f in flows:
        matches = map_flow_to_mitre(f)
        for m in matches:
            tid = m["id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            tactic = m["tactic"]
            tactics_affected[tactic] = tactics_affected.get(tactic, 0) + 1

    if canary_alerts:
        canary_hits = len(canary_alerts)
        if canary_hits > 0:
            technique_counts["T1046"] = technique_counts.get("T1046", 0) + canary_hits
            tactics_affected["Discovery"] = tactics_affected.get("Discovery", 0) + canary_hits

    techniques_list = []
    for tid, meta in MITRE_TECHNIQUES.items():
        techniques_list.append({
            **meta,
            "hits": technique_counts.get(tid, 0),
            "active": technique_counts.get(tid, 0) > 0,
        })

    return {
        "techniques": sorted(techniques_list, key=lambda x: x["hits"], reverse=True),
        "tactics": tactics_affected,
        "total_active_techniques": sum(1 for c in technique_counts.values() if c > 0),
        "total_detections": sum(technique_counts.values()),
    }
