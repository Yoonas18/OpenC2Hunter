import time
import uuid


def generate_stix21_bundle(flow: dict) -> dict:
    """
    Generates a valid, standardized OASIS STIX 2.1 JSON bundle
    representing the detected C2 beacon, process attribution, and network infrastructure.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    indicator_id = f"indicator--{uuid.uuid4()}"
    infra_id = f"infrastructure--{uuid.uuid4()}"
    malware_id = f"malware--{uuid.uuid4()}"
    relationship_id = f"relationship--{uuid.uuid4()}"

    dst_ip = flow.get("dst_ip", "0.0.0.0")  # nosec B104
    dst_port = flow.get("dst_port", 443)
    proc_name = flow.get("process_name", "unknown")
    intel_malware = flow.get("intel", {}).get("threatfox_malware") or "Suspected C2 Implant"

    pattern = f"[ipv4-addr:value = '{dst_ip}' AND network-traffic:dst_port = {dst_port}]"

    objects = [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"OpenC2Hunter Detection: C2 Beacon {proc_name} -> {dst_ip}",
            "description": f"Automated pre-compromise detection of C2 beaconing. Jitter: {flow.get('jitter_pct', 0)}%, Mean IAT: {flow.get('avg_iat', 0)}s, Risk: {flow.get('risk_score', 0)}/100.",
            "indicator_types": ["malicious-activity", "c2"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": min(100, int(flow.get("risk_score", 85)))
        },
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"C2 Server Node: {dst_ip}:{dst_port}",
            "infrastructure_types": ["command-and-control"],
            "aliases": [f"{dst_ip}:{dst_port}"]
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": now_iso,
            "modified": now_iso,
            "name": intel_malware,
            "is_family": False,
            "malware_types": ["beacon", "trojan", "bot"]
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": relationship_id,
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": malware_id
        }
    ]

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }

def generate_yara_rule(flow: dict) -> str:
    """
    Generates a targeted YARA detection rule for endpoint memory and disk scanning.
    """
    proc_name = flow.get("process_name", "implant")
    clean_name = "".join(c if c.isalnum() else "_" for c in proc_name)
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port", 0)
    dns_query = flow.get("dns_query") or ""
    raw_hex = flow.get("raw_preview") or ""
    threat_tag = flow.get("intel", {}).get("threatfox_malware") or "C2_Beacon"

    # Hex payload pattern if available
    hex_pattern = ""
    if raw_hex and len(raw_hex) >= 16:
        spaced_hex = " ".join(raw_hex[i:i+2] for i in range(0, min(len(raw_hex), 32), 2))
        hex_pattern = f"        $hex_payload = {{ {spaced_hex} }}"

    yara = f"""rule OpenC2Hunter_C2_{clean_name}_{int(time.time())}
{{
    meta:
        author = "OpenC2Hunter Defense Engine"
        description = "Detects C2 implant artifact associated with {proc_name} -> {dst_ip}:{dst_port}"
        threat_type = "{threat_tag}"
        date = "{time.strftime('%Y-%m-%d')}"
        severity = "HIGH"
        risk_score = {flow.get('risk_score', 90)}

    strings:
        $str_c2_ip = "{dst_ip}" ascii wide nocase
        $str_proc  = "{proc_name}" ascii wide nocase
"""
    if dns_query:
        yara += f'        $str_dns   = "{dns_query}" ascii wide nocase\n'
    if hex_pattern:
        yara += f"{hex_pattern}\n"

    yara += """
    condition:
        uint16(0) == 0x5A4D and ($str_c2_ip or ($str_proc and 1 of ($str_*)))
}"""
    return yara.strip()
