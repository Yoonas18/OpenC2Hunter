"""
Autonomous AI Threat Analyst & SOC Copilot for OpenC2Hunter.
Synthesizes telemetry, beacon patterns, DGA entropy, OSINT tags, and memory artifacts
into contextual natural-language investigation briefs and threat actor hypotheses.
"""

from typing import Any

from mitre_attack import map_flow_to_mitre


def analyze_threat_context(flow: dict[str, Any], memory_strings: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Performs autonomous defensive reasoning on a suspicious session.
    Returns executive summary, threat actor profile matching, kill-chain phase,
    and containment playbook.
    """
    proc = flow.get("process_name", "Unknown")
    dst_ip = flow.get("dst_ip", "0.0.0.0")
    dst_port = flow.get("dst_port", 0)
    jitter = flow.get("jitter_pct", 100.0)
    entropy = flow.get("entropy", 0.0)
    risk_score = flow.get("risk_score", 0)
    tags = [t.lower() for t in flow.get("osint_tags", [])]
    threatfox = flow.get("threatfox_malware") or ""
    dns_query = flow.get("dns_query") or ""

    mitre_techniques = map_flow_to_mitre(flow)

    # Heuristic Attribution Engine
    attribution_family = "Unknown / Custom C2 Implant"
    confidence = "MODERATE"
    kill_chain = "Command and Control (Stage 4)"

    # Sliver C2 fingerprinting
    if "sliver" in threatfox.lower() or "sliver" in str(tags) or (dst_port in (8443, 8888, 31337) and jitter < 15.0):
        attribution_family = "Sliver C2 Framework (BishopFox Open-Source Implant)"
        confidence = "HIGH"
        kill_chain = "Command and Control / Interactive Operator Shell"

    # Cobalt Strike fingerprinting
    elif "cobalt" in threatfox.lower() or "strike" in str(tags) or (dst_port in (50050, 443, 80) and jitter < 10.0 and "python" not in proc.lower()):
        attribution_family = "Cobalt Strike Malleable C2 Beacon"
        confidence = "HIGH"
        kill_chain = "Post-Exploitation / Lateral Staging"

    # Feodo / Qakbot / Emotet
    elif any(mal in str(tags) for mal in ("qakbot", "emotet", "feodo", "dridex", "botnet")):
        attribution_family = "Automated Botnet / Banking Trojan Loader"
        confidence = "HIGH"
        kill_chain = "Initial Foothold & Payload Execution"

    # Living off the land (Scripting)
    elif any(script in proc.lower() for script in ("python", "powershell", "cmd.exe", "pwsh", "wscript")):
        attribution_family = f"Living-off-the-Land Scripted Implant ({proc})"
        confidence = "MODERATE"
        kill_chain = "Execution / Interactive Script C2"

    # Dynamic summary generation
    beacon_desc = (
        f"exhibiting extreme heartbeat periodicity (Jitter: {jitter:.1f}%)"
        if jitter < 20.0
        else f"displaying sporadic session pulses (Jitter: {jitter:.1f}%)"
    )

    dga_desc = (
        f"DNS query '{dns_query}' exhibits high Shannon entropy ({entropy:.2f} bits/char), indicating automated Domain Generation Algorithm (DGA) evasion."
        if entropy > 3.5
        else "DNS resolution appears structured without apparent DGA perturbation."
    )

    exec_summary = (
        f"Autonomous analysis indicates host process '{proc}' is maintaining an outbound session with {dst_ip}:{dst_port}, "
        f"{beacon_desc}. {dga_desc} "
        f"Overall calculated adversarial risk stands at {risk_score}/100."
    )

    # Actionable containment steps
    actions = [
        f"Immediately terminate host process PID {flow.get('pid', 'N/A')} ({proc})",
        f"Add directional firewall block rule for target IP {dst_ip}",
        "Isolate host from internal subnet to prevent lateral movement",
        "Export STIX 2.1 IOC bundle and propagate to perimeter security controls",
    ]

    if memory_strings and memory_strings.get("urls"):
        actions.append(f"Block {len(memory_strings['urls'])} extracted URLs identified inside process memory")

    urgency = "IMMEDIATE_ACTION_REQUIRED" if risk_score >= 75 else "HIGH_PRIORITY_REVIEW" if risk_score >= 50 else "INFORMATIONAL"

    return {
        "status": "COMPLETED",
        "risk_score": risk_score,
        "urgency": urgency,
        "executive_summary": exec_summary,
        "attribution_hypothesis": attribution_family,
        "attribution_confidence": confidence,
        "kill_chain_stage": kill_chain,
        "mitre_techniques": mitre_techniques,
        "recommended_actions": actions,
        "key_indicators": {
            "remote_socket": f"{dst_ip}:{dst_port}",
            "process": proc,
            "pid": flow.get("pid"),
            "jitter_pct": jitter,
            "entropy": entropy,
            "dns_query": dns_query,
        },
    }

