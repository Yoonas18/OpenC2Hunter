import io
import math
import sqlite3
import time
from collections import deque
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap
from sniffer_daemon import analyze_dga_domain


def parse_pcap_forensics(file_bytes: bytes, db_path: str = "telemetry.db") -> dict:
    """
    Parses an uploaded PCAP / PCAPNG packet capture file, reconstructs flows,
    analyzes beacon jitter, DGA domain entropy, extracts raw payloads,
    and inserts the attributed forensic flows into the database.
    """
    try:
        packets = rdpcap(io.BytesIO(file_bytes))
    except Exception as e:
        raise ValueError(f"Invalid PCAP format or corrupted file: {e}")

    flow_aggregates = {}
    total_packets = len(packets)
    dns_queries_found = 0
    dga_detections = 0

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_time = float(pkt.time)

        proto = "OTHER"
        sport, dport = 0, 0
        is_new_session = False

        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            is_new_session = bool((flags & 0x02) and not (flags & 0x10))
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)

        flow_key = f"PCAP|{src_ip}->{dst_ip}:{dport}|{proto}"

        # DNS Query Inspection
        dns_query = None
        dns_entropy = 0.0
        is_dga = False
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                dns_query = qname[:253]
                dns_entropy, is_dga = analyze_dga_domain(dns_query)
                dns_queries_found += 1
                if is_dga:
                    dga_detections += 1
            except Exception:
                pass

        raw_hex = bytes(pkt[Raw].load)[:48].hex() if pkt.haslayer(Raw) else None

        if flow_key not in flow_aggregates:
            flow_aggregates[flow_key] = {
                "flow_key": flow_key,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dport,
                "protocol": proto,
                "pid": 0,
                "process_name": "pcap_forensic_replay",
                "exe_path": f"/forensics/replay/{Path(dst_ip).stem}",
                "process_sha256": f"PCAP_REPLAY:{dst_ip}:{dport}",
                "bytes_sent": 0,
                "bytes_recv": 0,
                "session_times": deque(maxlen=100),
                "last_ts": 0.0,
                "max_entropy": 0.0,
                "dns_query": None,
                "is_dga": False,
                "raw_preview": None
            }

        entry = flow_aggregates[flow_key]
        entry["bytes_sent"] += len(pkt)

        if proto == "UDP" and (pkt_time - entry["last_ts"]) > 2.0:
            is_new_session = True

        if is_new_session:
            entry["session_times"].append(pkt_time)

        entry["last_ts"] = pkt_time

        if raw_hex and not entry["raw_preview"]:
            entry["raw_preview"] = raw_hex

        if dns_entropy >= entry["max_entropy"] and dns_query:
            entry["max_entropy"] = dns_entropy
            entry["dns_query"] = dns_query
            entry["is_dga"] = is_dga

    # Calculate metrics and insert into database
    conn = sqlite3.connect(db_path, timeout=15.0)
    cur = conn.cursor()
    now = time.time()
    results = []

    for f in flow_aggregates.values():
        times = list(f["session_times"])
        iat_mean, jitter_pct = 0.0, 100.0
        if len(times) >= 3:
            deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
            iat_mean = sum(deltas) / len(deltas)
            if iat_mean > 0.001:
                variance = sum((d - iat_mean) ** 2 for d in deltas) / len(deltas)
                jitter_pct = round((math.sqrt(variance) / iat_mean) * 100.0, 2)

        risk_score = 0
        if len(times) >= 4 and jitter_pct < 25.0 and iat_mean >= 3.0:
            risk_score = max(risk_score, 85)
        if f["is_dga"]:
            risk_score = max(risk_score, 90)

        f["avg_iat"] = round(iat_mean, 2)
        f["jitter_pct"] = jitter_pct
        f["risk_score"] = risk_score

        # Insert process and flow
        cur.execute("""
            INSERT OR REPLACE INTO processes (sha256, process_name, exe_path, is_protected)
            VALUES (?, ?, ?, 0)
        """, (f["process_sha256"], f["process_name"], f["exe_path"]))

        cur.execute("""
            INSERT OR REPLACE INTO aggregated_flows
            (flow_key, last_seen, pid, process_sha256, dst_ip, dst_port, protocol,
             session_count, bytes_sent, bytes_recv, avg_iat, jitter_pct,
             dns_query, dns_entropy, is_dga, raw_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f["flow_key"], now, f["pid"], f["process_sha256"], f["dst_ip"],
            f["dst_port"], f["protocol"], max(len(times), 1), f["bytes_sent"],
            f["bytes_recv"], round(iat_mean, 2), jitter_pct,
            f["dns_query"], f["max_entropy"], int(f["is_dga"]), f["raw_preview"]
        ))

        results.append({
            "flow_key": f["flow_key"],
            "dst_ip": f["dst_ip"],
            "dst_port": f["dst_port"],
            "protocol": f["protocol"],
            "risk_score": risk_score,
            "is_dga": f["is_dga"],
            "dns_query": f["dns_query"],
            "avg_iat": f["avg_iat"],
            "jitter_pct": f["jitter_pct"]
        })

    conn.commit()
    conn.close()

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "status": "completed",
        "total_packets": total_packets,
        "flows_discovered": len(flow_aggregates),
        "dns_queries_analyzed": dns_queries_found,
        "dga_detections": dga_detections,
        "critical_flows": [r for r in results if r["risk_score"] >= 70],
        "top_flows": results[:15]
    }
