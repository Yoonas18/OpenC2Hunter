import hashlib
import math
import os
import socket
import sqlite3
import threading
import time
from collections import Counter, deque

import psutil
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, sniff

DB_PATH = os.getenv("DB_PATH", "telemetry.db")

def get_local_ips() -> set:
    ips = {"127.0.0.1"}
    try:
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except Exception:
        pass
    return ips

LOCAL_IPS = get_local_ips()
SOCKET_PID_CACHE = {}
PROCESS_HASH_CACHE = {}
FLOW_AGGREGATOR = {}
FLOW_LOCK = threading.Lock()

def analyze_dga_domain(qname: str) -> tuple[float, bool]:
    if not qname:
        return 0.0, False
    parts = [p for p in qname.lower().rstrip(".").split(".") if p]
    if len(parts) < 2:
        return 0.0, False

    label = max(parts[:-1], key=len)
    length = len(label)
    if length < 9:
        return 0.0, False

    counts = Counter(label)
    raw_entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    max_possible = math.log2(min(length, 37))
    norm_entropy = raw_entropy / max_possible if max_possible > 0 else 0.0
    total_bits = raw_entropy * length
    non_vowels = sum(1 for ch in label if ch not in "aeiou-")
    consonant_digit_ratio = non_vowels / length

    is_dga = (total_bits > 42.0) or (
        length >= 12 and norm_entropy > 0.88 and consonant_digit_ratio > 0.70
    )
    return round(raw_entropy, 3), bool(is_dga)

def get_process_identity(exe_path: str, proc_name: str, pid: int) -> tuple[str, int]:
    if exe_path and exe_path != "N/A" and exe_path in PROCESS_HASH_CACHE:
        return PROCESS_HASH_CACHE[exe_path], 0
    try:
        if not exe_path or exe_path == "N/A":
            return f"PROTECTED:{proc_name}:{pid}", 1
        h = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        PROCESS_HASH_CACHE[exe_path] = digest
        return digest, 0
    except Exception:
        return f"PROTECTED:{proc_name}:{pid}", 1

def refresh_socket_pid_map():
    while True:
        new_map = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr and conn.pid:
                    l_ip, l_port = conn.laddr.ip, conn.laddr.port
                    pid = conn.pid
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe = proc.exe() or "N/A"
                        proc_id, is_prot = get_process_identity(exe, name, pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name, exe = "System/Protected", "Protected"
                        proc_id, is_prot = f"PROTECTED:PID_{pid}", 1

                    new_map[(l_ip, l_port)] = (pid, name, exe, proc_id, is_prot)
                    new_map[("0.0.0.0", l_port)] = (pid, name, exe, proc_id, is_prot)  # nosec B104
        except Exception:
            pass
        SOCKET_PID_CACHE.update(new_map)
        time.sleep(1.0)

def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst

    is_outbound = src_ip in LOCAL_IPS and dst_ip not in LOCAL_IPS
    is_inbound = dst_ip in LOCAL_IPS and src_ip not in LOCAL_IPS
    if not (is_outbound or is_inbound):
        return

    now = float(pkt.time)
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
        is_new_session = bool((flags & 0x02) and not (flags & 0x10))
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        is_new_session = False
    else:
        return

    local_ip, local_port = (src_ip, sport) if is_outbound else (dst_ip, dport)
    remote_ip, remote_port = (dst_ip, dport) if is_outbound else (src_ip, sport)

    if remote_ip.startswith(("127.", "224.", "239.", "255.")):
        return

    pid_info = SOCKET_PID_CACHE.get(
        (local_ip, local_port),
        SOCKET_PID_CACHE.get(("0.0.0.0", local_port), (0, "Kernel/Unmapped", "N/A", f"UNMAPPED:{local_port}", 1))  # nosec B104
    )
    pid, proc_name, exe_path, proc_id, is_protected = pid_info

    dns_query, dns_entropy, is_dga = None, 0.0, False
    if is_outbound and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        try:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            dns_query = qname[:253]
            dns_entropy, is_dga = analyze_dga_domain(dns_query)
        except Exception:
            pass

    raw_hex = bytes(pkt[Raw].load)[:48].hex() if pkt.haslayer(Raw) else None
    flow_key = f"{proc_id}|{remote_ip}:{remote_port}|{proto}"

    with FLOW_LOCK:
        if flow_key not in FLOW_AGGREGATOR:
            FLOW_AGGREGATOR[flow_key] = {
                "flow_key": flow_key, "pid": pid, "proc_name": proc_name,
                "exe_path": exe_path, "proc_id": proc_id, "is_protected": is_protected,
                "remote_ip": remote_ip, "remote_port": remote_port, "proto": proto,
                "bytes_sent": 0, "bytes_recv": 0, "session_times": deque(maxlen=50),
                "last_outbound_ts": 0.0, "max_entropy": 0.0, "dns_query": None,
                "is_dga": False, "raw_preview": None
            }
        entry = FLOW_AGGREGATOR[flow_key]

        if is_outbound:
            entry["bytes_sent"] += len(pkt)
            if proto == "UDP" and (now - entry["last_outbound_ts"]) > 2.0:
                is_new_session = True
            if is_new_session:
                entry["session_times"].append(now)
            entry["last_outbound_ts"] = now
        else:
            entry["bytes_recv"] += len(pkt)

        if raw_hex and not entry["raw_preview"]:
            entry["raw_preview"] = raw_hex
        if dns_entropy >= entry["max_entropy"] and dns_query:
            entry["max_entropy"] = dns_entropy
            entry["dns_query"] = dns_query
            entry["is_dga"] = is_dga

def db_flusher_worker():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    last_prune = time.time()

    while True:
        time.sleep(3.0)
        with FLOW_LOCK:
            if not FLOW_AGGREGATOR:
                continue
            snapshot = list(FLOW_AGGREGATOR.values())

        cur = conn.cursor()
        now = time.time()
        for f in snapshot:
            times = list(f["session_times"])
            iat_mean, jitter_pct = 0.0, 100.0
            if len(times) >= 4:
                deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
                iat_mean = sum(deltas) / len(deltas)
                if iat_mean > 0.001:
                    variance = sum((d - iat_mean) ** 2 for d in deltas) / len(deltas)
                    jitter_pct = round((math.sqrt(variance) / iat_mean) * 100.0, 2)

            cur.execute("""
                INSERT OR REPLACE INTO processes (sha256, process_name, exe_path, is_protected)
                VALUES (?, ?, ?, ?)
            """, (f["proc_id"], f["proc_name"], f["exe_path"], f["is_protected"]))

            cur.execute("""
                INSERT OR REPLACE INTO aggregated_flows
                (flow_key, last_seen, pid, process_sha256, dst_ip, dst_port, protocol,
                 session_count, bytes_sent, bytes_recv, avg_iat, jitter_pct,
                 dns_query, dns_entropy, is_dga, raw_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f["flow_key"], now, f["pid"], f["proc_id"], f["remote_ip"],
                f["remote_port"], f["proto"], len(times), f["bytes_sent"],
                f["bytes_recv"], round(iat_mean, 2), jitter_pct,
                f["dns_query"], f["max_entropy"], int(f["is_dga"]), f["raw_preview"]
            ))

        if now - last_prune > 3600:
            cur.execute("DELETE FROM aggregated_flows WHERE last_seen < ?", (now - 86400,))
            last_prune = now

        conn.commit()

if __name__ == "__main__":
    threading.Thread(target=refresh_socket_pid_map, daemon=True).start()
    threading.Thread(target=db_flusher_worker, daemon=True).start()
    sniff(filter="tcp or udp", prn=packet_callback, store=False)
