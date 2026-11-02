import os
import time
import asyncio
import sqlite3
from collections import defaultdict

DB_PATH = os.getenv("DB_PATH", "telemetry.db")
CANARY_BIND_HOST = os.getenv("CANARY_BIND_HOST", "127.0.0.1")

CANARY_SEMAPHORE = asyncio.Semaphore(10)
IP_RATE_LIMIT = defaultdict(list)

HONEY_PORTS = {
    11434: {
        "service": "Ollama Local LLM API",
        "protocol": "http_ai",
        "banner": (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            '{"models":[{"name":"llama3.1:8b-instruct","size":4661224676}]}'
        )
    },
    6379: {"service": "Redis Trap", "protocol": "tcp", "banner": "-ERR NOAUTH Authentication required.\r\n"},
    2222: {"service": "SSH Deception Trap", "protocol": "tcp", "banner": "SSH-2.0-OpenSSH_8.9p1\r\n"},
    4445: {"service": "SMB Trap", "protocol": "tcp", "banner": "\x00\x00\x00\x55\xff\x53\x4d\x42"}
}

def is_rate_limited(attacker_ip: str, max_hits: int = 3, window_sec: int = 600) -> bool:
    now = time.time()
    history = [t for t in IP_RATE_LIMIT[attacker_ip] if now - t < window_sec]
    if len(history) >= max_hits:
        IP_RATE_LIMIT[attacker_ip] = history
        return True
    history.append(now)
    IP_RATE_LIMIT[attacker_ip] = history
    return False

def classify_inbound_probe(port: int, payload_str: str, payload_bytes: bytes) -> str:
    p_lower = payload_str.lower()
    if port == 11434 or any(k in p_lower for k in ["/api/generate", "/api/chat", "/v1/chat/completions"]):
        return "CRITICAL: Autonomous AI Agent / LLM-Jacking Probe"
    if "config set" in p_lower or "slaveof" in p_lower:
        return "CRITICAL: Redis RCE Worm"
    if any(s in p_lower for s in ["nmap", "nuclei", "zgrab", "masscan"]):
        return "HIGH: Automated Vulnerability Scanner"
    if b"SMB" in payload_bytes or payload_bytes.startswith(b"\x16\x03"):
        return "HIGH: Lateral Movement / Stager Probe"
    return f"MEDIUM: Unauthorized Probe on {HONEY_PORTS.get(port, {}).get('service', 'Canary')}"

async def handle_canary_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return
    attacker_ip, attacker_port = str(peer[0]), int(peer[1])

    if is_rate_limited(attacker_ip):
        writer.close()
        return

    async with CANARY_SEMAPHORE:
        cfg = HONEY_PORTS[port]
        payload_bytes = b""
        try:
            if cfg["protocol"] == "tcp":
                writer.write(cfg["banner"].encode("utf-8", errors="ignore"))
                await writer.drain()
                payload_bytes = await asyncio.wait_for(reader.read(256), timeout=3.0)
            else:
                payload_bytes = await asyncio.wait_for(reader.read(512), timeout=3.0)
                writer.write(cfg["banner"].encode("utf-8", errors="ignore"))
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        clipped = payload_bytes[:128]
        payload_preview = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in clipped.decode("ascii", errors="ignore")) or "[SYN/Empty Probe]"
        payload_hex = clipped.hex() if clipped else "00"
        classification = classify_inbound_probe(port, payload_preview, clipped)

        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        conn.execute("""
            INSERT INTO canary_alerts
            (attacker_ip, attacker_port, target_honey_port, service_emulated,
             payload_preview, payload_hex, threat_classification)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (attacker_ip, attacker_port, port, cfg["service"], payload_preview, payload_hex, classification))
        conn.commit()
        conn.close()

async def start_canary_listeners():
    servers = []
    for port in HONEY_PORTS:
        try:
            s = await asyncio.start_server(
                lambda r, w, p=port: handle_canary_connection(r, w, p),
                host=CANARY_BIND_HOST,
                port=port
            )
            servers.append(s)
        except OSError:
            pass
    if servers:
        await asyncio.gather(*(s.serve_forever() for s in servers))
