import asyncio
import logging
import os
import sqlite3
import time
from collections import defaultdict

logger = logging.getLogger("openc2hunter.canary")

DB_PATH = os.getenv("DB_PATH", "telemetry.db")
CANARY_BIND_HOST = os.getenv("CANARY_BIND_HOST", "127.0.0.1")

CANARY_SEMAPHORE = asyncio.Semaphore(15)
IP_RATE_LIMIT = defaultdict(list)
ALERT_CALLBACKS = []

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
    4445: {"service": "SMB Trap", "protocol": "tcp", "banner": "\x00\x00\x00\x55\xff\x53\x4d\x42"},
    3389: {"service": "RDP Terminal Service Trap", "protocol": "tcp", "banner": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x0f\x08\x00\x00\x00\x00\x00"},
    2375: {"service": "Docker Daemon REST API Trap", "protocol": "http_ai", "banner": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"Version":"24.0.5","ApiVersion":"1.43"}'}
}

ACTIVE_CANARY_SERVERS = {}

def register_alert_callback(cb):
    """Registers an async callback function for real-time alerting on canary hit."""
    ALERT_CALLBACKS.append(cb)

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
    if port == 2375 or any(k in p_lower for k in ["/containers", "/images/json", "/build"]):
        return "CRITICAL: Docker Escape / Container Breakout Probe"
    if port == 3389:
        return "HIGH: Remote Desktop (RDP) Brute-Force / BlueKeep Scanner"
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
        cfg = HONEY_PORTS.get(port, {"service": f"Custom Trap :{port}", "protocol": "tcp", "banner": "OK\r\n"})
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
        except Exception as e:
            logger.debug(f"Canary socket handled connection on port {port}: {e}")
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

        alert_event = {
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port,
            "port": port,
            "service": cfg["service"],
            "classification": classification,
            "timestamp": time.time()
        }

        # Dispatch alert to callbacks (WebSockets, Webhooks)
        for cb in ALERT_CALLBACKS:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(alert_event))
                else:
                    cb(alert_event)
            except Exception:
                pass

async def start_single_canary_listener(port: int, config: dict):
    """Starts a listener for a single canary port."""
    try:
        server = await asyncio.start_server(
            lambda r, w, p=port: handle_canary_connection(r, w, p),
            host=CANARY_BIND_HOST,
            port=port
        )
        ACTIVE_CANARY_SERVERS[port] = server
        logger.info(f"Canary trap active: {config['service']} on {CANARY_BIND_HOST}:{port}")
        return server
    except OSError as e:
        logger.warning(f"Could not bind canary port {port}: {e}")
        return None

async def start_canary_listeners():
    """Starts all configured honeypot traps."""
    for port, cfg in HONEY_PORTS.items():
        if port not in ACTIVE_CANARY_SERVERS:
            await start_single_canary_listener(port, cfg)

async def add_custom_canary(port: int, service_name: str, banner: str = "OK\r\n", protocol: str = "tcp") -> bool:
    """Dynamically adds and starts a new honeypot deception trap."""
    if port in HONEY_PORTS:
        return False
    cfg = {"service": service_name, "protocol": protocol, "banner": banner}
    HONEY_PORTS[port] = cfg
    server = await start_single_canary_listener(port, cfg)
    return server is not None

def get_active_traps_summary() -> list:
    """Returns a list of all defined honeypot traps and their active bind status."""
    return [
        {
            "port": port,
            "service": cfg["service"],
            "protocol": cfg["protocol"],
            "active": port in ACTIVE_CANARY_SERVERS
        }
        for port, cfg in HONEY_PORTS.items()
    ]
