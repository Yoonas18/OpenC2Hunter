import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import platform
import secrets
import sqlite3
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psutil
from ai_threat_analyst import analyze_threat_context
from canary_deception import (
    add_custom_canary,
    get_active_traps_summary,
    register_alert_callback,
    start_canary_listeners,
)
from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from forensic_pcap import parse_pcap_forensics
from incident_response import generate_triage_bundle, toggle_host_quarantine
from mitre_attack import get_mitre_summary, map_flow_to_mitre
from process_memory import inspect_process_memory_and_binary
from pydantic import BaseModel
from threat_export import generate_stix21_bundle, generate_yara_rule
from threat_intel_feed import check_intel_indicator, init_intel_table, sync_external_feeds
from url_analyzer import (
    analyze_with_urlscan,
    is_private_or_internal_target,
    lookup_urlhaus_local,
    sync_urlhaus_bulk_feed,
)
from webhooks import send_discord_alert, send_slack_alert

# --- Structured Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("openc2hunter.engine")

DB_PATH = os.getenv("DB_PATH", "telemetry.db")
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSE_CH_KEY = os.getenv("ABUSE_CH_KEY", "")
ENABLE_CANARIES = os.getenv("ENABLE_CANARIES", "false").lower() == "true"
SESSION_TOKEN = os.getenv("OPENC2_SESSION_TOKEN") or secrets.token_urlsafe(32)

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "superadmin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "OpenC2Hunter@2026!")

# Active sessions store (session token -> expiry/metadata)
ACTIVE_SESSIONS = {SESSION_TOKEN: {"username": ADMIN_USERNAME, "created_at": time.time()}}

PROTECTED_PROCESS_NAMES = {
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "msmpeng.exe",
    "systemd", "init", "launchd", "kernel_task", "sshd", "dockerd", "python", "python3", "python.exe"
}
SAFE_INFRA_IPS = {"127.0.0.1", "0.0.0.0", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}

def hash_password(password: str, salt: bytes | None = None) -> str:
    """Derives a PBKDF2-HMAC-SHA256 password hash for hardened credential storage."""
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"pbkdf2:sha256:100000:{salt.hex()}:{key.hex()}"

def verify_password(plain_password: str, stored_hash_or_plain: str) -> bool:
    """Validates passwords securely against PBKDF2 hashes or plaintext configs with timing safety."""
    if stored_hash_or_plain.startswith("pbkdf2:sha256:"):
        parts = stored_hash_or_plain.split(":")
        if len(parts) == 5:
            iterations = int(parts[2])
            salt = bytes.fromhex(parts[3])
            expected_key = parts[4]
            actual_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations).hex()
            return secrets.compare_digest(actual_key, expected_key)
    return secrets.compare_digest(plain_password, stored_hash_or_plain)

# --- Real-Time WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, event_type: str, data: dict):
        if not self.active_connections:
            return
        payload = json.dumps({"event": event_type, "data": data, "timestamp": time.time()})
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Asynchronous handler called whenever a canary trap fires
async def on_canary_alert_dispatched(alert_event: dict):
    # Broadcast to live UI via WebSockets
    await ws_manager.broadcast("canary_alert", alert_event)
    
    # Auto-dispatch webhooks if configured
    threat_info = {
        "title": f"Canary Trap Tripped: {alert_event.get('service')}",
        "description": f"Internal probe detected from {alert_event.get('attacker_ip')}:{alert_event.get('attacker_port')}",
        "target": f"Port {alert_event.get('port')}",
        "process": alert_event.get("service"),
        "risk_score": 85,
        "attribution": alert_event.get("classification")
    }
    if DISCORD_WEBHOOK_URL:
        asyncio.create_task(send_discord_alert(DISCORD_WEBHOOK_URL, threat_info))
    if SLACK_WEBHOOK_URL:
        asyncio.create_task(send_slack_alert(SLACK_WEBHOOK_URL, threat_info))

register_alert_callback(on_canary_alert_dispatched)

def init_db_schema():
    schema_file = Path(__file__).parent / "schema.sql"
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    if schema_file.exists():
        conn.executescript(schema_file.read_text(encoding="utf-8"))
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_schema()
    init_intel_table(DB_PATH)
    threading.Thread(target=sync_urlhaus_bulk_feed, daemon=True).start()
    asyncio.create_task(sync_external_feeds(DB_PATH))
    if ENABLE_CANARIES:
        asyncio.create_task(start_canary_listeners())
    yield

app = FastAPI(title="OpenC2Hunter Enterprise Threat Engine", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-OpenC2-Token", "Content-Type"],
)

class LoginRequest(BaseModel):
    username: str
    password: str

class CanaryTrapRequest(BaseModel):
    port: int
    service_name: str
    banner: str = "OK\r\n"
    protocol: str = "tcp"

class WebhookTestRequest(BaseModel):
    webhook_url: str
    platform: str = "discord"

class QuarantineRequest(BaseModel):
    enable: bool

class AIInvestigateRequest(BaseModel):
    flow: dict[str, Any]

class TriageBundleRequest(BaseModel):
    flow: dict[str, Any]

FAILED_LOGINS = {}

@app.post("/api/v1/auth/login")
def login(creds: LoginRequest):
    now = time.time()
    ip_key = creds.username.lower()
    recent_failures = [t for t in FAILED_LOGINS.get(ip_key, []) if now - t < 300]
    FAILED_LOGINS[ip_key] = recent_failures

    if len(recent_failures) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Gateway locked for 5 minutes."
        )

    user_match = secrets.compare_digest(creds.username, ADMIN_USERNAME)
    pass_match = verify_password(creds.password, ADMIN_PASSWORD)

    if not (user_match and pass_match):
        FAILED_LOGINS.setdefault(ip_key, []).append(now)
        raise HTTPException(status_code=401, detail="Invalid administrator credentials.")

    FAILED_LOGINS.pop(ip_key, None)
    new_token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[new_token] = {"username": ADMIN_USERNAME, "created_at": now}

    logger.info(f"Administrator authenticated successfully. New session: {new_token[:8]}...")
    return {
        "status": "authenticated",
        "token": new_token,
        "username": ADMIN_USERNAME,
        "expires_in": 86400
    }

@app.get("/api/v1/auth/verify")
def check_auth(x_openc2_token: str = Header(...)):
    if x_openc2_token not in ACTIVE_SESSIONS and not secrets.compare_digest(x_openc2_token, SESSION_TOKEN):
        raise HTTPException(status_code=403, detail="Session expired or invalid.")
    return {"status": "valid", "username": ADMIN_USERNAME}

@app.post("/api/v1/auth/logout")
def logout(x_openc2_token: str = Header(...)):
    ACTIVE_SESSIONS.pop(x_openc2_token, None)
    return {"status": "logged_out"}

def verify_token(x_openc2_token: str = Header(...)):
    is_valid = (
        x_openc2_token in ACTIVE_SESSIONS
        or secrets.compare_digest(x_openc2_token, SESSION_TOKEN)
    )
    if not is_valid:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or expired X-OpenC2-Token")

def is_safe_blockable_ip(ip_str: str) -> bool:
    if not ip_str or ip_str in SAFE_INFRA_IPS:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_global
            and not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
        )
    except ValueError:
        return False

# --- WebSockets Telemetry Endpoint ---
@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket, token: str | None = None):
    # Validate session token if provided
    if token and token not in ACTIVE_SESSIONS and not secrets.compare_digest(token, SESSION_TOKEN):
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            client_msg = await websocket.receive_text()
            if client_msg == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# --- Telemetry & Graphs ---
@app.get("/api/v1/graph-stats", dependencies=[Depends(verify_token)])
def get_dashboard_graph_and_stats():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("SELECT ip FROM blocked_ips")
        blocked_ips = [r[0] for r in cur.fetchall()]
    except sqlite3.OperationalError:
        blocked_ips = []

    blocked_set = set(blocked_ips)

    cur.execute("""
        SELECT f.flow_key, f.dst_ip, f.dst_port, f.protocol, f.pid,
               f.process_sha256, p.process_name, p.exe_path, p.is_protected,
               f.session_count, f.bytes_sent, f.bytes_recv,
               f.avg_iat, f.jitter_pct, f.dns_query, f.dns_entropy, f.is_dga,
               f.raw_preview, COALESCE(o.risk_score, 0) as osint_risk, o.source_hits
        FROM aggregated_flows f
        LEFT JOIN processes p ON f.process_sha256 = p.sha256
        LEFT JOIN osint_cache o ON f.dst_ip = o.ioc_value
        ORDER BY f.last_seen DESC LIMIT 100
    """)
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        is_blocked = d["dst_ip"] in blocked_set
        d["is_blocked"] = is_blocked
        behavioral_score = int(d["osint_risk"])
        if d["session_count"] >= 6 and d["jitter_pct"] < 20.0 and d["avg_iat"] >= 5.0:
            behavioral_score = max(behavioral_score, 80)
        if d["is_dga"]:
            behavioral_score = max(behavioral_score, 85)
        d["intel"] = json.loads(d["source_hits"]) if d.get("source_hits") else {}
        
        # Check offline/synced threat intelligence cache
        feed_hit = check_intel_indicator(d["dst_ip"], db_path=DB_PATH)
        if feed_hit:
            d["intel"]["threat_feed"] = feed_hit["threat_family"]
            behavioral_score = max(behavioral_score, feed_hit["confidence"])

        d["risk_score"] = 0 if is_blocked else min(100, behavioral_score)
        d["mitre_techniques"] = map_flow_to_mitre(d)
        rows.append(d)
    conn.close()
    return {"flows": rows, "blocked_ips": blocked_ips}

# --- Forensic PCAP Upload & Replay ---
@app.post("/api/v1/forensics/upload-pcap", dependencies=[Depends(verify_token)])
async def upload_pcap_forensics(file: UploadFile = File(...)):
    """Accepts and parses an uploaded PCAP or PCAPNG packet capture for offline threat hunting."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap packet captures are supported.")

    file_bytes = await file.read()
    if len(file_bytes) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="File too large. Maximum PCAP size is 50MB.")

    try:
        report = parse_pcap_forensics(file_bytes, db_path=DB_PATH)
        # Notify connected dashboard clients of new forensic flows
        asyncio.create_task(ws_manager.broadcast("pcap_analyzed", report))
        return report
    except Exception as e:
        logger.error(f"Error parsing forensic PCAP: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {e}")

# --- Process Memory Strings Inspector ---
@app.get("/api/v1/process-memory-strings", dependencies=[Depends(verify_token)])
def get_process_memory_strings(pid: int):
    """Inspects binary and runtime memory strings for a given PID to detect embedded C2 artifacts."""
    if pid <= 0:
        raise HTTPException(status_code=400, detail="Invalid PID")
    res = inspect_process_memory_and_binary(pid)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res

# --- Threat Intel Exporters (STIX 2.1 & YARA) ---
@app.get("/api/v1/export/stix", dependencies=[Depends(verify_token)])
def export_stix_bundle(dst_ip: str, proc_name: str = "implant", risk: int = 90):
    flow_mock = {
        "dst_ip": dst_ip,
        "process_name": proc_name,
        "risk_score": risk,
        "avg_iat": 60.0,
        "jitter_pct": 5.0,
        "intel": {"threatfox_malware": "Detected C2 Channel"}
    }
    return generate_stix21_bundle(flow_mock)

@app.get("/api/v1/export/yara", dependencies=[Depends(verify_token)])
def export_yara_rule_endpoint(dst_ip: str, proc_name: str = "implant", dns: str = "", hex_preview: str = ""):
    flow_mock = {
        "dst_ip": dst_ip,
        "process_name": proc_name,
        "dns_query": dns,
        "raw_preview": hex_preview,
        "risk_score": 90
    }
    return {"rule": generate_yara_rule(flow_mock)}

# --- Custom Honeypot Deception Traps ---
@app.get("/api/v1/canary/traps", dependencies=[Depends(verify_token)])
def list_canary_traps():
    return {"traps": get_active_traps_summary()}

@app.post("/api/v1/canary/add-trap", dependencies=[Depends(verify_token)])
async def add_canary_trap_endpoint(req: CanaryTrapRequest):
    if req.port < 1 or req.port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port number")
    success = await add_custom_canary(req.port, req.service_name, req.banner, req.protocol)
    if not success:
        raise HTTPException(status_code=400, detail=f"Port {req.port} is already configured or could not be bound.")
    return {"status": "started", "port": req.port, "service": req.service_name}

# --- Webhook Dispatch Test ---
@app.post("/api/v1/webhooks/test", dependencies=[Depends(verify_token)])
async def test_webhook(req: WebhookTestRequest):
    test_threat = {
        "title": "OpenC2Hunter Webhook Verification",
        "description": "Integration test from OpenC2Hunter SOC Threat Defense Gateway",
        "target": "185.220.101.45:8443",
        "process": "test_implant.exe",
        "pid": 1337,
        "risk_score": 95,
        "attribution": "Sliver C2 Simulation Test"
    }
    if req.platform.lower() == "slack":
        ok = await send_slack_alert(req.webhook_url, test_threat)
    else:
        ok = await send_discord_alert(req.webhook_url, test_threat)

    if not ok:
        raise HTTPException(status_code=400, detail="Webhook delivery failed. Verify URL endpoint.")
    return {"status": "success", "message": f"Test alert dispatched to {req.platform}"}

# --- Mitigation & Firewall Controls ---
@app.get("/api/v1/blocked-ips", dependencies=[Depends(verify_token)])
def get_blocked_ips():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    cur = conn.cursor()
    try:
        cur.execute("SELECT ip, pid, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
        items = [{"ip": r[0], "pid": r[1], "reason": r[2], "blocked_at": r[3]} for r in cur.fetchall()]
    except sqlite3.OperationalError:
        items = []
    conn.close()
    return {"blocked_ips": items}

@app.post("/api/v1/unblock", dependencies=[Depends(verify_token)])
def unblock_host(dst_ip: str):
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (dst_ip,))
    conn.commit()
    conn.close()

    os_name = platform.system()
    try:
        if os_name == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=OpenC2Block_{dst_ip}"], check=False, capture_output=True)
        elif os_name == "Linux":
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", dst_ip, "-j", "DROP"], check=False, capture_output=True)
    except Exception:
        pass

    return {"status": "unblocked", "ip": dst_ip}

@app.get("/api/v1/canary-alerts", dependencies=[Depends(verify_token)])
def get_canary_alerts():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM canary_alerts ORDER BY id DESC LIMIT 50")
    alerts = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "enabled": ENABLE_CANARIES,
        "active_traps": get_active_traps_summary() if ENABLE_CANARIES else [],
        "alerts": alerts
    }

@app.post("/api/v1/mitigate", dependencies=[Depends(verify_token)])
def active_contain_host(dst_ip: str, pid: int | None = None):
    if not is_safe_blockable_ip(dst_ip):
        raise HTTPException(status_code=400, detail=f"Refusing to block protected or private IP: {dst_ip}")

    actions = []
    if pid is not None:
        if pid <= 4 or pid == os.getpid():
            raise HTTPException(status_code=400, detail="Refusing to terminate system or self PID")
        try:
            proc = psutil.Process(pid)
            if proc.name().lower() in PROTECTED_PROCESS_NAMES:
                raise HTTPException(status_code=400, detail=f"Refusing to terminate critical process: {proc.name()}")
            proc.terminate()
            actions.append(f"Terminated PID {pid} ({proc.name()})")
        except psutil.NoSuchProcess:
            actions.append(f"PID {pid} already exited")
        except psutil.AccessDenied:
            raise HTTPException(status_code=403, detail=f"OS denied terminating PID {pid}")

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, pid, reason, blocked_at) VALUES (?, ?, ?, ?)",
        (dst_ip, pid, "Mitigated via Dashboard", time.time())
    )
    conn.commit()
    conn.close()
    actions.append(f"Recorded permanent containment for {dst_ip}")

    os_name = platform.system()
    try:
        if os_name == "Windows":
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name=OpenC2Block_{dst_ip}", "dir=out", "action=block", f"remoteip={dst_ip}"]
        elif os_name == "Linux":
            cmd = ["iptables", "-A", "OUTPUT", "-d", dst_ip, "-j", "DROP"]
        elif os_name == "Darwin":
            cmd = ["pfctl", "-t", "openc2_block", "-T", "add", dst_ip]
        else:
            raise HTTPException(status_code=400, detail="Unsupported OS")

        subprocess.run(cmd, check=True, capture_output=True)
        actions.append(f"Applied OS firewall block to {dst_ip}")
    except Exception as e:
        actions.append(f"OS firewall notice: Run BLOCK_C2_FIREWALL.bat as Admin if OS blocked netsh call ({str(e)[:60]})")

    return {"status": "completed", "actions": actions, "blocked_ip": dst_ip}

@app.get("/api/v1/analyze-url", dependencies=[Depends(verify_token)])
async def analyze_suspicious_url(target: str, detonate: bool = False):
    if is_private_or_internal_target(target):
        raise HTTPException(status_code=400, detail="Refusing to analyze private/internal address")
    urlhaus_hit = lookup_urlhaus_local(target)
    urlscan_data = await analyze_with_urlscan(target, explicit_user_detonate=detonate)
    combined_risk = 100 if urlhaus_hit else urlscan_data.get("verdict_score", 0)
    return {"target": target, "combined_risk_score": combined_risk, "urlhaus": urlhaus_hit, "urlscan": urlscan_data}

# --- MITRE ATT&CK Matrix Navigator Endpoint ---
@app.get("/api/v1/mitre/matrix", dependencies=[Depends(verify_token)])
def get_mitre_matrix_endpoint():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT f.*, p.process_name 
        FROM aggregated_flows f
        LEFT JOIN processes p ON f.process_sha256 = p.sha256
        ORDER BY f.last_seen DESC LIMIT 100
    """)
    flows = [dict(r) for r in cur.fetchall()]
    try:
        cur.execute("SELECT * FROM canary_alerts ORDER BY id DESC LIMIT 50")
        canaries = [dict(r) for r in cur.fetchall()]
    except Exception:
        canaries = []
    conn.close()

    return get_mitre_summary(flows, canaries)

# --- Incident Response Triage Bundle Download ---
@app.post("/api/v1/incident/triage-bundle", dependencies=[Depends(verify_token)])
def download_incident_triage_bundle(req: TriageBundleRequest):
    flow = req.flow
    pid = flow.get("pid", 0)
    mem_data = None
    if pid > 0:
        mem_data = inspect_process_memory_and_binary(pid)

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        cur = conn.cursor()
        cur.execute("SELECT ip FROM blocked_ips")
        blocked_ips = [r[0] for r in cur.fetchall()]
    except Exception:
        blocked_ips = []
    conn.close()

    zip_bytes = generate_triage_bundle(flow, mem_data, blocked_ips)
    filename = f"triage_bundle_{flow.get('dst_ip', 'threat')}_{int(time.time())}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# --- Host Isolation / Emergency Quarantine ---
@app.post("/api/v1/incident/quarantine", dependencies=[Depends(verify_token)])
def emergency_host_quarantine(req: QuarantineRequest):
    res = toggle_host_quarantine(req.enable)
    # Broadcast event to frontend
    asyncio.create_task(ws_manager.broadcast("quarantine_status", res))
    return res

# --- Autonomous AI Threat Analyst Copilot ---
@app.post("/api/v1/ai/investigate", dependencies=[Depends(verify_token)])
def ai_investigate_flow(req: AIInvestigateRequest):
    flow = req.flow
    pid = flow.get("pid", 0)
    mem_data = None
    if pid > 0:
        mem_data = inspect_process_memory_and_binary(pid)
    analysis = analyze_threat_context(flow, mem_data)
    return analysis

# --- Live Threat Intel Cache Sync & Query ---
@app.post("/api/v1/threat-intel/sync", dependencies=[Depends(verify_token)])
async def sync_threat_feeds_endpoint():
    res = await sync_external_feeds(DB_PATH)
    return res

@app.get("/api/v1/threat-intel/check", dependencies=[Depends(verify_token)])
def query_threat_intel(indicator: str):
    hit = check_intel_indicator(indicator, DB_PATH)
    return hit or {"matched": False, "indicator": indicator}
