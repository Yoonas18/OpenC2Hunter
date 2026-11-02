import os
import time
import json
import secrets
import sqlite3
import ipaddress
import platform
import threading
import subprocess
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
import psutil
import httpx
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from url_analyzer import sync_urlhaus_bulk_feed, lookup_urlhaus_local, analyze_with_urlscan, is_private_or_internal_target
from canary_deception import start_canary_listeners, HONEY_PORTS

DB_PATH = os.getenv("DB_PATH", "telemetry.db")
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSE_CH_KEY = os.getenv("ABUSE_CH_KEY", "")
ENABLE_CANARIES = os.getenv("ENABLE_CANARIES", "false").lower() == "true"
SESSION_TOKEN = os.getenv("OPENC2_SESSION_TOKEN") or secrets.token_urlsafe(32)

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

def init_db_schema():
    schema_file = Path(__file__).parent / "schema.sql"
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    if schema_file.exists():
        conn.executescript(schema_file.read_text(encoding="utf-8"))
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_schema()
    threading.Thread(target=sync_urlhaus_bulk_feed, daemon=True).start()
    if ENABLE_CANARIES:
        asyncio.create_task(start_canary_listeners())
    yield

app = FastAPI(title="OpenC2Hunter Hardened API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["X-OpenC2-Token", "Content-Type"],
)

class LoginRequest(BaseModel):
    username: str
    password: str

FAILED_LOGINS = {}

@app.post("/api/v1/auth/login")
def login(creds: LoginRequest):
    now = time.time()
    # Simple rate-limit check (5 failed attempts per 5 minutes)
    ip_key = creds.username.lower()
    recent_failures = [t for t in FAILED_LOGINS.get(ip_key, []) if now - t < 300]
    FAILED_LOGINS[ip_key] = recent_failures

    if len(recent_failures) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Gateway locked for 5 minutes."
        )

    user_match = secrets.compare_digest(creds.username, ADMIN_USERNAME)
    pass_match = secrets.compare_digest(creds.password, ADMIN_PASSWORD)

    if not (user_match and pass_match):
        FAILED_LOGINS.setdefault(ip_key, []).append(now)
        raise HTTPException(status_code=401, detail="Invalid administrator credentials.")

    # Successful login: clear failures and issue token
    FAILED_LOGINS.pop(ip_key, None)
    new_token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[new_token] = {"username": ADMIN_USERNAME, "created_at": now}

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

async def enrich_ioc(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type == "ip" and not is_safe_blockable_ip(ioc_value):
        return {"ioc": ioc_value, "risk_score": 0, "intel": {}, "cached": True}

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    cur = conn.cursor()
    cur.execute("SELECT risk_score, source_hits FROM osint_cache WHERE ioc_value = ?", (ioc_value,))
    row = cur.fetchone()
    if row:
        conn.close()
        return {"ioc": ioc_value, "risk_score": row[0], "intel": json.loads(row[1]), "cached": True}

    intel_summary, risk_score = {}, 0
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            if ioc_type == "ip":
                r = await client.get(f"https://internetdb.shodan.io/{ioc_value}")
                if r.status_code == 200:
                    data = r.json()
                    intel_summary["shodan_ports"] = data.get("ports", [])
                    intel_summary["shodan_tags"] = data.get("tags", [])
                    intel_summary["vulns"] = data.get("vulns", [])
                    if any(t in ["c2", "malware", "compromised", "tor"] for t in intel_summary["shodan_tags"]):
                        risk_score += 60

                tf_headers = {"Auth-Key": ABUSE_CH_KEY} if ABUSE_CH_KEY else {}
                tf_resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": ioc_value},
                    headers=tf_headers
                )
                if tf_resp.status_code == 200 and tf_resp.json().get("query_status") == "ok":
                    hit = tf_resp.json()["data"][0]
                    intel_summary["threatfox_malware"] = hit.get("malware_printable")
                    risk_score = 95

            elif ioc_type == "hash" and len(ioc_value) == 64 and not ioc_value.startswith("PROTECTED:"):
                if VT_API_KEY:
                    vt_resp = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{ioc_value}",
                        headers={"x-apikey": VT_API_KEY}
                    )
                    if vt_resp.status_code == 200:
                        stats = vt_resp.json()["data"]["attributes"]["last_analysis_stats"]
                        mal = stats.get("malicious", 0)
                        intel_summary["vt_detections"] = f"{mal}/{sum(stats.values())}"
                        if mal > 0:
                            risk_score = min(100, 40 + (mal * 10))
    except Exception:
        pass

    cur.execute(
        "INSERT OR REPLACE INTO osint_cache (ioc_value, ioc_type, risk_score, source_hits, last_updated) VALUES (?, ?, ?, ?, ?)",
        (ioc_value, ioc_type, risk_score, json.dumps(intel_summary), time.time())
    )
    conn.commit()
    conn.close()
    return {"ioc": ioc_value, "risk_score": risk_score, "intel": intel_summary, "cached": False}

@app.get("/api/v1/graph-stats", dependencies=[Depends(verify_token)])
def get_dashboard_graph_and_stats():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Load persistent blocked IPs
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
        # Blocked / neutralized flows are cleared of active risk
        d["risk_score"] = 0 if is_blocked else min(100, behavioral_score)
        d["intel"] = json.loads(d["source_hits"]) if d.get("source_hits") else {}
        rows.append(d)
    conn.close()
    return {"flows": rows, "blocked_ips": blocked_ips}

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
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=OpenC2Block_{dst_ip}"], capture_output=True)
        elif os_name == "Linux":
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", dst_ip, "-j", "DROP"], capture_output=True)
    except Exception:
        pass

    return {"status": "unblocked", "ip": dst_ip}

@app.get("/api/v1/analyze-url", dependencies=[Depends(verify_token)])
async def analyze_suspicious_url(target: str, detonate: bool = False):
    if is_private_or_internal_target(target):
        raise HTTPException(status_code=400, detail="Refusing to analyze private/internal address")
    urlhaus_hit = lookup_urlhaus_local(target)
    urlscan_data = await analyze_with_urlscan(target, explicit_user_detonate=detonate)
    combined_risk = 100 if urlhaus_hit else urlscan_data.get("verdict_score", 0)
    return {"target": target, "combined_risk_score": combined_risk, "urlhaus": urlhaus_hit, "urlscan": urlscan_data}

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
        "active_traps": [{"port": p, "service": c["service"]} for p, c in HONEY_PORTS.items()] if ENABLE_CANARIES else [],
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

    # Record persistent mitigation in database
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
