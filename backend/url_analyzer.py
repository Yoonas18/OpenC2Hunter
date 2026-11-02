import os
import csv
import io
import time
import sqlite3
import ipaddress
from urllib.parse import urlparse
import httpx

DB_PATH = os.getenv("DB_PATH", "telemetry.db")
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
URLSCAN_SCAN_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

INTERNAL_TLDS = (".local", ".lan", ".internal", ".corp", ".home", ".arpa", "localhost")

def is_private_or_internal_target(host: str) -> bool:
    if not host:
        return True
    clean_host = host.strip().lower()
    if clean_host.endswith(INTERNAL_TLDS) or "." not in clean_host:
        return True
    try:
        ip = ipaddress.ip_address(clean_host)
        return not ip.is_global
    except ValueError:
        return False

def sync_urlhaus_bulk_feed():
    while True:
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.get(URLHAUS_CSV_URL)
                if resp.status_code == 200:
                    lines = [l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()]
                    reader = csv.reader(io.StringIO("\n".join(lines)))
                    batch = []
                    for row in reader:
                        if len(row) >= 8:
                            url_id, dateadded, url, status, _, threat, tags, link = row[:8]
                            parsed_host = (urlparse(url).hostname or "").lower()
                            batch.append((url_id, dateadded, url, parsed_host, status, threat, tags, link))
                    conn = sqlite3.connect(DB_PATH, timeout=15.0)
                    conn.executemany("""
                        INSERT OR REPLACE INTO urlhaus_feed
                        (url_id, dateadded, url, host, url_status, threat, tags, urlhaus_link)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    conn.commit()
                    conn.close()
        except Exception:
            pass
        time.sleep(600)

def lookup_urlhaus_local(url_or_domain: str) -> dict | None:
    if not url_or_domain:
        return None
    target = url_or_domain.strip().lower()
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT url, url_status, threat, tags, urlhaus_link FROM urlhaus_feed WHERE url = ? OR host = ? LIMIT 1",
        (target, target)
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

async def analyze_with_urlscan(target: str, explicit_user_detonate: bool = False) -> dict:
    domain = (urlparse(target).hostname if "://" in target else target) or ""
    domain = domain.strip().lower()
    if is_private_or_internal_target(domain):
        return {"target": domain, "verdict_score": 0, "skipped": "Private/Internal target excluded"}

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM urlscan_cache WHERE target = ?", (domain,))
    cached = cur.fetchone()
    if cached:
        conn.close()
        return dict(cached)

    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
    record = {
        "target": domain, "scan_uuid": None, "verdict_score": 0, "malicious_bool": 0,
        "brands_targeted": "[]", "server_ip": "N/A", "asn_name": "N/A",
        "screenshot_url": None, "report_url": None
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            s_resp = await client.get(URLSCAN_SEARCH_URL, params={"q": f"domain:{domain}", "size": 1}, headers=headers)
            if s_resp.status_code == 200 and s_resp.json().get("results"):
                latest = s_resp.json()["results"][0]
                scan_id = latest.get("_id")
                page = latest.get("page", {})
                record.update({
                    "scan_uuid": scan_id,
                    "server_ip": page.get("ip", "N/A"),
                    "asn_name": page.get("asnname", "N/A"),
                    "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
                    "report_url": f"https://urlscan.io/result/{scan_id}/"
                })
            elif explicit_user_detonate and URLSCAN_API_KEY:
                scan_target = target if "://" in target else f"https://{domain}"
                post_resp = await client.post(
                    URLSCAN_SCAN_URL,
                    headers=headers,
                    json={"url": scan_target, "visibility": "unlisted"}
                )
                if post_resp.status_code == 200:
                    scan_id = post_resp.json().get("uuid")
                    record["scan_uuid"] = scan_id
                    record["report_url"] = f"https://urlscan.io/result/{scan_id}/"
    except Exception:
        pass

    cur.execute("""
        INSERT OR REPLACE INTO urlscan_cache
        (target, scan_uuid, verdict_score, malicious_bool, brands_targeted, server_ip, asn_name, screenshot_url, report_url)
        VALUES (:target, :scan_uuid, :verdict_score, :malicious_bool, :brands_targeted, :server_ip, :asn_name, :screenshot_url, :report_url)
    """, record)
    conn.commit()
    conn.close()
    return record
