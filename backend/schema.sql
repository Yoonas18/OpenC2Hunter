PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS processes (
    sha256 TEXT PRIMARY KEY,
    process_name TEXT NOT NULL,
    exe_path TEXT NOT NULL,
    is_protected INTEGER DEFAULT 0,
    vt_malicious_count INTEGER DEFAULT -1,
    mb_signature TEXT DEFAULT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS aggregated_flows (
    flow_key TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    pid INTEGER NOT NULL,
    process_sha256 TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    session_count INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    avg_iat REAL DEFAULT 0.0,
    jitter_pct REAL DEFAULT 100.0,
    dns_query TEXT DEFAULT NULL,
    dns_entropy REAL DEFAULT 0.0,
    is_dga INTEGER DEFAULT 0,
    raw_preview TEXT DEFAULT NULL,
    FOREIGN KEY(process_sha256) REFERENCES processes(sha256)
);
CREATE INDEX IF NOT EXISTS idx_agg_flows_dst_ip ON aggregated_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_agg_flows_last_seen ON aggregated_flows(last_seen);

CREATE TABLE IF NOT EXISTS osint_cache (
    ioc_value TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    source_hits TEXT NOT NULL,
    last_updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS urlhaus_feed (
    url_id TEXT PRIMARY KEY,
    dateadded TEXT,
    url TEXT,
    host TEXT,
    url_status TEXT,
    threat TEXT,
    tags TEXT,
    urlhaus_link TEXT
);
CREATE INDEX IF NOT EXISTS idx_urlhaus_host ON urlhaus_feed(host);
CREATE INDEX IF NOT EXISTS idx_urlhaus_url ON urlhaus_feed(url);

CREATE TABLE IF NOT EXISTS urlscan_cache (
    target TEXT PRIMARY KEY,
    scan_uuid TEXT,
    verdict_score INTEGER DEFAULT 0,
    malicious_bool INTEGER DEFAULT 0,
    brands_targeted TEXT,
    server_ip TEXT,
    asn_name TEXT,
    screenshot_url TEXT,
    report_url TEXT,
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    pid INTEGER,
    reason TEXT,
    blocked_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);

CREATE TABLE IF NOT EXISTS canary_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    attacker_ip TEXT NOT NULL,
    attacker_port INTEGER NOT NULL,
    target_honey_port INTEGER NOT NULL,
    service_emulated TEXT NOT NULL,
    payload_preview TEXT NOT NULL,
    payload_hex TEXT NOT NULL,
    threat_classification TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_canary_attacker ON canary_alerts(attacker_ip, timestamp);
