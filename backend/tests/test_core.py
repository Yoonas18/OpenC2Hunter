import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
test_db_path = Path(__file__).resolve().parent / "test_temp.db"
os.environ["OPENC2_SESSION_TOKEN"] = "test_secret_token_123"
os.environ["DB_PATH"] = str(test_db_path)

from backend_engine import app, init_db_schema  # noqa: E402

from sniffer_daemon import analyze_dga_domain  # noqa: E402
from url_analyzer import is_private_or_internal_target  # noqa: E402

init_db_schema()
client = TestClient(app)

def test_dga_entropy_math_accuracy():
    _, is_dga_clean = analyze_dga_domain("www.google.com")
    _, is_dga_cdn = analyze_dga_domain("assets.cloudflare.com")
    assert is_dga_clean is False
    assert is_dga_cdn is False

    entropy, is_dga_mal = analyze_dga_domain("x9k2m7p4q8z1w3.badc2.top")
    assert entropy > 3.5
    assert is_dga_mal is True

def test_private_target_privacy_filter():
    assert is_private_or_internal_target("192.168.1.50") is True
    assert is_private_or_internal_target("10.0.0.1") is True
    assert is_private_or_internal_target("intranet.corp.local") is True
    assert is_private_or_internal_target("185.220.101.45") is False

def test_csrf_protection_blocks_unauthenticated_requests():
    res_no_hdr = client.post("/api/v1/mitigate?dst_ip=185.220.101.45")
    assert res_no_hdr.status_code in (403, 422)

    res_bad_tok = client.post(
        "/api/v1/mitigate?dst_ip=185.220.101.45",
        headers={"X-OpenC2-Token": "wrong_token"}
    )
    assert res_bad_tok.status_code == 403

def test_mitigate_refuses_private_ips_and_critical_pids():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    res_lan = client.post("/api/v1/mitigate?dst_ip=192.168.1.1", headers=headers)
    assert res_lan.status_code == 400

    res_dns = client.post("/api/v1/mitigate?dst_ip=8.8.8.8", headers=headers)
    assert res_dns.status_code == 400

    res_pid = client.post("/api/v1/mitigate?dst_ip=185.220.101.45&pid=1", headers=headers)
    assert res_pid.status_code == 400

def test_superadmin_auth_flow():
    # Bad credentials should fail with 401
    res_bad = client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "WrongPassword!"})
    assert res_bad.status_code == 401

    # Valid default credentials should succeed
    res_ok = client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "OpenC2Hunter@2026!"})
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert "token" in data
    auth_token = data["token"]

    # Verify session endpoint
    res_verify = client.get("/api/v1/auth/verify", headers={"X-OpenC2-Token": auth_token})
    assert res_verify.status_code == 200
    assert res_verify.json()["status"] == "valid"

    # Authenticated API call with newly acquired token
    res_stats = client.get("/api/v1/graph-stats", headers={"X-OpenC2-Token": auth_token})
    assert res_stats.status_code == 200

    # Logout revokes session
    res_logout = client.post("/api/v1/auth/logout", headers={"X-OpenC2-Token": auth_token})
    assert res_logout.status_code == 200

    # After logout, token must be rejected
    res_after = client.get("/api/v1/graph-stats", headers={"X-OpenC2-Token": auth_token})
    assert res_after.status_code == 403

def test_pbkdf2_password_hashing():
    from backend_engine import hash_password, verify_password
    hashed = hash_password("SecretPass123!")
    assert hashed.startswith("pbkdf2:sha256:")
    assert verify_password("SecretPass123!", hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_stix_and_yara_export():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    # Test STIX 2.1 export
    stix_res = client.get("/api/v1/export/stix?dst_ip=185.220.101.45&proc_name=python3.exe", headers=headers)
    assert stix_res.status_code == 200
    stix_data = stix_res.json()
    assert stix_data["type"] == "bundle"
    assert len(stix_data["objects"]) >= 4

    # Test YARA rule export
    yara_res = client.get("/api/v1/export/yara?dst_ip=185.220.101.45&proc_name=python3.exe", headers=headers)
    assert yara_res.status_code == 200
    assert "rule OpenC2Hunter_C2_" in yara_res.json()["rule"]

def test_canary_traps_management():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    res = client.get("/api/v1/canary/traps", headers=headers)
    assert res.status_code == 200
    assert "traps" in res.json()
    assert len(res.json()["traps"]) >= 4

def test_process_memory_inspector():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    res = client.get(f"/api/v1/process-memory-strings?pid={os.getpid()}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "strings_extracted_count" in data
    assert data["pid"] == os.getpid()

def test_mitre_attack_mapping_and_matrix():
    from mitre_attack import get_mitre_summary, map_flow_to_mitre
    test_flow = {
        "dst_ip": "185.220.101.45",
        "dst_port": 8443,
        "jitter_pct": 4.8,
        "entropy": 4.12,
        "process_name": "python3.exe",
        "bytes_out": 600000,
    }
    techniques = map_flow_to_mitre(test_flow)
    tids = [t["id"] for t in techniques]
    assert "T1071.001" in tids  # Web protocols
    assert "T1568.002" in tids  # DGA
    assert "T1059" in tids      # Scripting
    assert "T1041" in tids      # Exfiltration

    summary = get_mitre_summary([test_flow], [{"service": "SSH", "port": 2222}])
    assert summary["total_active_techniques"] >= 4
    assert "Command and Control" in summary["tactics"]

def test_incident_response_triage_bundle():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    flow_payload = {
        "dst_ip": "185.220.101.45",
        "dst_port": 8443,
        "pid": os.getpid(),
        "process_name": "python.exe",
        "risk_score": 95,
        "jitter_pct": 4.8,
        "entropy": 4.12,
    }
    res = client.post("/api/v1/incident/triage-bundle", json={"flow": flow_payload}, headers=headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    assert len(res.content) > 500  # Non-empty ZIP archive

def test_ai_threat_analyst_copilot():
    headers = {"X-OpenC2-Token": "test_secret_token_123"}
    flow_payload = {
        "dst_ip": "185.220.101.45",
        "dst_port": 8443,
        "pid": 4812,
        "process_name": "python3.exe",
        "risk_score": 95,
        "jitter_pct": 4.8,
        "entropy": 4.12,
        "threatfox_malware": "Sliver C2 / Autonomous Agent",
        "dns_query": "x9k2m7p4q8z1w3.c2-routing.top",
    }
    res = client.post("/api/v1/ai/investigate", json={"flow": flow_payload}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert "Sliver" in data["attribution_hypothesis"]
    assert "IMMEDIATE_ACTION_REQUIRED" == data["urgency"]
    assert len(data["recommended_actions"]) >= 3

def test_threat_intel_cache_offline_lookup():
    from threat_intel_feed import check_intel_indicator, init_intel_table
    init_intel_table(str(test_db_path))
    hit = check_intel_indicator("185.220.101.45", str(test_db_path))
    assert hit is not None
    assert hit["matched"] is True
    assert "Sliver" in hit["threat_family"]
