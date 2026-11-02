import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OPENC2_SESSION_TOKEN"] = "test_secret_token_123"
os.environ["DB_PATH"] = ":memory:"

from sniffer_daemon import analyze_dga_domain
from url_analyzer import is_private_or_internal_target
from backend_engine import app, is_safe_blockable_ip

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
