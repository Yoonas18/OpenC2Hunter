# OpenC2Hunter

<p align="center">
  <img src="docs/banner.png" alt="OpenC2Hunter — Autonomous C2 Beacon & Network Threat Hunter" width="100%"/>
</p>

<p align="center">
  <strong>Autonomous AI-Powered C2 Beacon & Pre-Compromise Network Threat Hunter</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&style=for-the-badge" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&style=for-the-badge" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react&style=for-the-badge" alt="React"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Tests-4%20Passed-brightgreen?style=for-the-badge&logo=pytest" alt="Tests"/>
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Linux%20%7C%20macOS-informational?style=for-the-badge" alt="Platform"/>
</p>

---

OpenC2Hunter monitors your live network traffic in real-time, detects **Command & Control (C2) beacons**, **DGA-generated malicious domains**, and **suspicious outbound connections** — **before attackers get a foothold**. Runs entirely on your local machine with zero cloud dependency.

---

## 🚀 What It Does

| Capability | Description |
|---|---|
| 🔍 **Live Packet Sniffing** | Captures real-time TCP/UDP flows using Scapy |
| 🤖 **C2 Beacon Detection** | Detects periodic beaconing via inter-arrival time (IAT) + jitter analysis |
| 🧬 **DGA Domain Detection** | Shannon entropy analysis flags algorithmically-generated malicious domains |
| 🌐 **OSINT Enrichment** | Auto-enriches IPs with Shodan InternetDB, ThreatFox, VirusTotal & URLhaus |
| 🍯 **Canary Honeypot Traps** | Optional fake service listeners that alert on any internal probe |
| 🔥 **One-Click Mitigation** | Kills the malicious process & blocks outbound IP via OS firewall |
| 🛡️ **CSRF-Protected API** | Session-token authenticated REST API, localhost-only binding |
| 📊 **Threat Dashboard** | React UI with live risk scoring, flow graph & alert timeline |

---

## 🖼️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Your Machine                       │
│                                                     │
│  ┌─────────────┐    ┌──────────────────────────┐   │
│  │  Sniffer    │───▶│   FastAPI Backend         │   │
│  │  Daemon     │    │   (Port 8000)             │   │
│  │  (Scapy)    │    │   • Flow aggregation      │   │
│  └─────────────┘    │   • DGA detection         │   │
│                     │   • OSINT enrichment      │   │
│  ┌─────────────┐    │   • Mitigation engine     │   │
│  │  Canary     │───▶│                           │   │
│  │  Honeypots  │    └──────────┬───────────────┘   │
│  └─────────────┘               │                    │
│                     ┌──────────▼───────────────┐   │
│                     │   React Dashboard         │   │
│                     │   (Port 3000)             │   │
│                     │   • Live threat feed      │   │
│                     │   • Risk scoring          │   │
│                     │   • 1-click block         │   │
│                     └──────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### Option 1 — Native (Windows / Linux / macOS) ✅ Recommended

**Step 1:** Clone the repo
```bash
git clone https://github.com/Yoonas18/OpenC2Hunter.git
cd OpenC2Hunter
```

**Step 2:** Copy environment config
```bash
cp .env.example .env
```

**Step 3:** Install backend dependencies
```bash
pip install -r backend/requirements.txt
```

**Step 4:** Install frontend dependencies
```bash
cd frontend && npm install && cd ..
```

**Step 5:** Launch (run as **Administrator/sudo** for full packet capture)

- **Windows** (PowerShell as Administrator):
```powershell
python launch.py
```

- **Linux / macOS**:
```bash
sudo python3 launch.py
```

**Step 6:** Open your browser → **http://127.0.0.1:3000** 🎉

Login using your Superadmin credentials (see below).

---

## 🔐 Superadmin Lab Access & Authentication

OpenC2Hunter includes an enterprise-grade SOC access gateway protecting all API endpoints and workbench telemetry:

| Credential | Value | Config (.env) |
|---|---|---|
| **Default Username** | `superadmin` | `ADMIN_USERNAME=superadmin` |
| **Default Password** | `OpenC2Hunter@2026!` | `ADMIN_PASSWORD=your_secure_password` |
| **Session Lifetime** | 24 Hours | Cryptographically secure token (`token_urlsafe(32)`) |
| **Brute-Force Guard** | Active | Rate-limits & locks gateway for 5 mins after 5 failed attempts |

### Changing Credentials
To set your own custom superadmin credentials, add them to your `.env` file:
```env
ADMIN_USERNAME=superadmin
ADMIN_PASSWORD=YourSuperSecretPassword#2026!
```

---

### Option 2 — Docker 🐳

```bash
cp .env.example .env
docker compose up --build -d
```

Then open **http://127.0.0.1:3000**

---

## 🔑 Optional API Keys (BYOK)

All external lookups are cached locally in SQLite — free tiers work fine.

Edit your `.env` file:

```env
# VirusTotal — file hash reputation (free tier: 4 req/min)
VT_API_KEY=your_vt_key_here

# Abuse.ch ThreatFox — C2 IOC intel (free)
ABUSE_CH_KEY=your_abusech_key_here

# URLScan.io — URL detonation sandbox (free tier available)
URLSCAN_API_KEY=your_urlscan_key_here

# Enable honeypot canary traps (optional)
ENABLE_CANARIES=true
```

> **No keys needed to start.** The tool works out of the box using Shodan InternetDB (no auth) and local URLhaus feed.

---

## 🍯 Canary Honeypot Mode

Enable fake service listeners that catch internal lateral movement:

```bash
# Windows (Admin)
python launch.py --enable-canaries

# Linux/macOS
sudo python3 launch.py --enable-canaries
```

Any connection to the fake ports (SSH, RDP, SMB, WinRM, etc.) fires an instant alert on your dashboard.

---

## 🧪 Running Tests

```bash
pytest backend/tests/ -v
```

| Test | What It Validates |
|---|---|
| `test_dga_entropy_math_accuracy` | Shannon entropy correctly flags DGA domains |
| `test_private_target_privacy_filter` | Private IPs & internal hosts are never analyzed/blocked |
| `test_csrf_protection_blocks_unauthenticated_requests` | API rejects missing / wrong session tokens |
| `test_mitigate_refuses_private_ips_and_critical_pids` | Mitigation engine refuses to block safe IPs or system PIDs |

---

## 🗂️ Project Structure

```
OpenC2Hunter/
├── backend/
│   ├── backend_engine.py      # FastAPI REST API + CSRF auth + OSINT enrichment
│   ├── sniffer_daemon.py      # Live packet capture + C2 beacon + DGA detection
│   ├── url_analyzer.py        # URL/domain threat analysis + URLhaus feed
│   ├── canary_deception.py    # Honeypot canary trap listeners
│   ├── schema.sql             # SQLite schema (flows, processes, OSINT cache)
│   ├── requirements.txt       # Python dependencies
│   └── tests/
│       └── test_core.py       # Pytest unit tests
├── frontend/
│   └── src/
│       ├── ThreatHunterDashboard.jsx  # Main React dashboard
│       └── main.jsx                   # App entry point
├── .env.example               # Environment variable template
├── docker-compose.yml         # Docker setup
├── launch.py                  # One-command native launcher
└── README.md
```

---

## 🛡️ Detection Logic

### C2 Beacon Detection
A flow is flagged as a **C2 beacon** when:
- `session_count >= 6` (repeated connections)
- `jitter_pct < 20%` (very regular timing — like automated malware)
- `avg_inter_arrival_time >= 5s` (periodic check-in rhythm)

### DGA Domain Detection
Shannon entropy is computed on the hostname label:
- Entropy **> 3.5 bits/char** → flagged as DGA-generated
- Legitimate domains (google.com, cloudflare.com) score safely below threshold

### OSINT Risk Scoring
| Source | Trigger | Risk Added |
|---|---|---|
| Shodan InternetDB | Tags: `c2`, `malware`, `tor`, `compromised` | +60 |
| ThreatFox (Abuse.ch) | IOC match | → 95 |
| VirusTotal | Malicious detections > 0 | +40 to +100 |
| URLhaus | Known malware URL | → 100 |

---

## ⚙️ API Reference

All endpoints require the `X-OpenC2-Token` header (auto-set by the UI).

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Authenticate with superadmin credentials & receive session token |
| `GET` | `/api/v1/auth/verify` | Validate existing session token |
| `POST` | `/api/v1/auth/logout` | Revoke session token & lock lab |
| `GET` | `/api/v1/graph-stats` | Get all live flows with risk scores |
| `GET` | `/api/v1/analyze-url?target=<url>` | Analyze a URL/domain for threats |
| `GET` | `/api/v1/canary-alerts` | Get honeypot canary alert log |
| `POST` | `/api/v1/mitigate?dst_ip=<ip>&pid=<pid>` | Block IP + terminate process |

---

## 🔒 Security Design

- **Localhost-only binding** — API never exposes to the network
- **CSRF session token** — Random `secrets.token_urlsafe(32)` per launch, verified on every write
- **Private IP guard** — Refuses to block/analyze `RFC-1918`, loopback, or DNS infra IPs
- **Critical PID protection** — Will never terminate system processes (`lsass.exe`, `systemd`, PID ≤ 4, etc.)
- **No telemetry** — Zero data leaves your machine unless you configure BYOK API keys

---

## 🖥️ Supported Platforms

| Platform | Packet Capture | Firewall Block |
|---|---|---|
| Windows 10/11 | ✅ (Admin) | ✅ `netsh advfirewall` |
| Ubuntu / Debian | ✅ (root) | ✅ `iptables` |
| macOS | ✅ (sudo) | ✅ `pfctl` |
| Docker (Linux) | ✅ | ✅ |

> **Without admin/root:** The sniffer falls back to socket-level capture. The dashboard, OSINT enrichment, URL analysis, and manual mitigation all still work.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Legal Disclaimer

This tool is intended for **defensive security, network monitoring, and educational purposes only**. Only run it on networks and systems you own or have explicit written permission to monitor. The authors are not responsible for misuse.

---

*Built with ❤️ for defenders — catch threats before they catch you.*
