# Changelog

All notable changes to OpenC2Hunter will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-11-02

### 🚀 Initial Release

#### Added
- **Live packet sniffing** — real-time TCP/UDP flow capture via Scapy
- **C2 beacon detection** — inter-arrival time (IAT) + jitter behavioral analysis
- **DGA domain detection** — Shannon entropy scoring on DNS query labels
- **OSINT enrichment** — auto-lookup via Shodan InternetDB, ThreatFox (Abuse.ch), VirusTotal, URLhaus
- **Canary honeypot traps** — fake SSH, Redis, SMB, and Ollama AI API listeners
- **LLM-Jacking detection** — detects probes targeting local AI model APIs (Ollama port 11434)
- **One-click mitigation** — kill malicious process + OS firewall block (Windows/Linux/macOS)
- **CSRF-protected REST API** — session token auth, localhost-only binding
- **React threat dashboard** — live risk scoring, flow table, alert timeline
- **Docker support** — `docker compose up --build -d`
- **Native launcher** — single `python launch.py` starts backend + frontend
- **Cross-platform** — Windows 10/11, Ubuntu/Debian, macOS
- **CI/CD pipeline** — GitHub Actions: SAST (Bandit), lint (Ruff), pytest (3 OS matrix), frontend build
- **4 pytest unit tests** — DGA entropy math, private IP filter, CSRF guard, mitigation safety

