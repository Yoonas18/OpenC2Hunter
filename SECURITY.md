# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

If you discover a security vulnerability in OpenC2Hunter, **please do NOT open a public GitHub issue.**

Instead, report it responsibly by emailing the maintainer privately or opening a [GitHub Security Advisory](https://github.com/Yoonas18/OpenC2Hunter/security/advisories/new).

Please include:
- A clear description of the vulnerability
- Steps to reproduce it
- Potential impact
- (Optional) Suggested fix

You can expect a response within **72 hours**. We take all security reports seriously and will credit researchers in the release notes.

## Security Design Principles

- **Localhost-only API binding** — never exposed to the network
- **CSRF session tokens** — randomized per-launch via `secrets.token_urlsafe(32)`
- **Private IP guard** — refuses to analyze or block RFC-1918 / loopback addresses
- **Critical PID protection** — will never terminate system processes
- **No external telemetry** — zero data leaves your machine unless you configure BYOK API keys
