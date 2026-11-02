import time

import httpx


async def send_discord_alert(webhook_url: str, threat: dict) -> bool:
    """Dispatches a rich embed security alert to a Discord channel."""
    if not webhook_url:
        return False

    color = 0xEF4444 if threat.get("risk_score", 0) >= 70 else 0xF59E0B
    payload = {
        "username": "OpenC2Hunter Defense Bot",
        "avatar_url": "https://raw.githubusercontent.com/Yoonas18/OpenC2Hunter/main/docs/banner.png",
        "embeds": [
            {
                "title": f"🚨 {threat.get('title', 'Security Alert Triggered')}",
                "description": threat.get("description", "Potential C2 Beacon or Threat Activity Detected"),
                "color": color,
                "fields": [
                    {"name": "Remote Target", "value": f"`{threat.get('target', 'N/A')}`", "inline": True},
                    {"name": "Process", "value": f"`{threat.get('process', 'N/A')}` (PID: {threat.get('pid', 'N/A')})", "inline": True},
                    {"name": "Risk Score", "value": f"**{threat.get('risk_score', 0)}/100**", "inline": True},
                    {"name": "Attribution", "value": threat.get("attribution", "Autonomous Threat Hunter"), "inline": False}
                ],
                "footer": {"text": "OpenC2Hunter Automated SOC Guardian"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code in (200, 204)
    except Exception:
        return False

async def send_slack_alert(webhook_url: str, threat: dict) -> bool:
    """Dispatches a formatted security alert to a Slack channel."""
    if not webhook_url:
        return False

    payload = {
        "text": f"🚨 *[OpenC2Hunter Alert]* {threat.get('title', 'C2 Threat Detected')} — Target: `{threat.get('target', 'N/A')}` | Risk: {threat.get('risk_score', 0)}/100 | Process: `{threat.get('process', 'N/A')}`"
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code == 200
    except Exception:
        return False
