"""Notification integrations (e.g. Discord webhooks)."""
from __future__ import annotations

import requests
from .log import get_logger

logger = get_logger("notify")

def notify_finding(ctx, finding: dict, triage_status: str, triage_notes: str | None = None) -> None:
    discord = ctx.cfg.notifications.discord
    if not discord.enabled or not discord.webhook_url:
        return
        
    if discord.notify_on == "true_positive" and triage_status != "true_positive":
        return
    if discord.notify_on == "high_severity" and finding["severity"] not in ("critical", "high"):
        return

    payload = {
        "content": f"🚨 **New Secret Finding** [{finding['severity'].upper()}]",
        "embeds": [{
            "title": f"{finding['detector']} ({finding['service']})",
            "color": 16711680 if finding['severity'] in ("critical", "high") else 16753920,
            "fields": [
                {"name": "Target", "value": f"{finding['target_name']} ({finding['target_kind']})", "inline": True},
                {"name": "Location", "value": f"`{finding['file_path']}:{finding['line']}`", "inline": True},
                {"name": "Triage", "value": triage_status, "inline": True},
                {"name": "Preview", "value": f"`{finding['secret_preview']}`", "inline": False},
            ],
            "footer": {"text": "FAS Pipeline"}
        }]
    }
    
    if triage_notes:
        payload["embeds"][0]["fields"].append({
            "name": "Triage Notes",
            "value": triage_notes,
            "inline": False
        })
        
    try:
        requests.post(discord.webhook_url, json=payload, timeout=10)
    except Exception as exc:
        logger.warning("Discord webhook failed: %s", exc)
