"""Notification integrations (e.g. Discord webhooks)."""
from __future__ import annotations

import time
import requests
from .log import get_logger

logger = get_logger("notify")

def notify_finding(ctx, finding: dict, triage_status: str, triage_notes: str | None = None) -> None:
    discord = ctx.cfg.notifications.discord
    if not discord.enabled or not discord.webhook_url:
        return
        
    if discord.notify_on == "true_positive" and triage_status != "true_positive":
        return
    if discord.notify_on == "high_severity" and finding.get("severity") not in ("critical", "high"):
        return

    # Retrieve full uncensored key
    secret_val = finding.get("secret_full") or finding.get("secret")
    if not secret_val and "id" in finding and hasattr(ctx, "db"):
        secret_val = ctx.db.get_finding_secret(finding["id"])
    if not secret_val:
        secret_val = finding.get("secret_preview", "unknown")

    # Format secret value, respecting Discord's 1024-character field limit
    secret_display = str(secret_val)
    if len(secret_display) > 1000:
        secret_display = secret_display[:990] + "... [truncated]"

    if "\n" in secret_display:
        secret_formatted = f"```\n{secret_display}\n```"
    else:
        secret_formatted = f"`{secret_display}`"

    target_name = finding.get("target_name", "unknown")
    target_kind = finding.get("target_kind", "unknown")
    file_path = finding.get("file_path", "unknown")
    line = finding.get("line", "?")
    severity = str(finding.get("severity", "info"))
    detector = finding.get("detector", "unknown")
    service = finding.get("service", "unknown")

    payload = {
        "content": f"🚨 **New Secret Finding** [{severity.upper()}]",
        "embeds": [{
            "title": f"{detector} ({service})",
            "color": 16711680 if severity in ("critical", "high") else 16753920,
            "fields": [
                {"name": "Target", "value": f"{target_name} ({target_kind})", "inline": True},
                {"name": "Location", "value": f"`{file_path}:{line}`", "inline": True},
                {"name": "Triage", "value": triage_status, "inline": True},
                {"name": "Full Key / Secret", "value": secret_formatted, "inline": False},
            ],
            "footer": {"text": "FAS Pipeline"}
        }]
    }
    
    if triage_notes:
        payload["embeds"][0]["fields"].append({
            "name": "Triage Notes",
            "value": str(triage_notes)[:1000],
            "inline": False
        })
        
    try:
        for attempt in range(3):
            resp = requests.post(discord.webhook_url, json=payload, timeout=10)
            if resp.status_code == 429:
                try:
                    retry_after = float(resp.headers.get("Retry-After", 1.0))
                except ValueError:
                    retry_after = 1.0
                logger.warning("Discord rate limit hit, sleeping %.1fs", retry_after)
                time.sleep(retry_after)
                continue
            resp.raise_for_status()
            break
    except Exception as exc:
        logger.warning("Discord webhook failed: %s", exc)
