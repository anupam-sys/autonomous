"""Notification integrations (Discord interactive bot & webhooks)."""
from __future__ import annotations

import time
import requests
from .log import get_logger

logger = get_logger("notify")


def notify_finding(ctx, finding: dict, triage_status: str, triage_notes: str | None = None) -> None:
    discord = ctx.cfg.notifications.discord
    if not discord.enabled:
        return

    if discord.notify_on == "true_positive" and triage_status != "true_positive":
        return
    if discord.notify_on == "high_severity" and finding.get("severity") not in ("critical", "high"):
        return

    # Try interactive Discord Bot first (creates threads & enables instant interactive chat)
    bot_dispatched = False
    try:
        from .bot import dispatch_bot_finding
        bot_dispatched = dispatch_bot_finding(ctx, finding, triage_status, triage_notes)
    except Exception as b_exc:
        logger.debug("Bot dispatch skipped or failed: %s", b_exc)

    # If webhook URL is configured, also post to webhook (or fallback if bot inactive)
    if not discord.webhook_url:
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
    fid = finding.get("id")

    fields = [
        {"name": "Target", "value": f"{target_name} ({target_kind})", "inline": True},
        {"name": "Location", "value": f"`{file_path}:{line}`", "inline": True},
        {"name": "Triage", "value": triage_status, "inline": True},
    ]
    if fid:
        fields.append({"name": "Finding ID", "value": f"`#{fid}`", "inline": True})
    fields.append({"name": "Full Key / Secret", "value": secret_formatted, "inline": False})

    if triage_notes:
        fields.append({
            "name": "Triage Notes",
            "value": str(triage_notes)[:1000],
            "inline": False,
        })

    title_prefix = f"Finding #{fid}: " if fid else ""
    payload = {
        "content": f"🚨 **New Secret Finding** [{severity.upper()}]",
        "embeds": [{
            "title": f"{title_prefix}{detector} ({service})",
            "color": 16711680 if severity in ("critical", "high") else 16753920,
            "fields": fields,
            "footer": {"text": "FAS Pipeline"},
        }],
    }

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
