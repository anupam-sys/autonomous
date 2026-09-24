"""Notification integrations (Discord interactive bot & webhooks)."""
from __future__ import annotations

from pathlib import Path
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


def notify_report(ctx, report_result: dict) -> None:
    """Send generated report files (HTML + JSON) through Discord bot or webhook."""
    discord = ctx.cfg.notifications.discord
    if not discord.enabled:
        return

    # Try active Discord bot first (sends embed + attaches both files)
    try:
        from .bot import dispatch_bot_report
        if dispatch_bot_report(ctx, report_result):
            return
    except Exception as exc:
        logger.debug("Bot report dispatch skipped/failed: %s", exc)

    if not discord.webhook_url:
        return

    html_p = Path(report_result.get("html", ""))
    json_p = Path(report_result.get("json", ""))
    findings_count = report_result.get("findings", 0)

    embed = {
        "title": "📊 Security Findings Report Generated",
        "description": f"Generated report covering **{findings_count}** findings.",
        "color": 3066993 if findings_count == 0 else 15105570,
        "fields": [
            {"name": "Total Findings", "value": str(findings_count), "inline": True},
            {
                "name": "Report Files",
                "value": f"• `{html_p.name}` (Interactive HTML report)\n• `{json_p.name}` (Raw JSON findings export)",
                "inline": False,
            },
        ],
        "footer": {"text": "FAS Reporting Engine"},
    }

    payload = {
        "content": f"📊 **New Security Findings Report** ({findings_count} findings)",
        "embeds": [embed],
    }

    files = {}
    opened = []
    try:
        if html_p.exists() and html_p.stat().st_size < 25_000_000:
            f1 = open(html_p, "rb")
            opened.append(f1)
            files["files[0]"] = (html_p.name, f1, "text/html")
        if json_p.exists() and json_p.stat().st_size < 25_000_000:
            f2 = open(json_p, "rb")
            opened.append(f2)
            files["files[1]"] = (json_p.name, f2, "application/json")

        import json
        if files:
            resp = requests.post(
                discord.webhook_url,
                data={"payload_json": json.dumps(payload)},
                files=files,
                timeout=30,
            )
        else:
            resp = requests.post(discord.webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Discord webhook report notification failed: %s", exc)
    finally:
        for fh in opened:
            fh.close()
