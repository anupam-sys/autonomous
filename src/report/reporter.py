"""Report generation: per-run JSON + HTML with disclosure contacts.

Values are REDACTED by default (report.reveal_secrets=false) — the report is
safe to handle; full values never leave the VPS except via direct DB access.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..detect.url_filter import host_of, is_noise_url
from ..http_utils import PoliteSession
from ..log import get_logger
from .disclosure import security_txt_contact

logger = get_logger("report.reporter")

# well-known vendor security contacts for classified services
VENDOR_CONTACTS = {
    "aws": "https://aws.amazon.com/security/vulnerability-reporting/",
    "google": "https://bughunters.google.com/",
    "gcp": "https://bughunters.google.com/",
    "firebase": "https://bughunters.google.com/",
    "github": "https://hackerone.com/github",
    "gitlab": "https://hackerone.com/gitlab",
    "stripe": "https://hackerone.com/stripe",
    "slack": "https://hackerone.com/slack",
    "twilio": "https://hackerone.com/twilio",
    "sendgrid": "https://hackerone.com/sendgrid",
    "npm": "https://hackerone.com/npm",
    "pypi": "https://warehouse.pypa.io/security.html",
    "openai": "https://bugcrowd.com/openai",
    "anthropic": "https://hackerone.com/anthropic",
    "telegram": "https://core.telegram.org/tsi",
    "huggingface": "https://hackerone.com/huggingface",
    "mailgun": "https://hackerone.com/mailgun",
    "shopify": "https://hackerone.com/shopify",
    "paypal": "https://hackerone.com/paypal",
    "cloudflare": "https://hackerone.com/cloudflare",
    "digitalocean": "https://hackerone.com/digitalocean",
    "heroku": "https://hackerone.com/heroku",
    "sentry": "https://sentry.io/security/",
    "datadog": "https://hackerone.com/datadog",
    "mapbox": "https://hackerone.com/mapbox",
    "supabase": "https://supabase.com/security",
}


def run_report(ctx) -> dict:
    """Stage entry — interval-gated."""
    last = float(ctx.db.get_kv("report_last") or 0)
    if time.time() - last < ctx.cfg.report.interval_hours * 3600:
        return {"skipped": "interval"}
    return generate(ctx)


def generate(ctx) -> dict:
    rows = ctx.db.findings_for_report()
    contacts = _resolve_contacts(ctx, rows)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = Path(ctx.cfg.paths.report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reveal = ctx.cfg.report.reveal_secrets

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": ctx.db.counts(),
        "findings": [
            {
                "id": r["id"],
                "severity": r["severity"],
                "confidence": r["confidence"],
                "triage_status": r["triage_status"],
                "triage_notes": r["triage_notes"],
                "detector": r["detector"],
                "service": r["service"],
                "secret_type": r["secret_type"],
                "target": r["target_name"],
                "target_kind": r["target_kind"],
                "target_locator": r["target_locator"],
                "file": r["file_path"],
                "line": r["line"],
                "secret_preview": r["secret_preview"],
                # full value only when reveal_secrets=true (LOCAL json only)
                "secret": ctx.db.get_finding_secret(r["id"]) if reveal else None,
                "context": r["context"],
                "disclosure_contact": contacts.get(r["id"]),
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in rows
        ],
    }

    json_path = out_dir / f"report-{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("report.html.j2").render(report=payload)
    html_path = out_dir / f"report-{stamp}.html"
    html_path.write_text(html, encoding="utf-8")

    ctx.db.set_kv("report_last", str(time.time()))
    logger.info("report: %d findings -> %s / %s", len(rows), json_path, html_path)
    from ..activity import emit
    emit(ctx, "report", f"report generated: {html_path.name} ({len(rows)} findings)")
    return {"findings": len(rows), "json": str(json_path), "html": str(html_path)}


def _resolve_contacts(ctx, rows) -> dict[int, str]:
    """finding id -> best disclosure contact (vendor table, else security.txt)."""
    contacts: dict[int, str] = {}
    if not ctx.cfg.report.disclosure_lookup:
        for r in rows:
            contacts[r["id"]] = VENDOR_CONTACTS.get(r["service"], "")
        return contacts

    http = PoliteSession(min_interval=2.0)
    host_cache: dict[str, str | None] = {}
    for r in rows:
        contact = VENDOR_CONTACTS.get(r["service"])
        if not contact:
            host = _finding_host(r)
            if host:
                if host not in host_cache:
                    host_cache[host] = security_txt_contact(ctx, http, host)
                contact = host_cache[host]
        contacts[r["id"]] = contact or ""
    return contacts


def _finding_host(r) -> str | None:
    for text in (r["secret_preview"], r["target_locator"]):
        if text and "://" in text and not is_noise_url(text):
            host = host_of(text)
            if host and "." in host and not is_noise_url(f"https://{host}"):
                return host
    return None
