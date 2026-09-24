"""Disclosure-contact enrichment: security.txt lookup for affected hosts.

For each host seen in URL-type findings we try RFC 9116 security.txt and
cache the contact in the kv table for 7 days. Noise hosts (localhost etc.)
are skipped. Vendor contacts for well-known services live in reporter.py.
"""
from __future__ import annotations

import time

from ..detect.url_filter import is_noise_url
from ..http_utils import PoliteSession, HttpError
from ..log import get_logger

logger = get_logger("report.disclosure")

CACHE_TTL = 7 * 86400


def security_txt_contact(ctx, http: PoliteSession, host: str) -> str | None:
    """Best-effort 'Contact:' from https://{host}/.well-known/security.txt."""
    if is_noise_url(f"https://{host}"):
        return None
    cache_key = f"sectxt:{host}"
    cached = ctx.db.get_kv(cache_key)
    if cached is not None:
        contact, _, ts = cached.rpartition("|")
        if time.time() - float(ts or 0) < CACHE_TTL:
            return contact or None

    contact = None
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = http.get(f"https://{host}{path}")
        except HttpError:
            continue
        for line in resp.text.splitlines():
            if line.lower().startswith("contact:"):
                contact = line.split(":", 1)[1].strip()
                break
        if contact:
            break
    ctx.db.set_kv(cache_key, f"{contact or ''}|{time.time()}")
    return contact
