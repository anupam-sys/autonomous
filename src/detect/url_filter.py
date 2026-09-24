"""URL noise filter — suppress findings that point at non-targets.

localhost fixtures, documentation domains and XML namespaces generate endless
false positives in URL-bearing rules; they are never reportable findings.
"""
from __future__ import annotations

import re

_NOISE_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
    "example.com", "example.org", "example.net",
    "schemas.android.com", "www.w3.org", "w3.org",
    "xml.apache.org", "maven.apache.org", "schemas.xmlsoap.org",
    "opensource.org", "www.gnu.org", "gnu.org",
}

_HOST_RE = re.compile(r"://(?:[^/@\s]+@)?(?:\[([0-9a-fA-F:]+)\]|([A-Za-z0-9.\-]+))")


def host_of(url: str) -> str | None:
    m = _HOST_RE.search(url)
    if not m:
        return None
    return (m.group(1) or m.group(2) or "").lower() or None


def is_noise_url(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    if host in _NOISE_HOSTS:
        return True
    if host.endswith((".example.com", ".example.org", ".example.net", ".test", ".local", ".localhost")):
        return True
    if host.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    return False
