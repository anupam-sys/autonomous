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

_HOST_RE = re.compile(r"://(?:[^/@\s]+@)?(?:\[([0-9a-fA-F:]+)\]|([A-Za-z0-9.\-]+))(?::(\d+))?")


def host_of(url: str) -> str | None:
    m = _HOST_RE.search(url)
    if not m:
        return None
    return (m.group(1) or m.group(2) or "").lower() or None


def is_localhost(target: str) -> bool:
    """Return True if target (URL, host:port, or hostname/IP) is localhost / loopback."""
    clean = target.strip().lower()
    if "://" in clean:
        h = host_of(clean)
        if not h:
            return False
        clean = h
    if clean.startswith("[") and "]" in clean:
        clean = clean[1:clean.index("]")]
    elif ":" in clean:
        clean = clean.split(":", 1)[0]

    if clean in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return True
    if clean.endswith(".localhost"):
        return True
    if clean.startswith("127."):
        return True
    return False


def is_noise_url(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    if is_localhost(host):
        return True
    if host in _NOISE_HOSTS:
        return True
    if host.endswith((".example.com", ".example.org", ".example.net", ".test", ".local")):
        return True
    return False
