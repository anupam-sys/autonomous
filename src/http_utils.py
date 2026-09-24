"""Shared HTTP client: polite per-host throttling, retries, sane UA."""
from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

import requests

from .log import get_logger

logger = get_logger("http")


class HttpError(Exception):
    pass


class PoliteSession:
    """requests.Session wrapper.

    * min_interval seconds between requests to the SAME host (all sources)
    * exponential backoff on 429/5xx and network errors
    * honest User-Agent
    """

    def __init__(self, min_interval: float = 1.5, timeout: int = 30, max_retries: int = 3):
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "fas-research/0.1 (exposed-secret research; responsible disclosure)"}
        )
        self._min_interval = min_interval
        self._timeout = timeout
        self._max_retries = max_retries
        self._last_hit: dict[str, float] = {}
        self._lock = threading.Lock()

    def _throttle(self, url: str) -> None:
        host = urlparse(url).netloc
        with self._lock:
            last = self._last_hit.get(host, 0.0)
            now = time.monotonic()
            wait = self._min_interval - (now - last)
            if wait > 0:
                self._last_hit[host] = now + wait
            else:
                self._last_hit[host] = now

        if wait > 0:
            time.sleep(wait)

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        for attempt in range(self._max_retries + 1):
            self._throttle(url)
            try:
                resp = self._session.get(url, **kwargs)
            except requests.RequestException as exc:
                if attempt == self._max_retries:
                    raise HttpError(f"GET {url} failed: {exc}") from exc
                time.sleep(2 ** attempt * 2)
                continue
            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt * 2
                logger.debug("%s -> %s, backing off %.0fs", url, resp.status_code, delay)
                time.sleep(delay)
                continue
            if resp.status_code >= 400:
                raise HttpError(f"GET {url} -> HTTP {resp.status_code}")
            return resp
        raise HttpError(f"GET {url} failed after retries")
