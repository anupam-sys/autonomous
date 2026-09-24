"""Bandwidth-aware streaming downloader.

Enforces the daily bandwidth budget and per-file size caps; every byte
(partial downloads included) is accounted to the bandwidth table.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger

logger = get_logger("acquire.download")

CHUNK = 1 << 16  # 64 KiB


class BudgetExceeded(Exception):
    """Daily bandwidth budget is exhausted."""


class FileTooLarge(Exception):
    """Remote file exceeds the per-file size cap."""


def _budget_left(ctx) -> int:
    cap = ctx.cfg.limits.daily_bandwidth_mb * 1_000_000
    return cap - ctx.db.bandwidth_today()


def download(ctx, http: PoliteSession, url: str, dest: Path, max_bytes: int) -> tuple[str, int]:
    """Stream `url` to `dest`. Returns (sha256, size_bytes).

    Raises BudgetExceeded / FileTooLarge / HttpError.
    """
    if _budget_left(ctx) <= 0:
        raise BudgetExceeded("daily bandwidth budget exhausted")

    dest.parent.mkdir(parents=True, exist_ok=True)
    resp = http.get(url, stream=True)
    length = resp.headers.get("Content-Length")
    if length and int(length) > max_bytes:
        raise FileTooLarge(f"{url}: {int(length) // 1_000_000}MB > cap {max_bytes // 1_000_000}MB")

    sha = hashlib.sha256()
    size = 0
    unflushed_bandwidth = 0
    too_large = False
    budget_exceeded = False

    with dest.open("wb") as fh:
        for chunk in resp.iter_content(CHUNK):
            if not chunk:
                continue
            chunk_len = len(chunk)
            size += chunk_len
            unflushed_bandwidth += chunk_len
            sha.update(chunk)
            fh.write(chunk)

            if unflushed_bandwidth >= 1024 * 1024:
                ctx.db.add_bandwidth(unflushed_bandwidth)
                unflushed_bandwidth = 0

            if size > max_bytes:
                too_large = True
                break
            if _budget_left(ctx) <= 0:
                budget_exceeded = True
                break

    if unflushed_bandwidth > 0:
        ctx.db.add_bandwidth(unflushed_bandwidth)

    if too_large:
        dest.unlink(missing_ok=True)
        raise FileTooLarge(f"{url}: exceeded {max_bytes // 1_000_000}MB cap")
    if budget_exceeded:
        dest.unlink(missing_ok=True)
        raise BudgetExceeded("daily bandwidth budget exhausted mid-download")

    return sha.hexdigest(), size
