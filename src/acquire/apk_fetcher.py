"""APK acquisition: direct downloads (F-Droid) + mirror resolution.

* fdroid          -> direct .apk URL, just download
* apkmirror       -> release page -> variant page -> real file (best-effort;
                     Cloudflare often wins -> target is skipped, not failed)
* apkpure://pkg   -> direct-CDN pattern attempt
"""
from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target
from .downloader import download

logger = get_logger("acquire.apk")


class ApkResolveFailed(Exception):
    pass


def fetch_apk(ctx, target: Target, dest_dir: Path) -> tuple[Path, str, int]:
    """Resolve + download the APK. Returns (apk_path, sha256, size)."""
    http = PoliteSession(min_interval=4.0)
    max_bytes = ctx.cfg.limits.max_apk_mb * 1_000_000
    dest_dir.mkdir(parents=True, exist_ok=True)
    apk_path = dest_dir / f"{_safe(target.name)}.apk"

    url = _resolve(ctx, http, target)
    sha, size = download(ctx, http, url, apk_path, max_bytes)
    if size < 10_000 or not _looks_like_apk(apk_path):
        apk_path.unlink(missing_ok=True)
        raise ApkResolveFailed(f"{target.name}: downloaded file is not an APK")
    logger.info("apk %s -> %0.1fMB", target.name, size / 1e6)
    return apk_path, sha, size


def _resolve(ctx, http: PoliteSession, target: Target) -> str:
    loc = target.locator
    if loc.endswith(".apk"):
        return loc
    if loc.startswith("apkpure://"):
        pkg = loc.removeprefix("apkpure://")
        return f"https://d.apkpure.com/b/APK/{pkg}?version=latest"
    if "apkmirror.com" in loc:
        return _resolve_apkmirror(http, loc)
    raise ApkResolveFailed(f"unsupported APK locator: {loc}")


def _resolve_apkmirror(http: PoliteSession, release_page: str) -> str:
    """Walk APKMirror's release -> download pages looking for the file URL."""
    try:
        soup = BeautifulSoup(http.get(release_page).text, "html.parser")
    except HttpError as exc:
        raise ApkResolveFailed(f"release page failed: {exc}") from exc

    variant = None
    for a in soup.select("a[href*='-android-apk-download']"):
        variant = a.get("href")
        break
    if not variant:
        raise ApkResolveFailed("no download variant found (anti-bot or layout change)")
    if variant.startswith("/"):
        variant = "https://www.apkmirror.com" + variant

    try:
        soup = BeautifulSoup(http.get(variant).text, "html.parser")
    except HttpError as exc:
        raise ApkResolveFailed(f"variant page failed: {exc}") from exc

    # meta refresh or a direct anchor usually carries the final file link
    meta = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta and "url=" in (meta.get("content") or "").lower():
        candidate = re.split(r"url=", meta["content"], flags=re.I)[-1].strip()
        if candidate.startswith("/"):
            candidate = "https://www.apkmirror.com" + candidate
        return candidate
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if ".apk" in href and ("download" in href or "wp-content" in href):
            if href.startswith("/"):
                href = "https://www.apkmirror.com" + href
            return href
    raise ApkResolveFailed("final file link not found (anti-bot likely)")


def _looks_like_apk(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(2) == b"PK"  # APKs are ZIP archives


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80]
