"""APK discovery: F-Droid, APKMirror recent uploads, APKPure, config target list.

Mirror scraping is best-effort (Cloudflare etc.): when a direct APK URL can't
be resolved at discovery time, we enqueue a resolvable page URI and let
acquisition do (or skip) the heavy lifting.
"""
from __future__ import annotations

import re
from typing import Iterable

from bs4 import BeautifulSoup

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target, TargetKind
from .intelligence import evaluate_target

logger = get_logger("discovery.apk")

FDROID_PACKAGES = "https://f-droid.org/en/packages/"
FDROID_API = "https://f-droid.org/api/v1/packages"
FDROID_REPO = "https://f-droid.org/repo"
APKMIRROR_HOME = "https://www.apkmirror.com/"
APKPURE_NEW = "https://apkpure.com/app"


class FDroidSource:
    """Recently updated apps on F-Droid (fully legal source, reliable).

    Resolves at most MAX_RESOLVE apps per run; the listing is re-scraped
    every pass, so remaining apps are picked up incrementally.
    """

    name = "fdroid"
    MAX_RESOLVE = 15

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=2.0)
        try:
            resp = http.get(FDROID_PACKAGES)
        except HttpError as exc:
            logger.warning("f-droid listing failed: %s", exc)
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.select("a[href*='/en/packages/']"):
            href = a.get("href", "")
            m = re.search(r"/en/packages/([A-Za-z0-9_.]+)/?$", href)
            if m:
                links.append(m.group(1))
        resolved = 0
        for pkg in dict.fromkeys(links):  # unique, order-preserving
            if resolved >= self.MAX_RESOLVE:
                break
            resolved += 1  # count ATTEMPTS so failures can't loop forever
            target = self._resolve_fdroid(http, pkg)
            if target:
                yield target

    @staticmethod
    def _resolve_fdroid(http: PoliteSession, pkg: str) -> Target | None:
        try:
            meta = http.get(f"{FDROID_API}/{pkg}").json()
        except HttpError:
            return None
        packages = meta.get("packages") or []
        if not packages:
            return None
        latest = max(packages, key=lambda p: p.get("versionCode", 0))
        code = latest.get("versionCode")
        version = latest.get("versionName", "")
        if not code:
            return None
        # F-Droid download URL convention: /repo/{packageName}_{versionCode}.apk
        return Target(
            kind=TargetKind.APK,
            source="fdroid",
            locator=f"{FDROID_REPO}/{pkg}_{code}.apk",
            name=pkg,
            version=str(version),
        )


class ApkMirrorSource:
    """Recent uploads listed on APKMirror's front page (best-effort)."""

    name = "apkmirror"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=4.0)
        try:
            resp = http.get(APKMIRROR_HOME)
        except HttpError as exc:
            logger.warning("apkmirror front page failed (anti-bot likely): %s", exc)
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        seen: set[str] = set()
        intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
        intel_enabled = getattr(intel_cfg, "enabled", True) if intel_cfg else True

        for a in soup.select("a[href*='-release/']"):
            href = a.get("href", "")
            m = re.match(r"^(/apk/[^/]+/[^/]+/[^/]+-release/)", href)
            if not m:
                continue
            page = "https://www.apkmirror.com" + m.group(1)
            if page in seen:
                continue
            seen.add(page)
            slug = m.group(1).rstrip("/").split("/")[-1]
            target = Target(
                kind=TargetKind.APK,
                source=self.name,
                locator=page,  # acquisition resolves the real file URL
                name=slug,
            )
            if intel_enabled:
                ev = evaluate_target(target, cfg=intel_cfg)
                if not ev.keep:
                    continue
                target.priority = ev.score
            yield target
        logger.info("apkmirror yielded %d release pages", len(seen))


class ApkPureSource:
    """New apps listed on APKPure (best-effort)."""

    name = "apkpure"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=4.0)
        try:
            resp = http.get(APKPURE_NEW)
        except HttpError as exc:
            logger.warning("apkpure listing failed: %s", exc)
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        seen: set[str] = set()
        intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
        intel_enabled = getattr(intel_cfg, "enabled", True) if intel_cfg else True

        for a in soup.select("a[href]"):
            href = a.get("href", "")
            m = re.search(r"/([a-z0-9\-]+)/(com\.[A-Za-z0-9_.]+)$", href)
            if not m:
                continue
            pkg = m.group(2)
            if pkg in seen:
                continue
            seen.add(pkg)
            target = Target(
                kind=TargetKind.APK,
                source=self.name,
                locator=f"apkpure://{pkg}",  # resolved by acquisition
                name=pkg,
            )
            if intel_enabled:
                ev = evaluate_target(target, cfg=intel_cfg)
                if not ev.keep:
                    continue
                target.priority = ev.score
            yield target
        logger.info("apkpure yielded %d packages", len(seen))


class TargetListSource:
    """Explicit package names from config.discovery.apk.target_packages.

    Resolution order: F-Droid API -> apkpure:// URI (acquisition resolves).
    """

    name = "target_list"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=2.0)
        for pkg in ctx.cfg.discovery.apk.target_packages:
            target = FDroidSource._resolve_fdroid(http, pkg)
            if target:
                yield target
            else:
                yield Target(
                    kind=TargetKind.APK,
                    source="apkpure_target",
                    locator=f"apkpure://{pkg}",
                    name=pkg,
                )
