"""Package registry discovery: npm changes feed, PyPI RSS, Docker Hub.

Yields Target(kind=PACKAGE) with locator = tarball/sdist URL (or docker:// URI);
acquisition (batch 3) knows how to fetch each.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterable
from urllib.parse import quote

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.registries")

NPM_CHANGES = "https://replicate.npmjs.com/_changes"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_UPDATES_RSS = "https://pypi.org/rss/updates.xml"
PYPI_JSON = "https://pypi.org/pypi"
DOCKERHUB_SEARCH = "https://hub.docker.com/v2/search/repositories"


class NpmSource:
    """Recently-published npm packages via the CouchDB-style changes feed."""

    name = "npm"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=2.0)
        since = ctx.db.get_kv("npm_since") or "0"
        try:
            resp = http.get(NPM_CHANGES, params={"since": since, "limit": 100})
        except HttpError as exc:
            logger.warning("npm changes feed failed: %s", exc)
            return
        data = resp.json()
        last_seq = data.get("last_seq")
        names = [r["id"] for r in data.get("results", []) if r.get("id")]
        for pkg in names[:30]:  # resolve at most 30 per run
            try:
                doc = http.get(f"{NPM_REGISTRY}/{quote(pkg, safe='@')}/latest")
                meta = doc.json()
                tarball = (meta.get("dist") or {}).get("tarball")
                version = meta.get("version", "")
                if tarball:
                    yield Target(
                        kind=TargetKind.PACKAGE,
                        source=self.name,
                        locator=tarball,
                        name=f"npm:{pkg}",
                        version=str(version),
                    )
            except HttpError:
                continue
        if last_seq:
            ctx.db.set_kv("npm_since", str(last_seq))


class PypiSource:
    """Recently-updated PyPI packages via the updates RSS feed (capped per run)."""

    name = "pypi"
    MAX_RESOLVE = 40

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=2.0)
        try:
            resp = http.get(PYPI_UPDATES_RSS)
        except HttpError as exc:
            logger.warning("pypi RSS failed: %s", exc)
            return
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError:
            logger.warning("pypi RSS unparseable")
            return
        resolved = 0
        for title in root.iter("title"):
            if resolved >= self.MAX_RESOLVE:
                break
            text = (title.text or "").strip()
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s+([0-9][A-Za-z0-9.\-]*)$", text)
            if not match:
                continue
            name, version = match.groups()
            try:
                meta = http.get(f"{PYPI_JSON}/{name}/{version}/json").json()
            except HttpError:
                continue
            for url_info in meta.get("urls", []):
                if url_info.get("packagetype") == "sdist":
                    resolved += 1
                    yield Target(
                        kind=TargetKind.PACKAGE,
                        source=self.name,
                        locator=url_info["url"],
                        name=f"pypi:{name}",
                        version=version,
                    )
                    break


class DockerHubSource:
    """Recently-pushed public images. Off by default; best-effort unauthenticated."""

    name = "dockerhub"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=2.0)
        try:
            resp = http.get(DOCKERHUB_SEARCH, params={"query": "", "page_size": 25})
        except HttpError as exc:
            logger.warning("dockerhub search failed (expected unauth sometimes): %s", exc)
            return
        for repo in resp.json().get("results", []):
            slug = repo.get("repo_name")
            if slug:
                yield Target(
                    kind=TargetKind.PACKAGE,
                    source=self.name,
                    locator=f"docker://{slug}:latest",
                    name=f"docker:{slug}",
                    version="latest",
                )
