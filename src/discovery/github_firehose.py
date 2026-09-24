"""GitHub public events firehose — no token required.

GET /events returns the most recent public events (repo creation, pushes).
We sample it every discovery run for CreateEvent / PushEvent / PublicEvent
and enqueue the affected repos as scan targets. Duplicate repos are absorbed
by the targets-table dedup, so overlap between runs is harmless.
"""
from __future__ import annotations

from typing import Iterable

from ..http_utils import PoliteSession
from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.firehose")

EVENTS_URL = "https://api.github.com/events"
WANTED = {"CreateEvent", "PushEvent", "PublicEvent"}


class FirehoseSource:
    name = "github_firehose"

    def __init__(self, per_page: int = 100):
        self.per_page = per_page

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=6.0)  # unauth: 60 req/hr budget
        headers = {}
        if ctx.cfg.discovery.github_recent.token:
            headers["Authorization"] = f"Bearer {ctx.cfg.discovery.github_recent.token}"
        resp = http.get(EVENTS_URL, params={"per_page": self.per_page}, headers=headers)
        seen: set[str] = set()
        for event in resp.json():
            if event.get("type") not in WANTED:
                continue
            repo = event.get("repo") or {}
            name = repo.get("name")  # "owner/repo"
            if not name or name in seen:
                continue
            seen.add(name)
            yield Target(
                kind=TargetKind.REPO,
                source=self.name,
                locator=f"https://github.com/{name}.git",
                name=name,
            )
        logger.info("firehose yielded %d repos", len(seen))
