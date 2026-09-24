"""Bitbucket recently-created public repos (best-effort, off by default)."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Iterable

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.bitbucket")

API = "https://api.bitbucket.org/2.0/repositories"


class BitbucketSource:
    name = "bitbucket"

    def discover(self, ctx) -> Iterable[Target]:
        since = (date.today() - timedelta(days=2)).isoformat()
        http = PoliteSession(min_interval=3.0)
        params = {"q": f'created_on>={since}', "pagelen": 25, "sort": "-created_on"}
        try:
            resp = http.get(API, params=params)
        except HttpError as exc:
            logger.warning("bitbucket listing failed: %s", exc)
            return
        for repo in resp.json().get("values", []):
            for link in repo.get("links", {}).get("clone", []):
                if link.get("name") == "https":
                    yield Target(
                        kind=TargetKind.REPO,
                        source=self.name,
                        locator=link["href"],
                        name=repo.get("full_name", link["href"]),
                    )
