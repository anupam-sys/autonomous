"""GitLab recently-created public projects (no token required)."""
from __future__ import annotations

from typing import Iterable

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.gitlab")

API = "https://gitlab.com/api/v4/projects"


class GitlabSource:
    name = "gitlab"

    def discover(self, ctx) -> Iterable[Target]:
        http = PoliteSession(min_interval=3.0)
        params = {
            "order_by": "created_at",
            "sort": "desc",
            "visibility": "public",
            "per_page": 50,
        }
        headers = {}
        token = getattr(ctx.cfg, "gitlab_token", None)
        if token:
            headers["PRIVATE-TOKEN"] = token
        try:
            resp = http.get(API, params=params, headers=headers)
        except HttpError as exc:
            logger.warning("gitlab listing failed: %s", exc)
            return
        for proj in resp.json():
            url = proj.get("http_url_to_repo")
            path = proj.get("path_with_namespace")
            if url and path:
                yield Target(
                    kind=TargetKind.REPO,
                    source=self.name,
                    locator=url,
                    name=path,
                )
