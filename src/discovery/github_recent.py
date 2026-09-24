"""GitHub repository search, two modes:

* No token  -> /search/repositories for recently created repos (10 req/min).
* With token-> /search/code with secret dorks (much higher yield). Dorks come
               from SEED_DORKS plus LLM suggestions approved in the DB.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Iterable

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.github_recent")

SEARCH_REPOS = "https://api.github.com/search/repositories"
SEARCH_CODE = "https://api.github.com/search/code"

SEED_DORKS = [
    '"-----BEGIN RSA PRIVATE KEY"',
    '"-----BEGIN OPENSSH PRIVATE KEY"',
    '"-----BEGIN PRIVATE KEY"',
    '"AIzaSy" in:file',
    '"xoxb-" in:file',
    '"sk_live_" in:file',
    '"ghp_" in:file',
    '"AKIA" extension:properties',
    'filename:.env "PASSWORD"',
    '"firebaseio.com" in:file',
]


class GithubRecentSource:
    name = "github_recent"

    def discover(self, ctx) -> Iterable[Target]:
        token = ctx.cfg.discovery.github_recent.token
        per_page = ctx.cfg.discovery.github_recent.per_page
        http = PoliteSession(min_interval=7.0 if not token else 3.0)
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        if token:
            yield from self._dork_search(ctx, http, headers, per_page)
        else:
            yield from self._recent_repos(ctx, http, headers, per_page)

    def _recent_repos(self, ctx, http, headers, per_page) -> Iterable[Target]:
        since = (date.today() - timedelta(days=7)).isoformat()
        params = {
            "q": f"created:>{since}",
            "sort": "updated",
            "order": "desc",
            "per_page": per_page,
        }
        try:
            resp = http.get(SEARCH_REPOS, params=params, headers=headers)
        except HttpError as exc:
            logger.warning("recent-repo search failed: %s", exc)
            return
        for item in resp.json().get("items", []):
            yield Target(
                kind=TargetKind.REPO,
                source=self.name,
                locator=item["clone_url"],
                name=item["full_name"],
            )

    def _dork_search(self, ctx, http, headers, per_page) -> Iterable[Target]:
        dorks = list(SEED_DORKS)
        for row in ctx.db.suggestions(kind="dork", status="approved"):
            dorks.append(row["value"])

        # rotate through dorks so each run advances without hammering the API
        idx = int(ctx.db.get_kv("github_dork_idx") or 0)
        dork = dorks[idx % len(dorks)]
        ctx.db.set_kv("github_dork_idx", str(idx + 1))
        from ..activity import emit
        emit(ctx, "discovery", f"github dork search: {dork}")

        params = {"q": dork, "per_page": per_page, "sort": "indexed", "order": "desc"}
        try:
            resp = http.get(SEARCH_CODE, params=params, headers=headers)
        except HttpError as exc:
            logger.warning("dork search %r failed: %s", dork, exc)
            return
        repos: set[str] = set()
        for item in resp.json().get("items", []):
            repo = (item.get("repository") or {}).get("full_name")
            if repo and repo not in repos:
                repos.add(repo)
                yield Target(
                    kind=TargetKind.REPO,
                    source="github_dork",
                    locator=f"https://github.com/{repo}.git",
                    name=repo,
                )
        logger.info("dork %r matched %d repos", dork, len(repos))
