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
from .intelligence import evaluate_target

logger = get_logger("discovery.github_recent")

SEARCH_REPOS = "https://api.github.com/search/repositories"
SEARCH_CODE = "https://api.github.com/search/code"

INTELLIGENT_QUERIES = [
    'created:>{since} (api OR backend OR microservice OR "docker-compose")',
    'created:>{since} (fastapi OR express OR django OR "spring-boot" OR "nextjs")',
    'created:>{since} (terraform OR kubernetes OR pulumi OR serverless OR cloud)',
    'created:>{since} (bot OR webhook OR "telegram-bot" OR "discord-bot" OR integration)',
    'created:>{since} (stripe OR twilio OR openai OR supabase OR firebase)',
    'created:>{since} ("credentials" OR "config.json" OR ".env.example" OR "settings.py")',
]

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
        intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
        intel_enabled = getattr(intel_cfg, "enabled", True) if intel_cfg else True

        if intel_enabled:
            q_idx = int(ctx.db.get_kv("github_recent_q_idx") or 0)
            template = INTELLIGENT_QUERIES[q_idx % len(INTELLIGENT_QUERIES)]
            query = template.format(since=since)
            ctx.db.set_kv("github_recent_q_idx", str(q_idx + 1))
        else:
            query = f"created:>{since}"

        params = {
            "q": query,
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
            name = item.get("full_name")
            clone_url = item.get("clone_url")
            if not name or not clone_url:
                continue

            target = Target(
                kind=TargetKind.REPO,
                source=self.name,
                locator=clone_url,
                name=name,
            )

            if intel_enabled:
                meta = {
                    "description": item.get("description") or "",
                    "topics": item.get("topics") or [],
                    "language": item.get("language") or "",
                    "fork": item.get("fork", False),
                    "size": item.get("size", 0),
                    "archived": item.get("archived", False),
                }
                ev = evaluate_target(target, metadata=meta, cfg=intel_cfg)
                if not ev.keep:
                    logger.debug("skipping recent repo %s: %s", name, ev.reason)
                    continue
                target.priority = ev.score

            yield target

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
