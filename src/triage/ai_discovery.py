"""AI-assisted discovery expansion (the "find NEW apps/repos/docs" loop).

Periodically asks the LLM — based on what we're actually finding — for:
  * dorks   : new code-search queries (fed to github_recent when a token exists)
  * apps    : package names worth pulling from mirrors
  * sources : new public data sources worth adding

LLM proposes; the allow-list disposes: suggestions land in llm_suggestions as
'pending' unless ai_discovery.allow_auto_dorks=true (dorks only). Approved
dorks are consumed by GithubRecentSource automatically.
"""
from __future__ import annotations

import json
import re
import time

from ..log import get_logger

logger = get_logger("triage.ai_discovery")

PROMPT = """You expand the coverage of an exposed-secrets research pipeline.
Current detector hit counts: {detectors}
Current code-search dorks: {dorks}
Current discovery sources: GitHub events/search, GitLab, npm, PyPI, F-Droid,
APKMirror, APKPure, Docker Hub.

Propose NEW, specific, legal-to-access public discovery ideas. Respond ONLY
with JSON:
{{"dorks": ["<github code search query strings>", ...],
  "apps": ["<android package names likely to hardcode keys>", ...],
  "sources": ["<public site/feed hosting code or apps>", ...]}}
Max 8 dorks, 8 apps, 4 sources. No commentary."""


def run_ai_discovery(ctx) -> dict:
    cfg = ctx.cfg.llm
    if not (cfg.enabled and cfg.ai_discovery.enabled):
        return {}
    last = float(ctx.db.get_kv("ai_discovery_last") or 0)
    if time.time() - last < cfg.ai_discovery.interval_hours * 3600:
        return {}

    from .triage import _client

    dorks = [d.split(":", 1)[-1] for d in ctx.db.detector_counts()]  # cheap summary
    prompt = PROMPT.format(
        detectors=json.dumps(ctx.db.detector_counts()),
        dorks=json.dumps(dorks[:20]),
    )
    try:
        resp = _client(ctx).chat.completions.create(
            model=cfg.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        text = resp.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("ai_discovery LLM call failed: %s", exc)
        return {"error": str(exc)}

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {"error": "unparseable"}
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {"error": "unparseable"}

    auto = "approved" if cfg.ai_discovery.allow_auto_dorks else "pending"
    stats = {"dorks": 0, "apps": 0, "sources": 0}
    for dork in data.get("dorks", [])[:8]:
        if ctx.db.add_suggestion("dork", str(dork), status=auto):
            stats["dorks"] += 1
    for app in data.get("apps", [])[:8]:
        if ctx.db.add_suggestion("app", str(app)):
            stats["apps"] += 1
    for source in data.get("sources", [])[:4]:
        if ctx.db.add_suggestion("source", str(source)):
            stats["sources"] += 1
    ctx.db.set_kv("ai_discovery_last", str(time.time()))
    logger.info("ai_discovery suggestions: %s (dorks %s)", stats,
                "auto-approved" if cfg.ai_discovery.allow_auto_dorks else "awaiting approval")
    from ..activity import emit
    emit(ctx, "ai_discovery",
         f"LLM proposed {stats['dorks']} dorks, {stats['apps']} apps, "
         f"{stats['sources']} sources ({'auto-approved' if cfg.ai_discovery.allow_auto_dorks else 'awaiting approval'})")
    return stats
