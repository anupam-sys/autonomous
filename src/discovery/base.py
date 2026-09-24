"""Stage 1 runner: execute enabled discovery sources, enqueue new targets."""
from __future__ import annotations

import time

from ..activity import emit
from ..log import get_logger

logger = get_logger("discovery")


def run_discovery(ctx) -> dict:
    last = float(ctx.db.get_kv("discovery_last") or 0)
    if time.time() - last < ctx.cfg.discovery.interval_minutes * 60:
        logger.debug("discovery skipped (interval)")
        return {"skipped": "interval"}
    ctx.db.set_kv("discovery_last", str(time.time()))

    from .apk_source import ApkMirrorSource, ApkPureSource, FDroidSource, TargetListSource
    from .bitbucket_source import BitbucketSource
    from .github_firehose import FirehoseSource
    from .github_recent import GithubRecentSource
    from .gitlab_source import GitlabSource
    from .intelligence import evaluate_target
    from .registry_source import DockerHubSource, NpmSource, PypiSource

    d = ctx.cfg.discovery
    sources = []
    if d.firehose_enabled:
        sources.append(FirehoseSource())
    if d.github_recent.enabled:
        sources.append(GithubRecentSource())
    if d.gitlab_enabled:
        sources.append(GitlabSource())
    if d.bitbucket_enabled:
        sources.append(BitbucketSource())
    if d.registries.npm:
        sources.append(NpmSource())
    if d.registries.pypi:
        sources.append(PypiSource())
    if d.registries.docker_hub:
        sources.append(DockerHubSource())
    if d.apk.fdroid:
        sources.append(FDroidSource())
    if d.apk.apkmirror_recent:
        sources.append(ApkMirrorSource())
    if d.apk.apkpure_recent:
        sources.append(ApkPureSource())
    if d.apk.target_packages:
        sources.append(TargetListSource())

    intel_cfg = getattr(d, "intelligence", None)
    intel_enabled = getattr(intel_cfg, "enabled", True) if intel_cfg else True

    stats: dict[str, int] = {}
    emit(ctx, "discovery", f"discovery pass started ({len(sources)} sources)")
    for src in sources:
        try:
            emit(ctx, "discovery", f"searching source: {src.name} ...")
            new = 0
            filtered = 0
            for t in src.discover(ctx):
                if intel_enabled:
                    ev = evaluate_target(t, cfg=intel_cfg)
                    if not ev.keep:
                        filtered += 1
                        logger.debug("intelligence filtered %s: %s", t.name, ev.reason)
                        continue
                    t.priority = ev.score
                if ctx.queue.enqueue(t):
                    new += 1
            stats[src.name] = new
            logger.info("%-16s -> %d new targets (filtered %d noise)", src.name, new, filtered)
            emit(ctx, "discovery", f"{src.name} -> {new} new targets ({filtered} noise filtered)")
        except Exception:
            logger.exception("discovery source %s failed", src.name)
            emit(ctx, "discovery", f"source {src.name} FAILED", level="error")
            stats[src.name] = -1
    total = sum(v for v in stats.values() if v > 0)
    logger.info("discovery pass complete: %d new targets total", total)
    emit(ctx, "discovery", f"pass complete: {total} new targets")
    return stats
