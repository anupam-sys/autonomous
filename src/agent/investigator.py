"""Pipeline Stage Runner: Concurrent Autonomous Agent Investigations."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ..activity import emit
from ..log import get_logger
from .runner import investigate_finding, investigate_findings

logger = get_logger("agent.investigator")


def run_agent_investigations(ctx: Any) -> dict[str, Any]:
    """Execute autonomous agent investigations on untriaged findings concurrently."""
    if not getattr(ctx.cfg.agent, "enabled", True):
        logger.debug("Agent investigations disabled in config (agent.enabled: false)")
        return {}

    if not getattr(ctx.cfg.agent, "auto_investigate_high", True):
        logger.debug("Automatic agent investigations disabled "
                     "(agent.auto_investigate_high: false); manual triggers only")
        return {}

    api_key = (getattr(ctx.cfg.agent, "api_key", "") or getattr(ctx.cfg.llm, "api_key", ""))
    base_url = (getattr(ctx.cfg.agent, "base_url", "") or getattr(ctx.cfg.llm, "base_url", ""))
    if not api_key and "localhost" not in base_url and "127.0.0.1" not in base_url:
        logger.debug("Agent skipped: No LLM API key configured.")
        return {}

    min_confidence = getattr(ctx.cfg.agent, "min_confidence", 0.5)
    workers = max(1, getattr(ctx.cfg.limits, "agent_workers", 4))
    limit = workers * 10
    group_size = max(1, getattr(ctx.cfg.agent, "findings_per_investigation", 1))

    candidates = ctx.db.untriaged_findings_for_agent(min_confidence=min_confidence, limit=limit)
    if not candidates:
        return {"investigated": 0}

    groups = [candidates[i:i + group_size] for i in range(0, len(candidates), group_size)]

    stats = {
        "investigated": 0,
        "verified_live": 0,
        "false_positive_mock": 0,
        "revoked": 0,
        "unverified": 0,
        "errors": 0,
    }

    if group_size > 1:
        emit(ctx, "agent",
             f"autonomous investigation started ({len(candidates)} findings in "
             f"{len(groups)} grouped conversations, {workers} parallel threads)")
    else:
        emit(ctx, "agent",
             f"autonomous investigation started ({len(candidates)} findings, {workers} parallel threads)")

    def _worker(group) -> list[dict[str, Any]]:
        ids = [r["id"] for r in group]
        try:
            if len(ids) == 1:
                return [investigate_finding(ctx, ids[0])]
            return investigate_findings(ctx, ids)
        except Exception as exc:
            logger.exception("Agent worker failed for finding(s) %s: %s", ids, exc)
            return [{"finding_id": fid, "status": "error", "error": str(exc)} for fid in ids]

    with ThreadPoolExecutor(max_workers=min(workers, len(groups))) as executor:
        fut_map = {executor.submit(_worker, group): group for group in groups}
        for fut in as_completed(fut_map):
            group = fut_map[fut]
            rows_by_id = {r["id"]: r for r in group}
            for res in fut.result():
                fid = res.get("finding_id")
                row = rows_by_id.get(fid)
                status = res.get("status", "error")
                stats["investigated"] += 1

                if status in stats:
                    stats[status] += 1
                else:
                    stats["errors"] += 1

                summary = res.get("summary", "")
                blast = res.get("blast_radius", "")
                emit(
                    ctx,
                    "agent",
                    f"finding #{fid} [{row['detector'] if row else '?'}] -> {status.upper()}"
                    + (f" ({blast})" if blast else "")
                    + (f": {summary[:80]}" if summary else ""),
                    level="finding" if status == "verified_live" else "info",
                )

                # If verified live and Discord is active, trigger priority notification
                if status == "verified_live" and row is not None and ctx.cfg.notifications.discord.enabled:
                    _notify_verified_finding(ctx, row, res)

    logger.info("Agent investigation pass completed: %s", stats)
    return stats


def _notify_verified_finding(ctx: Any, finding_row: Any, investigation: dict[str, Any]) -> None:
    try:
        from ..notify import notify_finding

        row_dict = dict(finding_row)
        secret = ctx.db.get_finding_secret(row_dict["id"])
        if secret:
            row_dict["secret_full"] = secret

        notes = (
            f"🚨 **VERIFIED LIVE CREDENTIAL**\n"
            f"**Blast Radius:** {investigation.get('blast_radius', 'Unknown')}\n"
            f"**Summary:** {investigation.get('summary', '')}"
        )
        notify_finding(ctx, row_dict, "true_positive", notes)
    except Exception as exc:
        logger.debug("Failed notifying Discord for verified finding: %s", exc)
