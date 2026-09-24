"""Activity feed: stages narrate what they are doing, in real time.

The web dashboard reads the activity table to show exactly what the pipeline
is searching / downloading / extracting / analysing right now. Emitting must
never break a stage, so all failures are swallowed.
"""
from __future__ import annotations

from .log import get_logger

logger = get_logger("activity")


def emit(ctx, stage: str, message: str, target: str | None = None, level: str = "info") -> None:
    try:
        ctx.db.add_activity(stage, message, target, level)
    except Exception:
        logger.debug("activity emit failed", exc_info=True)
