"""SQLite-backed work queue — producers enqueue targets, workers claim them.

No external broker (Redis etc.) needed: claims are atomic UPDATE...RETURNING
statements, and crash recovery is `requeue_claimed()` at startup.
"""
from __future__ import annotations

import sqlite3
from typing import Iterable

from .db import Database
from .models import Target, TargetKind, TargetStatus


class WorkQueue:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---- producer side ----

    def enqueue(self, target: Target) -> bool:
        """True if this is a brand-new target (duplicate -> False, no-op)."""
        return self._db.upsert_target(target)[1]

    def enqueue_many(self, targets: Iterable[Target]) -> int:
        return sum(1 for t in targets if self.enqueue(t))

    # ---- consumer side ----

    def claim(self, limit: int = 1, status: str = "pending") -> list[Target]:
        rows = self._db.claim_targets(limit, status=status)
        return [self._row_to_target(r) for r in rows]

    def complete(self, target_id: int) -> None:
        self._db.set_target_status(target_id, TargetStatus.PROCESSED.value)

    def fail(self, target_id: int, error: str) -> None:
        self._db.set_target_status(target_id, TargetStatus.FAILED.value, error)

    def skip(self, target_id: int, reason: str) -> None:
        self._db.set_target_status(target_id, TargetStatus.SKIPPED.value, reason)

    def mark_acquired(self, target_id: int) -> None:
        self._db.set_target_status(target_id, TargetStatus.ACQUIRED.value)

    # ---- introspection ----

    def pending_count(self) -> int:
        return self._db.counts()["targets_by_status"].get("pending", 0)

    @staticmethod
    def _row_to_target(row: sqlite3.Row) -> Target:
        return Target(
            id=row["id"],
            kind=TargetKind(row["kind"]),
            source=row["source"],
            locator=row["locator"],
            name=row["name"],
            version=row["version"],
        )
