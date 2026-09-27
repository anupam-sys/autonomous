"""SQLite persistence layer: schema + data-access methods.

Dedup guarantees:
  * targets   — unique on sha256(kind|locator|version): re-discovery is a no-op,
                but a NEW version of the same app/package yields a new target.
  * artifacts — sha256 content hash lets callers skip identical binaries.
  * findings  — unique on (secret_hash, target_id, file_path, line): re-scans
                update last_seen instead of duplicating rows.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import date
from pathlib import Path
from typing import Any

from .models import Artifact, Finding, Target, TargetKind

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    source      TEXT NOT NULL,
    locator     TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    dedup_key   TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'pending',
    priority    REAL NOT NULL DEFAULT 0.0,
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id),
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_artifacts_target ON artifacts(target_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha ON artifacts(sha256);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    detector        TEXT NOT NULL,
    service         TEXT NOT NULL,
    secret_type     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    secret_preview  TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    secret_enc      BLOB,               -- full value, Fernet-encrypted (nullable)
    context         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    triage_status   TEXT NOT NULL DEFAULT 'pending',
    triage_notes    TEXT,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(secret_hash, target_id, file_path, line)
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_service ON findings(service);
CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(triage_status);

CREATE TABLE IF NOT EXISTS llm_suggestions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,          -- dork | app | source
    value       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    stage       TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    stats       TEXT
);

CREATE TABLE IF NOT EXISTS bandwidth (
    day         TEXT PRIMARY KEY,
    bytes_used  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv (
    key         TEXT PRIMARY KEY,
    value       TEXT
);

CREATE TABLE IF NOT EXISTS activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now')),
    stage       TEXT NOT NULL,
    level       TEXT NOT NULL DEFAULT 'info',
    message     TEXT NOT NULL,
    target      TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_id ON activity(id);

CREATE TABLE IF NOT EXISTS indexed_ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    service_type    TEXT NOT NULL,          -- ollama | kobold | unknown
    url             TEXT NOT NULL,
    api_url         TEXT NOT NULL,
    is_online       INTEGER NOT NULL DEFAULT 0,
    is_open         INTEGER NOT NULL DEFAULT 0,  -- unauthenticated / exposed
    models          TEXT NOT NULL DEFAULT '[]', -- JSON array of model names
    latency_ms      REAL NOT NULL DEFAULT 0.0,
    version_info    TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'port_scan',
    last_checked    TEXT NOT NULL DEFAULT (datetime('now')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host, port, service_type)
);
CREATE INDEX IF NOT EXISTS idx_indexed_ports_online ON indexed_ports(is_online, is_open);
CREATE INDEX IF NOT EXISTS idx_indexed_ports_service ON indexed_ports(service_type);

CREATE TABLE IF NOT EXISTS agent_investigations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id),
    status          TEXT NOT NULL,          -- verified_live | false_positive_mock | revoked | unverified | error
    blast_radius    TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL DEFAULT '',
    patch_diff      TEXT,
    tool_trace      TEXT NOT NULL DEFAULT '[]', -- JSON array of tool calls & outputs
    completed_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(finding_id)
);
CREATE INDEX IF NOT EXISTS idx_investigations_finding ON agent_investigations(finding_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON agent_investigations(status);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path = self.path.parent / "secret.key"
        from . import crypto_vault

        crypto_vault.configure(self.key_path)

        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self._conn.execute("PRAGMA cache_size = -64000")
        self._lock = threading.RLock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after the initial schema for existing databases."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(findings)")}
        if "secret_enc" not in cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN secret_enc BLOB")
        tcols = {r["name"] for r in self._conn.execute("PRAGMA table_info(targets)")}
        if "priority" not in tcols:
            self._conn.execute("ALTER TABLE targets ADD COLUMN priority REAL NOT NULL DEFAULT 0.0")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_priority ON targets(status, priority DESC)")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------- targets ----------------

    def upsert_target(self, t: Target) -> tuple[int, bool]:
        """Insert a new target or touch last_seen. Returns (target_id, is_new)."""
        prio = float(getattr(t, "priority", 0.0) or 0.0)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT id, priority FROM targets WHERE dedup_key = ?", (t.dedup_key,)
            ).fetchone()
            if row:
                existing_prio = float(row["priority"] or 0.0)
                new_prio = max(existing_prio, prio)
                self._conn.execute(
                    "UPDATE targets SET last_seen = datetime('now'), priority = ? WHERE id = ?",
                    (new_prio, row["id"]),
                )
                return row["id"], False
            cur = self._conn.execute(
                """INSERT INTO targets (kind, source, locator, name, version, dedup_key, status, priority)
                   VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (t.kind.value, t.source, t.locator, t.name, t.version, t.dedup_key, prio),
            )
            return cur.lastrowid, True

    def claim_targets(self, limit: int, status: str = "pending") -> list[sqlite3.Row]:
        """Atomically move targets of a given status to 'claimed' and return them."""
        with self._lock, self._conn:
            return self._conn.execute(
                """UPDATE targets SET status = 'claimed'
                   WHERE id IN (
                       SELECT id FROM targets WHERE status = ?
                       ORDER BY priority DESC, id ASC LIMIT ?
                   )
                   RETURNING *""",
                (status, limit),
            ).fetchall()

    def set_target_status(
        self, target_id: int, status: str, error: str | None = None
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE targets SET status = ?, error = ?, "
                "last_seen = datetime('now') WHERE id = ?",
                (status, error, target_id),
            )

    def requeue_claimed(self) -> int:
        """Crash recovery: claimed-but-never-finished targets go back to pending."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE targets SET status = 'pending' WHERE status = 'claimed'"
            )
            return cur.rowcount

    def prune_and_rescore_targets(self, eval_fn) -> dict[str, int]:
        """Evaluate pending targets: skip spam/noise, update priorities for high-value targets."""
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, kind, source, locator, name, version, priority FROM targets WHERE status = 'pending'"
            ).fetchall()
            skipped = 0
            rescored = 0
            for r in rows:
                t = Target(
                    id=r["id"],
                    kind=TargetKind(r["kind"]),
                    source=r["source"],
                    locator=r["locator"],
                    name=r["name"],
                    version=r["version"],
                    priority=float(r["priority"] or 0.0),
                )
                ev = eval_fn(t)
                if not ev.keep:
                    self._conn.execute(
                        "UPDATE targets SET status = 'skipped', error = ? WHERE id = ?",
                        (f"intelligence: {ev.reason}", r["id"]),
                    )
                    skipped += 1
                elif ev.score != float(r["priority"] or 0.0):
                    self._conn.execute(
                        "UPDATE targets SET priority = ? WHERE id = ?",
                        (ev.score, r["id"]),
                    )
                    rescored += 1
            return {"total": len(rows), "skipped": skipped, "rescored": rescored}

    # ---------------- artifacts ----------------

    def insert_artifact(self, a: Artifact) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO artifacts (target_id, path, sha256, size_bytes)
                   VALUES (?, ?, ?, ?)""",
                (a.target_id, a.path, a.sha256, a.size_bytes),
            )
            return cur.lastrowid

    def artifact_seen(self, sha256: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM artifacts WHERE sha256 = ? LIMIT 1", (sha256,)
            ).fetchone()
            return row is not None

    def latest_artifact_path(self, target_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT path FROM artifacts WHERE target_id = ? ORDER BY id DESC LIMIT 1",
                (target_id,),
            ).fetchone()
            return row["path"] if row else None

    # ---------------- findings ----------------

    def insert_finding(self, f: Finding) -> bool:
        """Insert a finding; True if new, False if it was a duplicate.

        The full secret value (f.secret_full) is stored ONLY Fernet-encrypted
        in secret_enc — never in plaintext. Duplicates update last_seen and
        only encrypt if backfilling a missing secret_enc.
        """
        from . import crypto_vault

        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT id, secret_enc FROM findings WHERE secret_hash = ? AND target_id = ? AND file_path = ? AND line = ?",
                (f.secret_hash, f.target_id, f.file_path, f.line),
            ).fetchone()
            if existing:
                enc = None
                if f.secret_full and existing["secret_enc"] is None:
                    enc = crypto_vault.encrypt(f.secret_full, self.key_path)
                self._conn.execute(
                    """UPDATE findings SET last_seen = datetime('now'),
                         secret_enc = COALESCE(secret_enc, ?)
                       WHERE id = ?""",
                    (enc, existing["id"]),
                )
                f.id = existing["id"]
                return False

            enc = crypto_vault.encrypt(f.secret_full, self.key_path) if f.secret_full else None
            cur = self._conn.execute(
                """INSERT INTO findings
                   (target_id, detector, service, secret_type, file_path, line,
                    secret_preview, secret_hash, secret_enc, context, severity,
                    confidence, triage_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f.target_id,
                    f.detector,
                    f.service,
                    f.secret_type.value,
                    f.file_path,
                    f.line,
                    f.secret_preview,
                    f.secret_hash,
                    enc,
                    f.context,
                    f.severity,
                    f.confidence,
                    f.triage_status.value,
                ),
            )
            f.id = cur.lastrowid
            return True

    def get_finding(self, finding_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                """SELECT f.*, t.name AS target_name, t.kind AS target_kind,
                          t.locator AS target_locator, t.source AS target_source
                   FROM findings f JOIN targets t ON t.id = f.target_id
                   WHERE f.id = ?""",
                (finding_id,),
            ).fetchone()

    def get_finding_secret(self, finding_id: int) -> str | None:
        """Decrypt and return the full secret value (or None if not stored)."""
        from . import crypto_vault

        with self._lock:
            row = self._conn.execute(
                "SELECT secret_enc FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        if not row or row["secret_enc"] is None:
            return None
        return crypto_vault.decrypt(row["secret_enc"], self.key_path)

    def untriaged_findings(
        self, min_confidence: float, limit: int
    ) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                """SELECT f.*, t.name AS target_name, t.kind AS target_kind
                   FROM findings f JOIN targets t ON t.id = f.target_id
                   WHERE f.triage_status = 'pending' AND f.confidence >= ?
                   ORDER BY f.confidence DESC, f.id LIMIT ?""",
                (min_confidence, limit),
            ).fetchall()

    def set_finding_triage(
        self,
        finding_id: int,
        status: str,
        notes: str | None = None,
        confidence: float | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """UPDATE findings
                   SET triage_status = ?, triage_notes = ?,
                       confidence = COALESCE(?, confidence)
                   WHERE id = ?""",
                (status, notes, confidence, finding_id),
            )

    def findings_for_report(self, max_severity_rank: int | None = None) -> list[sqlite3.Row]:
        sql = """SELECT f.*, t.name AS target_name, t.kind AS target_kind,
                        t.locator AS target_locator, t.source AS target_source
                 FROM findings f JOIN targets t ON t.id = f.target_id """
        params: list[Any] = []
        if max_severity_rank is not None:
            sql += """WHERE (CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                           WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                           ELSE 4 END) <= ? """
            params.append(max_severity_rank)
        sql += """ORDER BY
                   CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                   ELSE 4 END,
                   f.confidence DESC"""
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ---------------- llm suggestions ----------------

    def add_suggestion(self, kind: str, value: str, status: str = "pending") -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO llm_suggestions (kind, value, status) "
                "VALUES (?, ?, ?)",
                (kind, value, status),
            )
            return cur.rowcount > 0

    def suggestions(
        self, kind: str | None = None, status: str | None = None
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM llm_suggestions WHERE 1=1"
        params: list = []
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if status:
            sql += " AND status = ?"
            params.append(status)
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def set_suggestion_status(self, suggestion_id: int, status: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE llm_suggestions SET status = ? WHERE id = ?",
                (status, suggestion_id),
            )

    # ---------------- runs ----------------

    def start_run(self, stage: str) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO runs (stage) VALUES (?)", (stage,)
            )
            return cur.lastrowid

    def finish_run(self, run_id: int, stats: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE runs SET finished_at = datetime('now'), stats = ? WHERE id = ?",
                (json.dumps(stats), run_id),
            )

    # ---------------- bandwidth ----------------

    def add_bandwidth(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        today = date.today().isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO bandwidth (day, bytes_used) VALUES (?, ?)
                   ON CONFLICT(day) DO UPDATE SET bytes_used = bytes_used + ?""",
                (today, nbytes, nbytes),
            )

    def bandwidth_today(self) -> int:
        today = date.today().isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT bytes_used FROM bandwidth WHERE day = ?", (today,)
            ).fetchone()
            return row["bytes_used"] if row else 0

    def detector_counts(self) -> dict:
        with self._lock:
            return {
                r["detector"]: r["n"]
                for r in self._conn.execute(
                    "SELECT detector, COUNT(*) AS n FROM findings GROUP BY detector"
                )
            }

    def severity_counts(self) -> dict:
        with self._lock:
            return {
                r["severity"]: r["n"]
                for r in self._conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
                )
            }

    # ---------------- activity feed ----------------

    def add_activity(
        self, stage: str, message: str, target: str | None = None, level: str = "info"
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO activity (stage, level, message, target) VALUES (?, ?, ?, ?)",
                (stage, level, message, target),
            )
            # keep the table bounded (last ~5000 events)
            self._conn.execute(
                "DELETE FROM activity WHERE id < "
                "(SELECT COALESCE(MAX(id), 0) - 5000 FROM activity)"
            )

    def activity_since(self, after_id: int, limit: int = 300) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM activity WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()

    def activity_latest(self, limit: int = 1) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def recent_runs(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    # ---------------- kv (source state) ----------------

    def get_kv(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def set_kv(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = ?",
                (key, value, value),
            )

    # ---------------- indexed ports (ollama / kobold) ----------------

    def upsert_indexed_port(
        self,
        host: str,
        port: int,
        service_type: str,
        url: str,
        api_url: str,
        is_online: bool,
        is_open: bool,
        models: list[str] | str,
        latency_ms: float = 0.0,
        version_info: str = "",
        source: str = "port_scan",
    ) -> tuple[int, bool]:
        """Insert or update an indexed port. Returns (port_id, is_new)."""
        if isinstance(models, list):
            models_json = json.dumps(models)
        else:
            models_json = str(models)

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT id FROM indexed_ports WHERE host = ? AND port = ? AND service_type = ?",
                (host, port, service_type),
            ).fetchone()
            if row:
                self._conn.execute(
                    """UPDATE indexed_ports
                       SET url = ?, api_url = ?, is_online = ?, is_open = ?,
                           models = ?, latency_ms = ?, version_info = ?,
                           source = ?, last_checked = datetime('now')
                       WHERE id = ?""",
                    (url, api_url, int(is_online), int(is_open),
                     models_json, latency_ms, version_info, source, row["id"]),
                )
                return row["id"], False

            cur = self._conn.execute(
                """INSERT INTO indexed_ports
                   (host, port, service_type, url, api_url, is_online, is_open,
                    models, latency_ms, version_info, source, last_checked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (host, port, service_type, url, api_url, int(is_online), int(is_open),
                 models_json, latency_ms, version_info, source),
            )
            return cur.lastrowid, True

    def list_indexed_ports(
        self,
        service_type: str | None = None,
        only_open: bool = False,
        only_online: bool = False,
    ) -> list[sqlite3.Row]:
        """List indexed ports with optional filtering by service, open status, or online status."""
        query = "SELECT * FROM indexed_ports WHERE 1=1"
        params: list[Any] = []
        if service_type:
            query += " AND service_type = ?"
            params.append(service_type)
        if only_open:
            query += " AND is_open = 1"
        if only_online:
            query += " AND is_online = 1"
        query += " ORDER BY is_open DESC, is_online DESC, latency_ms ASC, id ASC"

        with self._lock, self._conn:
            return self._conn.execute(query, params).fetchall()

    def get_indexed_port(self, port_id: int) -> sqlite3.Row | None:
        with self._lock, self._conn:
            return self._conn.execute(
                "SELECT * FROM indexed_ports WHERE id = ?", (port_id,)
            ).fetchone()

    def delete_indexed_port(self, port_id: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM indexed_ports WHERE id = ?", (port_id,)
            )
            return cur.rowcount > 0

    def indexed_port_counts(self) -> dict[str, int]:
        with self._lock, self._conn:
            total = self._conn.execute("SELECT COUNT(*) FROM indexed_ports").fetchone()[0]
            online = self._conn.execute("SELECT COUNT(*) FROM indexed_ports WHERE is_online = 1").fetchone()[0]
            open_count = self._conn.execute("SELECT COUNT(*) FROM indexed_ports WHERE is_open = 1").fetchone()[0]
            ollama = self._conn.execute("SELECT COUNT(*) FROM indexed_ports WHERE service_type = 'ollama'").fetchone()[0]
            kobold = self._conn.execute("SELECT COUNT(*) FROM indexed_ports WHERE service_type = 'kobold'").fetchone()[0]
            return {
                "total": total,
                "online": online,
                "open": open_count,
                "ollama": ollama,
                "kobold": kobold,
            }

    # ---------------- agent investigations ----------------

    def upsert_investigation(
        self,
        finding_id: int,
        status: str,
        blast_radius: str = "",
        summary: str = "",
        patch_diff: str | None = None,
        tool_trace: list | str = "[]",
    ) -> int:
        trace_json = tool_trace if isinstance(tool_trace, str) else json.dumps(tool_trace, default=str)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO agent_investigations
                   (finding_id, status, blast_radius, summary, patch_diff, tool_trace, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(finding_id) DO UPDATE SET
                       status = excluded.status,
                       blast_radius = excluded.blast_radius,
                       summary = excluded.summary,
                       patch_diff = excluded.patch_diff,
                       tool_trace = excluded.tool_trace,
                       completed_at = datetime('now')""",
                (finding_id, status, blast_radius, summary, patch_diff, trace_json),
            )
            return cur.lastrowid

    def get_investigation(self, finding_id: int) -> sqlite3.Row | None:
        with self._lock, self._conn:
            return self._conn.execute(
                """SELECT ai.*, f.detector, f.service, f.file_path, f.line, f.secret_preview,
                          f.severity, f.context, t.name as target_name, t.kind as target_kind
                   FROM agent_investigations ai
                   JOIN findings f ON ai.finding_id = f.id
                   JOIN targets t ON f.target_id = t.id
                   WHERE ai.finding_id = ?""",
                (finding_id,),
            ).fetchone()

    def list_investigations(
        self, limit: int = 100, status: str | None = None
    ) -> list[sqlite3.Row]:
        query = (
            "SELECT ai.*, f.detector, f.service, f.file_path, f.line, f.secret_preview, "
            "f.severity, t.name as target_name, t.kind as target_kind "
            "FROM agent_investigations ai "
            "JOIN findings f ON ai.finding_id = f.id "
            "JOIN targets t ON f.target_id = t.id "
        )
        params: list[Any] = []
        if status:
            query += " WHERE ai.status = ?"
            params.append(status)
        query += " ORDER BY ai.id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn:
            return self._conn.execute(query, params).fetchall()

    def untriaged_findings_for_agent(
        self, min_confidence: float = 0.5, limit: int = 100
    ) -> list[sqlite3.Row]:
        with self._lock, self._conn:
            return self._conn.execute(
                """SELECT f.*, t.name AS target_name, t.kind AS target_kind, t.locator AS target_locator
                   FROM findings f
                   JOIN targets t ON f.target_id = t.id
                   WHERE f.confidence >= ?
                     AND f.id NOT IN (SELECT finding_id FROM agent_investigations)
                   ORDER BY CASE f.severity
                       WHEN 'critical' THEN 1
                       WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3
                       ELSE 4
                   END, f.id DESC
                   LIMIT ?""",
                (min_confidence, limit),
            ).fetchall()

    def investigation_counts(self) -> dict[str, Any]:
        with self._lock, self._conn:
            total = self._conn.execute("SELECT COUNT(*) FROM agent_investigations").fetchone()[0]
            by_status = {
                r["status"]: r["n"]
                for r in self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM agent_investigations GROUP BY status"
                )
            }
            return {"total": total, "by_status": by_status}

    # ---------------- stats ----------------

    def counts(self) -> dict:
        with self._lock:
            targets = {
                r["status"]: r["n"]
                for r in self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM targets GROUP BY status"
                )
            }
            findings = self._conn.execute(
                "SELECT COUNT(*) AS n FROM findings"
            ).fetchone()["n"]
            pending_triage = self._conn.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE triage_status = 'pending'"
            ).fetchone()["n"]
            suggestions = self._conn.execute(
                "SELECT COUNT(*) AS n FROM llm_suggestions WHERE status = 'pending'"
            ).fetchone()["n"]
            ports_stats = self.indexed_port_counts()
            investigations = self.investigation_counts()
        return {
            "targets_by_status": targets,
            "findings_total": findings,
            "findings_pending_triage": pending_triage,
            "suggestions_pending": suggestions,
            "indexed_ports": ports_stats,
            "agent_investigations": investigations,
            "bandwidth_today_mb": round(self.bandwidth_today() / 1e6, 1),
        }
