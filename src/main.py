"""Entry point: orchestrates discovery -> acquisition -> scanning.

Usage:
    python -m src.main init           # create dirs + database
    python -m src.main stats          # show queue / findings counts
    python -m src.main run --once     # single pipeline pass
    python -m src.main run            # continuous daemon
"""
from __future__ import annotations

import argparse
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .acquire.base import run_acquire
from .config import Config
from .db import Database
from .detect.base import run_scan
from .discovery.base import run_discovery
from .log import get_logger, setup_logging
from .queue import WorkQueue
from .report.reporter import run_report
from .triage.ai_discovery import run_ai_discovery
from .triage.triage import run_triage

logger = get_logger("main")

# Pipeline stages, in execution order.
STAGES: list = [run_discovery, run_acquire, run_scan, run_triage,
                run_ai_discovery, run_report]


class Context:
    """Everything a stage needs, wired once."""

    def __init__(self, cfg: Config, db: Database, queue: WorkQueue):
        self.cfg = cfg
        self.db = db
        self.queue = queue


def run_pass(ctx: Context) -> None:
    # reload config each pass so dashboard edits take effect without restart
    try:
        ctx.cfg = Config.load(ctx.cfg._base_path, ctx.cfg._overlay_path)
    except Exception:
        logger.exception("config reload failed; keeping previous config")

    if ctx.cfg.notifications.discord.enabled and ctx.cfg.notifications.discord.bot_token:
        from .bot import get_active_bot, start_discord_bot

        if get_active_bot() is None:
            start_discord_bot(ctx)
            logger.info("interactive discord bot started in background")

    for stage in STAGES:
        run_id = ctx.db.start_run(getattr(stage, "__name__", str(stage)))
        try:
            stats = stage(ctx) or {}
        except Exception:
            logger.exception("stage %s failed", getattr(stage, "__name__", stage))
            stats = {"error": True}
        ctx.db.finish_run(run_id, stats)


def cmd_init(cfg: Config) -> None:
    cfg.ensure_dirs()
    db = Database(cfg.paths.db_path)
    db.close()
    logger.info("initialised database at %s", cfg.paths.db_path)


def cmd_stats(cfg: Config) -> None:
    db = Database(cfg.paths.db_path)
    stats = db.counts()
    logger.info("targets by status : %s", stats["targets_by_status"])
    logger.info("findings total    : %s", stats["findings_total"])
    logger.info("pending triage    : %s", stats["findings_pending_triage"])
    logger.info("pending suggestions: %s", stats["suggestions_pending"])
    logger.info("bandwidth today   : %s MB", stats["bandwidth_today_mb"])
    db.close()


def _instance_lock(path: Path):
    """Single-instance guard: hold an OS-level file lock for process lifetime.
    Returns the open handle, or None if another instance already holds it."""
    fh = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def _utc_age(ts: str) -> float:
    parsed = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return max(0.0, time.time() - parsed.timestamp())


def _heartbeat_loop(ctx: "Context", stop: threading.Event, shared: dict) -> None:
    """Every 45s, say out loud what the daemon is doing — on the console AND
    in the activity feed (so the dashboard never looks dead during silent ops)."""
    from .activity import emit

    while not stop.wait(45):
        try:
            # anchor to the last REAL event (skip our own heartbeats)
            latest = None
            for row in ctx.db.activity_latest(10):
                if row["stage"] != "heartbeat":
                    latest = row
                    break
            age = _utc_age(latest["ts"]) if latest else 9999.0
            if age < 45:  # real events are flowing; heartbeat would be noise
                continue
            sleep_until = shared.get("sleep_until")
            if sleep_until and time.monotonic() < sleep_until:
                msg = (f"idle: next pass in {int(sleep_until - time.monotonic())}s "
                       f"| queue: {ctx.queue.pending_count()} pending")
            else:
                msg = (f"still working ({int(age)}s): {latest['message'][:100]}") \
                    if latest else "starting up"
            logger.info("%s", msg)
            emit(ctx, "heartbeat", msg)  # dashboard liveness pulse
        except Exception:
            pass


def cmd_run(cfg: Config, once: bool) -> None:
    cfg.ensure_dirs()
    db = Database(cfg.paths.db_path)
    lock = _instance_lock(Path(cfg.paths.data_dir) / "pipeline.lock")
    if lock is None:
        logger.error("another pipeline instance is already running — aborting")
        return
    recovered = db.requeue_claimed()
    if recovered:
        logger.warning("requeued %d target(s) left in 'claimed' state", recovered)

    intel_cfg = getattr(cfg.discovery, "intelligence", None)
    if intel_cfg and getattr(intel_cfg, "enabled", True):
        from .discovery.intelligence import evaluate_target
        res = db.prune_and_rescore_targets(lambda t: evaluate_target(t, cfg=intel_cfg))
        if res["skipped"] > 0 or res["rescored"] > 0:
            logger.info("intelligence queue optimization: %d spam/noise skipped, %d prioritized (of %d pending)",
                        res["skipped"], res["rescored"], res["total"])

    ctx = Context(cfg, db, WorkQueue(db))

    if cfg.web.enabled:
        from .web.server import run_web

        thread = threading.Thread(target=run_web, args=(cfg, db), daemon=True)
        thread.start()
        logger.info("dashboard: http://%s:%d", cfg.web.host, cfg.web.port)

    if cfg.notifications.discord.enabled and cfg.notifications.discord.bot_token:
        from .bot import start_discord_bot

        start_discord_bot(ctx)
        logger.info("interactive discord bot started in background")

    if not STAGES:
        logger.warning("no stages registered yet (skeleton build)")
    if once:
        run_pass(ctx)
        db.close()
        return

    stop = threading.Event()
    shared: dict = {}
    threading.Thread(target=_heartbeat_loop, args=(ctx, stop, shared),
                     daemon=True).start()

    tick = max(60, cfg.scan.interval_minutes * 60)
    logger.info("daemon mode: pass every %ds (dashboard included)", tick)
    try:
        while True:
            started = datetime.now(timezone.utc)
            logger.info("=== pipeline pass starting ===")
            run_pass(ctx)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            pending = ctx.queue.pending_count()
            if pending > 0:
                sleep_s = 2.0
                logger.info("=== pass done in %.0fs — %d targets still pending; next pass in %.0fs ===",
                            elapsed, pending, sleep_s)
            else:
                sleep_s = max(5.0, tick - elapsed)
                logger.info("=== pass done in %.0fs — sleeping %ds ===", elapsed, sleep_s)
            shared["sleep_until"] = time.monotonic() + sleep_s
            time.sleep(sleep_s)
            shared.pop("sleep_until", None)
    finally:
        stop.set()


def cmd_report(cfg: Config) -> None:
    from .report.reporter import generate

    db = Database(cfg.paths.db_path)
    result = generate(Context(cfg, db, WorkQueue(db)))
    logger.info("report: %s", result)
    db.close()


def cmd_web(cfg: Config) -> None:
    from .web.server import run_web

    db = Database(cfg.paths.db_path)
    run_web(cfg, db)


def cmd_discord(cfg: Config) -> None:
    """Run interactive Discord bot in foreground."""
    cfg.ensure_dirs()
    db = Database(cfg.paths.db_path)
    ctx = Context(cfg, db, WorkQueue(db))
    from .bot import run_discord_bot_blocking

    run_discord_bot_blocking(ctx)


def cmd_reveal(cfg: Config, finding_id: int) -> None:
    """Print one finding with the full decrypted secret value."""
    db = Database(cfg.paths.db_path)
    row = next((r for r in db.findings_for_report() if r["id"] == finding_id), None)
    if not row:
        logger.error("finding #%d not found", finding_id)
        return
    secret = db.get_finding_secret(finding_id)
    print(f"finding #{finding_id}: [{row['severity']}] {row['detector']} ({row['service']})")
    print(f"  target   : {row['target_name']}  {row['target_locator']}")
    print(f"  location : {row['file_path']}:{row['line']}")
    print(f"  triage   : {row['triage_status']}  {row['triage_notes'] or ''}")
    print(f"  secret   : {secret if secret is not None else '(not stored — predates encrypted storage)'}")
    db.close()


def cmd_suggestions(cfg: Config, action: str, sid: int | None) -> None:
    db = Database(cfg.paths.db_path)
    if action == "list":
        for row in db.suggestions():
            logger.info("[%d] %s/%s: %s", row["id"], row["kind"], row["status"], row["value"])
    elif action in ("approve", "reject") and sid is not None:
        db.set_suggestion_status(sid, "approved" if action == "approve" else "rejected")
        logger.info("suggestion %d -> %s", sid, action)
    db.close()


def cmd_prune(cfg: Config) -> None:
    """Filter out spam/noise targets from the queue and prioritize high-value targets."""
    db = Database(cfg.paths.db_path)
    from .discovery.intelligence import evaluate_target
    intel_cfg = getattr(cfg.discovery, "intelligence", None)
    res = db.prune_and_rescore_targets(lambda t: evaluate_target(t, cfg=intel_cfg))
    logger.info("queue pruned: %d total inspected, %d spam/noise skipped, %d prioritized",
                res["total"], res["skipped"], res["rescored"])
    db.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fas",
        description="fully-autonomous secret-exposure research pipeline",
    )
    parser.add_argument("--config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create data dirs and database")
    run_p = sub.add_parser("run", help="run the pipeline")
    run_p.add_argument("--once", action="store_true", help="single pass, then exit")
    sub.add_parser("stats", help="print queue / findings statistics")
    sub.add_parser("prune", help="clean spam/noise from queue and prioritize targets")
    sub.add_parser("report", help="generate JSON+HTML report now")
    sub.add_parser("web", help="run the transparency dashboard (standalone)")
    sub.add_parser("discord", help="run the interactive Discord bot (standalone)")
    rev_p = sub.add_parser("reveal", help="print a finding with its full secret value")
    rev_p.add_argument("id", type=int)
    sug_p = sub.add_parser("suggestions", help="manage LLM discovery suggestions")
    sug_p.add_argument("action", choices=["list", "approve", "reject"])
    sug_p.add_argument("id", type=int, nargs="?", default=None)
    args = parser.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.log_level)

    if args.command == "init":
        cmd_init(cfg)
    elif args.command == "stats":
        cmd_stats(cfg)
    elif args.command == "prune":
        cmd_prune(cfg)
    elif args.command == "run":
        cmd_run(cfg, once=args.once)
    elif args.command == "report":
        cmd_report(cfg)
    elif args.command == "web":
        cmd_web(cfg)
    elif args.command == "discord":
        cmd_discord(cfg)
    elif args.command == "reveal":
        cmd_reveal(cfg, args.id)
    elif args.command == "suggestions":
        cmd_suggestions(cfg, args.action, args.id)


if __name__ == "__main__":
    main()
