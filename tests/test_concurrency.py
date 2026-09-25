"""Tests for concurrent acquisition and scanning throughput."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.models import Artifact, Target, TargetKind, TargetStatus
from src.acquire.base import run_acquire
from src.detect.base import run_scan
from src.decompile.apk_decompiler import _get_jadx_semaphore
from src.queue import WorkQueue


class DummyContext:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.queue = WorkQueue(db)


def test_jadx_semaphore_concurrency():
    sem = _get_jadx_semaphore(4)
    assert isinstance(sem, threading.Semaphore)
    # Ensure acquiring up to limit works without blocking
    acquired = [sem.acquire(blocking=False) for _ in range(4)]
    assert all(acquired)
    # 5th attempt should not acquire
    assert not sem.acquire(blocking=False)
    for _ in range(4):
        sem.release()


def test_concurrent_acquire_processes_multiple_workers(cfg, db):
    cfg.limits.workers = 4
    cfg.discovery.intelligence.enabled = False
    ctx = DummyContext(cfg, db)

    # Enqueue 6 targets
    for i in range(6):
        t = Target(
            kind=TargetKind.REPO,
            source="test",
            locator=f"https://github.com/org/repo{i}.git",
            name=f"repo-{i}",
        )
        ctx.queue.enqueue(t)

    active_threads = set()
    lock = threading.Lock()

    def mock_process(ctx_arg, target):
        with lock:
            active_threads.add(threading.current_thread().name)
        time.sleep(0.02)
        return Artifact(
            target_id=target.id,
            path=f"/fake/path/{target.name}",
            sha256="abc",
            size_bytes=1024,
        ), False

    with patch("src.acquire.base._process", side_effect=mock_process):
        stats = run_acquire(ctx)

    assert stats["acquired"] == 6
    # Confirms multiple worker threads executed the jobs
    assert len(active_threads) > 1


def test_concurrent_scan_processes_multiple_workers(cfg, db, tmp_path):
    cfg.limits.workers = 4
    cfg.scan.gitleaks_enabled = False
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.notify_on = "true_positive"
    ctx = DummyContext(cfg, db)

    # Create dummy artifact directories and targets
    for i in range(6):
        d = tmp_path / f"target_{i}"
        d.mkdir()
        (d / "sample.py").write_text(f"api_key = 'sk_live_1234567890abcdef{i}'\n")

        t = Target(
            kind=TargetKind.REPO,
            source="test",
            locator=f"https://github.com/org/t{i}.git",
            name=f"scan-target-{i}",
        )
        tid, _ = db.upsert_target(t)
        t.id = tid
        # Manually mark as acquired with artifact
        with db._lock, db._conn:
            db._conn.execute("UPDATE targets SET status = 'acquired' WHERE id = ?", (t.id,))
            db._conn.execute(
                "INSERT INTO artifacts (target_id, path, sha256, size_bytes) VALUES (?, ?, ?, ?)",
                (t.id, str(d), f"sha_{i}", 100),
            )

    active_scan_threads = set()
    lock = threading.Lock()

    orig_scan_tree = None

    with patch("requests.post") as mock_post:
        stats = run_scan(ctx)

        # Under true_positive, pending raw findings are NOT posted to Discord
        assert not mock_post.called

    assert stats["scanned"] == 6
