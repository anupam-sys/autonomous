"""Stage 3 runner: scan acquired artifacts -> store findings -> cleanup."""
from __future__ import annotations

from pathlib import Path

from ..activity import emit
from ..fs_utils import force_rmtree
from ..log import get_logger
from ..models import TargetKind
from .gitleaks_runner import run_gitleaks
from .rules_loader import load_rules
from .scanner import Scanner

logger = get_logger("detect")


def run_scan(ctx) -> dict:
    rules = load_rules(ctx.cfg.paths.rules_dir)
    scanner = Scanner(ctx.cfg, rules)
    stats = {"scanned": 0, "files": 0, "findings_new": 0, "findings_dup": 0, "failed": 0}
    workers = max(1, getattr(ctx.cfg.limits, "workers", 2))
    batch = max(workers * 8, 64)

    targets = ctx.queue.claim(batch, status="acquired")
    if not targets:
        return stats

    if workers == 1 or len(targets) == 1:
        for target in targets:
            try:
                scanned, files, new, dup = _scan_single(ctx, target, scanner, rules)
                if scanned == 0 and files == 0 and new == 0:
                    stats["failed"] += 1
                else:
                    stats["scanned"] += scanned
                    stats["files"] += files
                    stats["findings_new"] += new
                    stats["findings_dup"] += dup
            except Exception as exc:
                logger.exception("scan failed for %s", target.name)
                ctx.queue.fail(target.id, str(exc)[:500])
                stats["failed"] += 1
                emit(ctx, "detect", f"scan FAILED {target.name}: {exc}",
                     target.name, level="error")
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as executor:
            fut_map = {
                executor.submit(_scan_single, ctx, t, scanner, rules): t
                for t in targets
            }
            for fut in as_completed(fut_map):
                t = fut_map[fut]
                try:
                    scanned, files, new, dup = fut.result()
                    if scanned == 0 and files == 0 and new == 0:
                        stats["failed"] += 1
                    else:
                        stats["scanned"] += scanned
                        stats["files"] += files
                        stats["findings_new"] += new
                        stats["findings_dup"] += dup
                except Exception as exc:
                    logger.exception("scan failed for %s", t.name)
                    ctx.queue.fail(t.id, str(exc)[:500])
                    stats["failed"] += 1
                    emit(ctx, "detect", f"scan FAILED {t.name}: {exc}",
                         t.name, level="error")

    return stats


def _scan_single(ctx, target, scanner: Scanner, rules: list) -> tuple[int, int, int, int]:
    """Scan a single acquired target."""
    artifact_path = ctx.db.latest_artifact_path(target.id)
    if not artifact_path:
        ctx.queue.fail(target.id, "no artifact recorded")
        return 0, 0, 0, 0
    root = Path(artifact_path)
    if not root.exists():
        ctx.queue.fail(target.id, "artifact path missing on disk")
        return 0, 0, 0, 0

    emit(ctx, "detect", f"analysing {target.name} ({artifact_path}) ...", target.name)
    findings, files = scanner.scan_tree(root, target.id)
    if (
        ctx.cfg.scan.gitleaks_enabled
        and target.kind is TargetKind.REPO
        and (root / ".git").exists()
    ):
        findings += run_gitleaks(ctx, root, rules, target.id)

    new = 0
    for f in findings:
        if ctx.db.insert_finding(f):
            new += 1
            emit(ctx, "finding",
                 f"[{f.severity.upper()}] {f.detector} ({f.service}) "
                 f"in {f.file_path}:{f.line} = {f.secret_preview}",
                 target.name, level="finding")

            from ..notify import maybe_notify_raw_finding

            maybe_notify_raw_finding(ctx, f, target)
    ctx.queue.complete(target.id)
    if new:
        logger.info("%s: %d NEW findings (%d files)", target.name, new, files)
        emit(ctx, "detect", f"{target.name}: {new} NEW findings ({files} files analysed)",
             target.name)
    else:
        logger.info("%s: clean (%d files)", target.name, files)
        emit(ctx, "detect", f"{target.name}: clean ({files} files analysed)", target.name)
    _cleanup(ctx, root, keep=bool(new))
    return 1, files, new, len(findings) - new


def _cleanup(ctx, root: Path, keep: bool) -> None:
    mode = ctx.cfg.limits.work_retention
    if mode == "keep" or (mode == "on_finding" and keep):
        return
    force_rmtree(root)
