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
    batch = max(1, ctx.cfg.limits.workers) * 2

    for target in ctx.queue.claim(batch, status="acquired"):
        artifact_path = ctx.db.latest_artifact_path(target.id)
        if not artifact_path:
            ctx.queue.fail(target.id, "no artifact recorded")
            stats["failed"] += 1
            continue
        root = Path(artifact_path)
        if not root.exists():
            ctx.queue.fail(target.id, "artifact path missing on disk")
            stats["failed"] += 1
            continue

        try:
            emit(ctx, "detect", f"analysing {target.name} ({artifact_path}) ...", target.name)
            findings, files = scanner.scan_tree(root, target.id)
            if (
                ctx.cfg.scan.gitleaks_enabled
                and target.kind is TargetKind.REPO
                and (root / ".git").exists()
            ):
                findings += run_gitleaks(ctx, root, rules, target.id)
        except Exception as exc:
            logger.exception("scan failed for %s", target.name)
            ctx.queue.fail(target.id, str(exc)[:500])
            stats["failed"] += 1
            emit(ctx, "detect", f"scan FAILED {target.name}: {exc}",
                 target.name, level="error")
            continue

        new = 0
        for f in findings:
            if ctx.db.insert_finding(f):
                new += 1
                emit(ctx, "finding",
                     f"[{f.severity.upper()}] {f.detector} ({f.service}) "
                     f"in {f.file_path}:{f.line} = {f.secret_preview}",
                     target.name, level="finding")
                     
                if ctx.cfg.notifications.discord.notify_on in ("any", "high_severity"):
                    from ..notify import notify_finding
                    notify_finding(ctx, {
                        "severity": f.severity,
                        "detector": f.detector,
                        "service": f.service,
                        "target_name": target.name,
                        "target_kind": target.kind.value,
                        "file_path": f.file_path,
                        "line": f.line,
                        "secret_preview": f.secret_preview,
                    }, "pending")
        stats["scanned"] += 1
        stats["files"] += files
        stats["findings_new"] += new
        stats["findings_dup"] += len(findings) - new
        ctx.queue.complete(target.id)
        if new:
            logger.info("%s: %d NEW findings (%d files)", target.name, new, files)
            emit(ctx, "detect", f"{target.name}: {new} NEW findings ({files} files analysed)",
                 target.name)
        else:
            logger.info("%s: clean (%d files)", target.name, files)
            emit(ctx, "detect", f"{target.name}: clean ({files} files analysed)", target.name)
        _cleanup(ctx, root, keep=bool(new))

    return stats


def _cleanup(ctx, root: Path, keep: bool) -> None:
    mode = ctx.cfg.limits.work_retention
    if mode == "keep" or (mode == "on_finding" and keep):
        return
    force_rmtree(root)
