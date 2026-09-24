"""Stage 2 runner: claim targets -> acquire -> (APK) decompile -> artifact.

After this stage a target has status 'acquired' and an artifact row pointing
at a scannable directory (repo checkout / extracted package / decompiled APK
tree). Stage 3 scans those directories.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..activity import emit
from ..fs_utils import force_rmtree
from ..log import get_logger
from ..models import Artifact, Target, TargetKind
from .apk_fetcher import ApkResolveFailed, fetch_apk
from .downloader import BudgetExceeded, FileTooLarge
from .package_fetcher import PackageFailed, fetch_package
from .repo_cloner import CloneFailed, clone_repo
from ..decompile.apk_decompiler import DecompileFailed, decompile_apk
from ..discovery.intelligence import evaluate_target

logger = get_logger("acquire")

_SKIP = (BudgetExceeded, FileTooLarge, ApkResolveFailed, CloneFailed,
         PackageFailed, DecompileFailed)


def run_acquire(ctx) -> dict:
    stats = {"acquired": 0, "skipped": 0, "failed": 0}
    batch = max(1, ctx.cfg.limits.workers) * 2
    intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
    intel_enabled = getattr(intel_cfg, "enabled", True) if intel_cfg else True

    for target in ctx.queue.claim(batch):
        if intel_enabled:
            ev = evaluate_target(target, cfg=intel_cfg)
            if not ev.keep:
                ctx.queue.skip(target.id, f"intelligence: {ev.reason}")
                stats["skipped"] += 1
                logger.info("skipped %s (intelligence): %s", target.name, ev.reason)
                emit(ctx, "acquire", f"skipped {target.name}: {ev.reason}",
                     target.name, level="warn")
                continue

        emit(ctx, "acquire",
             f"downloading {target.kind.value}: {target.name} <- {target.locator}",
             target.name)
        try:
            artifact, needs_scan = _process(ctx, target)
        except _SKIP as exc:
            ctx.queue.skip(target.id, f"{type(exc).__name__}: {exc}")
            stats["skipped"] += 1
            logger.info("skipped %s: %s: %s", target.name, type(exc).__name__, exc)
            emit(ctx, "acquire", f"skipped {target.name}: {exc}",
                 target.name, level="warn")
            continue
        except Exception as exc:  # unexpected -> failed, keeps the loop alive
            logger.exception("acquire failed for %s", target.name)
            ctx.queue.fail(target.id, str(exc)[:500])
            stats["failed"] += 1
            emit(ctx, "acquire", f"FAILED {target.name}: {exc}",
                 target.name, level="error")
            continue
        ctx.db.insert_artifact(artifact)
        if needs_scan:
            ctx.queue.mark_acquired(target.id)
        else:
            ctx.queue.complete(target.id)  # fully handled at acquire time
        stats["acquired"] += 1
        logger.info("target %s acquired -> %s", target.name, artifact.path)
        emit(ctx, "acquire",
             f"acquired {target.name} ({artifact.size_bytes / 1e6:.1f}MB) -> {artifact.path}",
             target.name)
    return stats


def _process(ctx, target: Target) -> tuple[Artifact, bool]:
    """Acquire (and for APKs: fast-scan) a target.

    Returns (artifact, needs_scan): needs_scan=True hands the artifact to the
    detect stage; False means it was fully analysed here (APK fast path).
    """
    data = Path(ctx.cfg.paths.data_dir)
    slug = _safe(target.name)

    if target.kind is TargetKind.REPO:
        dest = data / "repos" / f"{slug}-{target.id}"
        path, size = clone_repo(ctx, target, dest)
        sha = _hash_tree(path)
        return Artifact(target_id=target.id, path=str(path), sha256=sha, size_bytes=size), True

    if target.kind is TargetKind.PACKAGE:
        dest = data / "packages" / f"{slug}-{target.id}"
        path, sha, size = fetch_package(ctx, target, dest)
        return Artifact(target_id=target.id, path=str(path), sha256=sha, size_bytes=size), True

    if target.kind is TargetKind.APK:
        return _process_apk(ctx, target, data, slug)

    raise ValueError(f"unknown target kind: {target.kind}")


def _process_apk(ctx, target: Target, data: Path, slug: str) -> tuple[Artifact, bool]:
    from ..detect.apk_bytescan import scan_apk_file

    dest = data / "apk" / f"{slug}-{target.id}"
    apk_path, sha, size = fetch_apk(ctx, target, dest)
    if ctx.db.artifact_seen(sha):
        # identical binary already analysed under another name/version
        raise ApkResolveFailed("identical APK content already scanned")

    # ---- fast path: byte-level scan over dex/assets/arsc (no decompile) ----
    emit(ctx, "detect", f"byte-scanning {target.name} (dex/assets/arsc/xapk) ...",
         target.name)
    bres = scan_apk_file(apk_path, target.id)
    new = 0
    for f in bres.findings:
        if ctx.db.insert_finding(f):
            new += 1
            emit(ctx, "finding",
                 f"[{f.severity.upper()}] {f.detector} ({f.service}) "
                 f"in {f.file_path} = {f.secret_preview}",
                 target.name, level="finding")
            if ctx.cfg.notifications.discord.notify_on in ("any", "high_severity"):
                from ..notify import notify_finding
                notify_finding(ctx, {
                    "id": f.id,
                    "severity": f.severity,
                    "detector": f.detector,
                    "service": f.service,
                    "target_name": target.name,
                    "target_kind": target.kind.value,
                    "file_path": f.file_path,
                    "line": f.line,
                    "secret_preview": f.secret_preview,
                    "secret_full": f.secret_full,
                }, "pending")
    _store_url_findings(ctx, target, bres)
    emit(ctx, "detect",
         f"{target.name}: byte-scan done — {bres.entries_scanned} entries, "
         f"{new} new findings, {len(bres.cleartext_urls)} cleartext URLs"
         + (" [salvaged truncated zip]" if bres.salvaged else ""),
         target.name)

    mode = ctx.cfg.scan.apk_decompile_mode
    want_jadx = mode == "always" or (mode == "on_hit" and bres.findings)
    if not want_jadx:
        if ctx.cfg.limits.work_retention == "delete":
            force_rmtree(dest)
        return Artifact(target_id=target.id, path=str(apk_path),
                        sha256=sha, size_bytes=size), False

    # ---- context pass: jadx only when it adds value ----
    out_dir = data / "decompiled" / f"{slug}-{target.id}"
    emit(ctx, "decompile",
         f"decompiling {target.name} with jadx (context for "
         f"{len(bres.findings)} byte-scan hit(s)) ...", target.name)
    decompile_apk(ctx, apk_path, out_dir)
    n_java = sum(1 for _ in out_dir.rglob("*.java"))
    emit(ctx, "decompile",
         f"decompiled {target.name}: {n_java} java files extracted", target.name)
    if ctx.cfg.limits.work_retention == "delete":
        force_rmtree(dest)
    return Artifact(target_id=target.id, path=str(out_dir),
                    sha256=sha, size_bytes=size), True


def _store_url_findings(ctx, target: Target, bres, cap: int = 25) -> None:
    """Unsecured-URL surface: cleartext http + raw-IP endpoints (capped)."""
    from ..models import Finding, SecretType, redact, sha256_str

    for kind, urls in (("cleartext-url", bres.cleartext_urls),
                       ("raw-ip-url", bres.ip_urls)):
        for u in urls[:cap]:
            ctx.db.insert_finding(Finding(
                target_id=target.id,
                detector=f"apkscan:{kind}",
                service="generic",
                secret_type=SecretType.URL,
                file_path="(apk strings)",
                line=0,
                secret_preview=redact(u, keep=12) if len(u) > 40 else u,
                secret_hash=sha256_str(u),
                context=f"entry: (apk strings) url: {redact(u, keep=12)}",
                severity="low",
                confidence=0.4,
                secret_full=u,
            ))


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80]


def _hash_tree(root: Path) -> str:
    """Content hash for a directory (repos don't have a single-file hash)."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            h.update(str(p.relative_to(root)).encode())
            h.update(p.read_bytes()[:65536])
    return h.hexdigest()
