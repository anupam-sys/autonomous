"""Direct on-demand scanning for Discord integration (APKs & Git repos)."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from ..activity import emit
from ..fs_utils import force_rmtree
from ..log import get_logger
from ..models import Artifact, Target, TargetKind
from ..notify import notify_finding

logger = get_logger("bot.scanner")


def scan_target_on_demand(
    ctx,
    target_kind: str,
    target_locator: str,
    target_name: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> dict:
    """Run an immediate, high-priority scan of an APK or Git repo.

    Reports live findings to Discord as they are detected.
    """
    kind = TargetKind.APK if target_kind.lower() == "apk" else TargetKind.REPO
    name = target_name or Path(target_locator).stem or "target"
    slug = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

    if progress_callback:
        progress_callback(f"📦 Initializing target: `{name}` ({kind.value})")

    target = Target(
        kind=kind,
        source="discord",
        locator=target_locator,
        name=name,
        priority=100.0,
    )
    tid, _ = ctx.db.upsert_target(target)
    target.id = tid

    # Mark claimed so the main daemon doesn't double-acquire it
    ctx.db.claim_targets(1)

    data_dir = Path(ctx.cfg.paths.data_dir)
    findings_new = 0
    total_files = 0

    try:
        if kind is TargetKind.APK:
            findings_new, total_files = _scan_apk(
                ctx, target, target_locator, slug, data_dir, progress_callback
            )
        else:
            findings_new, total_files = _scan_repo(
                ctx, target, target_locator, slug, data_dir, progress_callback
            )

        if findings_new > 0 and getattr(ctx.cfg.llm, "enabled", False):
            if progress_callback:
                progress_callback("🤖 Verifying secrets with AI triage before alerting...")
            try:
                from ..triage.triage import run_triage
                run_triage(ctx)
            except Exception as t_err:
                logger.warning("Post-scan on-demand triage failed: %s", t_err)

        ctx.queue.complete(target.id)
        if progress_callback:
            progress_callback(
                f"✅ Scan complete for **{name}**!\n"
                f"Analysed **{total_files}** items • Found **{findings_new}** new secret(s)."
            )
        return {
            "status": "completed",
            "target_id": target.id,
            "target_name": name,
            "findings_new": findings_new,
            "files_scanned": total_files,
            "error": None,
        }
    except Exception as exc:
        logger.exception("On-demand scan failed for %s", name)
        ctx.queue.fail(target.id, str(exc)[:500])
        if progress_callback:
            progress_callback(f"❌ Scan failed for **{name}**: `{exc}`")
        return {
            "status": "failed",
            "target_id": target.id,
            "target_name": name,
            "findings_new": findings_new,
            "files_scanned": total_files,
            "error": str(exc),
        }


def _scan_apk(ctx, target: Target, locator: str, slug: str, data_dir: Path, progress: Callable | None) -> tuple[int, int]:
    from ..detect.apk_bytescan import scan_apk_file
    from ..decompile.apk_decompiler import decompile_apk
    from ..detect.scanner import Scanner
    from ..detect.rules_loader import load_rules

    dest_dir = data_dir / "apk" / f"discord-{slug}-{int(time.time())}"
    dest_dir.mkdir(parents=True, exist_ok=True)

    local_path = Path(locator)
    if local_path.is_file():
        apk_path = local_path
    else:
        if progress:
            progress(f"📥 Downloading APK from `{locator}`...")
        from ..acquire.apk_fetcher import fetch_apk
        apk_path, _, _ = fetch_apk(ctx, target, dest_dir)

    if progress:
        progress(f"🔍 Running fast byte-level scan on `{apk_path.name}` (dex/assets/arsc)...")

    bres = scan_apk_file(apk_path, target.id)
    new_findings = 0
    for f in bres.findings:
        if ctx.db.insert_finding(f):
            new_findings += 1
            if ctx.cfg.notifications.discord.notify_on in ("any", "high_severity"):
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

    total_files = bres.entries_scanned
    mode = ctx.cfg.scan.apk_decompile_mode
    want_jadx = mode == "always" or (mode == "on_hit" and bres.findings)

    if want_jadx:
        if progress:
            progress(f"⚙️ Decompiling APK with Jadx to retrieve full source context...")
        out_dir = data_dir / "decompiled" / f"discord-{slug}-{target.id}"
        decompile_apk(ctx, apk_path, out_dir)

        rules = load_rules(ctx.cfg.paths.rules_dir)
        scanner = Scanner(ctx.cfg, rules)
        more_findings, files = scanner.scan_tree(out_dir, target.id)
        total_files += files

        for f in more_findings:
            if ctx.db.insert_finding(f):
                new_findings += 1
                if ctx.cfg.notifications.discord.notify_on in ("any", "high_severity"):
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

        if ctx.cfg.limits.work_retention == "delete":
            force_rmtree(out_dir)

    return new_findings, total_files


def _scan_repo(ctx, target: Target, locator: str, slug: str, data_dir: Path, progress: Callable | None) -> tuple[int, int]:
    from ..acquire.repo_cloner import clone_repo
    from ..detect.scanner import Scanner
    from ..detect.rules_loader import load_rules
    from ..detect.gitleaks_runner import run_gitleaks

    if progress:
        progress(f"📥 Cloning repository `{locator}`...")

    dest = data_dir / "repos" / f"discord-{slug}-{int(time.time())}"
    path, _ = clone_repo(ctx, target, dest)

    if progress:
        progress(f"🔍 Scanning files in `{slug}`...")

    rules = load_rules(ctx.cfg.paths.rules_dir)
    scanner = Scanner(ctx.cfg, rules)
    findings, total_files = scanner.scan_tree(path, target.id)

    if ctx.cfg.scan.gitleaks_enabled and (path / ".git").exists():
        if progress:
            progress(f"📜 Scanning Git commit history with Gitleaks...")
        findings += run_gitleaks(ctx, path, rules, target.id)

    new_findings = 0
    for f in findings:
        if ctx.db.insert_finding(f):
            new_findings += 1
            if ctx.cfg.notifications.discord.notify_on in ("any", "high_severity"):
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

    if ctx.cfg.limits.work_retention == "delete":
        force_rmtree(path)

    return new_findings, total_files
