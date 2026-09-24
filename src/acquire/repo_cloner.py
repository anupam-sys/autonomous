"""Git repository acquisition.

Shallow clone (depth 1) by default; repos discovered via token dork search
('github_dork') get a full clone so the scanner can walk commit history —
that's where deleted-but-not-revoked keys hide.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..fs_utils import force_rmtree
from ..log import get_logger
from ..models import Target

logger = get_logger("acquire.repo")

CLONE_TIMEOUT_S = 300  # a repo that won't clone in 5 min gets skipped


class CloneFailed(Exception):
    pass


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def clone_repo(ctx, target: Target, dest: Path) -> tuple[Path, int]:
    """Clone target into dest. Returns (repo_dir, size_bytes)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    full_history = target.source == "github_dork"

    # credential.helper= (empty): never consult GCM/any helper — anonymous
    # clone or nothing. Prevents the "Connect to GitHub" GUI popup on 404s.
    cmd = ["git", "-c", "core.longpaths=true", "-c", "credential.helper=",
           "clone", "--quiet"]

    intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
    use_filter = (
        not full_history
        and getattr(intel_cfg, "smart_git_filter", True)
    )
    filter_arg = f"--filter=blob:limit={ctx.cfg.scan.max_file_kb}k"

    if not full_history:
        cmd += ["--depth", "1", "--single-branch", "--no-tags"]
        if use_filter:
            cmd += [filter_arg]
    cmd += [target.locator, str(dest)]

    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true",
           "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
    try:
        subprocess.run(
            cmd,
            check=True,
            timeout=CLONE_TIMEOUT_S,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired as exc:
        force_rmtree(dest)
        raise CloneFailed(f"clone timed out after {CLONE_TIMEOUT_S}s") from exc
    except subprocess.CalledProcessError as exc:
        if use_filter:
            # Fall back to standard shallow clone if server rejected the blob filter
            force_rmtree(dest)
            fallback_cmd = [c for c in cmd if not c.startswith("--filter=")]
            try:
                subprocess.run(
                    fallback_cmd,
                    check=True,
                    timeout=CLONE_TIMEOUT_S,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as exc2:
                force_rmtree(dest)
                tail = (exc2.stderr or b"")[-200:].decode(errors="replace")
                raise CloneFailed(f"git clone failed: {tail}") from exc2
            except subprocess.TimeoutExpired as exc2:
                force_rmtree(dest)
                raise CloneFailed(f"clone timed out after {CLONE_TIMEOUT_S}s") from exc2
        else:
            force_rmtree(dest)
            tail = (exc.stderr or b"")[-200:].decode(errors="replace")
            raise CloneFailed(f"git clone failed: {tail}") from exc

    size = _dir_size(dest)
    cap = ctx.cfg.limits.max_repo_mb * 1_000_000
    if size > cap:
        force_rmtree(dest)
        raise CloneFailed(f"repo too large: {size // 1_000_000}MB > {ctx.cfg.limits.max_repo_mb}MB")
    logger.info("cloned %s (%0.1fMB, %s)", target.name, size / 1e6,
                "full history" if full_history else "shallow")
    return dest, size
