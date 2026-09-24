"""Package acquisition: npm tarballs, PyPI sdists, Docker Hub config blobs.

Archives are extracted with a zip-bomb size guard. Docker images are NOT
pulled — we fetch only the image config blob (JSON with ENV vars, the
classic secret leak spot) via the anonymous registry token flow.
"""
from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

from ..http_utils import PoliteSession, HttpError
from ..log import get_logger
from ..models import Target
from .downloader import download

logger = get_logger("acquire.package")

EXTRACT_CAP = 500 * 1_000_000  # 500MB extracted-size guard

_SKIP_EXTENSIONS = {
    # Binaries, libraries, bytecode
    ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".whl", ".egg", ".class", ".jar", ".war", ".ear", ".o", ".a",
    # Images & media
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp",
    ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mkv", ".mov", ".flv",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Archives & documents
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".pdf", ".epub",
    # Source maps & cache
    ".map", ".ds_store",
}

_SKIP_DIR_PARTS = {
    "node_modules", "site-packages", "__pycache__", ".git",
    "docs", "doc", "man", "locale", "locales",
}


def is_scannable_member(name: str, size: int, max_file_kb: int = 2048) -> bool:
    """Return True if archive member is relevant for secret scanning."""
    p = Path(name)
    parts = set(p.parts)
    if _SKIP_DIR_PARTS & parts:
        return False
    if size > max_file_kb * 1024:
        return False
    if p.suffix.lower() in _SKIP_EXTENSIONS:
        return False
    return True


class PackageFailed(Exception):
    pass


def fetch_package(ctx, target: Target, dest_dir: Path) -> tuple[Path, str, int]:
    """Fetch + extract package. Returns (extract_dir, sha256, size)."""
    if target.locator.startswith("docker://"):
        return _fetch_docker_config(ctx, target, dest_dir)
    return _fetch_archive(ctx, target, dest_dir)


def _fetch_archive(ctx, target: Target, dest_dir: Path) -> tuple[Path, str, int]:
    http = PoliteSession(min_interval=2.0)
    max_bytes = 50 * 1_000_000
    dest_dir.mkdir(parents=True, exist_ok=True)
    blob = dest_dir / "package.blob"
    sha, size = download(ctx, http, target.locator, blob, max_bytes)

    extract_dir = dest_dir / "extracted"
    extract_dir.mkdir(exist_ok=True)

    intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
    selective = getattr(intel_cfg, "selective_extract", True) if intel_cfg else True
    max_file_kb = getattr(ctx.cfg.scan, "max_file_kb", 2048)

    try:
        if tarfile.is_tarfile(blob):
            with tarfile.open(blob) as tf:
                members = tf.getmembers()
                _guard_members(members)
                if selective:
                    members = [
                        m for m in members
                        if m.isdir() or is_scannable_member(m.name, m.size, max_file_kb)
                    ]
                tf.extractall(extract_dir, members=members, filter="data")
        elif zipfile.is_zipfile(blob):
            with zipfile.ZipFile(blob) as zf:
                total = sum(i.file_size for i in zf.infolist())
                if total > EXTRACT_CAP:
                    raise PackageFailed(f"zip expands to {total // 1_000_000}MB (bomb guard)")
                members = zf.infolist()
                if selective:
                    members = [
                        m for m in members
                        if m.is_dir() or is_scannable_member(m.filename, m.file_size, max_file_kb)
                    ]
                for m in members:
                    zf.extract(m, extract_dir)
        else:
            raise PackageFailed("unknown archive format")
    finally:
        blob.unlink(missing_ok=True)
    logger.info("package %s extracted to %s", target.name, extract_dir)
    return extract_dir, sha, size


def _guard_members(members) -> None:
    total = sum(m.size for m in members)
    if total > EXTRACT_CAP:
        raise PackageFailed(f"tar expands to {total // 1_000_000}MB (bomb guard)")
    for m in members:
        if m.name.startswith(("/", "..")) or ".." in Path(m.name).parts:
            raise PackageFailed(f"unsafe archive member: {m.name}")


def _fetch_docker_config(ctx, target: Target, dest_dir: Path) -> tuple[Path, str, int]:
    repo_tag = target.locator.removeprefix("docker://")
    repo, _, tag = repo_tag.partition(":")
    tag = tag or "latest"
    if "/" not in repo:
        repo = f"library/{repo}"

    http = PoliteSession(min_interval=2.0)
    try:
        token = http.get(
            "https://auth.docker.io/token",
            params={"service": "registry.docker.io", "scope": f"repository:{repo}:pull"},
        ).json()["token"]
    except (HttpError, KeyError) as exc:
        raise PackageFailed(f"docker auth failed for {repo}: {exc}") from exc

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": ", ".join([
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.index.v1+json",
        ]),
    }
    try:
        manifest = http.get(
            f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", headers=headers
        ).json()
    except HttpError as exc:
        raise PackageFailed(f"manifest fetch failed: {exc}") from exc

    # if it's an index, take the first linux/amd64 manifest
    if "manifests" in manifest:
        digest = next(
            (m["digest"] for m in manifest["manifests"]
             if m.get("platform", {}).get("architecture") == "amd64"),
            manifest["manifests"][0]["digest"],
        )
        manifest = http.get(
            f"https://registry-1.docker.io/v2/{repo}/manifests/{digest}", headers=headers
        ).json()

    cfg_digest = (manifest.get("config") or {}).get("digest")
    if not cfg_digest:
        raise PackageFailed("no config digest in manifest")
    cfg_resp = http.get(
        f"https://registry-1.docker.io/v2/{repo}/blobs/{cfg_digest}", headers=headers
    )

    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / "image_config.json"
    data = cfg_resp.json()
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    ctx.db.add_bandwidth(len(cfg_resp.content))
    import hashlib
    sha = hashlib.sha256(cfg_resp.content).hexdigest()
    logger.info("docker config for %s:%s -> %s", repo, tag, out)
    return dest_dir, sha, len(cfg_resp.content)
