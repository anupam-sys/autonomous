r"""APK decompilation via jadx, with native-library string extraction.

jadx output layout: <out>/sources/**.java  +  <out>/resources/** (incl.
AndroidManifest.xml, res/values/strings.xml). We additionally dump strings
from lib/**.so into <out>/native_strings/<lib>.txt so the scanner sees them.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from ..log import get_logger

logger = get_logger("decompile")


class DecompileFailed(Exception):
    pass


def find_tool(ctx, name_attr: str, fallback: str) -> str | None:
    """Resolve a tool path: configured name on PATH, else repo-local tools/."""
    configured = getattr(ctx.cfg.tools, name_attr)
    found = shutil.which(configured)
    if found:
        return found
    local = Path(fallback)
    if local.exists():
        return str(local)
    return None


def decompile_apk(ctx, apk_path: Path, out_dir: Path) -> Path:
    """Run jadx (+ strings on native libs). Returns the decompiled tree."""
    jadx = find_tool(
        ctx, "jadx_path",
        f"tools/jadx/bin/jadx{'.bat' if sys.platform == 'win32' else ''}",
    )
    if not jadx:
        raise DecompileFailed("jadx not found — run scripts/install_tools.py")

    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [jadx, "-d", str(out_dir), *ctx.cfg.tools.jadx_extra_args, str(apk_path)]
    if jadx.lower().endswith(".bat"):  # Windows batch files need cmd.exe
        cmd = ["cmd", "/c", *cmd]
    try:
        proc = subprocess.run(
            cmd,
            timeout=ctx.cfg.tools.jadx_timeout_min * 60,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise DecompileFailed("jadx timed out") from exc

    # jadx exits non-zero when SOME classes fail to decompile — that is normal
    # for real-world APKs and still yields a usable tree. Only hard-fail when
    # nothing was produced at all.
    produced = any(out_dir.rglob("*.java")) or any(out_dir.rglob("*.xml"))
    if not produced:
        tail = (proc.stdout or b"")[-300:].decode(errors="replace")
        raise DecompileFailed(f"jadx exit {proc.returncode}, no output: {tail}")
    if proc.returncode != 0:
        logger.warning("jadx finished with partial errors (exit %d) for %s — output kept",
                       proc.returncode, apk_path.name)

    _extract_native_strings(apk_path, out_dir)
    return out_dir


def _extract_native_strings(apk_path: Path, out_dir: Path) -> None:
    """Pull printable strings from bundled .so libraries."""
    from .strings_util import iter_strings

    dest = out_dir / "native_strings"
    try:
        with zipfile.ZipFile(apk_path) as zf:
            libs = [n for n in zf.namelist() if n.endswith(".so")]
            for lib in libs[:20]:  # cap: huge games ship dozens
                with zf.open(lib) as fh, tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copyfileobj(fh, tmp, 1 << 20)
                    tmp_path = Path(tmp.name)
                dest.mkdir(exist_ok=True)
                out_file = dest / (Path(lib).name + ".txt")
                with out_file.open("w", encoding="utf-8") as out:
                    for s in iter_strings(tmp_path):
                        out.write(s + "\n")
                tmp_path.unlink(missing_ok=True)
    except zipfile.BadZipFile:
        logger.warning("%s is not a valid zip/apk", apk_path)
