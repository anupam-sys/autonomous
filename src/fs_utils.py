"""Filesystem helpers."""
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def force_rmtree(path: Path | str) -> None:
    """rmtree that survives read-only files (git packfiles on Windows)."""
    path = str(path)
    if not os.path.exists(path):
        return

    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    shutil.rmtree(path, onerror=_onerror)
