"""Encrypted-at-rest storage for full secret values.

Findings in the DB stay redacted; the full value lives ONLY in the
findings.secret_enc column, Fernet-encrypted with a random key in
data/secret.key (created on first use). Lose the key -> values are
unrecoverable (they'd be re-found on future scans of new versions).

The key file lives next to the DB; it is gitignored via data/.
"""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

from cryptography.fernet import Fernet

_lock = threading.Lock()
_fernet: Fernet | None = None


def _key_path() -> Path:
    # kept next to the database
    from .config import Config

    return Path(Config.load().paths.data_dir) / "secret.key"


def _get() -> Fernet:
    global _fernet
    with _lock:
        if _fernet is None:
            kp = _key_path()
            kp.parent.mkdir(parents=True, exist_ok=True)
            if kp.exists():
                key = kp.read_bytes().strip()
            else:
                key = Fernet.generate_key()
                fd = os.open(str(kp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(key)
                if os.name == "nt":  # best-effort: hide the key file
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(kp), 0x02)
                    except Exception:
                        pass
            _fernet = Fernet(key)
        return _fernet


def encrypt(value: str) -> bytes:
    return _get().encrypt(value.encode("utf-8"))


def decrypt(blob: bytes) -> str:
    return _get().decrypt(blob).decode("utf-8")
