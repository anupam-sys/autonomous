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
_configured_key_path: Path | None = None


def configure(key_path: str | Path | None) -> None:
    """Set the active encryption key path from the loaded configuration or database."""
    global _configured_key_path, _fernet
    with _lock:
        if key_path is not None:
            new_path = Path(key_path)
            if _configured_key_path != new_path:
                _configured_key_path = new_path
                _fernet = None
        else:
            _configured_key_path = None
            _fernet = None


def _key_path() -> Path:
    if _configured_key_path is not None:
        return _configured_key_path
    from .config import Config

    return Path(Config.load().paths.data_dir) / "secret.key"


def _get(key_path: str | Path | None = None) -> Fernet:
    global _fernet
    with _lock:
        if _fernet is not None and (key_path is None or Path(key_path) == _configured_key_path):
            return _fernet
        kp = Path(key_path) if key_path is not None else _key_path()
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
        inst = Fernet(key)
        if key_path is None or Path(key_path) == _configured_key_path:
            _fernet = inst
        return inst


def encrypt(value: str, key_path: str | Path | None = None) -> bytes:
    return _get(key_path).encrypt(value.encode("utf-8"))


def decrypt(blob: bytes, key_path: str | Path | None = None) -> str:
    return _get(key_path).decrypt(blob).decode("utf-8")
