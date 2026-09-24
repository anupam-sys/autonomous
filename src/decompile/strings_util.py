"""Extract printable strings from binary files (`.so` native libs, dex).

Windows has no `strings(1)`; this is a small pure-Python equivalent.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % 6)
_CHUNK = 4 << 20  # 4MB


def iter_strings(path: Path, min_len: int = 6) -> Iterator[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len) if min_len != 6 else _PRINTABLE
    tail = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            data = tail + chunk
            cut = len(data)
            for m in pattern.finditer(data):
                if m.end() == len(data) and chunk:
                    cut = m.start()  # may continue into next chunk
                    break
                yield m.group().decode("ascii", errors="replace")
            tail = data[cut:]
    for m in pattern.finditer(tail):
        yield m.group().decode("ascii", errors="replace")
