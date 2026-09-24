"""APK byte-scanner: synthetic APK/XAPK fixtures."""
from __future__ import annotations

import io
import zipfile

from src.detect.apk_bytescan import scan_apk_file


def _mkzip(tmp_path, name, entries: dict[str, bytes]):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        for ename, data in entries.items():
            zf.writestr(ename, data)
    return p


def test_plain_apk_dex_hit(tmp_path):
    apk = _mkzip(tmp_path, "a.apk", {
        "classes.dex": b"\x00\x01dex-string gsk_abcdefghijklmnopqrstuvwxyzAB12CD more\x00",
        "res.png": b"\x89PNG binary",
    })
    res = scan_apk_file(apk, target_id=1)
    dets = {f.detector for f in res.findings}
    assert "apkscan:groq-key" in dets
    f = next(f for f in res.findings if f.detector == "apkscan:groq-key")
    assert f.file_path == "classes.dex"
    assert "gsk_" in f.secret_preview and "AB12CD" not in f.secret_preview


def test_xapk_nested(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("classes.dex", b"key AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234 tail")
    xapk = _mkzip(tmp_path, "x.xapk", {
        "manifest.json": b'{"package_name":"com.x"}',
        "base.apk": inner.getvalue(),
    })
    res = scan_apk_file(xapk, target_id=2)
    dets = {f.detector for f in res.findings}
    assert "apkscan:google-api-key" in dets
    f = next(f for f in res.findings if f.detector == "apkscan:google-api-key")
    assert f.file_path.startswith("base.apk!")


def test_identifier_fp_suppressed(tmp_path):
    # minified-JS identifier, not a key (their real-world FP class)
    apk = _mkzip(tmp_path, "a.apk", {
        "assets/index.android.bundle": b"var sk_updateQueueActionFeedbackPreviewConfirmar = 1;",
    })
    res = scan_apk_file(apk, target_id=3)
    assert not any(f.detector == "apkscan:openai-key" for f in res.findings)


def test_placeholder_suppressed(tmp_path):
    apk = _mkzip(tmp_path, "a.apk", {
        "classes.dex": b"AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1234",
    })
    res = scan_apk_file(apk, target_id=4)
    assert not any("google-api-key" in f.detector for f in res.findings)


def test_generic_assignment(tmp_path):
    apk = _mkzip(tmp_path, "a.apk", {
        "assets/env.properties": b'api_key = "aB3dE5fG7hI9jK1lM3nO5pQ7"\n',
    })
    res = scan_apk_file(apk, target_id=5)
    assert any(f.detector == "apkscan:generic-assignment" for f in res.findings)
