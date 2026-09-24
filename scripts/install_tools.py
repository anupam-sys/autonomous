"""Bootstrap external tools into ./tools: jadx (APK decompiler) + gitleaks.

Works on Windows and Linux. apktool is optional and not installed here —
jadx already decodes manifest + resources + code.

Usage:  python scripts/install_tools.py
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def latest_asset(repo: str, match) -> str:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.load(r)
    for asset in data["assets"]:
        if match(asset["name"]):
            return asset["browser_download_url"]
    raise RuntimeError(f"no matching asset in {repo}: {[a['name'] for a in data['assets']]}")


def install_jadx() -> None:
    dest = TOOLS / "jadx"
    marker = dest / "bin" / ("jadx.bat" if sys.platform == "win32" else "jadx")
    if marker.exists():
        print(f"jadx already installed at {dest}")
        return
    url = latest_asset("skylot/jadx", lambda n: n.startswith("jadx-") and n.endswith(".zip"))
    print(f"downloading jadx: {url}")
    with urllib.request.urlopen(url, timeout=300) as r:
        blob = r.read()
    tmp = TOOLS / "_jadx_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        zf.extractall(tmp)
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(tmp), str(dest))
    print(f"jadx installed -> {dest}")


def install_gitleaks() -> None:
    exe = "gitleaks.exe" if sys.platform == "win32" else "gitleaks"
    dest = TOOLS / exe
    if dest.exists():
        print(f"gitleaks already installed at {dest}")
        return
    if sys.platform == "win32":
        want = lambda n: n.endswith("windows_x64.zip")
    else:
        want = lambda n: n.endswith("linux_x64.tar.gz")
    url = latest_asset("gitleaks/gitleaks", want)
    print(f"downloading gitleaks: {url}")
    with urllib.request.urlopen(url, timeout=300) as r:
        blob = r.read()
    TOOLS.mkdir(exist_ok=True)
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            zf.extract(exe, TOOLS)
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            tf.extract("gitleaks", TOOLS, filter="data")
        dest.chmod(0o755)
    print(f"gitleaks installed -> {dest}")


if __name__ == "__main__":
    TOOLS.mkdir(exist_ok=True)
    install_jadx()
    install_gitleaks()
    print("done. jadx needs a JDK on PATH (java -version to check).")
