"""Core file scanner: rule engine + entropy + placeholder suppression."""
from __future__ import annotations

import re
from pathlib import Path

from ..log import get_logger
from ..models import Finding, redact, sha256_str
from .classifier import refine_service
from .entropy import shannon
from .rules_loader import Rule
from .url_filter import is_noise_url

logger = get_logger("detect.scanner")

# obvious dummies — checked against the matched secret itself
_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|dummy|test|demo|fake|placeholder|changeme|"
    r"your[_\-]?\w*|insert[_\-]?|replace|todo|xxx+|\*+|qwerty|asdf)"
)

# directories never scanned here (dependencies, build outputs, tests, caches)
_SKIP_DIRS = {
    ".git", "__pycache__", ".idea", ".vscode", "node_modules", "vendor",
    "dist", "build", "out", "target", ".next", ".nuxt", "venv", ".venv",
    "env", ".env.example", "site-packages", "bower_components", "Pods",
    ".gradle", ".cargo", ".tox", ".pytest_cache", ".cache", "obj", "bin",
    "coverage", ".nyc_output", "docs", "documentation", "test", "tests",
    "__tests__", "spec", "fixtures", "mocks", "samples", "examples",
}
_BINARY_EXTS = {
    # Binaries, archives & media
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".jar", ".so", ".dex", ".ttf", ".woff", ".woff2", ".mp3", ".mp4",
    ".ogg", ".otf", ".class", ".keystore", ".apk", ".aar", ".exe", ".dll",
    ".dylib", ".tar", ".gz", ".bz2", ".7z",
    # Generated / minified bundles & maps
    ".min.js", ".min.css", ".map", ".bundle.js", ".chunk.js",
    # Lock files (massive hashes with high entropy that create false positives)
    ".lock", ".lockb",
    # Data & translation dumps
    ".svg", ".csv", ".tsv", ".po", ".pot", ".mo", ".xlf", ".xliff",
    ".wasm", ".yarn", ".pack", ".idx", ".sample",
}

_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
    "poetry.lock", "composer.lock", "pipfile.lock", "gemfile.lock",
}


def is_placeholder(secret: str) -> bool:
    if len(set(secret)) <= 3:  # aaaaaa / ababab / 111111
        return True
    return bool(_PLACEHOLDER_RE.search(secret))


class Scanner:
    def __init__(self, cfg, rules: list[Rule]):
        self.cfg = cfg
        self.rules = rules
        self._max_bytes = cfg.scan.max_file_kb * 1024

    def scan_tree(self, root: Path, target_id: int) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        seen: set[tuple] = set()
        files = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if _SKIP_DIRS & set(path.parts):
                continue
            if path.suffix.lower() in _BINARY_EXTS:
                continue
            if path.name.lower() in _SKIP_FILENAMES:
                continue
            try:
                if path.stat().st_size > self._max_bytes:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:8192]:  # binary sniff
                continue
            files += 1
            text = raw.decode("utf-8", errors="replace")
            rel = str(path.relative_to(root)).replace("\\", "/")
            for f in self.scan_text(text, rel, target_id):
                key = (f.detector, f.secret_hash, f.file_path, f.line)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
        return findings, files

    def scan_text(self, text: str, rel_path: str, target_id: int) -> list[Finding]:
        out: list[Finding] = []
        lowered = text.lower()
        for rule in self.rules:
            if rule.keywords and not any(k.lower() in lowered for k in rule.keywords):
                continue
            for m in rule.pattern.finditer(text):
                secret = m.group(rule.group) if rule.group else m.group(0)
                secret = secret.strip()
                if len(secret) < self.cfg.scan.min_secret_length:
                    continue
                if is_placeholder(secret):
                    continue
                if "://" in secret and is_noise_url(secret):
                    continue
                if rule.entropy is not None and shannon(secret) < rule.entropy:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                context = self._context(text, m.start(), secret)
                service = refine_service(rule.service, context)
                out.append(
                    Finding(
                        target_id=target_id,
                        detector=rule.id,
                        service=service,
                        secret_type=rule.secret_type,
                        file_path=rel_path,
                        line=line,
                        secret_preview=redact(secret),
                        secret_hash=sha256_str(secret),
                        context=context,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        secret_full=secret,
                    )
                )
        return out

    def _context(self, text: str, pos: int, secret: str) -> str:
        n = self.cfg.scan.context_lines
        start = pos
        for _ in range(n):
            idx = text.rfind("\n", 0, start)
            if idx == -1:
                break
            start = idx
        end = pos
        for _ in range(n + 1):
            idx = text.find("\n", end + 1)
            if idx == -1:
                end = len(text)
                break
            end = idx
        snippet = text[start:end].strip("\n")
        return snippet.replace(secret, redact(secret))[:2000]
