"""Byte-level APK/XAPK secret scanner — no decompilation required.

APKs are ZIPs; secrets live in DEX string tables, assets (Flutter libapp.so,
RN bundles, json/env configs), resources.arsc and the binary manifest — all
reachable by byte-level regex over every entry. Handles UTF-16LE string pools
(AXML/arsc), nested APKs (XAPK), and truncated zips via local-header salvage.

Architecture and pattern ideas adapted from a proven standalone scanner
(apkscan/scanner.py); integrated here with Finding models, dedup, and the
pipeline's placeholder/entropy discipline. jadx is still used afterwards
(on_hit) to provide code context for triage.
"""
from __future__ import annotations

import io
import os
import re
import struct
import zlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..log import get_logger
from ..models import Finding, SecretType, redact, sha256_str
from .scanner import is_placeholder
from .url_filter import is_noise_url

logger = get_logger("detect.apkscan")

# ---------------------------------------------------------------- patterns
# name -> (bytes regex, service, secret_type, severity, confidence)
PATTERNS: dict[str, tuple[bytes, str, SecretType, str, float]] = {
    # AI providers (highest-value targets in modern wrapper apps)
    "openai-key":        (rb'sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{24,}', "openai", SecretType.API_KEY, "high", 0.75),
    "anthropic-key":     (rb'sk-ant-[A-Za-z0-9_\-]{24,}', "anthropic", SecretType.API_KEY, "high", 0.9),
    "openrouter-key":    (rb'sk-or-v1-[a-f0-9]{32,}', "openrouter", SecretType.API_KEY, "critical", 0.95),
    "groq-key":          (rb'gsk_[A-Za-z0-9]{32,}', "groq", SecretType.API_KEY, "critical", 0.95),
    "replicate-key":     (rb'r8_[A-Za-z0-9]{32,}', "replicate", SecretType.API_KEY, "critical", 0.95),
    "perplexity-key":    (rb'pplx-[A-Za-z0-9]{32,}', "perplexity", SecretType.API_KEY, "critical", 0.95),
    "huggingface-token": (rb'hf_[A-Za-z0-9]{30,}', "huggingface", SecretType.TOKEN, "high", 0.85),
    "google-api-key":    (rb'AIza[0-9A-Za-z_\-]{35}', "google", SecretType.API_KEY, "high", 0.9),
    "google-oauth-id":   (rb'\d{6,}-[0-9a-z]+\.apps\.googleusercontent\.com', "google", SecretType.CREDENTIAL, "medium", 0.8),
    "google-oauth-secret": (rb'GOCSPX-[A-Za-z0-9_\-]{28,}', "google", SecretType.CREDENTIAL, "high", 0.9),
    # cloud / infra
    "aws-access-key":    (rb'(?:AKIA|ASIA)[0-9A-Z]{16}', "aws", SecretType.API_KEY, "high", 0.9),
    "gcp-service-account": (rb'"type"\s*:\s*"service_account"', "gcp", SecretType.CREDENTIAL, "critical", 0.95),
    "private-key":       (rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----', "generic", SecretType.PRIVATE_KEY, "critical", 0.95),
    "azure-conn-string": (rb'(?:DefaultEndpointsProtocol|AccountKey)=[A-Za-z0-9+/=;:.\-]{20,}', "azure", SecretType.CREDENTIAL, "critical", 0.85),
    # payments / comms
    "stripe-live-key":   (rb'[sr]k_live_[0-9A-Za-z]{16,}', "stripe", SecretType.API_KEY, "critical", 0.95),
    "stripe-pub-live":   (rb'pk_live_[0-9A-Za-z]{16,}', "stripe", SecretType.API_KEY, "medium", 0.8),
    "slack-token":       (rb'xox[baprs]-[0-9A-Za-z\-]{10,}', "slack", SecretType.TOKEN, "high", 0.9),
    "twilio-key":        (rb'(?:AC|SK)[0-9a-f]{32}', "twilio", SecretType.API_KEY, "high", 0.6),
    "sendgrid-key":      (rb'SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}', "sendgrid", SecretType.API_KEY, "high", 0.95),
    "mailgun-key":       (rb'key-[0-9a-z]{32}', "mailgun", SecretType.API_KEY, "high", 0.6),
    "telegram-bot":      (rb'\d{8,10}:[A-Za-z0-9_\-]{35}', "telegram", SecretType.TOKEN, "high", 0.8),
    "discord-token":     (rb'[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}', "discord", SecretType.TOKEN, "critical", 0.9),
    # dev platforms
    "github-token":      (rb'(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{22,}', "github", SecretType.TOKEN, "high", 0.9),
    "shopify-token":     (rb'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}', "shopify", SecretType.TOKEN, "critical", 0.95),
    "square-token":      (rb'sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}', "square", SecretType.TOKEN, "critical", 0.95),
    "npm-token":         (rb'npm_[A-Za-z0-9]{36}', "npm", SecretType.TOKEN, "high", 0.9),
    "facebook-token":    (rb'EAA[A-Za-z0-9_\-]{40,}', "facebook", SecretType.TOKEN, "high", 0.7),
    "jwt":               (rb'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}', "generic", SecretType.TOKEN, "medium", 0.7),
    "mapbox-token":      (rb'[ps]k\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "mapbox", SecretType.TOKEN, "medium", 0.8),
    "branch-key":        (rb'key_live_[A-Za-z0-9]{20,}', "branch", SecretType.API_KEY, "medium", 0.8),
    # BaaS endpoints / misconfig surface
    "firebase-rtdb":     (rb'https?://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)', "firebase", SecretType.URL, "medium", 0.8),
    "supabase-url":      (rb'https?://[a-z0-9]{10,}\.supabase\.co', "supabase", SecretType.URL, "medium", 0.8),
    "appwrite-endpoint": (rb'https?://[A-Za-z0-9.\-]+/v1/(?:account|databases|storage|avatars|teams|functions)', "appwrite", SecretType.URL, "info", 0.7),
    "sentry-dsn":        (rb'https://[0-9a-f]{32}@[a-z0-9.\-]*sentry\.io/\d+', "sentry", SecretType.CREDENTIAL, "low", 0.8),
    "basic-auth-url":    (rb'https?://[^/\s:@\'"<>]{2,}:[^/\s@\'"<>]{4,}@[A-Za-z0-9.\-]+', "generic", SecretType.CREDENTIAL, "high", 0.8),
}
COMPILED = {n: (re.compile(rx), svc, st, sev, conf)
            for n, (rx, svc, st, sev, conf) in PATTERNS.items()}

GENERIC_ASSIGN = re.compile(
    rb'(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?secret|client[_-]?secret|'
    rb'secret[_-]?key|access[_-]?token|auth[_-]?token|x-api-key|xi-api-key|'
    rb'rapidapi-key|openai[_-]?api[_-]?key|gemini[_-]?api[_-]?key|anthropic[_-]?api[_-]?key)'
    rb'["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-\./+=]{14,})'
)
URL_RE = re.compile(rb'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,}')
UTF16_STRING = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')

TEXT_EXTS = (".json", ".js", ".txt", ".properties", ".env", ".yaml", ".yml",
             ".xml", ".html", ".htm", ".config", ".cfg", ".ini", ".ts",
             ".bundle", ".map", ".csv", ".md", ".sh", ".py", ".proto", ".pb")
MEDIA_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".mp3",
              ".mp4", ".m4a", ".aac", ".ogg", ".wav", ".flac", ".ttf",
              ".otf", ".woff", ".woff2", ".eot", ".mov", ".mkv", ".avi",
              ".3gp", ".webm", ".ico", ".pak", ".db", ".sqlite", ".zip")
MAX_ENTRY = 250 * 1024 * 1024
MAX_URLS_PER_APP = 1500

# base64 PNG/JPEG chunk markers that FP token regexes on embedded image data
_B64_IMAGE_MARKERS = ("SURBV", "REFU", "XNSR0", "CAYAAA", "iVBOR", "AAAACXBI",
                      "ElEQVR", "EUzRAM")

# minified-JS / Java identifier collisions (e.g. sk-updateQueueAction...)
_IDENTIFIER_RE = re.compile(
    r'^[a-z]+[A-Za-z]*(Error|Exception|Component|Manager|Fragment|Activity|'
    r'Listener|Callback|Drawable|Resource|Attribute|Parameter|Configuration|'
    r'Navigation|Animation|Layout|Button|Dialog|View|Item|Service|Provider|'
    r'Helper|Builder|Factory|Handler|Context)s?[A-Za-z]*$')
_ID_SUBSTRINGS = ("component", "function", "activity", "fragment", "resource",
                  "exception", "attribute", "parameter", "navigation", "animation",
                  "listener", "callback", "drawable", "layout", "manager",
                  "placeholder", "background", "permission", "configuration",
                  "documentation", "implementation")


def _looks_identifier(s: str) -> bool:
    """camelCase Java/JS identifier, not a secret (kills sk-<word><Word> FPs)."""
    if _IDENTIFIER_RE.match(s):
        return True
    low = s.lower()
    if any(x in low for x in _ID_SUBSTRINGS):
        return True
    return False


@dataclass
class ByteScanResult:
    findings: list[Finding] = field(default_factory=list)
    cleartext_urls: list[str] = field(default_factory=list)
    ip_urls: list[str] = field(default_factory=list)
    interesting_urls: list[str] = field(default_factory=list)
    entries_scanned: int = 0
    salvaged: bool = False


def scan_apk_file(apk_path: Path, target_id: int) -> ByteScanResult:
    """Scan an APK/XAPK directly. Returns findings + classified URLs."""
    res = ByteScanResult()
    found: dict[tuple, Finding] = {}
    urls: set[str] = set()

    def emit(pattern: str, sval: str, entry: str) -> None:
        key = (pattern, sval)
        if key in found:
            return
        found[key] = _make_finding(pattern, sval, entry, target_id)

    def scan_blob(data: bytes, entry: str) -> None:
        res.entries_scanned += 1
        for name, (rx, _svc, _st, _sev, _conf) in COMPILED.items():
            for m in rx.finditer(data):
                try:
                    sval = m.group(0).decode("utf-8", "replace")[:300]
                except Exception:
                    continue
                if any(mk in sval for mk in _B64_IMAGE_MARKERS):
                    continue
                if is_placeholder(sval):
                    continue
                if name == "openai-key" and _looks_identifier(sval[3:]):
                    continue  # sk-<minified-js-identifier> FP
                emit(name, sval, entry)
        low = entry.lower()
        ext = os.path.splitext(low)[1]
        if ext in TEXT_EXTS or "assets" in low or ext == "":
            for m in GENERIC_ASSIGN.finditer(data):
                k = m.group(1).decode("utf-8", "replace")
                v = m.group(2).decode("utf-8", "replace")
                if len(v) < 14 or is_placeholder(v) or _looks_identifier(v):
                    continue
                emit("generic-assignment", f"{k}={v}", entry)
        if len(urls) < MAX_URLS_PER_APP:
            for m in URL_RE.finditer(data):
                u = m.group(0).decode("utf-8", "replace").rstrip(").,;'\"<>\\")
                if is_noise_url(u):
                    continue
                urls.add(u)

    def scan_entry(zf: zipfile.ZipFile, name: str, prefix: str = "") -> None:
        try:
            info = zf.getinfo(name)
            if info.file_size > MAX_ENTRY:
                return
            data = zf.read(name)
        except Exception:
            return
        entry = prefix + name
        scan_blob(data, entry)
        low = name.lower()
        if low.endswith((".arsc", ".xml", ".so")):
            for m in UTF16_STRING.finditer(data):
                s = m.group(0).decode("utf-16-le", "ignore")
                scan_blob(s.encode("utf-8", "ignore"), entry + " [utf16]")

    try:
        with zipfile.ZipFile(apk_path) as outer:
            names = outer.namelist()
            inner = [n for n in names if n.lower().endswith(".apk")]
            if inner:  # XAPK: scan manifest too, then each nested apk
                for n in names:
                    if not n.lower().endswith(".apk") and os.path.splitext(n)[1].lower() not in MEDIA_EXTS:
                        scan_entry(outer, n)
                for apk_name in sorted(inner, key=lambda n: -outer.getinfo(n).file_size):
                    try:
                        blob = outer.read(apk_name)
                        with zipfile.ZipFile(io.BytesIO(blob)) as inner_zf:
                            for n in inner_zf.namelist():
                                if os.path.splitext(n)[1].lower() not in MEDIA_EXTS:
                                    scan_entry(inner_zf, n, prefix=apk_name + "!")
                    except Exception:
                        continue
            else:
                for n in names:
                    if os.path.splitext(n)[1].lower() not in MEDIA_EXTS:
                        scan_entry(outer, n)
    except zipfile.BadZipFile:
        res.salvaged = True
        blob = Path(apk_path).read_bytes()
        for name, data in _salvage_entries(blob):
            if os.path.splitext(name.lower())[1] in MEDIA_EXTS:
                continue
            scan_blob(data, name)

    res.findings = sorted(found.values(), key=lambda f: f.severity)
    res.cleartext_urls, res.ip_urls, res.interesting_urls = _classify_urls(urls)
    return res


def _make_finding(pattern: str, sval: str, entry: str, target_id: int) -> Finding:
    if pattern == "generic-assignment":
        service, stype, sev, conf = "generic", SecretType.API_KEY, "high", 0.6
    else:
        _rx, service, stype, sev, conf = PATTERNS[pattern]
    secret = sval.split("=", 1)[1] if pattern == "generic-assignment" and "=" in sval else sval
    return Finding(
        target_id=target_id,
        detector=f"apkscan:{pattern}",
        service=service,
        secret_type=stype,
        file_path=entry,
        line=0,
        secret_preview=redact(secret),
        secret_hash=sha256_str(secret),
        context=f"entry: {entry}",
        severity=sev,
        confidence=conf,
        secret_full=secret,
    )


_INTERESTING_HINTS = (
    "api.", ".api.", "openai.com", "anthropic.com", "openrouter", "groq.com",
    "googleapis.com", "firebaseio.com", "firebasedatabase.app", "cloudfunctions.net",
    "supabase.co", "appwrite", "onrender.com", "railway.app", "herokuapp.com",
    "ngrok", "amazonaws.com", "storage.googleapis", "huggingface.co",
    "replicate.com", "perplexity", "cohere", "mistral", "together.xyz",
    "deepseek", "elevenlabs", "assemblyai", "deepgram", "rapidapi.com",
    "workers.dev", "pages.dev", "fly.dev", "koyeb",
)


def _classify_urls(urls: set[str]) -> tuple[list[str], list[str], list[str]]:
    cleartext, ip_host, interesting = [], [], []
    for u in sorted(urls):
        ul = u.lower()
        if ul.startswith("http://"):
            cleartext.append(u)
        host = re.sub(r"^https?://", "", u).split("/")[0].split(":")[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ip_host.append(u)
        if any(h in ul for h in _INTERESTING_HINTS):
            interesting.append(u)
    return cleartext[:100], ip_host[:50], interesting[:200]


def _salvage_entries(blob: bytes):
    """Yield (name, data) from a truncated zip by walking local file headers."""
    off, n = 0, len(blob)
    while off + 30 <= n:
        idx = blob.find(b"PK\x03\x04", off)
        if idx < 0 or idx + 30 > n:
            break
        try:
            (_ver, _flags, method, _mt, _md, _crc, csize, usize,
             nlen, xlen) = struct.unpack("<HHHHHIIIHH", blob[idx + 4:idx + 30])
        except struct.error:
            break
        name = blob[idx + 30:idx + 30 + nlen].decode("utf-8", "replace")
        data_start = idx + 30 + nlen + xlen
        if data_start > n:
            break
        if method == 0:  # stored
            end = data_start + (csize or usize)
            yield name, blob[data_start:min(end, n)]
            off = end + (16 if blob[end:end + 4] == b"PK\x07\x08" else 0)
        elif method == 8 and csize:  # deflate, known size
            try:
                data = zlib.decompressobj(-15).decompress(blob[data_start:data_start + csize])
            except zlib.error:
                data = b""
            yield name, data
            off = data_start + csize + (16 if blob[data_start + csize:data_start + csize + 4] == b"PK\x07\x08" else 0)
        else:  # resync on next local header
            nxt = blob.find(b"PK\x03\x04", data_start)
            off = nxt if nxt > 0 else n
