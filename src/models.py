"""Shared data structures passed between pipeline stages."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class TargetKind(str, Enum):
    REPO = "repo"          # git repository (github / gitlab / bitbucket)
    APK = "apk"            # android package
    PACKAGE = "package"    # npm / pypi / docker artifact


class TargetStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    ACQUIRED = "acquired"
    PROCESSED = "processed"
    FAILED = "failed"
    SKIPPED = "skipped"    # too large / unsupported / bandwidth cap


class SecretType(str, Enum):
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    TOKEN = "token"
    CREDENTIAL = "credential"      # user/pass, connection strings
    URL = "url"                    # unsecured / internal endpoint
    OTHER = "other"


class TriageStatus(str, Enum):
    PENDING = "pending"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    PLACEHOLDER = "placeholder"    # example / dummy / test value


@dataclass
class Target:
    kind: TargetKind
    source: str        # which discovery module found it, e.g. "fdroid", "npm"
    locator: str       # clone URL / download URL
    name: str          # human-readable: "owner/repo", package name, app id
    version: str = ""  # versionCode / package version / commit sha if known
    id: int | None = None
    priority: float = 0.0

    @property
    def dedup_key(self) -> str:
        """Stable key: the same target+version is never scanned twice."""
        raw = f"{self.kind.value}|{self.locator}|{self.version}".encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass
class Artifact:
    target_id: int
    path: str          # where it was acquired/decompiled on disk
    sha256: str
    size_bytes: int
    id: int | None = None


@dataclass
class Finding:
    target_id: int
    detector: str        # rule id, e.g. "aws-access-key"
    service: str         # classified service: aws, stripe, firebase, generic...
    secret_type: SecretType
    file_path: str
    line: int
    secret_preview: str  # redacted: first4********last4
    secret_hash: str     # sha256 of full value — used for dedup
    context: str         # surrounding lines, secret masked
    severity: str        # critical | high | medium | low | info
    confidence: float    # 0.0 - 1.0 rule-based; LLM triage may adjust
    triage_status: TriageStatus = TriageStatus.PENDING
    id: int | None = None
    # transient: carried to insert_finding, which stores it ENCRYPTED.
    # never written to DB/logs in plaintext.
    secret_full: str | None = None


def redact(secret: str, keep: int = 4) -> str:
    """Mask a secret, keeping a small prefix/suffix for identification."""
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * 8}{secret[-keep:]}"


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def mask_context(context: str, secret: str) -> str:
    return context.replace(secret, redact(secret))
