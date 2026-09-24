"""Configuration loading: config.yaml + environment variable overrides."""
from __future__ import annotations

import os
import typing
from dataclasses import dataclass, field, is_dataclass
from pathlib import Path

import yaml


@dataclass
class PathsConfig:
    data_dir: str = "data"
    db_path: str = "data/findings.db"
    report_dir: str = "reports"
    rules_dir: str = "src/detect/rules"


@dataclass
class LimitsConfig:
    workers: int = 2
    jadx_concurrency: int = 1
    max_apk_mb: int = 150
    max_repo_mb: int = 300
    daily_bandwidth_mb: int = 5120
    work_retention: str = "on_finding"  # keep | on_finding | delete


@dataclass
class GithubRecentConfig:
    enabled: bool = True
    token: str = ""
    per_page: int = 50


@dataclass
class ApkDiscoveryConfig:
    fdroid: bool = True
    apkmirror_recent: bool = True
    apkpure_recent: bool = False
    target_packages: list[str] = field(default_factory=list)


@dataclass
class RegistriesConfig:
    npm: bool = True
    pypi: bool = True
    docker_hub: bool = False


@dataclass
class IntelligenceConfig:
    enabled: bool = True
    min_relevance_score: float = 0.25
    filter_spam: bool = True
    filter_forks: bool = True
    filter_noise_types: bool = True
    filter_system_apks: bool = True
    smart_git_filter: bool = True
    selective_extract: bool = True
    target_keywords: list[str] = field(default_factory=lambda: [
        "api", "auth", "token", "secret", "key", "cred", "config", "env",
        "backend", "server", "service", "client", "sdk", "bot", "webhook",
        "cloud", "aws", "azure", "gcp", "database", "payment", "stripe",
        "openai", "connect", "internal", "admin", "gateway", "infra"
    ])
    exclude_keywords: list[str] = field(default_factory=lambda: [
        "awesome-", "curated-", "cheatsheet", "interview", "leetcode",
        "hackerrank", "homework", "assignment", "coursework", "tutorial",
        "syllabus", "wallpaper", "icon-theme", "dotfiles", "translation",
        "i18n", "subtitles", "novel", "manga", "dataset", "corpus"
    ])


@dataclass
class DiscoveryConfig:
    interval_minutes: int = 60
    firehose_enabled: bool = True
    gitlab_enabled: bool = True
    bitbucket_enabled: bool = False
    github_recent: GithubRecentConfig = field(default_factory=GithubRecentConfig)
    registries: RegistriesConfig = field(default_factory=RegistriesConfig)
    apk: ApkDiscoveryConfig = field(default_factory=ApkDiscoveryConfig)
    intelligence: IntelligenceConfig = field(default_factory=IntelligenceConfig)


@dataclass
class ToolsConfig:
    jadx_path: str = "jadx"
    apktool_path: str = "apktool"
    gitleaks_path: str = "gitleaks"
    jadx_timeout_min: int = 15
    jadx_extra_args: list[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    interval_minutes: int = 30
    entropy_threshold: float = 4.5
    min_secret_length: int = 8
    context_lines: int = 3
    max_file_kb: int = 2048      # skip individual files larger than this
    gitleaks_enabled: bool = True  # git-history scan for repos
    apk_decompile_mode: str = "on_hit"  # always | on_hit | never
    #   on_hit: byte-scan every APK; jadx ONLY when byte-scan finds something
    #           (context for triage). Massive throughput win vs jadx-everything.


@dataclass
class AiDiscoveryConfig:
    enabled: bool = False
    allow_auto_dorks: bool = False
    interval_hours: int = 24


@dataclass
class LlmConfig:
    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    timeout_seconds: int = 60
    triage_confidence_floor: float = 0.5
    max_findings_per_run: int = 100
    batch_size: int = 15
    ai_discovery: AiDiscoveryConfig = field(default_factory=AiDiscoveryConfig)


@dataclass
class WebConfig:
    enabled: bool = False
    host: str = "127.0.0.1"   # set 0.0.0.0 + token to expose on VPS
    port: int = 8080
    token: str = ""           # empty = no auth (localhost only!)


@dataclass
class ReportConfig:
    interval_hours: int = 24
    reveal_secrets: bool = False
    disclosure_lookup: bool = True


@dataclass
class DiscordConfig:
    enabled: bool = False
    webhook_url: str = ""
    notify_on: str = "true_positive"  # any, high_severity, true_positive


@dataclass
class NotificationsConfig:
    discord: DiscordConfig = field(default_factory=DiscordConfig)


@dataclass
class Config:
    paths: PathsConfig = field(default_factory=PathsConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    llm: LlmConfig = field(default_factory=LlmConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    web: WebConfig = field(default_factory=WebConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path = "config.yaml",
             overlay: str | Path = "config.local.yaml") -> "Config":
        """Load base config, then deep-merge the local override file.

        config.local.yaml is written by the web dashboard's Config tab and
        holds operator secrets (API keys/tokens) — it is gitignored.
        Environment variables still win over both files.
        """
        path = Path(path)
        overlay = Path(overlay)
        data: dict = {}
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        if overlay.exists():
            with overlay.open("r", encoding="utf-8") as fh:
                data = deep_merge(data, yaml.safe_load(fh) or {})
        cfg = _build(cls, data)
        cfg._apply_env()
        cfg._base_path = str(path)      # for per-pass reloads
        cfg._overlay_path = str(overlay)
        return cfg

    def _apply_env(self) -> None:
        env = os.environ
        gh = env.get("GITHUB_TOKEN")
        if gh:
            self.discovery.github_recent.token = gh
        if env.get("LLM_API_KEY"):
            self.llm.api_key = env["LLM_API_KEY"]
        if env.get("LLM_BASE_URL"):
            self.llm.base_url = env["LLM_BASE_URL"]
        if env.get("LLM_MODEL"):
            self.llm.model = env["LLM_MODEL"]
        if env.get("GITLAB_TOKEN"):
            self.gitlab_token = env["GITLAB_TOKEN"]  # consumed by gitlab source

    def ensure_dirs(self) -> None:
        Path(self.paths.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.paths.report_dir).mkdir(parents=True, exist_ok=True)
        Path("logs").mkdir(parents=True, exist_ok=True)


def _build(cls, data: dict | None):
    """Recursively build a dataclass from a (possibly partial) dict."""
    hints = typing.get_type_hints(cls)
    data = data or {}
    kwargs = {}
    for name, hint in hints.items():
        if name not in data:
            continue
        value = data[name]
        if is_dataclass(hint) and isinstance(value, dict):
            value = _build(hint, value)
        kwargs[name] = value
    return cls(**kwargs)


def deep_merge(base: dict, override: dict) -> dict:
    """Recursive merge; override wins on leaf values."""
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def deep_set(data: dict, dotted: str, value) -> None:
    """Set data['a']['b']['c'] = value for dotted='a.b.c'."""
    parts = dotted.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise ValueError(f"config path {dotted!r} crosses a non-mapping")
    node[parts[-1]] = value


def save_overlay(updates: dict, overlay: str | Path = "config.local.yaml") -> None:
    """Persist dotted-path updates into the local override file."""
    overlay = Path(overlay)
    data: dict = {}
    if overlay.exists():
        with overlay.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    for dotted, value in updates.items():
        deep_set(data, dotted, value)
    header = ("# written by the web dashboard Config tab — gitignored,\n"
              "# overrides config.yaml. Edit via the dashboard, not by hand.\n")
    overlay.write_text(header + yaml.safe_dump(data, sort_keys=False),
                       encoding="utf-8")
