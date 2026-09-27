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
    workers: int = 8                    # fallback general concurrency
    acquire_workers: int = 16           # concurrent network clones & downloads
    scan_workers: int = 8               # concurrent filesystem & regex scans
    agent_workers: int = 4              # concurrent autonomous agent investigation threads
    discovery_workers: int = 8          # concurrent discovery source runners
    jadx_concurrency: int = 4
    max_apk_mb: int = 300
    max_repo_mb: int = 500
    daily_bandwidth_mb: int = 51200
    work_retention: str = "on_finding"  # keep | on_finding | delete


@dataclass
class AgentConfig:
    enabled: bool = True
    active_probing: bool = True         # safe non-destructive read-only identity verification
    exclude_localhost: bool = True      # strictly exclude localhost & loopback
    max_turns: int = 4                  # maximum tool turns per investigation
    auto_investigate_high: bool = True  # auto-run agent on high & critical findings
    min_confidence: float = 0.5         # minimum rule confidence for agent analysis


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
class OnlinePortsConfig:
    enabled: bool = False
    mode: str = "custom"        # custom (explicit hosts/subnets) | ivre (local IVRE recon DB) | internet
    interval_minutes: int = 60
    internet_sample_size: int = 50
    hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "host.docker.internal"])
    subnets: list[str] = field(default_factory=list)  # explicit authorized CIDRs
    ports_ollama: list[int] = field(default_factory=lambda: [11434])
    ports_kobold: list[int] = field(default_factory=lambda: [5000, 5001, 5002])
    timeout: float = 2.0
    concurrency: int = 8
    auto_use_for_triage: bool = False
    ivre_cli_path: str = "ivre"


@dataclass
class DiscoveryConfig:
    interval_minutes: int = 60
    firehose_enabled: bool = True
    gitlab_enabled: bool = True
    gitlab_token: str = ""
    bitbucket_enabled: bool = False
    github_recent: GithubRecentConfig = field(default_factory=GithubRecentConfig)
    registries: RegistriesConfig = field(default_factory=RegistriesConfig)
    apk: ApkDiscoveryConfig = field(default_factory=ApkDiscoveryConfig)
    intelligence: IntelligenceConfig = field(default_factory=IntelligenceConfig)
    online_ports: OnlinePortsConfig = field(default_factory=OnlinePortsConfig)


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
    max_findings_per_run: int = 500
    batch_size: int = 25
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
    bot_token: str = ""
    channel_id: int | str | None = None
    authorized_users: list[int] = field(default_factory=list)
    notify_on: str = "true_positive"  # any, high_severity, true_positive
    create_threads: bool = True


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
    agent: AgentConfig = field(default_factory=AgentConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    web: WebConfig = field(default_factory=WebConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    gitlab_token: str = ""
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
            self.llm.enabled = True
        if env.get("LLM_ENABLED"):
            self.llm.enabled = env["LLM_ENABLED"].lower() in ("1", "true", "yes")
        if env.get("LLM_BASE_URL"):
            self.llm.base_url = env["LLM_BASE_URL"]
        if env.get("LLM_MODEL"):
            self.llm.model = env["LLM_MODEL"]
        if env.get("GITLAB_TOKEN"):
            self.gitlab_token = env["GITLAB_TOKEN"]
            self.discovery.gitlab_token = env["GITLAB_TOKEN"]
        if env.get("DISCORD_ENABLED"):
            self.notifications.discord.enabled = env["DISCORD_ENABLED"].lower() in ("1", "true", "yes")
        if env.get("DISCORD_WEBHOOK_URL"):
            self.notifications.discord.webhook_url = env["DISCORD_WEBHOOK_URL"]
        if env.get("DISCORD_BOT_TOKEN"):
            self.notifications.discord.bot_token = env["DISCORD_BOT_TOKEN"]
            self.notifications.discord.enabled = True
        if env.get("DISCORD_CHANNEL_ID"):
            try:
                self.notifications.discord.channel_id = int(env["DISCORD_CHANNEL_ID"])
            except ValueError:
                pass
        if env.get("DISCORD_NOTIFY_ON"):
            self.notifications.discord.notify_on = env["DISCORD_NOTIFY_ON"]
        if env.get("DISCORD_CREATE_THREADS"):
            self.notifications.discord.create_threads = env["DISCORD_CREATE_THREADS"].lower() in ("1", "true", "yes")
        if env.get("ONLINE_PORTS_ENABLED"):
            self.discovery.online_ports.enabled = env["ONLINE_PORTS_ENABLED"].lower() in ("1", "true", "yes")
        if env.get("ONLINE_PORTS_MODE"):
            self.discovery.online_ports.mode = env["ONLINE_PORTS_MODE"].lower().strip()
        if env.get("ONLINE_PORTS_HOSTS"):
            self.discovery.online_ports.hosts = [h.strip() for h in env["ONLINE_PORTS_HOSTS"].split(",") if h.strip()]
        if env.get("ONLINE_PORTS_SUBNETS"):
            self.discovery.online_ports.subnets = [s.strip() for s in env["ONLINE_PORTS_SUBNETS"].split(",") if s.strip()]
        if env.get("AGENT_ENABLED"):
            self.agent.enabled = env["AGENT_ENABLED"].lower() in ("1", "true", "yes")
        if env.get("AGENT_ACTIVE_PROBING"):
            self.agent.active_probing = env["AGENT_ACTIVE_PROBING"].lower() in ("1", "true", "yes")
        if env.get("AGENT_MAX_TURNS"):
            try:
                self.agent.max_turns = int(env["AGENT_MAX_TURNS"])
            except ValueError:
                pass
        if env.get("WEB_HOST"):
            self.web.host = env["WEB_HOST"]
        if env.get("WEB_PORT"):
            try:
                self.web.port = int(env["WEB_PORT"])
            except ValueError:
                pass
        if env.get("WEB_TOKEN"):
            self.web.token = env["WEB_TOKEN"]
        if env.get("WEB_ENABLED"):
            self.web.enabled = env["WEB_ENABLED"].lower() in ("1", "true", "yes")

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
