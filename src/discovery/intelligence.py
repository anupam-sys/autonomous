"""Target intelligence engine: relevance scoring, spam/bot filtering, and noise suppression.

Prevents the pipeline from downloading random junk (bot-generated repos, student
homework, wallpaper archives, bloatware APKs, empty dummy packages) and prioritizes
high-value targets (APIs, auth systems, cloud infra, bot integrations, SDKs).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..log import get_logger
from ..models import Target, TargetKind

logger = get_logger("discovery.intelligence")

# Bot-generated repo patterns (e.g. repo-dwtuo59t, repo-qm4h6vvg)
BOT_REPO_PATTERNS = [
    re.compile(r"^repo-[a-z0-9]{6,}$", re.I),
    re.compile(r"^[0-9a-f]{16,}$", re.I),
    re.compile(r"^[a-zA-Z0-9]{25,}$"),
    re.compile(r"^(temp|test|dump|sync|bot|autogen)-[a-z0-9]{6,}$", re.I),
    re.compile(r"^([a-z0-9]+)/\1-[a-z0-9]{6,}$", re.I),
]

# Non-code, educational, or generic repository patterns that rarely contain leaked secrets
NOISE_TARGET_PATTERNS = [
    re.compile(r"(^|[\b_\-/])awesome-", re.I),
    re.compile(r"(^|[\b_\-/])curated-", re.I),
    re.compile(r"(^|[\b_\-/])roadmap", re.I),
    re.compile(r"(^|[\b_\-/])cheat-?sheet", re.I),
    re.compile(r"(^|[\b_\-/])interview", re.I),
    re.compile(r"(^|[\b_\-/])leetcode", re.I),
    re.compile(r"(^|[\b_\-/])hackerrank", re.I),
    re.compile(r"(^|[\b_\-/])codewars", re.I),
    re.compile(r"(^|[\b_\-/])coursework", re.I),
    re.compile(r"(^|[\b_\-/])homework", re.I),
    re.compile(r"(^|[\b_\-/])assignment", re.I),
    re.compile(r"(^|[\b_\-/])syllabus", re.I),
    re.compile(r"(^|[\b_\-/])cs101", re.I),
    re.compile(r"(^|[\b_\-/])exercises?", re.I),
    re.compile(r"(^|[\b_\-/])algorithm-visualizer", re.I),
    re.compile(r"(^|[\b_\-/])wallpapers?", re.I),
    re.compile(r"(^|[\b_\-/])icon-theme", re.I),
    re.compile(r"(^|[\b_\-/])dotfiles", re.I),
    re.compile(r"(^|[\b_\-/])subtitles?", re.I),
    re.compile(r"(^|[\b_\-/])novels?", re.I),
    re.compile(r"(^|[\b_\-/])manga", re.I),
    re.compile(r"(^|[\b_\-/])dataset", re.I),
    re.compile(r"(^|[\b_\-/])corpus", re.I),
    re.compile(r"-archive$", re.I),
    # Additional noise: static sites, portfolios, student exercises, media
    re.compile(r"(^|[\b_\-/])(portfolio|resume|curriculum-vitae|cv)(\b|$)", re.I),
    re.compile(r"(^|[\b_\-/])(hugo-theme|jekyll-theme|gatsby-starter|astro-template)(\b|$)", re.I),
    re.compile(r"(^|[\b_\-/])(freecodecamp|frontend-mentor|100-days-of-code|bootcamp)(\b|$)", re.I),
    re.compile(r"(^|[\b_\-/])(tutorial|study|notes|handbook|guide)(\b|$)", re.I),
    re.compile(r"(^|[\b_\-/])(spigot|paper-plugin|minecraft|roblox|unity-assets)(\b|$)", re.I),
    re.compile(r"\.github\.io$", re.I),
]

# System bloatware, OEM firmware apps, and non-target APKs
APK_BLOATWARE_PATTERNS = [
    re.compile(r"(setup-wizard|pixel-setup|android-setup|google-setup)", re.I),
    re.compile(r"(diagnosticstool|networkstack|systemui|keyboard)", re.I),
    re.compile(r"(compass|screenshot|screen-recorder|calculator|clock)", re.I),
    re.compile(r"(carrier-services|backup|theme-store|emoji|quicksearchbox)", re.I),
    re.compile(r"(sound-recorder|settings-intelligence|device-health)", re.I),
    re.compile(r"(youtube|adobe-acrobat|plex|roblox|minecraft|pubg|candy-crush)", re.I),
    re.compile(r"^com\.google\.android\.(apps\.)?(setupwizard|youtube|play\.games)", re.I),
    re.compile(r"^com\.sec\.android\.app\.(launcher|soundalive|voicenote)", re.I),
    re.compile(r"^com\.miui\.(calculator|compass|screenrecorder|notes)", re.I),
    re.compile(r"^com\.xiaomi\.(compass|screenshot|screenrecorder|backup)", re.I),
]

# Package dummy / test patterns (PyPI / npm)
DUMMY_PACKAGE_PATTERNS = [
    re.compile(r"^(test|dummy|demo|example|sample|temp|asdf)[_\-]", re.I),
    re.compile(r"[_\-](test|dummy|demo|example|sample)$", re.I),
    re.compile(r"^my-first-", re.I),
    re.compile(r"^foo-?bar", re.I),
]

# High-signal domains where secret exposure commonly occurs
SIGNAL_CATEGORIES = {
    "auth": [
        "auth", "oauth", "jwt", "sso", "login", "session", "identity",
        "keycloak", "ldap", "cognito", "auth0", "firebase", "token",
        "credential", "secret", "password"
    ],
    "cloud_infra": [
        "aws", "azure", "gcp", "kubernetes", "k8s", "terraform", "pulumi",
        "docker", "serverless", "helm", "ansible", "deploy", "cloud",
        "infra", "lambda", "ec2", "s3", "iam"
    ],
    "backend_api": [
        "api", "backend", "microservice", "rest", "graphql", "grpc",
        "server", "endpoint", "router", "controller", "gateway",
        "fastapi", "express", "django", "flask", "spring", "nest"
    ],
    "integration_bot": [
        "sdk", "client", "bot", "discord", "slack", "telegram",
        "webhook", "stripe", "paypal", "twilio", "sendgrid", "openai",
        "anthropic", "gemini", "mcp", "resend", "mailgun"
    ],
    "database": [
        "database", "postgres", "mysql", "mongodb", "redis", "storage",
        "kafka", "rabbitmq", "supabase", "cockroach", "dynamo"
    ],
    "internal_devops": [
        "internal", "admin", "portal", "dashboard", "crm", "erp",
        "pipeline", "automation", "connect", "sync", "config", "vault"
    ],
    "mobile_fintech": [
        "bank", "fintech", "wallet", "crypto", "exchange", "invest",
        "pay", "trading", "loan", "insurance", "ecommerce", "shop"
    ],
}


@dataclass
class TargetEvaluation:
    keep: bool
    score: float
    reason: str
    category: str = "generic"


def evaluate_target(
    target: Target,
    metadata: dict[str, Any] | None = None,
    cfg: Any = None,
) -> TargetEvaluation:
    """Intelligently score a target and decide whether to download/acquire it."""
    # 1. Exempt special high-confidence sources immediately
    if target.source in ("github_dork", "target_list", "ai_discovery", "approved_suggestion"):
        return TargetEvaluation(
            keep=True,
            score=1.0,
            reason="explicit high-value discovery source",
            category="dork",
        )

    name_clean = target.name.strip()
    short_name = name_clean.split("/")[-1] if "/" in name_clean else name_clean
    meta = metadata or {}

    filter_spam = getattr(cfg, "filter_spam", True) if cfg else True
    filter_noise = getattr(cfg, "filter_noise_types", True) if cfg else True
    filter_system_apks = getattr(cfg, "filter_system_apks", True) if cfg else True
    filter_forks = getattr(cfg, "filter_forks", True) if cfg else True
    min_score = getattr(cfg, "min_relevance_score", 0.25) if cfg else 0.25

    # 2. Reject user profile README repositories (e.g. username/username)
    if "/" in name_clean:
        parts = name_clean.split("/")
        if len(parts) == 2 and parts[0].lower() == parts[1].lower():
            return TargetEvaluation(
                keep=False,
                score=0.0,
                reason="user profile README repository (no secrets)",
                category="profile_readme",
            )

    # 3. Reject bot-generated spam repositories
    if filter_spam:
        for pat in BOT_REPO_PATTERNS:
            if pat.search(short_name) or pat.search(name_clean):
                return TargetEvaluation(
                    keep=False,
                    score=0.0,
                    reason=f"bot-generated or spam pattern ({pat.pattern})",
                    category="spam",
                )

    # 4. Reject noise / homework / media repositories
    if filter_noise:
        for pat in NOISE_TARGET_PATTERNS:
            if pat.search(name_clean):
                return TargetEvaluation(
                    keep=False,
                    score=0.05,
                    reason=f"noise/homework/media pattern ({pat.pattern})",
                    category="noise",
                )

    # 5. Reject APK bloatware / system utilities
    if target.kind == TargetKind.APK and filter_system_apks:
        for pat in APK_BLOATWARE_PATTERNS:
            if pat.search(name_clean) or pat.search(target.locator):
                return TargetEvaluation(
                    keep=False,
                    score=0.05,
                    reason=f"system bloatware / firmware APK ({pat.pattern})",
                    category="bloatware",
                )

    # 5. Reject dummy packages (PyPI / npm)
    if target.kind == TargetKind.PACKAGE:
        clean_pkg = short_name.removeprefix("pypi:").removeprefix("npm:")
        for pat in DUMMY_PACKAGE_PATTERNS:
            if pat.search(clean_pkg):
                return TargetEvaluation(
                    keep=False,
                    score=0.05,
                    reason=f"dummy/test package pattern ({pat.pattern})",
                    category="dummy_package",
                )

    # 6. Metadata checks (when available from API)
    if filter_forks and meta.get("fork"):
        return TargetEvaluation(
            keep=False,
            score=0.1,
            reason="forked repository (duplicate upstream code)",
            category="fork",
        )

    if meta.get("archived"):
        return TargetEvaluation(
            keep=False,
            score=0.1,
            reason="archived repository",
            category="archived",
        )

    if meta.get("size") == 0:
        return TargetEvaluation(
            keep=False,
            score=0.0,
            reason="empty repository",
            category="empty",
        )

    # 7. Category and keyword relevance scoring
    eval_text = f"{target.name} {target.locator}"
    desc = meta.get("description") or ""
    topics = " ".join(meta.get("topics") or [])
    eval_text += f" {desc} {topics}".lower()

    # Base score by kind
    if target.kind == TargetKind.REPO:
        base_score = 0.35
    elif target.kind == TargetKind.PACKAGE:
        base_score = 0.30
    else:
        base_score = 0.25

    matched_categories: list[str] = []
    bonus = 0.0

    for cat_name, kw_list in SIGNAL_CATEGORIES.items():
        if any(re.search(rf"\b{re.escape(k)}\b", eval_text) for k in kw_list):
            matched_categories.append(cat_name)
            bonus += 0.15

    # Target keywords bonus
    target_kws = getattr(cfg, "target_keywords", None)
    has_target_kw = False
    if target_kws:
        for kw in target_kws:
            if re.search(rf"\b{re.escape(kw)}\b", eval_text):
                bonus += 0.10
                has_target_kw = True
                break

    # If no relevance signal category and no target keyword matched, heavily penalize
    if not matched_categories and not has_target_kw:
        score = 0.10
    else:
        score = base_score + bonus

    score = max(0.0, min(1.0, score))
    primary_category = matched_categories[0] if matched_categories else "generic"

    if score < min_score:
        return TargetEvaluation(
            keep=False,
            score=round(score, 2),
            reason=f"relevance score ({score:.2f}) < threshold ({min_score:.2f})" if matched_categories else "no security or backend signal detected",
            category=primary_category,
        )

    return TargetEvaluation(
        keep=True,
        score=round(score, 2),
        reason=f"matched {primary_category} (score {score:.2f})",
        category=primary_category,
    )
