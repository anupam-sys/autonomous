"""Safe, non-destructive read-only identity verification probes.

Only identity check endpoints are queried (e.g. sts:GetCallerIdentity, /user, /v1/balance).
Never performs state-modifying requests (no PUT/DELETE/POST data creation).
Strictly blocks all localhost and loopback targets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import requests

from ..detect.url_filter import is_localhost
from ..log import get_logger

logger = get_logger("agent.probes")

PROBE_TIMEOUT = 5.0  # seconds


@dataclass
class ProbeResult:
    is_live: bool
    service: str
    blast_radius: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_live": self.is_live,
            "service": self.service,
            "blast_radius": self.blast_radius,
            "details": self.details,
            "error": self.error,
        }


def probe_github(token: str) -> ProbeResult:
    """Check GitHub Personal Access Token or OAuth token identity and scopes."""
    token = token.strip()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "FAS-Security-Researcher/1.0",
    }
    try:
        resp = requests.get("https://api.github.com/user", headers=headers, timeout=PROBE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            scopes = resp.headers.get("X-OAuth-Scopes", "none")
            login = data.get("login", "unknown")
            user_type = data.get("type", "User")
            plan = data.get("plan", {}).get("name", "standard")
            blast = f"GitHub {user_type} '{login}' (Scopes: {scopes}, Plan: {plan})"
            return ProbeResult(
                is_live=True,
                service="github",
                blast_radius=blast,
                details={"login": login, "scopes": scopes, "type": user_type, "plan": plan},
            )
        elif resp.status_code in (401, 403):
            return ProbeResult(
                is_live=False,
                service="github",
                error=f"HTTP {resp.status_code}: Token rejected or revoked",
            )
        else:
            return ProbeResult(
                is_live=False,
                service="github",
                error=f"HTTP {resp.status_code} from api.github.com",
            )
    except Exception as exc:
        return ProbeResult(is_live=False, service="github", error=f"Probe connection error: {exc}")


def probe_stripe(key: str) -> ProbeResult:
    """Check Stripe Secret API Key identity and balance."""
    key = key.strip()
    headers = {
        "Authorization": f"Bearer {key}",
        "User-Agent": "FAS-Security-Researcher/1.0",
    }
    try:
        resp = requests.get("https://api.stripe.com/v1/balance", headers=headers, timeout=PROBE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            livemode = bool(data.get("livemode", False))
            mode_str = "LIVE PRODUCTION" if livemode else "TEST MODE"
            blast = f"Stripe Account Balance Access ({mode_str})"
            return ProbeResult(
                is_live=True,
                service="stripe",
                blast_radius=blast,
                details={"livemode": livemode, "object": data.get("object")},
            )
        elif resp.status_code in (401, 403):
            return ProbeResult(
                is_live=False,
                service="stripe",
                error=f"HTTP {resp.status_code}: Invalid or revoked Stripe key",
            )
        else:
            return ProbeResult(
                is_live=False,
                service="stripe",
                error=f"HTTP {resp.status_code} from api.stripe.com",
            )
    except Exception as exc:
        return ProbeResult(is_live=False, service="stripe", error=f"Probe connection error: {exc}")


def probe_openai(key: str) -> ProbeResult:
    """Check OpenAI API Key access and available models."""
    key = key.strip()
    headers = {
        "Authorization": f"Bearer {key}",
        "User-Agent": "FAS-Security-Researcher/1.0",
    }
    try:
        resp = requests.get("https://api.openai.com/v1/models", headers=headers, timeout=PROBE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            models = [m.get("id") for m in data.get("data", []) if isinstance(m, dict)]
            blast = f"OpenAI Organization API Access ({len(models)} models available)"
            return ProbeResult(
                is_live=True,
                service="openai",
                blast_radius=blast,
                details={"models_count": len(models), "sample_models": models[:5]},
            )
        elif resp.status_code in (401, 403):
            return ProbeResult(
                is_live=False,
                service="openai",
                error=f"HTTP {resp.status_code}: Invalid or expired OpenAI API key",
            )
        else:
            return ProbeResult(
                is_live=False,
                service="openai",
                error=f"HTTP {resp.status_code} from api.openai.com",
            )
    except Exception as exc:
        return ProbeResult(is_live=False, service="openai", error=f"Probe connection error: {exc}")


def probe_slack(token: str) -> ProbeResult:
    """Check Slack Token via auth.test."""
    token = token.strip()
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "FAS-Security-Researcher/1.0",
    }
    try:
        resp = requests.post("https://slack.com/api/auth.test", headers=headers, timeout=PROBE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                team = data.get("team", "unknown")
                user = data.get("user", "unknown")
                url = data.get("url", "")
                blast = f"Slack Workspace '{team}' (User/Bot: {user}, URL: {url})"
                return ProbeResult(
                    is_live=True,
                    service="slack",
                    blast_radius=blast,
                    details=data,
                )
            else:
                return ProbeResult(
                    is_live=False,
                    service="slack",
                    error=f"Slack auth.test error: {data.get('error')}",
                )
        elif resp.status_code in (401, 403):
            return ProbeResult(is_live=False, service="slack", error="Invalid Slack token")
        else:
            return ProbeResult(is_live=False, service="slack", error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return ProbeResult(is_live=False, service="slack", error=f"Probe connection error: {exc}")


def probe_url(url: str) -> ProbeResult:
    """Safe read-only probe for exposed endpoints, strictly excluding localhost/loopback."""
    clean = url.strip()
    if is_localhost(clean):
        return ProbeResult(
            is_live=False,
            service="url",
            error="Excluded: Target is localhost/loopback",
        )
    try:
        resp = requests.get(
            clean,
            headers={"User-Agent": "FAS-Security-Researcher/1.0"},
            timeout=PROBE_TIMEOUT,
            allow_redirects=True,
        )
        is_live = resp.status_code < 500
        blast = f"Accessible Endpoint (HTTP {resp.status_code})"
        return ProbeResult(
            is_live=is_live,
            service="url",
            blast_radius=blast if is_live else "",
            details={"status_code": resp.status_code, "server": resp.headers.get("Server", "")},
        )
    except Exception as exc:
        return ProbeResult(is_live=False, service="url", error=f"Connection failed: {exc}")


def dispatch_probe(service: str, secret: str) -> ProbeResult:
    """Route credential to the appropriate safe validation probe."""
    svc = (service or "").lower().strip()
    sec = secret.strip()

    if is_localhost(sec):
        return ProbeResult(is_live=False, service=svc, error="Excluded localhost/loopback")

    if svc == "github" or sec.startswith(("ghp_", "gho_", "github_pat_")):
        return probe_github(sec)
    elif svc == "stripe" or sec.startswith(("sk_live_", "sk_test_", "rk_live_")):
        return probe_stripe(sec)
    elif svc == "openai" or sec.startswith("sk-proj-"):
        return probe_openai(sec)
    elif svc == "slack" or sec.startswith(("xoxb-", "xoxp-", "xoxa-")):
        return probe_slack(sec)
    elif svc in ("url", "generic") and ("http://" in sec or "https://" in sec):
        return probe_url(sec)
    else:
        return ProbeResult(
            is_live=False,
            service=svc,
            error=f"No automated safe probe available for service '{svc}'",
        )
