"""Q&A engine for interactive conversational LLM analysis."""
from __future__ import annotations

import os
from typing import Any
from ..log import get_logger

logger = get_logger("bot.qa")

SYSTEM_PROMPT = """You are the FAS Autonomous Security Assistant, chatting directly with a security researcher in Discord.
You assist the operator with analyzing exposed credentials, API keys, tokens, and vulnerabilities discovered across codebases and Android APKs.

Guidelines:
- Directly, concisely, and conversationally answer whatever question the operator asks.
- Do NOT generate a rigid, canned 4-point template or predetermined audit report unless the operator specifically asks for a full formal report.
- If the operator asks a direct question (e.g., "is this live?", "what API is this?", "can you explain how to rotate it?"), answer that question directly.
- Use technical, precise DevSecOps language.
- Format responses cleanly with GitHub-flavored Markdown.
"""


def _reload_config_if_possible(ctx: Any) -> None:
    """Reload config overlay if configured so dashboard edits take effect immediately."""
    if getattr(ctx, "disable_auto_reload", False):
        return
    try:
        base_path = getattr(ctx.cfg, "_base_path", None)
        overlay_path = getattr(ctx.cfg, "_overlay_path", None)
        if base_path and os.path.exists(base_path):
            from ..config import Config
            fresh = Config.load(base_path, overlay_path or "none.yaml")
            ctx.cfg = fresh
    except Exception as exc:
        logger.debug("Config reload in qa helper failed: %s", exc)


def ask_security_assistant(
    ctx: Any,
    user_question: str,
    finding_id: int | None = None,
    conversation_history: list[dict] | None = None,
) -> str:
    """Query the LLM about a specific finding or general security question.

    Maintains conversational thread history when available.
    """
    _reload_config_if_possible(ctx)

    api_key = ctx.cfg.llm.api_key or os.environ.get("LLM_API_KEY", "")
    base_url = ctx.cfg.llm.base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
    is_custom_endpoint = bool(base_url and "api.openai.com" not in base_url)

    if not ctx.cfg.llm.enabled and not api_key:
        has_llm = False
    else:
        has_llm = bool(api_key or (ctx.cfg.llm.enabled and is_custom_endpoint))

    if not has_llm:
        if finding_id and hasattr(ctx, "db"):
            row = ctx.db.get_finding(finding_id)
            if row:
                secret_val = ctx.db.get_finding_secret(finding_id) or row["secret_preview"]
                return _build_offline_notice(dict(row), str(secret_val), finding_id)

        return (
            "🤖 **LLM Assistant is not configured.**\n\n"
            "To chat with the model and ask custom questions:\n"
            "1. Open the Web Dashboard (**Config** tab) and locate **NEURAL NETWORK — TRIAGE & AI DISCOVERY**.\n"
            "2. Enter your **AUTHENTICATION KEY** (or export `LLM_API_KEY` in `.env`).\n"
            "3. Check **ENABLE LLM TRIAGE** (or enter a custom local endpoint like `http://host.docker.internal:11434/v1` for Ollama).\n"
            "4. Click **Save Configuration**."
        )

    # Build prompt context
    system_content = SYSTEM_PROMPT
    if finding_id and hasattr(ctx, "db"):
        row = ctx.db.get_finding(finding_id)
        if row:
            r = dict(row)
            secret_val = ctx.db.get_finding_secret(finding_id) or r.get("secret_preview", "unknown")
            system_content += f"""

Finding #{finding_id} Details:
• Target: {r.get('target_name', 'unknown')} ({r.get('target_kind', 'unknown')}) — {r.get('target_locator', '')}
• Location: {r.get('file_path', 'unknown')}:{r.get('line', '?')}
• Detector: {r.get('detector', 'unknown')}
• Service: {r.get('service', 'unknown')}
• Severity: {str(r.get('severity', 'info')).upper()} (Confidence: {r.get('confidence', 0.0):.2f})
• Triage Status: {r.get('triage_status', 'pending')} {f'({r.get("triage_notes")})' if r.get("triage_notes") else ''}
• Secret Value: {secret_val}

Code Context:
```
{r.get('context', '')}
```
"""

    messages = [{"role": "system", "content": system_content}]
    if conversation_history:
        messages.extend(conversation_history[-6:])
    messages.append({"role": "user", "content": user_question})

    try:
        from openai import OpenAI

        client = OpenAI(
            base_url=base_url,
            api_key=api_key or "unused",
            timeout=ctx.cfg.llm.timeout_seconds,
            max_retries=2,
        )

        response = client.chat.completions.create(
            model=ctx.cfg.llm.model,
            messages=messages,
            temperature=0.3,
            max_tokens=1000,
        )
        ans = response.choices[0].message.content or ""
        return ans.strip()
    except Exception as exc:
        logger.exception("LLM Q&A call failed: %s", exc)
        return (
            f"⚠️ **LLM Model Error**: `{exc}`\n\n"
            f"The LLM provider could not complete your request. Please check:\n"
            f"• **Base URL**: `{base_url}`\n"
            f"• **Model**: `{ctx.cfg.llm.model}`\n"
            f"• **API Key**: {'Configured' if api_key else 'Missing'}\n"
            f"• Verify endpoint reachability and token quota."
        )


def answer_finding_question(ctx: Any, finding_id: int, user_question: str) -> str:
    """Backward-compatible wrapper for answering questions on a finding."""
    return ask_security_assistant(ctx, user_question, finding_id=finding_id)


def _build_offline_notice(row: dict, secret_val: str, finding_id: int) -> str:
    service = row.get("service", "generic")
    detector = row.get("detector", "unknown")
    severity = row.get("severity", "info")
    target_name = row.get("target_name", "target")
    file_path = row.get("file_path", "")
    line = row.get("line", "")

    service_advice = {
        "aws": "AWS IAM / Secret credentials grant programmatic cloud access. Check IAM policies attached to the identity.",
        "openai": "OpenAI API keys allow querying models and bill to account owner. Revoke on platform.openai.com.",
        "stripe": "Stripe secret keys allow full transaction control. Revoke in Stripe Dashboard.",
        "google": "Google API keys may access GCP/Firebase depending on restrictions in Google Cloud Console.",
        "firebase": "Firebase database URLs / tokens can expose collections if security rules are unconfigured.",
        "github": "GitHub tokens allow accessing repos, packages, or org management.",
        "gitlab": "GitLab Personal Access Tokens allow project and API control.",
    }
    advice = service_advice.get(service.lower(), f"Secrets for service `{service}` may expose backend APIs or data.")

    return (
        f"ℹ️ **LLM reasoning is offline.** Set `llm.api_key` or `llm.enabled: true` in config/dashboard to ask dynamic questions.\n\n"
        f"### Static Analysis for Finding #{finding_id}: {detector} ({severity.upper()})\n"
        f"• **Target:** `{target_name}`\n"
        f"• **Location:** `{file_path}:{line}`\n"
        f"• **Secret Value:** `{secret_val}`\n\n"
        f"**Service Impact:** {advice}\n\n"
        f"**Recommended Remediation:**\n"
        f"1. Revoke the key in the provider console.\n"
        f"2. Issue a rotated credential.\n"
        f"3. Remove hardcoded strings from code."
    )


_build_offline_response = _build_offline_notice
