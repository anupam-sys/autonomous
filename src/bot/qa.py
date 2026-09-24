"""Q&A engine for discussing findings with LLM or static context."""
from __future__ import annotations

import os
from ..log import get_logger

logger = get_logger("bot.qa")

SYSTEM_PROMPT = """You are an elite Application Security and DevSecOps analyst embedded in an autonomous secret-exposure research pipeline.
You assist security operators by analyzing exposed credentials, tokens, and cryptographic secrets discovered in open-source repos and mobile APKs.

When an operator asks a question, provide concise, highly practical technical guidance:
1. Explain what service or API the credential accesses and what permissions or resources might be compromised.
2. Analyze the file path, variable name, and code context to evaluate if it is a live credential, test fixture, or dummy mock.
3. Suggest safe, non-intrusive verification methods (e.g. checking auth endpoints without modifying data) if relevant.
4. Detail specific remediation steps (rotation, revocation, secret manager usage, git history scrubbing).

Keep responses direct, authoritative, and formatted cleanly in Markdown.
"""


def answer_finding_question(ctx, finding_id: int, user_question: str) -> str:
    """Answer an operator's question about a specific finding.

    Uses the configured LLM endpoint (OpenAI / local / Ollama) if available,
    or falls back to structured offline technical analysis.
    """
    row = ctx.db.get_finding(finding_id)
    if not row:
        return f"❌ **Finding #{finding_id} not found in database.**"

    row_dict = dict(row)
    secret_val = ctx.db.get_finding_secret(finding_id) or row_dict.get("secret_preview", "unknown")
    target_name = row_dict.get("target_name", "unknown")
    target_kind = row_dict.get("target_kind", "unknown")
    target_locator = row_dict.get("target_locator", "")
    file_path = row_dict.get("file_path", "unknown")
    line = row_dict.get("line", "?")
    detector = row_dict.get("detector", "unknown")
    service = row_dict.get("service", "unknown")
    severity = row_dict.get("severity", "info")
    confidence = row_dict.get("confidence", 0.0)
    context_code = row_dict.get("context", "")
    triage_status = row_dict.get("triage_status", "pending")
    triage_notes = row_dict.get("triage_notes", "")

    # Check if LLM is enabled and configured
    api_key = ctx.cfg.llm.api_key or os.environ.get("LLM_API_KEY", "")
    has_llm = bool(ctx.cfg.llm.enabled and api_key)

    if has_llm:
        try:
            from openai import OpenAI

            client = OpenAI(
                base_url=ctx.cfg.llm.base_url,
                api_key=api_key or "unused",
                timeout=ctx.cfg.llm.timeout_seconds,
                max_retries=2,
            )

            prompt = f"""Finding Context:
• ID: #{finding_id}
• Target: {target_name} ({target_kind}) — {target_locator}
• Location: {file_path}:{line}
• Detector: {detector}
• Service: {service}
• Severity: {severity.upper()} (Confidence: {confidence:.2f})
• Triage: {triage_status} {f'({triage_notes})' if triage_notes else ''}
• Secret (decrypted): {secret_val}

Code context:
```
{context_code}
```

Operator Question:
{user_question}"""

            response = client.chat.completions.create(
                model=ctx.cfg.llm.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=900,
            )
            ans = response.choices[0].message.content or ""
            return ans.strip()
        except Exception as exc:
            logger.warning("LLM Q&A query failed for finding #%d: %s", finding_id, exc)
            # Fall through to offline response with failure note

    # Offline / rule-based fallback response
    return _build_offline_response(row_dict, secret_val, user_question, has_llm)


def _build_offline_response(row: dict, secret_val: str, question: str, had_llm_attempt: bool) -> str:
    service = row.get("service", "generic")
    detector = row.get("detector", "unknown")
    severity = row.get("severity", "info")
    target_name = row.get("target_name", "target")
    file_path = row.get("file_path", "")
    line = row.get("line", "")

    # Basic service knowledge base
    service_advice = {
        "aws": "AWS IAM / Secret credentials grant programmatic cloud access. Check IAM policies attached to the identity and review CloudTrail logs.",
        "openai": "OpenAI API keys allow querying models and bill to the account owner. Revoke on platform.openai.com.",
        "stripe": "Stripe secret keys (`sk_live_...`) allow full transaction and customer data control. Revoke in Stripe Dashboard.",
        "google": "Google API keys (`AIza...`) may access Firebase, Maps, or GCP services depending on API key restrictions in Google Cloud Console.",
        "firebase": "Firebase database URLs / tokens can allow reading or writing collections if security rules are unconfigured (`.read: true`).",
        "github": "GitHub tokens allow accessing repos, packages, or org management. Revoke under GitHub Settings -> Developer settings.",
        "gitlab": "GitLab Personal Access Tokens allow project and API control. Revoke under GitLab User Preferences -> Access Tokens.",
    }
    advice = service_advice.get(service.lower(), f"Secrets for service `{service}` may expose backend APIs or data. Verify if this key is active with its provider.")

    notice = ""
    if had_llm_attempt:
        notice = "⚠️ *(LLM query could not be completed; showing static analysis)*\n\n"
    else:
        notice = "ℹ️ *(LLM reasoning is disabled. Set `llm.enabled: true` or `LLM_API_KEY` for conversational AI)*\n\n"

    return (
        f"{notice}### Finding #{row.get('id', '?')}: {detector} ({severity.upper()})\n"
        f"• **Target:** `{target_name}`\n"
        f"• **Location:** `{file_path}:{line}`\n"
        f"• **Secret Value:** `{secret_val}`\n\n"
        f"**Service Impact:** {advice}\n\n"
        f"**Remediation Steps:**\n"
        f"1. Revoke the key immediately in the provider's management console.\n"
        f"2. Issue a rotated credential and migrate to environment variables or secret vaults.\n"
        f"3. Scrub commit history or publish an updated APK without embedded secrets."
    )
