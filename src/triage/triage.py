"""LLM triage of findings — works with ANY OpenAI-compatible endpoint
(OpenAI, Azure, Ollama /v1, LM Studio, vLLM, Together, ...).

The LLM only ever sees REDACTED context: secret previews, detector type,
file path and surrounding lines with values masked. Never full secrets.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..log import get_logger
from ..models import TriageStatus

logger = get_logger("triage")

SYSTEM_PROMPT = """You are a security-research triage assistant. You review potential
leaked credentials found in PUBLIC source code / decompiled apps, destined for
responsible disclosure reports.

For each finding, classify it as exactly one of:
- "true_positive": looks like a real, live credential exposed by mistake
- "false_positive": syntactically similar but not a real credential
  (test fixture, doc example, library constant, placeholder, benign string)
- "placeholder": obviously a dummy/example value

The secret VALUE is redacted (you see only a masked preview) — judge from the
detector type, variable/file names, surrounding code, and context.

Respond with ONLY a JSON object, no prose:
{"verdict": "true_positive|false_positive|placeholder",
 "confidence": 0.0-1.0,
 "severity_adjustment": "critical|high|medium|low|info|null",
 "reason": "<=160 chars"}"""

_VALID = {
    "true_positive": TriageStatus.TRUE_POSITIVE,
    "false_positive": TriageStatus.FALSE_POSITIVE,
    "placeholder": TriageStatus.PLACEHOLDER,
}


@dataclass
class Verdict:
    status: TriageStatus
    confidence: float
    reason: str
    severity: str | None = None


def _client(ctx):
    from openai import OpenAI

    return OpenAI(
        base_url=ctx.cfg.llm.base_url,
        api_key=ctx.cfg.llm.api_key or "unused",
        timeout=ctx.cfg.llm.timeout_seconds,
        max_retries=2,
    )


def triage_one(client, ctx, row) -> Verdict | None:
    user = (
        f"Detector: {row['detector']}\n"
        f"Classified service: {row['service']}\n"
        f"Secret type: {row['secret_type']}\n"
        f"File: {row['file_path']} (line {row['line']})\n"
        f"Rule severity: {row['severity']}, rule confidence: {row['confidence']}\n"
        f"Masked preview: {row['secret_preview']}\n"
        f"Context (secrets masked):\n{row['context'][:1500]}"
    )
    try:
        resp = client.chat.completions.create(
            model=ctx.cfg.llm.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("LLM call failed for finding %s: %s", row["id"], exc)
        return None
    return parse_verdict(text)


def parse_verdict(text: str) -> Verdict | None:
    """Tolerant JSON extraction (handles ```json fences and prose)."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        logger.warning("unparseable LLM verdict: %.120s", text)
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    status = _VALID.get(str(data.get("verdict", "")).strip())
    if not status:
        return None
    sev = data.get("severity_adjustment")
    return Verdict(
        status=status,
        confidence=max(0.0, min(1.0, float(data.get("confidence", 0.5)))),
        reason=str(data.get("reason", ""))[:400],
        severity=sev if sev in {"critical", "high", "medium", "low", "info"} else None,
    )


def run_triage(ctx) -> dict:
    if not ctx.cfg.llm.enabled:
        logger.info("LLM triage disabled (llm.enabled=false)")
        return {}
    client = _client(ctx)
    rows = ctx.db.untriaged_findings(
        ctx.cfg.llm.triage_confidence_floor, ctx.cfg.llm.max_findings_per_run
    )
    stats = {"triaged": 0, "true_positive": 0, "false_positive": 0,
             "placeholder": 0, "errors": 0}
    for row in rows:
        from ..activity import emit
        emit(ctx, "triage",
             f"LLM judging finding #{row['id']} ({row['detector']}, {row['service']}) ...")
        verdict = triage_one(client, ctx, row)
        if not verdict:
            stats["errors"] += 1
            continue
        ctx.db.set_finding_triage(
            row["id"], verdict.status.value, notes=verdict.reason,
            confidence=verdict.confidence,
        )
        emit(ctx, "triage",
             f"finding #{row['id']} -> {verdict.status.value} "
             f"({verdict.confidence:.2f}): {verdict.reason}")
        if verdict.severity:
            _adjust_severity(ctx, row["id"], verdict.severity)
            
        if ctx.cfg.notifications.discord.notify_on == "true_positive" and verdict.status.value == "true_positive":
            from ..notify import notify_finding
            row_dict = dict(row)
            if verdict.severity:
                row_dict["severity"] = verdict.severity
            notify_finding(ctx, row_dict, verdict.status.value, verdict.reason)

        stats["triaged"] += 1
        stats[verdict.status.value] += 1
    logger.info("triage pass: %s", stats)
    return stats


def _adjust_severity(ctx, finding_id: int, severity: str) -> None:
    with ctx.db._lock, ctx.db._conn:
        ctx.db._conn.execute(
            "UPDATE findings SET severity = ? WHERE id = ?", (severity, finding_id)
        )
