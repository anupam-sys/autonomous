"""LLM triage of findings — works with ANY OpenAI-compatible endpoint
(OpenAI, Azure, Ollama /v1, LM Studio, vLLM, Together, ...).

The LLM only ever sees REDACTED context: secret previews, detector type,
file path and surrounding lines with values masked. Never full secrets.
Batch processing aggregates multiple findings into a single request,
drastically reducing API request count and maximizing token efficiency.
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

For each finding ID, classify it as exactly one of:
- "true_positive": looks like a real, live credential exposed by mistake
- "false_positive": syntactically similar but not a real credential
  (test fixture, doc example, library constant, placeholder, benign string)
- "placeholder": obviously a dummy/example value

The secret VALUE is redacted (you see only a masked preview) — judge from the
detector type, variable/file names, surrounding code, and context.

Respond with ONLY a JSON object containing a "verdicts" array:
{"verdicts": [
  {"id": <finding_id_integer>,
   "verdict": "true_positive|false_positive|placeholder",
   "confidence": 0.0-1.0,
   "severity_adjustment": "critical|high|medium|low|info|null",
   "reason": "<=160 chars"}
]}"""

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


def _dict_to_verdict(data: dict) -> Verdict | None:
    if not isinstance(data, dict):
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


def parse_verdict(text: str) -> Verdict | None:
    """Tolerant JSON extraction for a single verdict (handles ```json fences and prose)."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        logger.warning("unparseable LLM verdict: %.120s", text)
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return _dict_to_verdict(data)


def parse_batch_verdicts(text: str) -> dict[int, Verdict]:
    """Tolerant JSON extraction for batch verdicts keyed by finding ID."""
    match = re.search(r"(\{|\[).*(?:\}|\])", text, re.DOTALL)
    if not match:
        logger.warning("unparseable batch LLM verdict: %.120s", text)
        return {}
    try:
        raw = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}

    results: dict[int, Verdict] = {}
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and "id" in item:
                v = _dict_to_verdict(item)
                if v:
                    try:
                        results[int(item["id"])] = v
                    except (ValueError, TypeError):
                        pass
    elif isinstance(raw, dict):
        if "verdicts" in raw:
            vlist = raw["verdicts"]
            if isinstance(vlist, list):
                for item in vlist:
                    if isinstance(item, dict) and "id" in item:
                        v = _dict_to_verdict(item)
                        if v:
                            try:
                                results[int(item["id"])] = v
                            except (ValueError, TypeError):
                                pass
            elif isinstance(vlist, dict):
                for k, item in vlist.items():
                    if isinstance(item, dict):
                        v = _dict_to_verdict(item)
                        if v:
                            try:
                                key_id = int(str(k).replace("finding_", ""))
                                results[key_id] = v
                            except (ValueError, TypeError):
                                pass
        else:
            for k, item in raw.items():
                if isinstance(item, dict) and (str(k).isdigit() or str(k).startswith("finding_")):
                    key_id_str = str(k).replace("finding_", "")
                    try:
                        v = _dict_to_verdict(item)
                        if v:
                            results[int(key_id_str)] = v
                    except (ValueError, TypeError):
                        pass
            if not results and "id" in raw:
                v = _dict_to_verdict(raw)
                if v:
                    try:
                        results[int(raw["id"])] = v
                    except (ValueError, TypeError):
                        pass
    return results


def triage_batch(client, ctx, batch: list) -> dict[int, Verdict]:
    """Evaluate a batch of findings in a single LLM request."""
    if not batch:
        return {}
    items = []
    for row in batch:
        items.append(
            f"=== FINDING #{row['id']} ===\n"
            f"Detector: {row['detector']}\n"
            f"Classified service: {row['service']}\n"
            f"Secret type: {row['secret_type']}\n"
            f"File: {row['file_path']} (line {row['line']})\n"
            f"Rule severity: {row['severity']}, rule confidence: {row['confidence']}\n"
            f"Masked preview: {row['secret_preview']}\n"
            f"Context (secrets masked):\n{row['context'][:1200]}"
        )
    user_prompt = "Triage the following findings by ID:\n\n" + "\n\n".join(items)

    try:
        resp = client.chat.completions.create(
            model=ctx.cfg.llm.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("LLM batch call failed for findings %s: %s",
                       [r["id"] for r in batch], exc)
        return {}

    return parse_batch_verdicts(text)


def triage_one(client, ctx, row) -> Verdict | None:
    res = triage_batch(client, ctx, [row])
    if row["id"] in res:
        return res[row["id"]]
    # Fallback to single prompt if needed
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
                {"role": "system", "content": "You are a security-research triage assistant.\nClassify this finding as JSON: {\"verdict\": \"true_positive|false_positive|placeholder\", \"confidence\": 0.0-1.0, \"severity_adjustment\": \"critical|high|medium|low|info|null\", \"reason\": \"<=160 chars\"}"},
                {"role": "user", "content": user},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("LLM single triage call failed for finding %s: %s", row["id"], exc)
        return None
    return parse_verdict(text)


def run_triage(ctx) -> dict:
    if not ctx.cfg.llm.enabled:
        logger.info("LLM triage disabled (llm.enabled=false)")
        return {}
    client = _client(ctx)
    rows = ctx.db.untriaged_findings(
        ctx.cfg.llm.triage_confidence_floor, ctx.cfg.llm.max_findings_per_run
    )
    if not rows:
        return {"triaged": 0, "true_positive": 0, "false_positive": 0,
                "placeholder": 0, "errors": 0}

    batch_size = max(1, getattr(ctx.cfg.llm, "batch_size", 15))
    stats = {"triaged": 0, "true_positive": 0, "false_positive": 0,
             "placeholder": 0, "errors": 0, "requests": 0}

    from ..activity import emit

    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        f_ids = [r["id"] for r in batch]
        emit(ctx, "triage",
             f"LLM evaluating batch of {len(batch)} findings in 1 request (#{f_ids[0]}..#{f_ids[-1]}) ...")

        stats["requests"] += 1
        verdicts = triage_batch(client, ctx, batch)

        if not verdicts:
            stats["errors"] += len(batch)
            logger.warning("No verdicts returned for batch %s", f_ids)
            continue

        for row in batch:
            verdict = verdicts.get(row["id"])
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
                secret = ctx.db.get_finding_secret(row["id"])
                if secret:
                    row_dict["secret_full"] = secret
                notify_finding(ctx, row_dict, verdict.status.value, verdict.reason)

            stats["triaged"] += 1
            stats[verdict.status.value] += 1

    logger.info("triage pass completed in %d request(s): %s", stats["requests"], stats)
    return stats


def _adjust_severity(ctx, finding_id: int, severity: str) -> None:
    with ctx.db._lock, ctx.db._conn:
        ctx.db._conn.execute(
            "UPDATE findings SET severity = ? WHERE id = ?", (severity, finding_id)
        )
