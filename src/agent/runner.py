"""Autonomous Agent ReAct Runner using native OpenAI function calling."""
from __future__ import annotations

import json
import re
from typing import Any
from ..log import get_logger
from .tools import AGENT_TOOL_SCHEMAS, AgentToolExecutor

logger = get_logger("agent.runner")

SYSTEM_PROMPT = """You are the FAS Autonomous Security Agent, an elite DevSecOps researcher investigating potential credential exposures found in public source code and APKs.

Your goal is to investigate finding #{finding_id} ({detector} in {service}):
1. Explore the codebase context using `read_code_context` or `inspect_test_environment`.
2. Check if the credential is an obvious mock, dummy, or test fixture.
3. If it looks like a real credential, safely verify it using `validate_credential_safe` (read-only identity probe).
4. If verified or high-risk, generate a remediation patch with `draft_remediation`.

When you have finished your investigation or reached a confident verdict, provide a final JSON response:
```json
{{
  "status": "verified_live|false_positive_mock|revoked|unverified",
  "blast_radius": "<concise description of permissions / access scope / account>",
  "summary": "<clear 2-3 sentence executive explanation of your findings>",
  "patch_diff": "<unified git diff patch if applicable, or null>"
}}
```
"""

SYSTEM_PROMPT_MULTI = """You are the FAS Autonomous Security Agent, an elite DevSecOps researcher investigating potential credential exposures found in public source code and APKs.

You are investigating {count} findings in THIS ONE conversation:
{briefs}

For EACH finding:
1. Explore its codebase context using `read_code_context` or `inspect_test_environment`.
2. Check if the credential is an obvious mock, dummy, or test fixture.
3. If it looks like a real credential, safely verify it using `validate_credential_safe` (read-only identity probe).
4. If verified or high-risk, generate a remediation patch with `draft_remediation`.

IMPORTANT: pass `finding_id` in EVERY tool call so the correct codebase and secret is examined.

When you have finished ALL findings, provide ONE final JSON response covering every finding id listed above:
```json
{{
  "verdicts": [
    {{
      "finding_id": <int>,
      "status": "verified_live|false_positive_mock|revoked|unverified",
      "blast_radius": "<concise description of permissions / access scope / account>",
      "summary": "<clear 2-3 sentence executive explanation of your findings>",
      "patch_diff": "<unified git diff patch if applicable, or null>"
    }}
  ]
}}
```
"""


def _agent_llm_settings(ctx: Any) -> tuple[str, str, str, int]:
    """Resolve the agent's effective LLM settings.

    agent.* overrides win; empty/0 falls back to the shared llm.* settings.
    Returns (model, base_url, api_key, timeout_seconds).
    """
    llm = ctx.cfg.llm
    ag = getattr(ctx.cfg, "agent", None)
    model = (getattr(ag, "model", "") or "") or getattr(llm, "model", "gpt-4o-mini")
    base_url = ((getattr(ag, "base_url", "") or "")
                or getattr(llm, "base_url", "https://api.openai.com/v1"))
    api_key = (getattr(ag, "api_key", "") or "") or getattr(llm, "api_key", "")
    timeout = int(getattr(ag, "timeout_seconds", 0) or 0) or getattr(llm, "timeout_seconds", 45)
    return model, base_url, api_key, timeout


def _get_openai_client(ctx: Any):
    from openai import OpenAI

    _, base_url, api_key, timeout = _agent_llm_settings(ctx)

    return OpenAI(
        base_url=base_url,
        api_key=api_key or "unused",
        timeout=timeout,
        max_retries=2,
    )


def investigate_finding(ctx: Any, finding_id: int) -> dict[str, Any]:
    """Run an autonomous agent investigation loop for a single finding."""
    return investigate_findings(ctx, [finding_id])[0]


def investigate_findings(ctx: Any, finding_ids: list[int]) -> list[dict[str, Any]]:
    """Run ONE agent conversation covering one or more findings.

    Grouping several findings into a single conversation drastically reduces
    API request count (one ReAct loop per group instead of per finding) while
    still producing an individual verdict + investigation row per finding.
    """
    if not hasattr(ctx, "db"):
        return [{"finding_id": fid, "status": "error", "error": "No database context"}
                for fid in finding_ids]

    findings: dict[int, dict[str, Any]] = {}
    artifacts: dict[int, str | None] = {}
    results: dict[int, dict[str, Any]] = {}
    for fid in finding_ids:
        row = ctx.db.get_finding(fid)
        if not row:
            results[fid] = {"finding_id": fid, "status": "error",
                            "error": f"Finding #{fid} not found"}
            continue
        f = dict(row)
        findings[fid] = f
        artifacts[fid] = ctx.db.latest_artifact_path(f["target_id"])
    if not findings:
        return [results[fid] for fid in finding_ids]

    primary_id = next(iter(findings))
    multi = len(findings) > 1

    executor = AgentToolExecutor(
        ctx, findings[primary_id], artifacts[primary_id],
        findings={fid: (f, artifacts[fid]) for fid, f in findings.items()},
    )
    tool_trace: list[dict[str, Any]] = []

    if multi:
        briefs = "\n".join(
            f"  • Finding #{fid} ({f.get('detector', 'unknown')} in {f.get('service', 'unknown')})"
            for fid, f in findings.items()
        )
        prompt = SYSTEM_PROMPT_MULTI.format(count=len(findings), briefs=briefs)
    else:
        prompt = SYSTEM_PROMPT.format(
            finding_id=primary_id,
            detector=findings[primary_id].get("detector", "unknown"),
            service=findings[primary_id].get("service", "unknown"),
        )

    blocks = []
    for fid, f in findings.items():
        blocks.append(
            f"Investigate Finding #{fid}:\n"
            f"• Detector: {f.get('detector')}\n"
            f"• Service: {f.get('service')}\n"
            f"• File: {f.get('file_path')}:{f.get('line')}\n"
            f"• Severity: {f.get('severity')}\n"
            f"• Secret Preview: {f.get('secret_preview')}\n"
            f"• Code Context:\n```\n{f.get('context', '')[:800]}\n```"
        )

    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": "\n\n".join(blocks)},
    ]

    max_turns = getattr(ctx.cfg.agent, "max_turns", 4)
    model, _, _, _ = _agent_llm_settings(ctx)

    client = _get_openai_client(ctx)
    verdicts: dict[int, dict[str, Any]] = {}

    for turn in range(max_turns):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=AGENT_TOOL_SCHEMAS,
                tool_choice="auto",
                temperature=0.1,
            )
            choice = resp.choices[0]
            msg = choice.message
            messages.append(msg)

            # Check if tools were called
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    fn_name = str(getattr(tc.function, "name", "") or "")
                    try:
                        raw_args = getattr(tc.function, "arguments", "{}")
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except Exception:
                        args = {}

                    tool_output = executor.execute(fn_name, args)
                    tool_trace.append({
                        "turn": turn + 1,
                        "tool": fn_name,
                        "arguments": args,
                        "output": json.loads(tool_output) if isinstance(tool_output, str) and tool_output.startswith("{") else str(tool_output),
                    })

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "name": fn_name,
                        "content": tool_output,
                    })
            else:
                # Text response - parse final verdict JSON
                content = msg.content or ""
                parsed = _extract_verdicts_json(content)
                if parsed:
                    for fid, verdict in parsed.items():
                        verdicts[fid if fid else primary_id] = verdict
                    break
        except Exception as exc:
            logger.warning("Agent investigation loop error on finding(s) %s: %s",
                           list(findings), exc)
            tool_trace.append({"error": str(exc)})
            break

    for fid, f in findings.items():
        final_verdict = {
            "status": "unverified",
            "blast_radius": "",
            "summary": "Agent reached turn limit without a conclusive verdict.",
            "patch_diff": None,
        }
        if fid in verdicts:
            final_verdict.update(verdicts[fid])

        status = final_verdict.get("status", "unverified")
        blast_radius = final_verdict.get("blast_radius", "")
        summary = final_verdict.get("summary", "")
        patch_diff = final_verdict.get("patch_diff")

        ctx.db.upsert_investigation(
            finding_id=fid,
            status=status,
            blast_radius=blast_radius,
            summary=summary,
            patch_diff=patch_diff,
            tool_trace=tool_trace,
        )

        if status == "verified_live":
            ctx.db.set_finding_triage(fid, "true_positive", notes=f"[Agent Verified] {summary[:200]}")
        elif status == "false_positive_mock":
            ctx.db.set_finding_triage(fid, "false_positive", notes=f"[Agent Mock] {summary[:200]}")

        results[fid] = {
            "finding_id": fid,
            "status": status,
            "blast_radius": blast_radius,
            "summary": summary,
            "patch_diff": patch_diff,
            "tool_trace": tool_trace,
        }

    return [results[fid] for fid in finding_ids]


def _extract_verdicts_json(text: str) -> dict[int, dict[str, Any]] | None:
    """Tolerant extraction of verdict JSON keyed by finding id.

    Accepts a bare object {"status": ...} (mapped to key 0 = primary finding),
    a bare array [{...}, ...], or an object wrapper {"verdicts": [...]}.
    """
    match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except Exception:
        return None

    items: list[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if isinstance(data.get("verdicts"), list):
            items = data["verdicts"]
        elif "status" in data:
            items = [data]

    out: dict[int, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or "status" not in item:
            continue
        try:
            fid = int(item.get("finding_id", item.get("id", 0)) or 0)
        except (TypeError, ValueError):
            fid = 0
        out[fid] = item
    return out or None
