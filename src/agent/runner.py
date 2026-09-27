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


def _get_openai_client(ctx: Any):
    from openai import OpenAI

    base_url = getattr(ctx.cfg.llm, "base_url", "https://api.openai.com/v1")
    api_key = getattr(ctx.cfg.llm, "api_key", "")
    timeout = getattr(ctx.cfg.llm, "timeout_seconds", 45)

    return OpenAI(
        base_url=base_url,
        api_key=api_key or "unused",
        timeout=timeout,
        max_retries=2,
    )


def investigate_finding(ctx: Any, finding_id: int) -> dict[str, Any]:
    """Run an autonomous agent investigation loop for a single finding."""
    if not hasattr(ctx, "db"):
        return {"error": "No database context"}

    row = ctx.db.get_finding(finding_id)
    if not row:
        return {"error": f"Finding #{finding_id} not found"}

    finding = dict(row)
    artifact_path = ctx.db.latest_artifact_path(finding["target_id"])

    executor = AgentToolExecutor(ctx, finding, artifact_path)
    tool_trace: list[dict[str, Any]] = []

    prompt = SYSTEM_PROMPT.format(
        finding_id=finding_id,
        detector=finding.get("detector", "unknown"),
        service=finding.get("service", "unknown"),
    )

    initial_user_message = (
        f"Investigate Finding #{finding_id}:\n"
        f"• Detector: {finding.get('detector')}\n"
        f"• Service: {finding.get('service')}\n"
        f"• File: {finding.get('file_path')}:{finding.get('line')}\n"
        f"• Severity: {finding.get('severity')}\n"
        f"• Secret Preview: {finding.get('secret_preview')}\n"
        f"• Code Context:\n```\n{finding.get('context', '')[:800]}\n```"
    )

    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": initial_user_message},
    ]

    max_turns = getattr(ctx.cfg.agent, "max_turns", 4)
    model = getattr(ctx.cfg.llm, "model", "gpt-4o-mini")

    client = _get_openai_client(ctx)
    final_verdict = {
        "status": "unverified",
        "blast_radius": "",
        "summary": "Agent reached turn limit without a conclusive verdict.",
        "patch_diff": None,
    }

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
                parsed = _extract_verdict_json(content)
                if parsed:
                    final_verdict.update(parsed)
                    break
        except Exception as exc:
            logger.warning("Agent investigation loop error on finding #%d: %s", finding_id, exc)
            tool_trace.append({"error": str(exc)})
            break

    status = final_verdict.get("status", "unverified")
    blast_radius = final_verdict.get("blast_radius", "")
    summary = final_verdict.get("summary", "")
    patch_diff = final_verdict.get("patch_diff")

    ctx.db.upsert_investigation(
        finding_id=finding_id,
        status=status,
        blast_radius=blast_radius,
        summary=summary,
        patch_diff=patch_diff,
        tool_trace=tool_trace,
    )

    if status == "verified_live":
        ctx.db.set_finding_triage(finding_id, "true_positive", notes=f"[Agent Verified] {summary[:200]}")
    elif status == "false_positive_mock":
        ctx.db.set_finding_triage(finding_id, "false_positive", notes=f"[Agent Mock] {summary[:200]}")

    return {
        "finding_id": finding_id,
        "status": status,
        "blast_radius": blast_radius,
        "summary": summary,
        "patch_diff": patch_diff,
        "tool_trace": tool_trace,
    }


def _extract_verdict_json(text: str) -> dict[str, Any] | None:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        if "status" in data:
            return data
    except Exception:
        pass
    return None
