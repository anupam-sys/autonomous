"""Autonomous Agent Tools: Code exploration, git history, mock analysis, and safe probing."""
from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from ..log import get_logger
from ..models import redact
from .probes import dispatch_probe

logger = get_logger("agent.tools")

AGENT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_code_context",
            "description": "Read source code context around a finding line in the acquired target directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative file path of the finding in the repository",
                    },
                    "line": {
                        "type": "integer",
                        "description": "The line number of the finding (1-indexed)",
                    },
                    "radius": {
                        "type": "integer",
                        "description": "Number of lines to read before and after (default 15)",
                    },
                },
                "required": ["file_path", "line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_git_history",
            "description": "Inspect git commit history, author, and blame for the file to see if the credential was committed or modified in subsequent commits.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative file path of the finding",
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number where the secret was found",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_test_environment",
            "description": "Analyze whether the file path and surrounding code belong to a test fixture, mock data, sample, or documentation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative file path to evaluate",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_credential_safe",
            "description": "Safely probe read-only identity endpoints (e.g. AWS STS GetCallerIdentity, GitHub User, Stripe Balance, OpenAI Models) to verify if the credential is live.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service name (e.g. github, stripe, openai, slack, aws, url)",
                    },
                    "secret": {
                        "type": "string",
                        "description": "The secret key or token to validate",
                    },
                },
                "required": ["service", "secret"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "draft_remediation",
            "description": "Generate a unified git diff patch redacting the hardcoded secret and replacing it with an environment variable or secret manager lookup.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative file path",
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number containing the credential",
                    },
                    "secret_snippet": {
                        "type": "string",
                        "description": "The exact code snippet or variable name to replace",
                    },
                    "env_var_name": {
                        "type": "string",
                        "description": "Suggested environment variable name (e.g. STRIPE_SECRET_KEY)",
                    },
                },
                "required": ["file_path", "line", "secret_snippet"],
            },
        },
    },
]


class AgentToolExecutor:
    """Dispatches tool calls with access to workspace artifacts and database."""

    def __init__(self, ctx: Any, finding: dict[str, Any], artifact_path: str | None = None):
        self.ctx = ctx
        self.finding = finding
        self.artifact_path = Path(artifact_path) if artifact_path else None

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Route tool call to local implementation."""
        try:
            if tool_name == "read_code_context":
                return self._read_code_context(
                    arguments.get("file_path", ""),
                    int(arguments.get("line", 1)),
                    int(arguments.get("radius", 15)),
                )
            elif tool_name == "check_git_history":
                return self._check_git_history(
                    arguments.get("file_path", ""),
                    int(arguments.get("line", 1)),
                )
            elif tool_name == "inspect_test_environment":
                return self._inspect_test_environment(arguments.get("file_path", ""))
            elif tool_name == "validate_credential_safe":
                return self._validate_credential_safe(
                    arguments.get("service", ""),
                    arguments.get("secret", ""),
                )
            elif tool_name == "draft_remediation":
                return self._draft_remediation(
                    arguments.get("file_path", ""),
                    int(arguments.get("line", 1)),
                    arguments.get("secret_snippet", ""),
                    arguments.get("env_var_name", ""),
                )
            else:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})
        except Exception as exc:
            logger.exception("Agent tool '%s' error: %s", tool_name, exc)
            return json.dumps({"error": f"Tool execution failed: {exc}"})

    def _read_code_context(self, file_path: str, line: int, radius: int = 15) -> str:
        if not self.artifact_path or not self.artifact_path.exists():
            return json.dumps({
                "source": "database_context",
                "file_path": file_path,
                "context": self.finding.get("context", "No artifact on disk."),
            })

        target_file = self.artifact_path / file_path
        if not target_file.exists():
            matches = list(self.artifact_path.rglob(Path(file_path).name))
            if matches:
                target_file = matches[0]
            else:
                return json.dumps({"error": f"File '{file_path}' not found in artifact on disk."})

        try:
            lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(1, line - radius)
            end = min(len(lines), line + radius)
            snippet = []
            for idx in range(start, end + 1):
                marker = ">" if idx == line else " "
                snippet.append(f"{marker} {idx:4d} | {lines[idx - 1]}")
            return json.dumps({
                "file_path": file_path,
                "lines_range": f"{start}-{end}",
                "content": "\n".join(snippet),
            })
        except Exception as exc:
            return json.dumps({"error": f"Failed reading file: {exc}"})

    def _check_git_history(self, file_path: str, line: int) -> str:
        if not self.artifact_path or not (self.artifact_path / ".git").exists():
            return json.dumps({"is_git": False, "note": "Target is not a Git repo or history was not preserved."})

        try:
            cmd_log = ["git", "log", "-n", "3", "--oneline", "--", file_path]
            proc_log = subprocess.run(
                cmd_log,
                cwd=str(self.artifact_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5.0,
            )
            cmd_blame = ["git", "blame", "-L", f"{line},{line}", "--porcelain", "--", file_path]
            proc_blame = subprocess.run(
                cmd_blame,
                cwd=str(self.artifact_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5.0,
            )
            return json.dumps({
                "recent_commits": proc_log.stdout.strip() or "No commit history found.",
                "blame_summary": proc_blame.stdout.strip()[:300] if proc_blame.returncode == 0 else "Blame unavailable",
            })
        except Exception as exc:
            return json.dumps({"error": f"Git inspection failed: {exc}"})

    def _inspect_test_environment(self, file_path: str) -> str:
        path_lower = file_path.lower().replace("\\", "/")
        test_indicators = [
            "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures",
            "mock", "mocks", "sample", "samples", "example", "examples", "dummy",
            "testdata", "demo", "doc", "docs", "faker"
        ]
        matched_indicators = [ind for ind in test_indicators if f"/{ind}/" in f"/{path_lower}/" or path_lower.endswith(f"_{ind}.py") or f".{ind}." in path_lower]
        is_mock_path = bool(matched_indicators)
        return json.dumps({
            "is_test_or_mock": is_mock_path,
            "matched_indicators": matched_indicators,
            "path": file_path,
            "verdict": "likely_test_or_fixture" if is_mock_path else "likely_production_code",
        })

    def _validate_credential_safe(self, service: str, secret: str) -> str:
        active_enabled = getattr(self.ctx.cfg.agent, "active_probing", True)
        if not active_enabled:
            return json.dumps({
                "is_live": False,
                "note": "Active probing is disabled in config.yaml (agent.active_probing: false).",
            })

        actual_secret = secret
        fid = self.finding.get("id")
        if (not actual_secret or "*" in actual_secret) and fid and hasattr(self.ctx, "db"):
            decrypted = self.ctx.db.get_finding_secret(fid)
            if decrypted:
                actual_secret = decrypted

        res = dispatch_probe(service, actual_secret)
        return json.dumps(res.to_dict())

    def _draft_remediation(self, file_path: str, line: int, secret_snippet: str, env_var_name: str = "") -> str:
        if not env_var_name:
            env_var_name = "EXPOSED_SECRET_KEY"

        replacement = f"os.environ.get('{env_var_name}')"
        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{line},1 +{line},1 @@",
            f"- {secret_snippet}",
            f"+ {secret_snippet.replace(secret_snippet, replacement)}",
        ]
        guidance = (
            f"1. Revoke the exposed credential immediately in the service provider console.\n"
            f"2. Add '{env_var_name}' to your environment variables or secret manager.\n"
            f"3. Rotate with a new key and deploy the patch."
        )
        return json.dumps({
            "patch_diff": "\n".join(diff_lines),
            "remediation_guidance": guidance,
        })
