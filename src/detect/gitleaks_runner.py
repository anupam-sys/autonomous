"""gitleaks wrapper — git-history scanning for cloned repos.

Our own Scanner covers working trees; gitleaks adds commit-history coverage.
A sanitized config (only fields gitleaks understands) is generated from our
rules so both engines share one ruleset.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ..decompile.apk_decompiler import find_tool
from ..log import get_logger
from ..models import Finding, SecretType, redact, sha256_str
from .rules_loader import Rule

logger = get_logger("detect.gitleaks")

_SEVERITY_FALLBACK = "medium"


def run_gitleaks(ctx, repo_dir: Path, rules: list[Rule], target_id: int) -> list[Finding]:
    exe = find_tool(
        ctx, "gitleaks_path",
        f"tools/gitleaks{'.exe' if sys.platform == 'win32' else ''}",
    )
    if not exe:
        logger.warning("gitleaks not found — skipping git-history scan")
        return []

    by_id = {r.id: r for r in rules}
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "gitleaks.toml"
        report_path = Path(tmp) / "report.json"
        cfg_path.write_text(_gen_config(rules), encoding="utf-8")
        cmd = [
            exe, "git",
            "--config", str(cfg_path),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--exit-code", "0",
            "--log-level", "error",
            str(repo_dir),
        ]
        try:
            proc = subprocess.run(cmd, timeout=600, capture_output=True)
        except subprocess.TimeoutExpired:
            logger.warning("gitleaks timed out on %s", repo_dir)
            return []
        if not report_path.exists():
            logger.debug("gitleaks produced no report (exit %d)", proc.returncode)
            return []
        try:
            entries = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    findings: list[Finding] = []
    for e in entries:
        secret = e.get("Secret", "")
        if not secret:
            continue
        rule = by_id.get(e.get("RuleID", ""))
        commit = e.get("Commit", "")
        context = (e.get("Match", "") or e.get("Line", ""))[:2000].replace(
            secret, redact(secret)
        )
        if commit:
            context = f"[commit {commit[:10]}] {context}"
        findings.append(
            Finding(
                target_id=target_id,
                detector=f"gitleaks:{e.get('RuleID', 'unknown')}",
                service=rule.service if rule else "generic",
                secret_type=rule.secret_type if rule else SecretType.OTHER,
                file_path=e.get("File", ""),
                line=int(e.get("StartLine", 0) or 0),
                secret_preview=redact(secret),
                secret_hash=sha256_str(secret),
                context=context,
                severity=rule.severity if rule else _SEVERITY_FALLBACK,
                confidence=(rule.confidence if rule else 0.7) + 0.05,  # history hit = stronger
                secret_full=secret,
            )
        )
    logger.info("gitleaks: %d findings in %s", len(findings), repo_dir.name)
    return findings


def _gen_config(rules: list[Rule]) -> str:
    lines = ["title = \"fas-generated\"", ""]
    for r in rules:
        lines.append("[[rules]]")
        lines.append(f"id = {json.dumps(r.id)}")
        lines.append(f"description = {json.dumps(r.description)}")
        lines.append(f"regex = {json.dumps(r.regex)}")
        if r.entropy is not None:
            lines.append(f"entropy = {r.entropy}")
        if r.group:
            lines.append(f"secretGroup = {r.group}")
        if r.keywords:
            kw = ", ".join(json.dumps(k.lower()) for k in r.keywords)
            lines.append(f"keywords = [{kw}]")
        lines.append("")
    return "\n".join(lines)
