"""Unit tests for lean autonomous agent, safe identity probes, and tools."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.models import Finding, SecretType, Target, TargetKind, TriageStatus
from src.agent.probes import (
    dispatch_probe,
    probe_github,
    probe_openai,
    probe_slack,
    probe_stripe,
    probe_url,
    ProbeResult,
)
from src.agent.tools import AgentToolExecutor
from src.agent.runner import investigate_finding
from src.agent.investigator import run_agent_investigations
from src.queue import WorkQueue


class DummyContext:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.queue = WorkQueue(db)


def test_probe_localhost_strictly_excluded():
    res = probe_url("http://localhost:8080/api")
    assert not res.is_live
    assert "localhost" in (res.error or "").lower()

    res_ip = probe_url("http://127.0.0.1:3000/metrics")
    assert not res_ip.is_live
    assert "localhost" in (res_ip.error or "").lower()

    # dispatch_probe also blocks localhost
    res_disp = dispatch_probe("url", "http://localhost:5000")
    assert not res_disp.is_live


def test_probe_github_mock():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "secops", "type": "User", "plan": {"name": "pro"}}
        mock_resp.headers = {"X-OAuth-Scopes": "repo, read:org"}
        mock_get.return_value = mock_resp

        res = probe_github("ghp_validtoken123")
        assert res.is_live
        assert res.service == "github"
        assert "secops" in res.blast_radius
        assert "repo" in res.details["scopes"]


def test_probe_stripe_mock():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"object": "balance", "livemode": True}
        mock_get.return_value = mock_resp

        res = probe_stripe("sk_live_123456789")
        assert res.is_live
        assert "LIVE PRODUCTION" in res.blast_radius


def test_probe_openai_mock():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]}
        mock_get.return_value = mock_resp

        res = probe_openai("sk-proj-testkey123")
        assert res.is_live
        assert "2 models available" in res.blast_radius


def test_probe_slack_mock():
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True, "team": "SecTeam", "user": "U12345"}
        mock_post.return_value = mock_resp

        res = probe_slack("xoxb-12345")
        assert res.is_live
        assert "SecTeam" in res.blast_radius


def test_agent_tools_execution(cfg, db, tmp_path):
    ctx = DummyContext(cfg, db)
    # Create fake repo artifact with source file
    artifact_dir = tmp_path / "repo-1"
    artifact_dir.mkdir()
    src_file = artifact_dir / "config.py"
    src_file.write_text("API_KEY = 'sk-live-123'\nDEBUG = False\n", encoding="utf-8")

    finding = {
        "id": 1,
        "detector": "stripe-key",
        "service": "stripe",
        "file_path": "config.py",
        "line": 1,
        "secret_preview": "sk-live-***",
        "context": "API_KEY = 'sk-live-123'",
    }

    executor = AgentToolExecutor(ctx, finding, str(artifact_dir))

    # Test read_code_context
    ctx_res = json.loads(executor.execute("read_code_context", {"file_path": "config.py", "line": 1, "radius": 5}))
    assert "content" in ctx_res
    assert "API_KEY" in ctx_res["content"]

    # Test inspect_test_environment on test file
    mock_res = json.loads(executor.execute("inspect_test_environment", {"file_path": "tests/fixtures/keys.py"}))
    assert mock_res["is_test_or_mock"] is True

    # Test inspect_test_environment on prod file
    prod_res = json.loads(executor.execute("inspect_test_environment", {"file_path": "src/services/stripe.py"}))
    assert prod_res["is_test_or_mock"] is False

    # Test draft_remediation
    rem_res = json.loads(executor.execute("draft_remediation", {
        "file_path": "config.py",
        "line": 1,
        "secret_snippet": "API_KEY = 'sk-live-123'",
        "env_var_name": "STRIPE_KEY",
    }))
    assert "patch_diff" in rem_res
    assert "STRIPE_KEY" in rem_res["patch_diff"]


def test_investigate_finding_runner(cfg, db):
    target = Target(kind=TargetKind.REPO, source="test", locator="https://github.com/org/app.git", name="org/app")
    target_id, _ = db.upsert_target(target)

    finding = Finding(
        target_id=target_id,
        detector="stripe-secret",
        service="stripe",
        secret_type=SecretType.API_KEY,
        file_path="src/payments.py",
        line=14,
        secret_preview="sk_live_***",
        secret_hash="hash_stripe_1",
        secret_full="sk_live_realSecretKey12345",
        context="stripe.api_key = 'sk_live_realSecretKey12345'",
        severity="critical",
        confidence=0.9,
        triage_status=TriageStatus.PENDING,
    )
    db.insert_finding(finding)
    f_row = db.findings_for_report()[0]
    fid = f_row["id"]

    ctx = DummyContext(cfg, db)

    # Mock OpenAI client
    with patch("src.agent.runner._get_openai_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client

        # Mock 1 tool call turn followed by final JSON answer
        func_mock = MagicMock()
        func_mock.name = "inspect_test_environment"
        func_mock.arguments = json.dumps({"file_path": "src/payments.py"})

        msg_tool_call = MagicMock()
        msg_tool_call.tool_calls = [
            MagicMock(
                id="call_1",
                function=func_mock,
            )
        ]
        msg_tool_call.content = None

        msg_final = MagicMock()
        msg_final.tool_calls = None
        msg_final.content = json.dumps({
            "status": "verified_live",
            "blast_radius": "Production Stripe Payments Balance",
            "summary": "Live Stripe production key hardcoded in payments.py",
            "patch_diff": "--- a/src/payments.py\n+++ b/src/payments.py\n",
        })

        resp1 = MagicMock(choices=[MagicMock(message=msg_tool_call)])
        resp2 = MagicMock(choices=[MagicMock(message=msg_final)])
        mock_client.chat.completions.create.side_effect = [resp1, resp2]

        res = investigate_finding(ctx, fid)

        assert res["status"] == "verified_live"
        assert "Stripe" in res["blast_radius"]
        assert len(res["tool_trace"]) >= 1

        # Check DB persistence
        inv = db.get_investigation(fid)
        assert inv is not None
        assert inv["status"] == "verified_live"
        assert "payments" in inv["summary"]

        # Check triage status updated
        f_updated = db.get_finding(fid)
        assert f_updated["triage_status"] == "true_positive"


def test_run_agent_investigations_pipeline_stage(cfg, db):
    target = Target(kind=TargetKind.REPO, source="test", locator="test/repo", name="test/repo")
    target_id, _ = db.upsert_target(target)

    # Insert 3 findings
    for i in range(3):
        f = Finding(
            target_id=target_id,
            detector="github-token",
            service="github",
            secret_type=SecretType.TOKEN,
            file_path=f"src/mod_{i}.py",
            line=20,
            secret_preview=f"ghp_preview_{i}",
            secret_hash=f"hash_gh_{i}",
            secret_full=f"ghp_fullTokenValue_{i}",
            context="token = 'ghp_...'",
            severity="high",
            confidence=0.85,
            triage_status=TriageStatus.PENDING,
        )
        db.insert_finding(f)

    ctx = DummyContext(cfg, db)
    ctx.cfg.agent.enabled = True
    ctx.cfg.llm.api_key = "test-key"
    ctx.cfg.limits.agent_workers = 3

    with patch("src.agent.investigator.investigate_finding") as mock_investigate:
        mock_investigate.side_effect = lambda c, fid: {
            "finding_id": fid,
            "status": "verified_live",
            "blast_radius": "Full GitHub Admin",
            "summary": "Verified live token",
        }
        stats = run_agent_investigations(ctx)

        assert stats["investigated"] == 3
        assert stats["verified_live"] == 3
        assert mock_investigate.call_count == 3
