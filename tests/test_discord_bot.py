"""Tests for Discord Bot integration, Q&A reasoning, and commands."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from src.config import Config
from src.models import Finding, SecretType, Target, TargetKind
from src.bot.client import FasDiscordBot, _split_message
from src.bot.qa import answer_finding_question, _build_offline_response
from src.bot.scanner import scan_target_on_demand


class DummyContext:
    def __init__(self, cfg, db=None, queue=None):
        self.cfg = cfg
        self.db = db
        self.queue = queue


def test_discord_config_env():
    env = {
        "DISCORD_ENABLED": "true",
        "DISCORD_BOT_TOKEN": "bot-token-12345",
        "DISCORD_CHANNEL_ID": "987654321",
        "DISCORD_NOTIFY_ON": "high_severity",
        "DISCORD_CREATE_THREADS": "false",
    }
    with patch.dict(os.environ, env):
        cfg = Config()
        cfg._apply_env()
        assert cfg.notifications.discord.enabled is True
        assert cfg.notifications.discord.bot_token == "bot-token-12345"
        assert cfg.notifications.discord.channel_id == 987654321
        assert cfg.notifications.discord.notify_on == "high_severity"
        assert cfg.notifications.discord.create_threads is False


def test_db_get_finding_and_id(db):
    tid, _ = db.upsert_target(Target(
        kind=TargetKind.APK,
        source="fdroid",
        locator="https://f-droid.org/app.apk",
        name="com.test.app",
    ))

    f = Finding(
        target_id=tid,
        detector="aws-secret-access-key",
        service="aws",
        secret_type=SecretType.API_KEY,
        file_path="smali/com/test/Config.smali",
        line=42,
        secret_preview="wJal****KEY",
        secret_hash="hash12345",
        context="const-string v0, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        severity="critical",
        confidence=0.95,
        secret_full="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    inserted = db.insert_finding(f)
    assert inserted is True
    assert f.id is not None

    row = db.get_finding(f.id)
    assert row is not None
    assert row["id"] == f.id
    assert row["detector"] == "aws-secret-access-key"
    assert row["target_name"] == "com.test.app"
    assert row["target_kind"] == "apk"

    # Decrypted secret check
    secret = db.get_finding_secret(f.id)
    assert secret == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_split_message():
    short = "Hello world"
    assert _split_message(short) == ["Hello world"]

    lines = [f"Line {i} with some extra padding text" for i in range(100)]
    long_text = "\n".join(lines)
    chunks = _split_message(long_text, limit=300)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c) <= 300
    assert "".join(chunks).replace("\n", "") == long_text.replace("\n", "")


def test_qa_offline_response(cfg, db):
    tid, _ = db.upsert_target(Target(
        kind=TargetKind.REPO,
        source="github",
        locator="https://github.com/org/repo.git",
        name="org/repo",
    ))
    f = Finding(
        target_id=tid,
        detector="openai-key",
        service="openai",
        secret_type=SecretType.API_KEY,
        file_path="src/config.py",
        line=10,
        secret_preview="sk-proj-****5678",
        secret_hash="hash987",
        context="OPENAI_KEY = 'sk-proj-testkey12345678'",
        severity="high",
        confidence=0.9,
        secret_full="sk-proj-testkey12345678",
    )
    db.insert_finding(f)
    ctx = DummyContext(cfg, db)
    ctx.disable_auto_reload = True

    # With LLM disabled and no key, returns structured offline analysis
    cfg.llm.enabled = False
    cfg.llm.api_key = ""
    with patch.dict(os.environ, {"LLM_API_KEY": ""}):
        ans = answer_finding_question(ctx, f.id, "How can I rotate this?")
    assert "Finding #" in ans
    assert "openai" in ans.lower()
    assert "sk-proj-testkey12345678" in ans
    assert "Remediation" in ans


def test_qa_llm_response(cfg, db):
    tid, _ = db.upsert_target(Target(
        kind=TargetKind.REPO,
        source="github",
        locator="https://github.com/org/repo.git",
        name="org/repo",
    ))
    f = Finding(
        target_id=tid,
        detector="stripe-secret-key",
        service="stripe",
        secret_type=SecretType.API_KEY,
        file_path="server.js",
        line=5,
        secret_preview="sk_live_****9999",
        secret_hash="hashstripe",
        context="const stripe = require('stripe')('sk_live_test')",
        severity="critical",
        confidence=0.99,
        secret_full="sk_live_test_1234567890",
    )
    db.insert_finding(f)
    ctx = DummyContext(cfg, db)

    cfg.llm.enabled = True
    cfg.llm.api_key = "dummy-key"

    with patch("openai.OpenAI") as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = "This is a Stripe live secret key granting full API access."
        mock_client.chat.completions.create.return_value = mock_resp

        ans = answer_finding_question(ctx, f.id, "What does this key do?")
        assert "Stripe live secret key" in ans


def test_qa_general_question(cfg, db):
    ctx = DummyContext(cfg, db)
    cfg.llm.enabled = True
    cfg.llm.api_key = "dummy-key"

    with patch("openai.OpenAI") as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = "To rotate an AWS key, create a new access key, update clients, then deactivate the old one."
        mock_client.chat.completions.create.return_value = mock_resp

        from src.bot.qa import ask_security_assistant
        ans = ask_security_assistant(ctx, "How do I rotate an AWS key?")
        assert "rotate an AWS key" in ans


@pytest.mark.anyio
async def test_bot_post_finding_alert_with_thread(cfg, db):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.create_threads = True
    ctx = DummyContext(cfg, db)

    bot = FasDiscordBot(ctx)

    mock_channel = AsyncMock()
    mock_msg = AsyncMock()
    mock_thread = AsyncMock()
    mock_msg.create_thread = AsyncMock(return_value=mock_thread)
    mock_channel.send = AsyncMock(return_value=mock_msg)
    bot.get_alert_channel = MagicMock(return_value=mock_channel)

    finding = {
        "id": 101,
        "detector": "aws-access-key",
        "service": "aws",
        "severity": "critical",
        "target_name": "backend-api",
        "target_kind": "repo",
        "file_path": "deploy.env",
        "line": 14,
        "secret_full": "AKIAIOSFODNN7EXAMPLE",
    }

    try:
        sent_msg = await bot.post_finding_alert(finding, "pending")
        assert sent_msg == mock_msg
        assert mock_channel.send.called
        call_kwargs = mock_channel.send.call_args[1]
        embed = call_kwargs["embed"]
        assert "aws-access-key" in embed.title
        assert "AKIAIOSFODNN7EXAMPLE" in embed.fields[5].value

        # Verify thread was created
        assert mock_msg.create_thread.called
        assert bot._thread_findings[mock_thread.id] == 101
    finally:
        await bot.close()


@pytest.mark.anyio
async def test_bot_authorized_users(cfg):
    cfg.notifications.discord.authorized_users = [111, 222]
    ctx = DummyContext(cfg, None)
    bot = FasDiscordBot(ctx)
    try:
        assert bot.is_authorized(111) is True
        assert bot.is_authorized(222) is True
        assert bot.is_authorized(999) is False

        # Empty list means unrestricted
        cfg.notifications.discord.authorized_users = []
        assert bot.is_authorized(999) is True
    finally:
        await bot.close()


def test_scan_target_on_demand_repo(cfg, db, tmp_path):
    repo_dir = tmp_path / "mock_repo"
    repo_dir.mkdir()
    (repo_dir / "secrets.env").write_text('stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\n', encoding="utf-8")

    from src.queue import WorkQueue
    ctx = DummyContext(cfg, db, WorkQueue(db))

    with patch("src.acquire.repo_cloner.clone_repo", return_value=(repo_dir, 100)):
        res = scan_target_on_demand(
            ctx,
            target_kind="repo",
            target_locator="https://github.com/example/mock.git",
            target_name="example/mock",
        )
        assert res["status"] == "completed"
        assert res["target_name"] == "example/mock"
        assert res["findings_new"] >= 1


@pytest.mark.anyio
async def test_bot_post_report_alert(cfg, db, tmp_path):
    html_f = tmp_path / "report.html"
    json_f = tmp_path / "report.json"
    html_f.write_text("<h1>Report</h1>", encoding="utf-8")
    json_f.write_text("{}", encoding="utf-8")

    ctx = DummyContext(cfg, db)
    bot = FasDiscordBot(ctx)

    mock_channel = AsyncMock()
    mock_msg = AsyncMock()
    mock_channel.send = AsyncMock(return_value=mock_msg)
    bot.get_alert_channel = MagicMock(return_value=mock_channel)

    report_data = {
        "findings": 5,
        "html": str(html_f),
        "json": str(json_f),
    }

    try:
        msg = await bot.post_report_alert(report_data)
        assert msg == mock_msg
        assert mock_channel.send.called
        kwargs = mock_channel.send.call_args[1]
        embed = kwargs["embed"]
        assert "Security Findings Report" in embed.title
        assert len(kwargs["files"]) == 2
    finally:
        await bot.close()
    assert msg == mock_msg
    assert mock_channel.send.called
    kwargs = mock_channel.send.call_args[1]
    embed = kwargs["embed"]
    assert "Security Findings Report" in embed.title
    assert len(kwargs["files"]) == 2


def test_notify_report_webhook(cfg, tmp_path):
    html_f = tmp_path / "report.html"
    json_f = tmp_path / "report.json"
    html_f.write_text("<h1>Report</h1>", encoding="utf-8")
    json_f.write_text("{}", encoding="utf-8")

    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"

    ctx = DummyContext(cfg)
    report_data = {
        "findings": 3,
        "html": str(html_f),
        "json": str(json_f),
    }

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        from src.notify import notify_report
        notify_report(ctx, report_data)

        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert "files" in call_kwargs and call_kwargs["files"] is not None
        assert "files[0]" in call_kwargs["files"]
        assert "files[1]" in call_kwargs["files"]
