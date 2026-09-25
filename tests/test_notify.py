from unittest.mock import MagicMock, patch
import pytest
from src.notify import notify_finding


class DummyContext:
    def __init__(self, cfg, db=None):
        self.cfg = cfg
        self.db = db


def test_notify_finding_sends_full_key(cfg):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"
    cfg.notifications.discord.notify_on = "any"

    ctx = DummyContext(cfg)
    finding = {
        "severity": "high",
        "detector": "openai-key",
        "service": "openai",
        "target_name": "test-repo",
        "target_kind": "repo",
        "file_path": "config.json",
        "line": 12,
        "secret_preview": "sk-proj-****1234",
        "secret_full": "sk-proj-uncensored-full-key-secret-1234567890",
    }

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        notify_finding(ctx, finding, "pending")

        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        embed = payload["embeds"][0]
        secret_field = next(f for f in embed["fields"] if f["name"] == "Full Key / Secret")
        assert "sk-proj-uncensored-full-key-secret-1234567890" in secret_field["value"]


def test_notify_finding_db_lookup(cfg, db):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"
    cfg.notifications.discord.notify_on = "any"

    # Mock db.get_finding_secret
    db.get_finding_secret = MagicMock(return_value="full-secret-from-db")
    ctx = DummyContext(cfg, db)

    finding = {
        "id": 99,
        "severity": "critical",
        "detector": "google-api-key",
        "service": "google",
        "target_name": "app",
        "target_kind": "apk",
        "file_path": "strings.xml",
        "line": 4,
        "secret_preview": "AIza****5678",
    }

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        notify_finding(ctx, finding, "pending")

        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        embed = payload["embeds"][0]
        secret_field = next(f for f in embed["fields"] if f["name"] == "Full Key / Secret")
        assert "full-secret-from-db" in secret_field["value"]


def test_notify_finding_rate_limit_retry(cfg):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"
    cfg.notifications.discord.notify_on = "any"

    ctx = DummyContext(cfg)
    finding = {
        "severity": "high",
        "detector": "test",
        "service": "test",
        "target_name": "test",
        "target_kind": "repo",
        "file_path": "a.txt",
        "line": 1,
        "secret_preview": "test",
        "secret_full": "test-key",
    }

    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "0.01"}

    resp_200 = MagicMock()
    resp_200.status_code = 200

    with patch("requests.post", side_effect=[resp_429, resp_200]) as mock_post, \
         patch("time.sleep") as mock_sleep:
        notify_finding(ctx, finding, "pending")

        assert mock_post.call_count == 2
        mock_sleep.assert_called_once_with(0.01)


def test_notify_finding_drops_unverified_when_notify_on_true_positive(cfg):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"
    cfg.notifications.discord.notify_on = "true_positive"

    ctx = DummyContext(cfg)
    finding = {
        "severity": "critical",
        "detector": "aws-secret-access-key",
        "service": "aws",
        "target_name": "test-repo",
        "target_kind": "repo",
        "file_path": "creds.env",
        "line": 1,
        "secret_preview": "AKIA****",
        "secret_full": "AKIAIOSFODNN7EXAMPLE",
    }

    with patch("requests.post") as mock_post:
        # Pending unverified findings should NOT be sent
        notify_finding(ctx, finding, "pending")
        assert not mock_post.called

        # False positive findings should NOT be sent
        notify_finding(ctx, finding, "false_positive")
        assert not mock_post.called

        # Placeholder findings should NOT be sent
        notify_finding(ctx, finding, "placeholder")
        assert not mock_post.called


def test_notify_finding_sends_when_verified_true_positive(cfg):
    cfg.notifications.discord.enabled = True
    cfg.notifications.discord.webhook_url = "https://discord.com/api/webhooks/test"
    cfg.notifications.discord.notify_on = "true_positive"

    ctx = DummyContext(cfg)
    finding = {
        "id": 42,
        "severity": "critical",
        "detector": "stripe-live-key",
        "service": "stripe",
        "target_name": "backend-api",
        "target_kind": "repo",
        "file_path": "stripe.json",
        "line": 5,
        "secret_preview": "sk_live_****abcd",
        "secret_full": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    }

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        notify_finding(ctx, finding, "true_positive", "Confirmed active production secret")
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        embed = payload["embeds"][0]
        triage_field = next(f for f in embed["fields"] if f["name"] == "Triage")
        assert triage_field["value"] == "true_positive"
        notes_field = next(f for f in embed["fields"] if f["name"] == "Triage Notes")
        assert "Confirmed active production secret" in notes_field["value"]
