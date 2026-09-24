"""Config overlay + web config API."""
from __future__ import annotations

import pytest
import yaml

from src.config import Config, deep_merge, save_overlay
from src.web.server import _coerce, _sanitized_config, create_app


def test_deep_merge():
    base = {"a": {"b": 1, "c": 2}, "d": 3}
    over = {"a": {"b": 9}}
    assert deep_merge(base, over) == {"a": {"b": 9, "c": 2}, "d": 3}


def test_overlay_roundtrip(tmp_path):
    base = tmp_path / "config.yaml"
    base.write_text("llm:\n  model: base-model\n  timeout_seconds: 30\n")
    overlay = tmp_path / "config.local.yaml"
    save_overlay({"llm.model": "web-set-model", "llm.enabled": True}, overlay)
    cfg = Config.load(base, overlay)
    assert cfg.llm.model == "web-set-model"      # overlay wins
    assert cfg.llm.enabled is True
    assert cfg.llm.timeout_seconds == 30          # base preserved


def test_env_still_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "env-model")
    base = tmp_path / "config.yaml"
    base.write_text("llm:\n  model: file-model\n")
    cfg = Config.load(base, tmp_path / "none.yaml")
    assert cfg.llm.model == "env-model"


def test_sanitized_masks_secrets():
    cfg = Config.load("config.yaml")
    cfg.llm.api_key = "sk-real-key-123"
    data = _sanitized_config(cfg)
    assert data["llm"]["api_key"] == ""
    assert "sk-real-key-123" not in str(data)


def test_coerce():
    assert _coerce("bool", True) is True
    assert _coerce("int", "42") == 42
    assert _coerce("float", "0.5") == 0.5
    assert _coerce("list", "a\nb\n") == ["a", "b"]
    assert _coerce("choice:keep,delete", "keep") == "keep"
    with pytest.raises((ValueError, TypeError)):
        _coerce("bool", "yes")
    with pytest.raises((ValueError, TypeError)):
        _coerce("choice:keep,delete", "nope")


@pytest.fixture()
def web_client(tmp_path):
    base = tmp_path / "config.yaml"
    base.write_text("web:\n  token: ''\n")
    cfg = Config.load(base, tmp_path / "ov.yaml")
    app = create_app(cfg)
    app.testing = True
    return app.test_client(), tmp_path / "ov.yaml"


def test_config_get_masked(web_client):
    client, _ = web_client
    d = client.get("/api/config").get_json()
    assert "config" in d and "secrets_set" in d and "editable" in d
    assert d["config"]["llm"]["api_key"] == ""


def test_config_get_reveal(web_client):
    client, overlay = web_client
    # Set a secret in overlay
    client.post("/api/config", json={"updates": {"llm.api_key": "sk-secret-test-key"}})
    d = client.get("/api/config?reveal=1").get_json()
    assert "secrets" in d
    assert d["secrets"]["llm.api_key"] == "sk-secret-test-key"


def test_config_post_writes_overlay(web_client):
    client, overlay = web_client
    r = client.post("/api/config", json={"updates": {
        "llm.enabled": True, "llm.model": "qwen2.5:7b", "limits.workers": 3,
    }})
    assert r.status_code == 200, r.get_json()
    data = yaml.safe_load(overlay.read_text())
    assert data["llm"]["enabled"] is True
    assert data["llm"]["model"] == "qwen2.5:7b"
    assert data["limits"]["workers"] == 3


def test_config_post_validation(web_client):
    client, _ = web_client
    r = client.post("/api/config", json={"updates": {"llm.enabled": "maybe"}})
    assert r.status_code == 400
    r = client.post("/api/config", json={"updates": {"evil.path": 1}})
    assert r.status_code == 400
    r = client.post("/api/config", json={"updates": {
        "scan.apk_decompile_mode": "sideways"}})
    assert r.status_code == 400


def test_config_post_secret_writeonly(web_client):
    client, overlay = web_client
    r = client.post("/api/config", json={"updates": {"llm.api_key": "sk-new-key"}})
    assert r.status_code == 200
    assert "sk-new-key" in overlay.read_text()          # persisted
    assert "sk-new-key" not in str(r.get_json())         # but never echoed
