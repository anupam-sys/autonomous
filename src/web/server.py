"""Live transparency dashboard (Flask).

Reads ONLY from the SQLite DB, so it works both:
  * embedded in the daemon (same process, `web.enabled: true`), and
  * standalone (`python -m src.main web`) while the daemon runs separately.

Config editing (GET/POST /api/config) writes config.local.yaml; secret values
are write-only (never returned to the browser). Without a web.token, config
writes are restricted to localhost clients.

Optional bearer token for when it's exposed beyond localhost.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from ..config import Config, save_overlay
from ..db import Database
from ..log import get_logger

logger = get_logger("web")

# paths whose values are write-only over the API
SECRET_PATHS = {"llm.api_key", "discovery.github_recent.token", "web.token", "notifications.discord.webhook_url"}

# editable config whitelist: dotted path -> type
# (bool | int | float | str | secret | list | choice:a,b,c)
EDITABLE: dict[str, str] = {
    "llm.enabled": "bool", "llm.base_url": "str", "llm.api_key": "secret",
    "llm.model": "str", "llm.timeout_seconds": "int",
    "llm.triage_confidence_floor": "float", "llm.max_findings_per_run": "int",
    "llm.batch_size": "int",
    "llm.ai_discovery.enabled": "bool", "llm.ai_discovery.allow_auto_dorks": "bool",
    "llm.ai_discovery.interval_hours": "int",
    "limits.workers": "int", "limits.jadx_concurrency": "int",
    "limits.max_apk_mb": "int", "limits.max_repo_mb": "int",
    "limits.daily_bandwidth_mb": "int",
    "limits.work_retention": "choice:keep,on_finding,delete",
    "discovery.interval_minutes": "int", "discovery.firehose_enabled": "bool",
    "discovery.gitlab_enabled": "bool", "discovery.bitbucket_enabled": "bool",
    "discovery.github_recent.enabled": "bool",
    "discovery.github_recent.token": "secret",
    "discovery.github_recent.per_page": "int",
    "discovery.registries.npm": "bool", "discovery.registries.pypi": "bool",
    "discovery.registries.docker_hub": "bool",
    "discovery.apk.fdroid": "bool", "discovery.apk.apkmirror_recent": "bool",
    "discovery.apk.apkpure_recent": "bool",
    "discovery.apk.target_packages": "list",
    "discovery.intelligence.enabled": "bool",
    "discovery.intelligence.min_relevance_score": "float",
    "discovery.intelligence.filter_spam": "bool",
    "discovery.intelligence.filter_forks": "bool",
    "discovery.intelligence.filter_noise_types": "bool",
    "discovery.intelligence.filter_system_apks": "bool",
    "discovery.intelligence.smart_git_filter": "bool",
    "discovery.intelligence.selective_extract": "bool",
    "scan.interval_minutes": "int", "scan.entropy_threshold": "float",
    "scan.min_secret_length": "int", "scan.context_lines": "int",
    "scan.max_file_kb": "int", "scan.gitleaks_enabled": "bool",
    "scan.apk_decompile_mode": "choice:always,on_hit,never",
    "report.interval_hours": "int", "report.reveal_secrets": "bool",
    "report.disclosure_lookup": "bool",
    "web.host": "str", "web.port": "int", "web.token": "secret",
    "notifications.discord.enabled": "bool",
    "notifications.discord.webhook_url": "secret",
    "notifications.discord.notify_on": "choice:any,high_severity,true_positive",
}


def _dig(data: dict, dotted: str, default=None):
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _coerce(kind: str, value):
    """Validate + coerce one config value; raises ValueError."""
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("must be boolean")
        return value
    if kind == "int":
        iv = int(value)
        if iv < 0 or iv > 1_000_000:
            raise ValueError("out of range")
        return iv
    if kind == "float":
        return float(value)
    if kind in ("str", "secret"):
        return str(value)
    if kind == "list":
        if isinstance(value, str):
            value = [ln.strip() for ln in value.splitlines() if ln.strip()]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError("must be a list of strings")
        return value
    if kind.startswith("choice:"):
        options = kind.split(":", 1)[1].split(",")
        if value not in options:
            raise ValueError(f"must be one of {options}")
        return value
    raise ValueError(f"unknown type {kind}")


def _sanitized_config(cfg: Config) -> dict:
    """Effective config as a dict, with secret values blanked out."""
    data = dataclasses.asdict(cfg)
    for path in SECRET_PATHS:
        parts = path.split(".")
        node = data
        for part in parts[:-1]:
            node = node.get(part)
            if not isinstance(node, dict):
                node = None
                break
        if node is not None and parts[-1] in node:
            node[parts[-1]] = ""  # never send secrets to the browser
    return data


def create_app(cfg: Config, db: Database | None = None) -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["TEMPLATES_AUTO_RELOAD"] = True  # template edits need no restart
    db = db or Database(cfg.paths.db_path)

    def _authorized() -> bool:
        if not cfg.web.token:
            return True
        tok = request.args.get("token", "")
        if not tok:
            tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return tok == cfg.web.token

    @app.before_request
    def _auth():
        if not _authorized():
            return jsonify({"error": "unauthorized"}), 401

    @app.get("/")
    def index():
        return render_template("dashboard.html.j2", token=cfg.web.token)

    @app.get("/api/state")
    def state():
        latest = db.activity_latest(1)
        return jsonify({
            "now_id": latest[0]["id"] if latest else 0,
            "now_ts": latest[0]["ts"] if latest else None,
            "now_stage": latest[0]["stage"] if latest else None,
            "now_message": latest[0]["message"] if latest else "idle — no activity yet",
            "now_target": latest[0]["target"] if latest else None,
            "counts": db.counts(),
            "severity": db.severity_counts(),
            "detectors": db.detector_counts(),
        })

    @app.get("/api/events")
    def events():
        since = request.args.get("since", 0, type=int)
        return jsonify([dict(r) for r in db.activity_since(since, 300)])

    @app.get("/api/findings")
    def findings():
        return jsonify([dict(r) for r in db.findings_for_report()[:300]])

    @app.get("/api/runs")
    def runs():
        return jsonify([dict(r) for r in db.recent_runs(60)])

    @app.get("/api/suggestions")
    def suggestions():
        return jsonify([dict(r) for r in db.suggestions()])

    @app.post("/api/suggestions/<int:sid>/<action>")
    def suggestion_action(sid: int, action: str):
        if action not in ("approve", "reject"):
            return jsonify({"error": "bad action"}), 400
        db.set_suggestion_status(sid, "approved" if action == "approve" else "rejected")
        return jsonify({"ok": True})

    @app.post("/api/finding/<int:fid>/reveal")
    def reveal_finding(fid: int):
        """Decrypt and return the full secret value (gated by reveal_secrets)."""
        if not cfg.report.reveal_secrets:
            return jsonify({"error": "reveal_secrets is disabled in config"}), 403
        secret = db.get_finding_secret(fid)
        if secret is None:
            return jsonify({"error": "no stored value (predates encrypted storage)"}), 404
        return jsonify({"secret": secret})

    # ---------------- configuration ----------------

    def _write_allowed() -> bool:
        """Config writes: token if configured, else localhost only."""
        if cfg.web.token:
            return True  # _authorized() already enforced it
        return request.remote_addr in ("127.0.0.1", "::1")

    @app.get("/api/config")
    def get_config():
        overlay = getattr(cfg, "_overlay_path", "config.local.yaml")
        base = getattr(cfg, "_base_path", "config.yaml")
        try:
            fresh = Config.load(base, overlay)
            for f in dataclasses.fields(Config):
                setattr(cfg, f.name, getattr(fresh, f.name))
        except Exception:
            pass

        cfg_dict = dataclasses.asdict(cfg)
        secrets_set = {
            p: bool(_dig(cfg_dict, p)) for p in SECRET_PATHS
        }
        res = {
            "config": _sanitized_config(cfg),
            "secrets_set": secrets_set,
            "editable": EDITABLE,
        }
        if request.args.get("reveal") == "1" and _write_allowed():
            res["secrets"] = {
                p: (_dig(cfg_dict, p) or "") for p in SECRET_PATHS
            }
        return jsonify(res)

    @app.post("/api/config")
    def post_config():
        if not _write_allowed():
            return jsonify({"error": "config writes are localhost-only "
                                     "(set web.token for remote access)"}), 403
        updates = (request.get_json(silent=True) or {}).get("updates")
        if not isinstance(updates, dict) or not updates:
            return jsonify({"error": "body must be {updates: {path: value}}"}), 400
        clean: dict = {}
        errors: dict = {}
        for path, value in updates.items():
            kind = EDITABLE.get(path)
            if not kind:
                errors[path] = "not editable"
                continue
            try:
                clean[path] = _coerce(kind, value)
            except (ValueError, TypeError):
                errors[path] = f"invalid value for type {kind}"
        if errors:
            return jsonify({"error": "validation failed", "fields": errors}), 400
        overlay = getattr(cfg, "_overlay_path", "config.local.yaml")
        try:
            save_overlay(clean, overlay)
        except OSError as exc:
            return jsonify({"error": f"write failed: {exc}"}), 500
        logger.info("config updated via dashboard: %s", sorted(clean))
        fresh = Config.load(getattr(cfg, "_base_path", "config.yaml"), overlay)
        for f in dataclasses.fields(Config):
            setattr(cfg, f.name, getattr(fresh, f.name))
        return jsonify({"ok": True, "applied": sorted(clean),
                        "config": _sanitized_config(fresh)})

    return app


def run_web(cfg: Config, db: Database | None = None) -> None:
    app = create_app(cfg, db)
    logger.info("dashboard on http://%s:%d%s", cfg.web.host, cfg.web.port,
                "" if cfg.web.token else " (no auth — localhost only!)")
    app.run(host=cfg.web.host, port=cfg.web.port, threaded=True,
            debug=False, use_reloader=False)
