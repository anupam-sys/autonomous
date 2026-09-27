# FAS — Fully Autonomous Scanner & Research Pipeline

FAS is a high-throughput, continuous credential-exposure research engine designed to ingest public targets, decompile Android APKs and Git repositories, extract high-entropy tokens and API keys, and run autonomous agentic investigations with safe identity probing.

---

## Key Features

- **Continuous Ingestion:** Concurrent discovery across GitHub Firehose, GitHub Dorks, GitLab, Bitbucket, F-Droid, APKMirror, npm, PyPI, and Docker Hub.
- **Fast APK Byte-Scanning:** Instant DEX, asset, and resource scanning for Android packages without mandatory initial decompilation, triggering JADX on match.
- **Autonomous Agentic Triage & Probing:** Multi-turn ReAct agent examining codebase context, commit blame, and non-destructive read-only identity endpoints (AWS STS, GitHub User, Stripe Balance, OpenAI Models, Slack auth).
- **Encrypted at Rest:** Secrets are stored with Fernet encryption (`data/secret.key`) in a SQLite database with WAL mode and high-concurrency PRAGMAs.
- **Live Cyberpunk Web HUD:** Real-time system telemetry, active network port recon for open Ollama/Kobold endpoints, anomaly tables with one-click decryption, and agent investigation traces.
- **Discord Bot Copilot:** Thread-based alerts with interactive Q&A (`/ask`), on-demand scanning (`/scan_repo`, `/scan_apk`), and agent deep investigation (`/investigate`).

---

## Quickstart

### Prerequisites
- Python 3.11+
- Git
- Java Runtime Environment (for JADX)

### Installation
```bash
git clone https://github.com/your-org/fully-autonomous.git
cd fully-autonomous
pip install -r requirements.txt -r requirements-dev.txt

# Download JADX & Gitleaks
python scripts/install_tools.py
```

### Initializing and Running
```bash
# Initialize database and directories
python -m src.main init

# Run a single pipeline pass
python -m src.main run --once

# Run continuous daemon with embedded Web Dashboard
python -m src.main run

# Run Web Dashboard standalone (http://127.0.0.1:8080)
python -m src.main web

# Run Discord Bot
python -m src.main discord
```

---

## Architecture

```
Discovery (GitHub, GitLab, APKs, Registries)
       │ (ThreadPoolExecutor - 8 workers)
       ▼
Acquisition & Decompilation (Cloners, Fetchers, JADX)
       │ (ThreadPoolExecutor - 16 workers)
       ▼
Detection Engine (Rules Loader + Gitleaks + Entropy)
       │ (ThreadPoolExecutor - 8 workers)
       ▼
Autonomous Agent Triage (ReAct loop + Safe Probes)
       │ (ThreadPoolExecutor - 4 workers)
       ▼
Persistence (SQLite WAL) ──► Web Dashboard & Discord Alerts
```

---

## Configuration

Settings are controlled in `config.yaml` or overridden via environment variables (see `.env.example`).
Runtime overrides can also be saved directly via the Web Dashboard's **Config** tab into `config.local.yaml`.

---

## Testing

```bash
pytest -v
```
