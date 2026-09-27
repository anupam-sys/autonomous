FROM python:3.12-slim

# git for cloning, JRE for jadx
RUN apt-get update \
 && apt-get install -y --no-install-recommends git default-jre-headless ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# jadx + gitleaks into /app/tools
COPY scripts/ scripts/
RUN python scripts/install_tools.py

COPY config.yaml .
COPY src/ src/

# Ensure runtime directories exist with appropriate ownership
RUN mkdir -p /app/data /app/reports /app/logs /app/tools && \
    chown -R appuser:appuser /app

ENV PYTHONUNBUFFERED=1
VOLUME ["/app/data", "/app/reports", "/app/logs"]

USER appuser

# continuous daemon; use `docker compose run --rm pipeline run --once` for a single pass
CMD ["python", "-m", "src.main", "run"]
