# syntax=docker/dockerfile:1
# Native arm64 builds for Raspberry Pi OS 64-bit; amd64 builds for PCs/servers.
FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=10070 \
    OUTHMAN_DB=/data/outhman.sqlite3
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 outhman \
    && useradd --uid 10001 --gid outhman --no-create-home --shell /usr/sbin/nologin outhman \
    && mkdir /data && chown outhman:outhman /data && chmod 700 /data
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt

FROM runtime AS test
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY server.py backups.py backup_service.py log_export.py backMan.py backMan_runner.py ./
COPY public/ ./public/
COPY test_*.py ./
USER 10001:10001
RUN python -m unittest -v

FROM runtime AS app
COPY server.py backups.py backup_service.py log_export.py ./
COPY public/ ./public/
USER 10001:10001
EXPOSE 10070
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',10070),timeout=5); s.sendall(b'GET /api/me HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n'); assert s.makefile('rb').readline(256).split()[1]==b'200'; s.close()"]
CMD ["python", "server.py"]
