# syntax=docker/dockerfile:1
# ARM64 and ARMv7 Raspberry Pi builds; amd64 builds for PCs/servers.
# CFFI has no wheel on some ARMv7/Python combinations. Build it in an isolated
# stage while requiring a prebuilt cryptography wheel (no Rust toolchain).
FROM python:3.12-slim-bookworm AS dependencies
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN python -m pip wheel --no-cache-dir --only-binary=cryptography --wheel-dir=/wheels -r requirements.txt

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=10070 \
    OUTHMAN_DB=/data/outhman.sqlite3
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata libffi8 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 outhman \
    && useradd --uid 10001 --gid outhman --no-create-home --shell /usr/sbin/nologin outhman \
    && mkdir /data && chown outhman:outhman /data && chmod 700 /data
COPY requirements.txt ./
RUN --mount=type=bind,from=dependencies,source=/wheels,target=/wheels,ro \
    python -m pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

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
