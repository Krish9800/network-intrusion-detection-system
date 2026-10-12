# Multi-stage rootless Dockerfile for Network Intrusion Detection System (NIDS)

# Stage 1: Build virtualenv and install dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml /app/
RUN pip install --upgrade pip && \
    pip install .

COPY src/ /app/src/
RUN pip install .

# Stage 2: Minimal rootless production runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    NIDS_DATA_DIR="/data" \
    NIDS_DATABASE_URL="/data/nids.db"

# Create unprivileged system user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser && \
    mkdir -p /data && \
    chown -R appuser:appgroup /app /data

COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv
COPY --chown=appuser:appgroup src/ /app/src/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').read()" || exit 1

ENTRYPOINT ["nids"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
