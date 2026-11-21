# syntax=docker/dockerfile:1
# Multi-stage image: `dev` (compose, hot reload, dev deps) and `prod` (no dev deps, non-root).
# Base image is pinned by digest; Dependabot proposes updates.

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"
# Same uv version as development; installed from PyPI so builds need no extra registry.
RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /app

# Third-party dependencies only: cached until uv.lock / pyproject.toml change.
FROM base AS deps
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

FROM deps AS dev
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project
COPY README.md LICENSE alembic.ini sandbox-images.lock ./
COPY src ./src
# The artifact-store volume takes this directory's owner and mode on first mount (ADR 0028).
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked \
 && install -d -m 700 /var/lib/attacksurf/artifact-store
EXPOSE 5000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"]
CMD ["flask", "--app", "attacksurf", "run", "--host", "0.0.0.0", "--port", "5000", "--debug"]

FROM deps AS prod
ARG APP_VERSION=""
LABEL org.opencontainers.image.title="AttackSurf" \
      org.opencontainers.image.description="Open-source, AI-powered attack surface management" \
      org.opencontainers.image.source="https://github.com/cpt9m0/attacksurf" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${APP_VERSION}"
COPY README.md LICENSE alembic.ini sandbox-images.lock ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && install -d -m 700 -o app -g app /var/lib/attacksurf/artifact-store
USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"]
# Request logs come from the app (JSON, with request_id); /dev/shm avoids disk-backed heartbeats on ro rootfs.
CMD ["gunicorn", "attacksurf.app:create_app()", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "--graceful-timeout", "30", "--keep-alive", "5", "--max-requests", "1000", "--max-requests-jitter", "100", "--worker-tmp-dir", "/dev/shm"]
