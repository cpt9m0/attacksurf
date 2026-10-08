# syntax=docker/dockerfile:1
# Multi-stage image: `dev` (compose, hot reload, dev deps) and `prod` (no dev deps, non-root).
# Base image is pinned by digest; Dependabot proposes updates.

FROM python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c AS base
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
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked
EXPOSE 5000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"]
CMD ["flask", "--app", "attacksurf", "run", "--host", "0.0.0.0", "--port", "5000", "--debug"]

FROM deps AS prod
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"]
# Request logs come from the app (JSON, with request_id); gunicorn tuning/hardening: #29.
CMD ["gunicorn", "attacksurf.app:create_app()", "--bind", "0.0.0.0:5000"]
