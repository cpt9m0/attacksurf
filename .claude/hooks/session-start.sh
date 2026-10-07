#!/usr/bin/env bash
# SessionStart hook: make sure deps are installed (cloud sessions start from a fresh clone).
set -euo pipefail
cd "${CLAUDE_PROJECT_DIR:-.}"
uv sync --quiet
