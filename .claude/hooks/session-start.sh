#!/usr/bin/env bash
# SessionStart hook: install deps + git hooks (cloud sessions start from a fresh clone) and load the
# STATE.md handoff into the agent's context (stdout of this hook is added to context).
set -euo pipefail
cd "${CLAUDE_PROJECT_DIR:-.}"
uv sync --quiet >/dev/null 2>&1 || echo "warning: uv sync failed; run it manually."
# Git hooks (pre-commit, commit-msg, pre-push) so agent commits are checked too. Idempotent.
uv run --quiet pre-commit install >/dev/null 2>&1 || echo "warning: pre-commit install failed."
if [[ -f STATE.md ]]; then
  echo "=== STATE.md (handoff from the previous session) ==="
  cat STATE.md
fi
