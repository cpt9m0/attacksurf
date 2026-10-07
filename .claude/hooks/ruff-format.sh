#!/usr/bin/env bash
# PostToolUse hook: format + autofix the Python file Claude just edited.
set -euo pipefail
command -v jq >/dev/null || exit 0
file=$(jq -r '.tool_input.file_path // empty')
[[ "$file" == *.py && -f "$file" ]] || exit 0
uv run --quiet ruff format "$file" >/dev/null 2>&1 || true
uv run --quiet ruff check --fix --quiet "$file" >/dev/null 2>&1 || true
