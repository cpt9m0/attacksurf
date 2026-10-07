#!/usr/bin/env bash
# Stop hook: if code/tests/config changed but STATE.md didn't, ask the agent (once) to run
# /finish-task. Changes are compared against the default branch plus the working tree.
set -euo pipefail
command -v jq >/dev/null || exit 0
input=$(cat)
# Already reminded during this stop cycle: let the agent stop.
[[ "$(jq -r '.stop_hook_active // false' <<<"$input")" == "true" ]] && exit 0

cd "${CLAUDE_PROJECT_DIR:-.}"
base=$(git merge-base HEAD origin/main 2>/dev/null || git rev-list --max-parents=0 HEAD | tail -1)
changed=$( { git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u )

code_changed=$(grep -E '^(src/|tests/|pyproject\.toml|\.claude/|compose|Dockerfile)' <<<"$changed" || true)
state_changed=$(grep -x 'STATE.md' <<<"$changed" || true)

if [[ -n "$code_changed" && -z "$state_changed" ]]; then
  jq -n '{decision: "block", reason: "Code changed on this branch but STATE.md was not updated. If the task is finished, run the finish-task skill (/finish-task) to sync tests, docs, agent files and STATE.md. If the task is not finished (e.g. you are waiting on the user), you may stop."}'
fi
exit 0
