#!/usr/bin/env bash
# Validates a PR title as a Conventional Commit subject (docs/conventions.md §2-3).
# PRs are squash-merged, so the title becomes the commit subject on main.
# Usage: check-pr-title.sh "<title>"
set -euo pipefail

title="${1:-}"
types='feat|fix|perf|refactor|test|docs|build|ci|chore|security|revert'
pattern="^(${types})(\([a-z0-9-]+\))?!?: [a-z0-9].*[^.]$"
max_len=72

if [[ ! "$title" =~ $pattern ]]; then
  echo "::error::PR title must be a Conventional Commit: <type>(<scope>): <subject>"
  echo "  got:      $title"
  echo "  types:    ${types//|/ }"
  echo "  example:  feat(dns): add DMARC policy check"
  echo "  rules:    lowercase subject start, no trailing period (see docs/conventions.md)"
  exit 1
fi

if (( ${#title} > max_len )); then
  echo "::error::PR title is ${#title} chars; max is ${max_len}."
  exit 1
fi

echo "PR title OK: $title"
