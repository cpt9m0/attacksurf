#!/usr/bin/env bash
# Validates a PR title as a Conventional Commit subject (docs/conventions.md §2-3).
# PRs are squash-merged, so the title becomes the commit subject on main.
# Usage: check-pr-title.sh [--bot] "<title>"
#   --bot: Dependabot PRs. Its subjects start with "Bump"/"Update" and can be long, so only
#          the type/scope prefix is checked (set via .github/dependabot.yml commit-message).
set -euo pipefail

bot=false
if [[ "${1:-}" == "--bot" ]]; then
  bot=true
  shift
fi

title="${1:-}"
types='feat|fix|perf|refactor|test|docs|build|ci|chore|security|revert'
pattern="^(${types})(\([a-z0-9-]+\))?!?: [a-z0-9].*[^.]$"
max_len=72

if $bot; then
  if [[ "$title" =~ ^(${types})(\([a-z0-9-]+\))?!?:\ .+ ]]; then
    echo "PR title OK (bot, prefix only): $title"
    exit 0
  fi
  echo "::error::Bot PR title must start with a Conventional Commit type, e.g. build(deps): ..."
  echo "  got: $title"
  exit 1
fi

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
