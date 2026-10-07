#!/usr/bin/env bash
# commit-msg hook: the subject line must pass the same rules as PR titles
# (check-pr-title.sh). Git-generated merge/revert/fixup subjects are allowed.
# Usage: check-commit-msg.sh <commit-msg-file>
set -euo pipefail

subject=$(grep -v '^#' "$1" | sed '/^[[:space:]]*$/d' | head -n 1)

case "$subject" in
  "Merge "* | "Revert \""* | "fixup! "* | "squash! "* | "amend! "*) exit 0 ;;
esac

exec "$(dirname "$0")/check-pr-title.sh" "$subject"
