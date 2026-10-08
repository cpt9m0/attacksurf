#!/usr/bin/env bash
# commit-msg hook: the subject line must pass the same rules as PR titles
# (check-pr-title.sh). Git-generated merge/revert/fixup subjects are allowed.
# Usage: check-commit-msg.sh <commit-msg-file>
set -euo pipefail

# Single reader that stops at the first match: no pipe, so no SIGPIPE on long bodies.
subject=$(awk '!/^#/ && NF { print; exit }' "$1")

case "$subject" in
  "Merge "* | "Revert \""* | "fixup! "* | "squash! "* | "amend! "*) exit 0 ;;
esac

exec "$(dirname "$0")/check-pr-title.sh" "$subject"
