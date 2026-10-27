#!/usr/bin/env bash
# pre-push hook: run the full suite against a test database.
#
# Plain `pytest` here skipped every DB test (no TEST_DATABASE_URL), so coverage fell under the
# gate and every push failed. Resolution and the `*_test` guard live in test_database.py; this
# wrapper only checks reachability and then runs the suite.
set -euo pipefail

here="$(dirname "$0")"

if ! url=$(uv run --frozen python "$here/test_database.py" --print); then
  exit 1
fi

# Fail once, with the reason, instead of letting DB tests skip and coverage fail later.
if ! uv run --frozen python - "$url" <<'PY'
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

try:
    engine = create_engine(sys.argv[1], connect_args={"connect_timeout": 3})
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
except (SQLAlchemyError, OSError) as exc:
    detail = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
    print(f"pre-push: cannot reach the test database: {detail}", file=sys.stderr)
    print(
        "Start it with `sg docker -c 'make up'`, or create the database with "
        "`docker compose exec postgres createdb -U attacksurf attacksurf_test`.",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
then
  exit 1
fi

exec env TEST_DATABASE_URL="$url" uv run --frozen pytest -q
