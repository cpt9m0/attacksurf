"""Resolve the database the pre-push hook runs the test suite against.

The hook used to run plain `pytest`, which skipped every DB-backed test without
`TEST_DATABASE_URL`, dropped coverage under the gate and failed every push. It now resolves a
test database first and stops with an actionable message when there isn't one.

Resolution order (first hit wins):
1. `TEST_DATABASE_URL` from the environment (an explicit choice always wins).
2. `TEST_DATABASE_URL` set in `.env`.
3. `.env`'s `DATABASE_URL` with the database name renamed to `<name>_test` (same host and
   credentials, so a developer who configured the app gets a working hook for free).
4. The documented local default, `...@localhost:5432/attacksurf_test`.

A resolved URL that does not end in `_test` is refused outright: the DB fixtures drop and
recreate the `public` schema, so anything else is data loss. The conftest guard stays as a
second line of defence, not the only one.
"""

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_TEST_DATABASE_URL = (
    "postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test"
)
TEST_DATABASE_SUFFIX = "_test"


class DatabaseNotResolved(Exception):
    """No usable test database URL could be determined."""


def test_database_url(environ: Mapping[str, str], dotenv: Mapping[str, str]) -> str:
    """Pick the test database URL from the shell, then `.env`, then the documented default."""
    explicit = environ.get("TEST_DATABASE_URL") or dotenv.get("TEST_DATABASE_URL")
    if explicit:
        return check_test_database(explicit)
    app_url = environ.get("DATABASE_URL") or dotenv.get("DATABASE_URL")
    if app_url:
        return check_test_database(rename_to_test(app_url))
    return check_test_database(DEFAULT_TEST_DATABASE_URL)


def rename_to_test(url: str) -> str:
    """`.../attacksurf` -> `.../attacksurf_test`, keeping host, port and credentials."""
    parts = urlsplit(url)
    database = parts.path.lstrip("/")
    if not database:
        raise DatabaseNotResolved(f"the database URL in .env has no database name: {url!r}")
    return urlunsplit(parts._replace(path=f"/{database}{TEST_DATABASE_SUFFIX}"))


def check_test_database(url: str) -> str:
    """Refuse anything that is not a `*_test` database: the fixtures wipe the schema."""
    database = urlsplit(url).path.lstrip("/")
    if not database.endswith(TEST_DATABASE_SUFFIX):
        raise DatabaseNotResolved(
            f"refusing to run against {database or '(unnamed)'!r}: "
            f"the test database name must end in {TEST_DATABASE_SUFFIX!r} (its schema is wiped)"
        )
    return url


def read_dotenv(path: Path = Path(".env")) -> dict[str, str]:
    """Minimal `.env` reader: `KEY=value`, optional quotes, `#` comments, no interpolation."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        key, _, raw = entry.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = raw.strip()
        if len(value) > 1 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def main(argv: list[str], environ: Mapping[str, str]) -> int:
    """Print the resolved URL on success; explain what to do on failure."""
    try:
        url = test_database_url(environ, read_dotenv())
    except DatabaseNotResolved as exc:
        print(f"pre-push: {exc}", file=sys.stderr)
        print(
            "Set TEST_DATABASE_URL in your shell or .env, and start the dev database with "
            "`sg docker -c 'make up'` (or set DATABASE_URL in .env to derive the _test database).",
            file=sys.stderr,
        )
        return 1
    if argv:
        print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], os.environ))
