# 0008. Plain SQLAlchemy 2.0 + Alembic, UUIDv7 keys

- Status: accepted
- Date: 2026-10-08

## Context
Services and Celery workers need database sessions without a Flask app context, and inner layers
must not import Flask (import-linter, ADR 0001). Flask-SQLAlchemy / Flask-Migrate tie sessions and
migrations to the app object. Primary keys must not leak row counts or be guessable, and must index
well in Postgres.

## Decision
- Plain SQLAlchemy 2.0 (typed `Mapped[...]`) in `infra/db`; plain Alembic with migrations inside
  the package (`attacksurf.infra.db:migrations`) so they ship in the image. The URL comes from
  `Settings`, never from `alembic.ini`.
- The web layer gets one session per request (`web/db.py`); Celery tasks use
  `sessionmaker.begin()`. Services commit explicitly.
- Constraint naming convention on the metadata; sequential revision IDs (`0001`, `0002`, ...).
- Primary keys are UUIDv7 (time-ordered, random tail), generated in Python (`domain/ids.py`)
  until the stdlib's `uuid.uuid7` (3.14) is our minimum.
- Tenant-owned models use the `TenantScoped` mixin; services read them only via
  `infra/db/tenancy.scoped()` / `get_scoped()`.
- psycopg 3 driver; tests run against real Postgres (no SQLite substitute).

## Consequences
- A few lines of glue we own instead of two extensions.
- Migrations don't run on startup: `make migrate` (or `alembic upgrade head`) is an explicit step.
- Tests need a Postgres (`TEST_DATABASE_URL`); CI provides one, `make test` uses compose's.
