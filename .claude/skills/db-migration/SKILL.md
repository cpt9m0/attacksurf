---
name: db-migration
description: Change the database schema safely (SQLAlchemy model + Alembic migration). Use whenever adding or modifying a model, column, index, or constraint.
---

# Database schema change

1. **Model:** edit/add the SQLAlchemy 2.0 model (typed `Mapped[...]`) in
   `src/attacksurf/infra/db/models.py`, inheriting from `attacksurf.infra.db.base`:
   tenant-owned tables use `TenantScoped, Timestamps, Base` (UUIDv7 `id` + `org_id`, indexed,
   NOT NULL, cascade on org delete); others `UUIDPrimaryKey, Timestamps, Base`. Add unique
   constraints and indexes the queries need (names come from the naming convention).
2. **Generate** (with `make up` running): `make revision id=<next 4-digit id> m="<short description>"`
   (= `uv run alembic revision --autogenerate --rev-id ...`; files land in
   `src/attacksurf/infra/db/migrations/versions/`).
3. **Review the generated file by hand.** Autogenerate misses or gets wrong:
   enum changes, server defaults, renames (shows as drop + add: rewrite as rename),
   data migrations, constraint names.
4. **Safety:**
   - Never drop or rename a column with data in the same release that stops using it.
   - Adding a NOT NULL column to an existing table needs a server default or a backfill step.
   - Large tables: create indexes concurrently in Postgres (`postgresql_concurrently=True`,
     outside a transaction).
   - `downgrade()` must work.
5. **Verify:** `uv run alembic upgrade head`, then `downgrade -1`, then `upgrade head` again
   against a clean dev DB. `uv run pytest` with `TEST_DATABASE_URL` set (or `make test`) also runs
   `alembic check` (models and migrations must match) and a full down/up round trip.
6. **Test:** model/service tests in `tests/integration/` with the `db_session` fixture, plus a
   tenant-isolation test for new tenant tables (query via `scoped()` / `get_scoped()`; see
   `tests/integration/db/test_tenancy.py`).
7. Never edit a migration that has been merged to `main`; write a new one.
