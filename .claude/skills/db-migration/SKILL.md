---
name: db-migration
description: Change the database schema safely (SQLAlchemy model + Alembic migration). Use whenever adding or modifying a model, column, index, or constraint.
---

# Database schema change

1. **Model:** edit/add the SQLAlchemy 2.0 model (typed `Mapped[...]`). Tenant-owned tables use the
   `TenantScoped` mixin (`org_id`, indexed, NOT NULL). Add unique constraints and indexes the
   queries need.
2. **Generate:** `uv run alembic revision --autogenerate -m "<short description>"`
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
   against a clean dev DB.
6. **Test:** model/service tests, plus a tenant-isolation test for new tenant tables.
7. Never edit a migration that has been merged to `main`; write a new one.
