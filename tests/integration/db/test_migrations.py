import os
import subprocess

from sqlalchemy import Engine, inspect

from tests.integration.conftest import run_alembic


def test_migrations_create_schema_matching_models(db_engine: Engine) -> None:
    # `alembic check` raises if autogenerate would emit anything: models and migrations agree.
    run_alembic(db_engine, "check")


def test_migrations_downgrade_to_base_and_upgrade_again(db_engine: Engine) -> None:
    run_alembic(db_engine, "downgrade", "base")
    assert "orgs" not in inspect(db_engine).get_table_names()

    run_alembic(db_engine, "upgrade", "head")
    assert "orgs" in inspect(db_engine).get_table_names()


def test_alembic_cli_connects_with_database_url_setting(db_engine: Engine) -> None:
    url = db_engine.url.render_as_string(hide_password=False)

    result = subprocess.run(
        ["alembic", "current"],  # noqa: S607
        env={**os.environ, "DATABASE_URL": url},
        capture_output=True,
        text=True,
        check=True,
    )

    assert "0001 (head)" in result.stdout
