"""Fixtures for tests that need PostgreSQL (`TEST_DATABASE_URL`, see docs/development.md)."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.orm import Session

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def run_alembic(engine: Engine, cmd: str, *args: str) -> None:
    """Run an Alembic command through `engine` (env.py uses `attributes["connection"]`)."""
    config = Config(ALEMBIC_INI)
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        getattr(command, cmd)(config, *args)


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("TEST_DATABASE_URL must be set in CI")
        pytest.skip("TEST_DATABASE_URL not set (see docs/development.md)")
    database = make_url(url).database or ""
    # The schema is wiped below: refuse anything that doesn't look like a throwaway database.
    if not database.endswith("_test"):
        pytest.fail(f"TEST_DATABASE_URL must point at a *_test database, got {database!r}")

    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    run_alembic(engine, "upgrade", "head")
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Session inside a transaction that is rolled back after the test, even if it commits."""
    with db_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()
