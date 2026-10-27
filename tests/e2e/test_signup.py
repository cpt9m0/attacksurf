"""Verify the schema prepared by `make up`, without migrating it in the test.

Shares the opt-in Compose smoke suite (`make test-worker`). All account writes roll back;
no existing users, credentials or schema are changed.
"""

import os
import re

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from attacksurf.app import create_app
from attacksurf.config import Settings
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.session import create_db_engine
from tests.helpers import make_settings

pytestmark = [
    pytest.mark.worker,
    pytest.mark.skipif(
        os.environ.get("RUN_WORKER_TESTS") != "1", reason="needs RUN_WORKER_TESTS=1 + Compose"
    ),
]


def test_signup_succeeds_against_the_started_stack_schema() -> None:
    settings = make_settings(
        env="test",
        secret_key=SecretStr("test-secret-key"),
        database_url=Settings().database_url,
    )
    engine = create_db_engine(settings)
    email = f"signup-smoke-{uuid7().hex}@example.com"
    try:
        with engine.connect() as connection, connection.begin() as transaction:
            app = create_app(settings)
            app.extensions["db_session_factory"] = lambda: Session(
                bind=connection, join_transaction_mode="create_savepoint"
            )
            client = app.test_client()
            form = client.get("/signup")
            assert form.status_code == 200
            token = re.search(r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True))
            assert token is not None

            response = client.post(
                "/signup",
                data={
                    "email": email,
                    "password": "correct horse battery",
                    "csrf_token": token.group(1),
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            assert response.request.path == "/"
            assert email in response.get_data(as_text=True)
            transaction.rollback()
    finally:
        engine.dispose()
