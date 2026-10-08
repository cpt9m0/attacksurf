from unittest.mock import MagicMock

from flask import Flask

from attacksurf.web.db import get_session


def test_get_session_reuses_one_session_per_app_context(app: Flask) -> None:
    with app.app_context():
        assert get_session() is get_session()


def test_get_session_is_new_per_app_context(app: Flask) -> None:
    with app.app_context():
        first = get_session()
    with app.app_context():
        second = get_session()

    assert first is not second


def test_session_is_closed_at_teardown(app: Flask) -> None:
    session = MagicMock()
    app.extensions["db_session_factory"] = lambda: session

    with app.app_context():
        get_session()
        session.close.assert_not_called()

    session.close.assert_called_once_with()


def test_teardown_without_session_does_not_create_one(app: Flask) -> None:
    factory = MagicMock()
    app.extensions["db_session_factory"] = factory

    with app.app_context():
        pass

    factory.assert_not_called()


def test_engine_url_comes_from_settings(app: Flask) -> None:
    factory = app.extensions["db_session_factory"]

    assert factory.kw["bind"].url.render_as_string(hide_password=False) == (
        "postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf"
    )
