"""One SQLAlchemy session per request, closed (and rolled back if uncommitted) at teardown."""

from flask import Flask, current_app, g
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings
from attacksurf.infra.db.session import create_db_engine, create_session_factory

_FACTORY_KEY = "db_session_factory"


def init_db(app: Flask, settings: Settings) -> None:
    # The engine connects lazily: the app starts (and /healthz answers) without a database.
    app.extensions[_FACTORY_KEY] = create_session_factory(create_db_engine(settings))

    @app.teardown_appcontext
    def _close_session(_exc: BaseException | None) -> None:
        session: Session | None = g.pop("db_session", None)
        if session is not None:
            session.close()


def get_session() -> Session:
    if "db_session" not in g:
        factory: sessionmaker[Session] = current_app.extensions[_FACTORY_KEY]
        g.db_session = factory()
    return g.db_session
