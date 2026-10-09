"""Flask application factory."""

import structlog
from flask import Flask

from attacksurf.config import Settings, get_settings
from attacksurf.infra.logging import configure_logging, init_request_logging
from attacksurf.web.api.v1 import bp as api_v1_bp
from attacksurf.web.db import init_db
from attacksurf.web.errors import init_error_handlers
from attacksurf.web.health import bp as health_bp
from attacksurf.web.security import init_security_headers
from attacksurf.web.ui import bp as ui_bp


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or get_settings()
    configure_logging(settings)

    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config.update(
        SECRET_KEY=settings.secret_key.get_secret_value(),
        TESTING=settings.env == "test",
    )
    app.extensions["settings"] = settings

    init_request_logging(app)
    init_db(app, settings)
    init_security_headers(app, settings)
    init_error_handlers(app)
    app.register_blueprint(ui_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(api_v1_bp)

    if settings.secret_key_generated:
        structlog.get_logger(__name__).warning(
            "no SECRET_KEY set; using an ephemeral key (sessions reset on restart)",
            env=settings.env,
        )
    return app
