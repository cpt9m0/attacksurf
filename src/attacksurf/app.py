"""Flask application factory."""

import structlog
from flask import Flask

from attacksurf.ai.config import resolve_llm_config
from attacksurf.config import Settings, get_settings
from attacksurf.infra.logging import configure_logging, init_request_logging
from attacksurf.scanners.dns import axfr as _dns_axfr  # noqa: F401
from attacksurf.scanners.dns import caa as _dns_caa  # noqa: F401

# Importing the module registers its plugin; production plugins are listed here explicitly.
from attacksurf.scanners.dns import discovery as _ct_discovery  # noqa: F401
from attacksurf.scanners.dns import dnssec as _dns_dnssec  # noqa: F401
from attacksurf.scanners.dns import email as _dns_email  # noqa: F401
from attacksurf.scanners.dns import mx as _dns_mx  # noqa: F401
from attacksurf.scanners.dns import ns as _dns_ns  # noqa: F401
from attacksurf.scanners.dns import resolve as _dns_resolve  # noqa: F401
from attacksurf.scanners.dns import takeover as _dns_takeover  # noqa: F401
from attacksurf.scanners.dns import takeover_http as _dns_takeover_http  # noqa: F401
from attacksurf.scanners.dns import whois as _dns_whois  # noqa: F401
from attacksurf.web.api.v1 import bp as api_v1_bp
from attacksurf.web.auth import init_auth
from attacksurf.web.db import init_db
from attacksurf.web.errors import init_error_handlers
from attacksurf.web.health import bp as health_bp
from attacksurf.web.queue import init_queue
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
    init_queue(app, settings)
    init_security_headers(app, settings)
    init_error_handlers(app)
    init_auth(app, settings)
    app.register_blueprint(ui_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(api_v1_bp)

    log = structlog.get_logger(__name__)
    if settings.secret_key_generated:
        log.warning(
            "no SECRET_KEY set; using an ephemeral key (sessions reset on restart)",
            env=settings.env,
        )
    if resolve_llm_config(None, settings) is None:
        # Not an error: AI is optional. Said once at startup so a missing setting isn't silent.
        log.warning(
            "AI is off for orgs without their own key: set LLM_API_KEY and LLM_MODEL to enable it"
        )
    return app
