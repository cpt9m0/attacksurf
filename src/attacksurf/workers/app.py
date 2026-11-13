"""Celery entrypoint: `celery -A attacksurf.workers.app worker -Q passive`."""

import logging
from typing import Any

from celery import Celery
from celery.signals import setup_logging, worker_process_init

from attacksurf.infra.logging import configure_logging
from attacksurf.infra.queue import celery_config
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
from attacksurf.workers import runtime

TASK_MODULES = (
    "attacksurf.workers.tasks.system",
    "attacksurf.workers.tasks.pipeline",
    "attacksurf.workers.tasks.verification",
)

app = Celery("attacksurf", include=list(TASK_MODULES))
# Read settings on first use, not at import: importing tasks (tests, tooling) must not depend on
# the environment, and tests swap `runtime.settings` for hermetic ones.
app.add_defaults(lambda: celery_config(runtime.settings()))


@setup_logging.connect
def _setup_logging(**_kwargs: Any) -> None:
    # Connecting this signal stops Celery from configuring logging itself.
    configure_logging(runtime.settings())
    # Celery's tracer logs every failure and retry with the raw exception message and
    # traceback, which can carry tokens or scan evidence. TrackedTask logs them sanitized.
    logging.getLogger("celery.app.trace").setLevel(logging.CRITICAL)


@worker_process_init.connect
def _fresh_db_pool(**_kwargs: Any) -> None:
    # A pool inherited from the parent would share sockets between processes.
    runtime.session_factory.cache_clear()
    # The Redis client (and its connection pool) must also be created after the fork.
    runtime.scan_cache.cache_clear()
