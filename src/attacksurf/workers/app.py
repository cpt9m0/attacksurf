"""Celery entrypoint: `celery -A attacksurf.workers.app worker -Q passive`."""

import logging
from typing import Any

from celery import Celery
from celery.signals import setup_logging, worker_process_init

from attacksurf.infra.logging import configure_logging
from attacksurf.infra.queue import celery_config
from attacksurf.workers import runtime

TASK_MODULES = ("attacksurf.workers.tasks.system",)

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
