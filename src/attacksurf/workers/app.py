"""Celery entrypoint: `celery -A attacksurf.workers.app worker -Q passive`."""

from typing import Any

from celery.signals import setup_logging, worker_process_init

from attacksurf.infra.logging import configure_logging
from attacksurf.infra.queue import create_celery
from attacksurf.workers import runtime

TASK_MODULES = ("attacksurf.workers.tasks.system",)

app = create_celery(runtime.settings(), include=TASK_MODULES)


@setup_logging.connect
def _setup_logging(**_kwargs: Any) -> None:
    # Connecting this signal stops Celery from configuring logging itself.
    configure_logging(runtime.settings())


@worker_process_init.connect
def _fresh_db_pool(**_kwargs: Any) -> None:
    # A pool inherited from the parent would share sockets between processes.
    runtime.session_factory.cache_clear()
