"""The app's `TaskQueue`: routes enqueue background work through it, never run it inline."""

from flask import Flask, current_app

from attacksurf.config import Settings
from attacksurf.domain.jobs import TaskQueue
from attacksurf.infra.queue import CeleryTaskQueue, create_celery

_QUEUE_KEY = "task_queue"


def init_queue(app: Flask, settings: Settings) -> None:
    # Connects to the broker only when the first task is sent.
    app.extensions[_QUEUE_KEY] = CeleryTaskQueue(create_celery(settings))


def get_task_queue() -> TaskQueue:
    return current_app.extensions[_QUEUE_KEY]
