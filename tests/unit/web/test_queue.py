from flask import Flask

from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.web.queue import get_task_queue


def test_app_provides_a_celery_task_queue(app: Flask) -> None:
    with app.app_context():
        assert isinstance(get_task_queue(), CeleryTaskQueue)
