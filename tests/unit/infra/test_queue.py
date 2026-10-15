from typing import Any
from uuid import UUID

import pytest
from celery import Celery
from pydantic import SecretStr

from attacksurf.infra.queue import (
    QUEUES,
    RESERVED_QUEUES,
    CeleryTaskQueue,
    create_celery,
    queue_for,
)
from attacksurf.workers.app import app as worker_app
from tests.helpers import make_settings

ORG = UUID("00000000-0000-7000-8000-000000000001")
JOB = UUID("00000000-0000-7000-8000-000000000002")


@pytest.mark.parametrize(
    ("task_name", "queue"),
    [("passive.ping", "passive"), ("ai.triage", "ai"), ("active.axfr", "active")],
)
def test_task_name_prefix_is_the_queue(task_name: str, queue: str) -> None:
    assert queue_for(task_name) == queue


@pytest.mark.parametrize("task_name", ["ping", "celery.ping", "Passive.ping", ""])
def test_unroutable_task_names_are_rejected(task_name: str) -> None:
    with pytest.raises(ValueError, match=r"<queue>\.<task>"):
        queue_for(task_name)


def test_celery_is_configured_for_reliable_json_tasks() -> None:
    app = create_celery(make_settings(redis_url=SecretStr("redis://redis.test:6379/2")))
    conf = app.conf

    assert conf.broker_url == "redis://redis.test:6379/2"
    assert (conf.task_serializer, conf.accept_content) == ("json", ["json"])
    assert (conf.task_acks_late, conf.task_reject_on_worker_lost) == (True, True)
    assert conf.worker_prefetch_multiplier == 1
    assert conf.task_create_missing_queues is False
    assert conf.worker_hijack_root_logger is False
    assert {q.name for q in conf.task_queues} == set(QUEUES + RESERVED_QUEUES)
    assert app.amqp.default_queue.name in QUEUES


def test_each_queue_has_its_own_exchange_and_routing_key() -> None:
    # Regression: queues without an explicit exchange all bound to the default queue's
    # exchange and routing key, so the `ai` worker could consume `passive` tasks.
    queues = worker_app.amqp.queues

    for name in QUEUES + RESERVED_QUEUES:
        assert (queues[name].exchange.name, queues[name].routing_key) == (name, name)


def test_every_registered_task_routes_to_a_known_queue() -> None:
    worker_app.loader.import_default_modules()  # what a worker does at startup (`include`)
    names = [name for name in worker_app.tasks if not name.startswith("celery.")]

    assert "passive.ping" in names
    for name in names:
        assert worker_app.amqp.router.route({}, name)["queue"].name in QUEUES


class _RecordingCelery:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def send_task(self, name: str, **options: Any) -> Any:
        self.calls.append((name, options))
        return type("Result", (), {"id": "task-123"})()


def test_task_queue_sends_ids_as_strings_to_the_named_queue() -> None:
    celery = _RecordingCelery()
    queue = CeleryTaskQueue(celery)  # type: ignore[arg-type]

    task_id = queue.enqueue("passive.ping", org_id=ORG, job_id=JOB)

    assert task_id == "task-123"
    assert celery.calls == [
        ("passive.ping", {"kwargs": {"org_id": str(ORG), "job_id": str(JOB)}, "queue": "passive"})
    ]


def test_task_queue_refuses_unroutable_tasks() -> None:
    queue = CeleryTaskQueue(Celery("t"))

    with pytest.raises(ValueError, match=r"<queue>\.<task>"):
        queue.enqueue("ping", org_id=ORG, job_id=JOB)
