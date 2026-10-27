"""Celery app factory and the `TaskQueue` adapter (ADR 0003).

A task's name prefix is its queue: `passive.ping` runs on the `passive` queue.
"""

from typing import Any
from uuid import UUID

from celery import Celery, chain, chord
from celery.canvas import Signature
from kombu import Exchange, Queue

from attacksurf.config import Settings
from attacksurf.domain.jobs import JobTask

QUEUES = ("passive", "ai")
RESERVED_QUEUES = ("active", "analysis")  # no workers yet: active checks, sandboxed analysis


def queue_for(task_name: str) -> str:
    queue, dot, task = task_name.partition(".")
    if not dot or not task or queue not in QUEUES + RESERVED_QUEUES:
        # Fail loudly: a task routed to a queue nobody consumes would wait forever.
        raise ValueError(f"task {task_name!r} must be named <queue>.<task>, queue in {QUEUES}")
    return queue


def _route(name: str, *_args: Any, **_kwargs: Any) -> dict[str, str]:
    return {"queue": queue_for(name)}


def create_celery(settings: Settings) -> Celery:
    app = Celery("attacksurf")
    app.conf.update(celery_config(settings))
    return app


def celery_config(settings: Settings) -> dict[str, Any]:
    redis_url = settings.redis_url.get_secret_value()
    return {
        "broker_url": redis_url,
        "result_backend": redis_url,
        "accept_content": ["json"],
        "task_serializer": "json",
        "result_serializer": "json",
        # Explicit exchange + routing key per queue: otherwise kombu binds every queue to the
        # default queue's exchange and key, and an `ai` worker would also consume `passive`.
        "task_queues": [
            Queue(name, Exchange(name, type="direct"), routing_key=name)
            for name in QUEUES + RESERVED_QUEUES
        ],
        "task_routes": (_route,),
        "task_create_missing_queues": False,
        "task_default_queue": "passive",  # Celery needs one; `_route` still picks every queue
        # Ack after the task ran, and requeue if the worker dies mid-task: tasks are idempotent,
        # and TrackedTask caps deliveries via `Job.attempts` so a poison task cannot loop.
        "task_acks_late": True,
        "task_reject_on_worker_lost": True,
        "worker_prefetch_multiplier": 1,
        # Reclaim any abandoned scanner threads; a timed-out Python thread cannot be killed.
        "worker_max_tasks_per_child": 100,
        # The `Job` row is the source of truth; tasks that feed a chord turn results back on.
        "task_ignore_result": True,
        "result_expires": 24 * 3600,
        "worker_hijack_root_logger": False,  # logging comes from infra.logging
        "broker_connection_retry_on_startup": True,
        "enable_utc": True,
        "timezone": "UTC",
    }


class CeleryTaskQueue:
    """`domain.jobs.TaskQueue` over Celery. Sends by name, so callers never import tasks."""

    def __init__(self, app: Celery) -> None:
        self._app = app

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        result = self._app.send_task(
            task_name,
            kwargs={"org_id": str(org_id), "job_id": str(job_id)},
            queue=queue_for(task_name),
        )
        return result.id

    def enqueue_workflow(
        self, header: tuple[JobTask, ...], tail: tuple[JobTask, ...], error: JobTask
    ) -> None:
        body = chain(*(self._signature(task) for task in tail))
        body.link_error(self._signature(error))
        if header:
            chord([self._signature(task) for task in header], body, app=self._app).apply_async()
        else:
            body.apply_async()

    def _signature(self, task: JobTask) -> Signature:
        return self._app.signature(
            task.task_name,
            kwargs={"org_id": str(task.org_id), "job_id": str(task.job_id)},
            immutable=True,
            queue=queue_for(task.task_name),
        )
