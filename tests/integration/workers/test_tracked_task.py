"""TrackedTask lifecycle against Postgres, with tasks run in-process (`Task.apply`)."""

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
import structlog
import structlog.testing
from billiard.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Job, Scan
from attacksurf.services import jobs
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import EXTRA_DELIVERIES, TrackedTask
from attacksurf.workers.tasks.system import ping
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan

calls: list[str] = []
seen_context: list[dict[str, Any]] = []


@app.task(base=TrackedTask, name="passive.test_flaky", max_retries=2, retry_backoff=False)
def flaky(*, org_id: str, job_id: str, failures: int) -> str:
    calls.append("run")
    seen_context.append(structlog.contextvars.get_contextvars())
    if len(calls) <= failures:
        raise TransientJobError("upstream timeout")
    return "done"


@app.task(base=TrackedTask, name="passive.test_broken")
def broken(*, org_id: str, job_id: str) -> None:
    raise RuntimeError("parser bug")


@app.task(base=TrackedTask, name="passive.test_slow")
def slow(*, org_id: str, job_id: str) -> None:
    raise SoftTimeLimitExceeded()


@pytest.fixture(autouse=True)
def worker_db(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Tasks open their own sessions; share the test's rolled-back connection with them."""
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    calls.clear()
    seen_context.clear()
    yield
    structlog.contextvars.clear_contextvars()


@pytest.fixture
def job(db_session: Session) -> Job:
    scan: Scan = make_scan(db_session)
    return jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="checks",
        task_name="passive.ping",
    )


def _ids(job: Job) -> dict[str, str]:
    return {"org_id": str(job.org_id), "job_id": str(job.id)}


def _reload(session: Session, job: Job) -> Job:
    session.expire_all()
    return session.get_one(Job, job.id)


def test_successful_task_completes_its_job(db_session: Session, job: Job) -> None:
    result = ping.apply(kwargs=_ids(job))

    assert result.successful()
    stored = _reload(db_session, job)
    assert (stored.status, stored.attempts, stored.error) == (JobStatus.COMPLETED, 1, None)
    assert stored.celery_task_id == result.id
    assert stored.finished_at is not None


def test_failing_task_fails_its_job(db_session: Session, job: Job) -> None:
    result = broken.apply(kwargs=_ids(job))

    assert result.failed()
    stored = _reload(db_session, job)
    assert (stored.status, stored.error) == (JobStatus.FAILED, "RuntimeError")


def test_soft_time_limit_fails_the_job(db_session: Session, job: Job) -> None:
    slow.apply(kwargs=_ids(job))

    assert _reload(db_session, job).status == JobStatus.FAILED


def test_transient_error_is_retried_until_it_succeeds(db_session: Session, job: Job) -> None:
    result = flaky.apply(kwargs={**_ids(job), "failures": 2})

    assert result.successful()
    assert calls == ["run", "run", "run"]
    stored = _reload(db_session, job)
    assert (stored.status, stored.attempts) == (JobStatus.COMPLETED, 3)


def test_transient_error_fails_the_job_after_max_retries(db_session: Session, job: Job) -> None:
    result = flaky.apply(kwargs={**_ids(job), "failures": 99})

    assert result.failed()
    assert len(calls) == 3  # first try + max_retries
    stored = _reload(db_session, job)
    assert (stored.status, stored.error) == (
        JobStatus.FAILED,
        "TransientJobError: upstream timeout",
    )


def test_redelivered_task_of_finished_job_does_not_run(db_session: Session, job: Job) -> None:
    flaky.apply(kwargs={**_ids(job), "failures": 0})

    flaky.apply(kwargs={**_ids(job), "failures": 0})

    assert calls == ["run"]
    assert _reload(db_session, job).attempts == 1


def test_logs_carry_job_context_only_while_the_task_runs(job: Job) -> None:
    flaky.apply(kwargs={**_ids(job), "failures": 0})

    context = seen_context[0]
    assert (context["org_id"], context["job_id"], context["scan_id"]) == (
        str(job.org_id),
        str(job.id),
        str(job.scan_id),
    )
    assert context["task"] == "passive.test_flaky"
    assert structlog.contextvars.get_contextvars() == {}


def test_task_for_unknown_job_fails_without_running(job: Job) -> None:
    result = flaky.apply(kwargs={"org_id": str(job.org_id), "job_id": str(uuid4()), "failures": 0})

    assert result.failed()
    assert calls == []


@pytest.mark.parametrize("kwargs", [{}, {"org_id": "nope", "job_id": "nope"}])
def test_task_without_valid_job_ids_fails_without_running(kwargs: dict[str, str]) -> None:
    result = flaky.apply(kwargs={**kwargs, "failures": 0})

    assert result.failed()
    assert isinstance(result.result, (ValueError, TypeError))
    assert calls == []


SECRET = "s3cret-token"


@app.task(base=TrackedTask, name="passive.test_leaky")
def leaky(*, org_id: str, job_id: str) -> None:
    url = f"https://user:{SECRET}@api.example/"  # built at runtime, like a real client error
    raise RuntimeError(f"GET {url} failed")


def test_database_blip_when_starting_is_retried(
    db_session: Session, job: Job, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = jobs.mark_job_running
    failures = iter([True])

    def flaky_start(*args: Any, **kwargs: Any) -> Job | None:
        if next(failures, False):
            raise OperationalError("SELECT", {}, Exception("server closed the connection"))
        return real(*args, **kwargs)

    monkeypatch.setattr(jobs, "mark_job_running", flaky_start)

    result = flaky.apply(kwargs={**_ids(job), "failures": 0})

    assert result.successful()
    assert calls == ["run"]
    assert _reload(db_session, job).status == JobStatus.COMPLETED


def test_task_that_keeps_crashing_its_worker_is_given_up(db_session: Session, job: Job) -> None:
    job.attempts = (flaky.max_retries or 0) + EXTRA_DELIVERIES  # e.g. redelivered after OOM kills
    db_session.commit()

    result = flaky.apply(kwargs={**_ids(job), "failures": 0})

    assert result.successful()  # acked: no further redelivery
    assert calls == []
    assert _reload(db_session, job).status == JobStatus.FAILED


def test_failure_logs_and_stores_no_exception_message(db_session: Session, job: Job) -> None:
    with structlog.testing.capture_logs() as logs:
        leaky.apply(kwargs=_ids(job))

    assert SECRET not in repr(logs)
    failed = next(entry for entry in logs if entry["event"] == "job failed")
    assert failed["error"] == "RuntimeError"
    assert "leaky" in failed["stack"]  # frames are kept for debugging
    assert _reload(db_session, job).error == "RuntimeError"
