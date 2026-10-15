import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from attacksurf.domain.jobs import JobError, JobNotFound, TransientJobError
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Job, Scan
from attacksurf.services import jobs
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan

TASK = "passive.ping"
MAX = 5


@pytest.fixture
def scan(db_session: Session) -> Scan:
    return make_scan(db_session)


@pytest.fixture
def job(db_session: Session, scan: Scan) -> Job:
    return jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="checks",
        task_name=TASK,
    )


def test_create_job_commits_before_enqueueing(db_session: Session, scan: Scan) -> None:
    queue = FakeQueue(db_session)

    job = jobs.create_job(
        db_session,
        queue,
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="checks",
        task_name=TASK,
        scanner="dns.email",
    )

    assert queue.sent == [(TASK, scan.org_id, job.id, True)]
    assert (job.status, job.attempts, job.scanner) == (JobStatus.QUEUED, 0, "dns.email")


def test_create_job_marks_job_failed_when_broker_is_down(db_session: Session, scan: Scan) -> None:
    with pytest.raises(ConnectionError):
        jobs.create_job(
            db_session,
            FakeQueue(db_session, fail=True),
            org_id=scan.org_id,
            scan_id=scan.id,
            stage="checks",
            task_name=TASK,
        )

    job = db_session.query(Job).one()
    assert job.status == JobStatus.FAILED
    assert job.error == "ConnectionError"  # not a JobError: type only
    assert job.finished_at is not None


def test_mark_running_starts_an_attempt(db_session: Session, job: Job) -> None:
    running = jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)

    assert running is not None
    db_session.refresh(job)
    assert (job.status, job.attempts, job.celery_task_id) == (JobStatus.RUNNING, 1, "task-1")
    assert job.started_at is not None


def test_redelivered_running_job_counts_another_attempt_and_keeps_start(
    db_session: Session, job: Job
) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)
    db_session.refresh(job)
    first_start = job.started_at

    jobs.mark_job_running(db_session, job.org_id, job.id, "task-2", max_attempts=MAX)

    db_session.refresh(job)
    assert (job.attempts, job.celery_task_id, job.started_at) == (2, "task-2", first_start)


@pytest.mark.parametrize("status", sorted(jobs.FINISHED))
def test_finished_job_is_not_restarted(db_session: Session, job: Job, status: JobStatus) -> None:
    job.status = status
    db_session.commit()

    assert jobs.mark_job_running(db_session, job.org_id, job.id, "task-2", max_attempts=MAX) is None
    db_session.refresh(job)
    assert (job.status, job.attempts) == (status, 0)


def test_mark_completed_finishes_the_job(db_session: Session, job: Job) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)

    jobs.mark_job_completed(db_session, job.org_id, job.id)

    db_session.refresh(job)
    assert (job.status, job.error) == (JobStatus.COMPLETED, None)
    assert job.finished_at is not None
    assert job.started_at is not None
    assert job.finished_at >= job.started_at


def test_mark_failed_records_the_error(db_session: Session, job: Job) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)

    jobs.mark_job_failed(db_session, job.org_id, job.id, RuntimeError("resolver crashed"))

    db_session.refresh(job)
    assert (job.status, job.error) == (JobStatus.FAILED, "RuntimeError")


def test_mark_retrying_requeues_with_the_error(db_session: Session, job: Job) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)

    jobs.mark_job_retrying(db_session, job.org_id, job.id, TimeoutError())

    db_session.refresh(job)
    assert (job.status, job.error, job.finished_at) == (JobStatus.QUEUED, "TimeoutError", None)


def test_cancellation_wins_over_a_late_result(db_session: Session, job: Job) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)
    job.status = JobStatus.CANCELLED
    db_session.commit()

    jobs.mark_job_completed(db_session, job.org_id, job.id)
    jobs.mark_job_failed(db_session, job.org_id, job.id, RuntimeError("late"))
    jobs.mark_job_retrying(db_session, job.org_id, job.id, RuntimeError("late"))

    db_session.refresh(job)
    assert (job.status, job.error) == (JobStatus.CANCELLED, None)


def test_jobs_are_looked_up_within_the_org(db_session: Session, job: Job) -> None:
    other = make_scan(db_session, "globex")

    with pytest.raises(JobNotFound):
        jobs.mark_job_running(db_session, other.org_id, job.id, "task-1", max_attempts=MAX)
    with pytest.raises(JobNotFound):
        jobs.mark_job_failed(db_session, other.org_id, job.id, RuntimeError())


def test_describe_error_is_capped() -> None:
    error = jobs.describe_error(JobError("x" * 5000))

    assert error.startswith("JobError: xxx")
    assert len(error) == jobs.MAX_ERROR_LENGTH


def test_job_out_of_attempts_is_failed_instead_of_run(db_session: Session, job: Job) -> None:
    job.attempts = MAX
    db_session.commit()

    assert jobs.mark_job_running(db_session, job.org_id, job.id, "task-9", max_attempts=MAX) is None

    db_session.refresh(job)
    assert job.status == JobStatus.FAILED
    assert job.error is not None
    assert "5 attempts" in job.error
    assert job.attempts == MAX


def test_lock_sees_a_status_committed_by_another_transaction(db_session: Session, job: Job) -> None:
    jobs.mark_job_running(db_session, job.org_id, job.id, "task-1", max_attempts=MAX)
    assert job.status == JobStatus.RUNNING  # loaded in this session's identity map
    # Bypasses the ORM, like a cancellation committed by another process.
    db_session.execute(text("UPDATE jobs SET status = 'cancelled' WHERE id = :id"), {"id": job.id})
    db_session.commit()

    jobs.mark_job_completed(db_session, job.org_id, job.id)

    db_session.expire_all()
    assert db_session.get_one(Job, job.id).status == JobStatus.CANCELLED


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (TransientJobError("crt.sh timed out"), "TransientJobError: crt.sh timed out"),
        (JobError("Domain is not verified."), "JobError: Domain is not verified."),
        (RuntimeError("GET https://user:token@api.example/ failed"), "RuntimeError"),
        (ConnectionError(), "ConnectionError"),
    ],
)
def test_describe_error_keeps_messages_only_of_our_own_errors(
    exc: BaseException, expected: str
) -> None:
    assert jobs.describe_error(exc) == expected
