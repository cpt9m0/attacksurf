"""Ownership verification tasks: one tracked job per proof, retried on lookup failures."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import TxtError
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.verification import VerificationStatus, record_value
from attacksurf.infra.db.models import Asset, Job, Org, Verification
from attacksurf.services import verifications
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import verification
from tests.fakes import FakeQueue

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


class FakeLookup:
    def __init__(self, values: tuple[str, ...] = (), *, error: Exception | None = None) -> None:
        self.values = values
        self.error = error

    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        if self.error is not None:
            raise self.error
        return self.values


@pytest.fixture
def env(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> sessionmaker[Session]:
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    monkeypatch.setitem(app.conf, "task_always_eager", True)
    monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    return factory


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def root(db_session: Session, org: Org) -> Asset:
    root = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,
        value="example.com",
        source=AssetSource.USER,
        first_seen=NOW,
        last_seen=NOW,
    )
    db_session.add(root)
    db_session.flush()
    return root


def _job(db_session: Session, org: Org, root: Asset) -> Job:
    job = Job(
        org_id=org.id,
        scan_id=None,
        asset_id=root.id,
        stage="verify",
        status=JobStatus.QUEUED,
    )
    db_session.add(job)
    db_session.flush()
    return job


def test_verify_task_records_a_found_record(
    env: sessionmaker[Session],
    db_session: Session,
    org: Org,
    root: Asset,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=org.id, asset_id=root.id, actor_id=None
    )
    job = _job(db_session, org, root)
    monkeypatch.setattr(
        verification.runtime, "txt_lookup", lambda: FakeLookup((record_value(proof.token),))
    )

    verification.verify_ownership(org_id=str(org.id), job_id=str(job.id))
    db_session.expire_all()

    assert db_session.get_one(Verification, proof.id).status is VerificationStatus.VERIFIED
    assert db_session.get_one(Job, job.id).status is JobStatus.COMPLETED


def test_verify_task_retries_when_the_nameservers_fail(
    env: sessionmaker[Session],
    db_session: Session,
    org: Org,
    root: Asset,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=org.id, asset_id=root.id, actor_id=None
    )
    job = _job(db_session, org, root)
    monkeypatch.setattr(verification.runtime, "txt_lookup", lambda: FakeLookup(error=TxtError()))

    with pytest.raises(TransientJobError, match="retried"):
        verification.verify_ownership(org_id=str(org.id), job_id=str(job.id))

    # The proof stays pending: a nameserver outage must not revoke it (its grace still holds).
    db_session.expire_all()
    assert db_session.get_one(Verification, proof.id).status is VerificationStatus.PENDING


def test_verify_task_is_a_no_op_when_the_proof_is_gone(
    env: sessionmaker[Session],
    db_session: Session,
    org: Org,
    root: Asset,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job(db_session, org, root)  # no verification row for the asset
    monkeypatch.setattr(verification.runtime, "txt_lookup", lambda: FakeLookup(()))

    verification.verify_ownership(org_id=str(org.id), job_id=str(job.id))
    db_session.expire_all()

    assert db_session.get_one(Job, job.id).status is JobStatus.COMPLETED


def test_reverify_task_queues_a_check_per_due_proof(
    env: sessionmaker[Session],
    db_session: Session,
    org: Org,
    root: Asset,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=org.id, asset_id=root.id, actor_id=None
    )
    verifications.record_check(
        db_session, proof, (record_value(proof.token),), now=datetime.now(UTC) - timedelta(days=2)
    )
    db_session.commit()
    queue = FakeQueue(db_session)
    monkeypatch.setattr(verification, "CeleryTaskQueue", lambda _app: queue)

    verification.reverify_ownership()
    db_session.expire_all()

    assert [task for task, *_ in queue.sent] == ["passive.verify_ownership"]
