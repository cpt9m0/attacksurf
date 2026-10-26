"""Against the running Compose stack: a real worker picks up a job and completes it.

Needs `RUN_WORKER_TESTS=1`, a migrated `DATABASE_URL` and a `worker-passive` consuming
`REDIS_URL` (CI's compose job runs it; locally: `make test-worker`). Writes real rows to that
database and deletes them afterwards.
"""

import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from attacksurf.config import Settings
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.ids import uuid7
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Job, Org, Scan
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.queue import CeleryTaskQueue, create_celery
from attacksurf.services.jobs import create_job

pytestmark = [
    pytest.mark.worker,
    pytest.mark.skipif(
        os.environ.get("RUN_WORKER_TESTS") != "1", reason="needs RUN_WORKER_TESTS=1 + workers"
    ),
]

TIMEOUT_SECONDS = 30


@pytest.fixture
def session() -> Iterator[Session]:
    settings = Settings()
    engine = create_db_engine(settings)
    with create_session_factory(engine)() as session:
        yield session
    engine.dispose()


@pytest.fixture
def scan(session: Session) -> Iterator[Scan]:
    slug = f"worker-test-{uuid7().hex[:12]}"
    org = Org(name=slug, slug=slug)
    session.add(org)
    session.flush()
    now = datetime.now(UTC)
    root = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,
        value=f"{slug}.example",
        source=AssetSource.USER,
        first_seen=now,
        last_seen=now,
    )
    session.add(root)
    session.flush()
    scan = Scan(
        org_id=org.id,
        root_asset_id=root.id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
    )
    session.add(scan)
    session.commit()
    yield scan
    session.rollback()
    session.execute(delete(Org).where(Org.id == org.id))  # cascades to everything above
    session.commit()


def test_real_worker_completes_an_enqueued_job(session: Session, scan: Scan) -> None:
    queue = CeleryTaskQueue(create_celery(Settings()))

    job = create_job(
        session,
        queue,
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="system",
        task_name="passive.ping",
    )

    deadline = time.monotonic() + TIMEOUT_SECONDS
    status = JobStatus.QUEUED
    while time.monotonic() < deadline:
        session.expire_all()
        status = session.get_one(Job, job.id).status
        if status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
            break
        time.sleep(0.5)
    assert status == JobStatus.COMPLETED
    stored = session.get_one(Job, job.id)
    assert stored.attempts == 1
    assert stored.celery_task_id is not None
