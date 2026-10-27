"""Real Redis chords and prefork workers, with a broker namespace isolated from Compose."""

import os
import time
from collections.abc import Iterator

import pytest
from celery.backends.redis import RedisBackend
from celery.contrib.testing.worker import start_worker
from sqlalchemy import delete
from sqlalchemy.orm import Session

from attacksurf.config import Settings
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.ids import uuid7
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.infra.db.models import Asset, AssetRelation, Evidence, Finding, Job, Org
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.queue import CeleryTaskQueue, celery_config
from attacksurf.services.assets import record_asset
from attacksurf.services.scans import start_scan
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import pipeline
from tests.scanner_fixtures import PROFILES, RULE, FixtureGate, fixture_registry

pytestmark = [
    pytest.mark.worker,
    pytest.mark.skipif(
        os.environ.get("RUN_WORKER_TESTS") != "1",
        reason="needs RUN_WORKER_TESTS=1 + Redis/Postgres",
    ),
]


@pytest.fixture
def real_pipeline(monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    settings = Settings()
    engine = create_db_engine(settings)
    namespace = f"pipeline-test-{uuid7().hex}:"
    for name, value in celery_config(settings).items():
        monkeypatch.setitem(app.conf, name, value)
    monkeypatch.setitem(app.conf, "task_always_eager", False)
    monkeypatch.setitem(app.conf, "broker_transport_options", {"global_keyprefix": namespace})
    monkeypatch.setitem(
        app.conf, "result_backend_transport_options", {"global_keyprefix": namespace}
    )
    monkeypatch.setattr(
        app.__dict__["_local"],
        "backend",
        RedisBackend(
            app=app,
            url=settings.redis_url.get_secret_value(),
        ),
        raising=False,
    )
    monkeypatch.setattr(runtime, "settings", lambda: settings)
    runtime.session_factory.cache_clear()
    monkeypatch.setattr(runtime, "scanner_gate", FixtureGate)
    monkeypatch.setattr(pipeline, "registry", fixture_registry())
    monkeypatch.setattr(pipeline, "PROFILES", PROFILES)
    monkeypatch.setattr(pipeline, "RULES", {RULE.id: RULE})
    try:
        with (
            start_worker(
                app,
                pool="prefork",
                concurrency=2,
                perform_ping_check=False,
                queues=("passive",),
                shutdown_timeout=20,
            ),
            create_session_factory(engine)() as session,
        ):
            yield session
    finally:
        runtime.session_factory.cache_clear()
        engine.dispose()


def test_real_pipeline_persists_results_despite_a_failing_check(real_pipeline: Session) -> None:
    session = real_pipeline
    slug = f"pipeline-{uuid7().hex[:12]}"
    org = Org(name=slug, slug=slug)
    session.add(org)
    session.flush()
    org_id = org.id
    root = record_asset(
        session, org_id, AssetType.DOMAIN, f"{slug}.example", source=AssetSource.USER
    )
    session.commit()
    try:
        scan = start_scan(
            session,
            CeleryTaskQueue(app),
            org_id=org_id,
            root_asset_id=root.id,
            profile="fixture",
            registry=fixture_registry(),
            profiles=PROFILES,
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            session.expire_all()
            if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED}:
                break
            session.rollback()
            time.sleep(0.1)
        assert scan.status == ScanStatus.COMPLETED
        assert len(session.scalars(scoped(Asset, org_id)).all()) == 2
        assert len(session.scalars(scoped(AssetRelation, org_id)).all()) == 1
        assert len(session.scalars(scoped(Finding, org_id)).all()) == 2
        assert len(session.scalars(scoped(Evidence, org_id)).all()) == 2
        assert (
            len(session.scalars(scoped(Job, org_id).where(Job.status == JobStatus.FAILED)).all())
            == 2
        )
    finally:
        session.rollback()
        session.execute(delete(Org).where(Org.id == org_id))
        session.commit()
