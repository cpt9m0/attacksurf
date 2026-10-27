"""Scan-time limits that come from the guard work: the per-root discovery cap."""

from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.infra.db.models import Asset, AssetRelation, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import scans
from attacksurf.services.assets import record_asset
from attacksurf.workers.tasks import pipeline
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan
from tests.integration.workers.test_pipeline import pipeline_env  # noqa: F401 - fixture
from tests.scanner_fixtures import PROFILES, capped_registry

pytestmark = pytest.mark.usefixtures("pipeline_env")


def _start(session: Session, name: str) -> tuple[UUID, Scan]:
    root = make_scan(session, name)
    scan = scans.start_scan(
        session,
        FakeQueue(session),
        org_id=root.org_id,
        root_asset_id=root.root_asset_id,
        profile="capped",
        registry=capped_registry(),
        profiles=PROFILES,
    )
    pipeline.registry = capped_registry()  # the task resolves plugins by profile name
    return root.org_id, scan


def _run_discovery(session: Session, org_id: UUID, scan: Scan) -> None:
    job = session.scalars(scoped(Job, org_id).where(Job.scan_id == scan.id)).one()
    pipeline.discover.apply(kwargs={"org_id": str(org_id), "job_id": str(job.id)})
    session.expire_all()


def _discovered(session: Session, org_id: UUID) -> list[str]:
    rows = session.scalars(
        scoped(Asset, org_id).where(Asset.source == AssetSource.DISCOVERED)
    ).all()
    return sorted(value for row in rows if isinstance(value := row.value, str))


def test_capped_discovery_stops_at_the_profile_limit(
    db_session: Session,
) -> None:
    org_id, scan = _start(db_session, "capped")
    _run_discovery(db_session, org_id, scan)

    assert scan.status == ScanStatus.COMPLETED
    assert _discovered(db_session, org_id) == ["h0.capped.example", "h1.capped.example"]
    assert db_session.scalars(scoped(Job, org_id).where(Job.status == JobStatus.FAILED)).all() == []


def test_assets_already_under_the_root_count_toward_the_cap(
    db_session: Session,
) -> None:
    org_id, scan = _start(db_session, "rescan")
    for index in range(3):
        record_asset(
            db_session,
            org_id,
            AssetType.SUBDOMAIN,
            f"h{index}.rescan.example",
            source=AssetSource.DISCOVERED,
            parent_id=scan.root_asset_id,
        )
    db_session.flush()

    _run_discovery(db_session, org_id, scan)

    assert scan.status == ScanStatus.COMPLETED
    # The root already has three discovered assets (cap 2): nothing new is added. The relation
    # the plugin reported for h0 is still recorded (it exists); h2's is skipped, never guessed.
    assert _discovered(db_session, org_id) == [
        "h0.rescan.example",
        "h1.rescan.example",
        "h2.rescan.example",
    ]
    relations = db_session.scalars(scoped(AssetRelation, org_id)).all()
    assert len(relations) == 1
