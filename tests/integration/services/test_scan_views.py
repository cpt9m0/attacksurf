"""`services.scan_views`: scan list, scan detail, diff parsing, tenant isolation."""

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus
from attacksurf.infra.db.models import Scan
from attacksurf.services import jobs, scan_views
from attacksurf.services import scans as scans_service
from attacksurf.services.assets import record_asset
from attacksurf.services.scan_views import DiffAsset, ScanFilter
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan
from tests.scanner_fixtures import PROFILES, fixture_registry


def _started(session: Session, root: Scan) -> Scan:
    return scans_service.start_scan(
        session,
        FakeQueue(session),
        org_id=root.org_id,
        root_asset_id=root.root_asset_id,
        profile="fixture",
        registry=fixture_registry(),
        profiles=PROFILES,
    )


def _finish(session: Session, scan: Scan, status: ScanStatus = ScanStatus.COMPLETED) -> None:
    scan.status = status
    session.flush()


def _job(
    session: Session,
    scan: Scan,
    stage: str,
    status: JobStatus,
    scanner: str | None = "fixture.check",
) -> None:
    job = jobs.create_job(
        session,
        FakeQueue(session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage=stage,
        task_name="passive.scan",
        scanner=scanner,
        asset_id=scan.root_asset_id,
    )
    if status is JobStatus.RUNNING:
        jobs.mark_job_running(session, scan.org_id, job.id, "celery-1", max_attempts=3)
    elif status is JobStatus.COMPLETED:
        jobs.mark_job_completed(session, scan.org_id, job.id)
    elif status is JobStatus.FAILED:
        jobs.mark_job_failed(session, scan.org_id, job.id, RuntimeError("boom"))


_STATS = {
    "findings": {
        "new": {
            "total": 2,
            "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
        "fixed": {
            "total": 1,
            "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        },
        "regressed": {
            "total": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "total": {
            "total": 5,
            "by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
        },
    },
    "assets": {
        "new": {
            "total": 1,
            "assets": [{"id": str(uuid4()), "type": "subdomain", "value": "new.example.com"}],
        },
        "disappeared": {"total": 0, "assets": []},
    },
}


def test_list_scans_newest_first_with_progress_and_root_value(db_session: Session) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    first = _started(db_session, root)
    _job(db_session, first, "check", JobStatus.COMPLETED)
    _job(db_session, first, "check", JobStatus.FAILED)
    _finish(db_session, first)
    second = _started(db_session, root)
    _finish(db_session, second)

    page = scan_views.list_scans(db_session, root.org_id, ScanFilter())

    assert page.total == 3  # the fixture scan plus the two started above
    assert [row.id for row in page.items] == [second.id, first.id, root.id]
    assert (page.page, page.pages) == (1, 1)
    by_id = {row.id: row for row in page.items}
    # Kickoff plus the two check jobs; the kickoff is still queued.
    assert (by_id[first.id].jobs_finished, by_id[first.id].jobs_total) == (2, 3)
    assert by_id[first.id].root_value == "acme.example"
    assert by_id[first.id].status == ScanStatus.COMPLETED
    assert by_id[root.id].jobs_total == 0


def test_list_scans_filters_by_root_and_status(db_session: Session) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    other = make_scan(db_session, "other")
    _finish(db_session, other)
    running = _started(db_session, root)

    assert [
        row.id for row in scan_views.list_scans(db_session, root.org_id, ScanFilter()).items
    ] == [
        running.id,
        root.id,
    ]
    assert [
        row.id
        for row in scan_views.list_scans(
            db_session, root.org_id, ScanFilter(status=ScanStatus.QUEUED)
        ).items
    ] == [running.id]
    assert (
        scan_views.list_scans(db_session, root.org_id, ScanFilter(root_id=root.root_asset_id)).total
        == 2
    )
    # Another org's root matches nothing here: no existence leak through the filter.
    assert (
        scan_views.list_scans(
            db_session, root.org_id, ScanFilter(root_id=other.root_asset_id)
        ).total
        == 0
    )


def test_list_scans_paginates_and_clamps(db_session: Session) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    for _ in range(scan_views.PAGE_SIZE):
        scan = _started(db_session, root)
        _finish(db_session, scan)

    first = scan_views.list_scans(db_session, root.org_id, ScanFilter())
    second = scan_views.list_scans(db_session, root.org_id, ScanFilter(), page=2)
    beyond = scan_views.list_scans(db_session, root.org_id, ScanFilter(), page=99)

    assert (first.total, first.pages, len(first.items)) == (26, 2, 25)
    assert (second.page, len(second.items)) == (2, 1)
    assert beyond.page == 2  # clamped to the last page, never empty
    assert {row.id for row in first.items}.isdisjoint({row.id for row in second.items})


def test_list_scans_hides_other_orgs(db_session: Session) -> None:
    root = make_scan(db_session)

    assert scan_views.list_scans(db_session, uuid4(), ScanFilter()).total == 0
    assert scan_views.active_scan_for_root(db_session, uuid4(), root.root_asset_id) is None


def test_active_scan_for_root(db_session: Session) -> None:
    root = make_scan(db_session)

    active = scan_views.active_scan_for_root(db_session, root.org_id, root.root_asset_id)

    assert active is not None
    assert active.id == root.id

    root.status = ScanStatus.COMPLETED
    db_session.flush()

    assert scan_views.active_scan_for_root(db_session, root.org_id, root.root_asset_id) is None


def test_get_scan_detail_jobs_diff_and_cancel_flag(db_session: Session) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    scan = _started(db_session, root)
    _job(db_session, scan, "discovery", JobStatus.COMPLETED, scanner="fixture.discover")
    _job(db_session, scan, "check", JobStatus.RUNNING)
    _job(db_session, scan, "check", JobStatus.FAILED)
    scan.stats = dict(_STATS)
    db_session.flush()

    detail = scan_views.get_scan_detail(db_session, scan.org_id, scan.id)

    assert detail.scan.id == scan.id
    assert detail.scan.root_value == "acme.example"
    assert (detail.jobs_finished, detail.jobs_total) == (2, 4)
    assert dict(detail.by_status)[JobStatus.COMPLETED.value] == 1
    assert [job.stage for job in detail.jobs] == ["discover", "discovery", "check", "check"]
    assert detail.jobs[1].scanner == "fixture.discover"
    assert detail.jobs[1].asset_value == "acme.example"
    assert detail.jobs[3].error == "RuntimeError"  # sanitized at write time
    assert detail.can_cancel is True
    assert detail.diff is not None
    assert detail.diff.new_findings.total == 2
    assert dict(detail.diff.new_findings.by_severity)["critical"] == 1
    assert detail.diff.fixed_findings.total == 1
    assert detail.diff.total_findings.total == 5
    assert detail.diff.new_assets.assets == (
        DiffAsset(
            id=_STATS["assets"]["new"]["assets"][0]["id"],
            type="subdomain",
            value="new.example.com",
        ),
    )
    assert detail.diff.disappeared_assets.total == 0


def test_terminal_scan_cannot_cancel_and_deleted_asset_shows_blank(
    db_session: Session,
) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    scan = _started(db_session, root)
    child = record_asset(
        db_session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        "gone.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    job = jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="check",
        task_name="passive.scan",
        asset_id=child.id,
    )
    db_session.delete(child)  # the job row survives, unlinked (SET NULL)
    _finish(db_session, scan)
    db_session.expire_all()  # the web layer always reads with a fresh session

    detail = scan_views.get_scan_detail(db_session, scan.org_id, scan.id)

    assert detail.can_cancel is False
    assert detail.diff is None  # this scan never ran the diff stage
    row = next(item for item in detail.jobs if item.id == job.id)
    assert row.asset_id is None
    assert row.asset_value is None


def test_get_scan_detail_rejects_other_tenant(db_session: Session) -> None:
    root = make_scan(db_session)

    with pytest.raises(ScanNotFound):
        scan_views.get_scan_detail(db_session, uuid4(), root.id)


@pytest.mark.parametrize(
    "stats",
    [
        None,
        {},
        {"revision": "abc", "artifact_id": str(uuid4())},  # upload scan, no diff yet
        {"findings": {"new": {"total": 1}}},  # no assets half
        {"findings": [], "assets": {}},  # wrong shapes
        "not-a-dict",
    ],
)
def test_parse_diff_returns_none_without_a_diff(stats: object) -> None:
    assert scan_views.parse_diff(stats) is None


def test_parse_diff_ignores_unknown_severities_and_bad_entries() -> None:
    stats = {
        "findings": {
            "new": {"total": -3, "by_severity": {"critical": 2, "made-up": 9, "high": True}},
        },
        "assets": {
            "new": {
                "total": 2,
                "assets": [
                    {"id": str(uuid4()), "type": "subdomain", "value": "ok.example.com"},
                    {"id": 7, "type": "subdomain", "value": "bad.example.com"},
                    "also-bad",
                ],
            },
            "disappeared": {"total": 0, "assets": []},
        },
    }

    diff = scan_views.parse_diff(stats)

    assert diff is not None
    assert diff.new_findings.total == 2  # clamped up to the real bucket sum
    assert dict(diff.new_findings.by_severity)["high"] == 0  # booleans are not counts
    assert [asset.value for asset in diff.new_assets.assets] == ["ok.example.com"]
    assert diff.new_assets.total == 2  # the writer's true total is kept


def test_parse_diff_caps_asset_lists_but_keeps_the_total() -> None:
    stats = {
        "findings": {},
        "assets": {
            "new": {
                "total": scan_views.MAX_DIFF_ASSETS + 5,
                "assets": [
                    {"id": str(uuid4()), "type": "subdomain", "value": f"h{i}.example.com"}
                    for i in range(scan_views.MAX_DIFF_ASSETS + 5)
                ],
            },
            "disappeared": {"total": 0, "assets": []},
        },
    }

    diff = scan_views.parse_diff(stats)

    assert diff is not None
    assert len(diff.new_assets.assets) == scan_views.MAX_DIFF_ASSETS
    assert diff.new_assets.total == scan_views.MAX_DIFF_ASSETS + 5
    assert diff.new_assets.truncated is True


def test_get_scan_detail_caps_large_job_lists_with_exact_counts(db_session: Session) -> None:
    root = make_scan(db_session)
    _finish(db_session, root)
    scan = _started(db_session, root)
    total_checks = scan_views.MAX_DETAIL_JOBS + 10
    for _ in range(total_checks):
        _job(db_session, scan, "check", JobStatus.COMPLETED)
    _job(db_session, scan, "check", JobStatus.FAILED)
    _job(db_session, scan, "finalize", JobStatus.QUEUED, scanner=None)

    detail = scan_views.get_scan_detail(db_session, scan.org_id, scan.id)

    assert detail.jobs_truncated is True
    assert len(detail.jobs) == scan_views.MAX_DETAIL_JOBS
    # Exact counts reflect every job in SQL (kickoff + total_checks + failed + finalize).
    assert detail.jobs_total == total_checks + 3
    assert detail.jobs_finished == total_checks + 1
    by_status = dict(detail.by_status)
    assert by_status[JobStatus.COMPLETED.value] == total_checks
    assert by_status[JobStatus.FAILED.value] == 1
    assert by_status[JobStatus.QUEUED.value] == 2  # kickoff + finalize
    # Priority ordering surfaces the failure, queued jobs, and stage jobs within the cap.
    assert detail.jobs[0].status is JobStatus.FAILED
    assert any(job.stage == "finalize" for job in detail.jobs)
