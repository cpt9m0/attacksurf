"""End-to-end DB pipeline tests for `web.probe` under `ScopeGuard` (#72)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.events import DomainEvent
from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import (
    Asset,
    AssetRelation,
    Evidence,
    Finding,
    Job,
    Org,
    Scan,
    Verification,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.scanners.web import probe as _web_probe  # noqa: F401
from attacksurf.services import assets as assets_service
from attacksurf.services import scans
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.services.scanner_jobs import run_check
from tests.dns_fakes import FakeScopeHttp, MutableDnsZone


class _Queue(TaskQueue, PipelineQueue):
    def __init__(self) -> None:
        self.tasks: list[tuple[str, UUID, UUID]] = []
        self.header: tuple[JobTask, ...] = ()
        self.tail: tuple[JobTask, ...] = ()

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        self.tasks.append((task_name, org_id, job_id))
        return "task-1"

    def enqueue_workflow(
        self, header: tuple[JobTask, ...], tail: tuple[JobTask, ...], error: JobTask
    ) -> None:
        del error
        self.header = header
        self.tail = tail


class _Events:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)


def _setup_org_root(db_session: Session, *, verified: bool) -> tuple[Org, Asset]:
    org = Org(name="Acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    root = assets_service.add_root_domain(db_session, org.id, "example.com", actor_id=None)
    assets_service.record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "app.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )
    if verified:
        now = datetime.now(UTC)
        db_session.add(
            Verification(
                org_id=org.id,
                asset_id=root.id,
                method=VerificationMethod.DNS_TXT,
                token="verify-tok",
                status=VerificationStatus.VERIFIED,
                verified_at=now,
                last_checked_at=now,
                recheck_at=now + timedelta(hours=20),
                expires_at=now + timedelta(hours=24),
            )
        )
    db_session.commit()
    return org, root


def _build_guard(
    db_session: Session,
    routes: dict[str, HttpBody | Callable[[str], HttpBody]],
) -> tuple[ScopeGuard, FakeScopeHttp]:
    dns = MutableDnsZone()
    dns.set_records("example.com", "A", ("93.184.216.34",))
    dns.set_records("app.example.com", "A", ("93.184.216.34",))
    http = FakeScopeHttp(routes)
    factory = sessionmaker(bind=db_session.get_bind())
    guard = ScopeGuard(
        dns=dns,
        http=http,
        ownership=DbOwnershipChecker(factory),
        classify=public_suffix.classify,
        active_scans_enabled=True,
    )
    return guard, http


def _unreachable(_url: str) -> HttpBody:
    raise DnsError("unreachable")


def test_web_active_discovers_urls_for_verified_hosts_and_deactivates_missing_on_rescan(
    db_session: Session,
) -> None:
    org, root = _setup_org_root(db_session, verified=True)
    guard, _ = _build_guard(
        db_session,
        {
            "https://example.com/": HttpBody(
                200,
                b'<title>Acme Root</title><meta name="generator" content="WordPress 6.5.2">',
                False,
                {"content-type": "text/html", "server": "nginx/1.26.2"},
                final_url="https://example.com/",
            ),
            "http://example.com/": _unreachable,
            "https://app.example.com/": HttpBody(
                200,
                b"<title>Acme App</title>",
                False,
                {"content-type": "text/html", "server": "nginx"},
                final_url="https://app.example.com/",
            ),
            "http://app.example.com/": _unreachable,
        },
    )
    queue = _Queue()
    events = _Events()

    scan = scans.start_scan(
        db_session,
        queue,
        org_id=org.id,
        root_asset_id=root.id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans.dispatch_stage(
        db_session,
        queue,
        org.id,
        queue.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()

    assert [t.task_name for t in queue.header] == ["active.scan", "active.scan"]
    for task in queue.header:
        run_check(
            db_session,
            org.id,
            task.job_id,
            registry=registry,
            gate=guard,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )

    urls = db_session.scalars(
        scoped(Asset, org.id).where(Asset.type == AssetType.URL).order_by(Asset.value)
    ).all()
    assert [u.value for u in urls] == ["https://app.example.com/", "https://example.com/"]
    assert all(u.is_active for u in urls)
    by_val = {u.value: u for u in urls}
    assert by_val["https://example.com/"].details["web"]["title"] == "Acme Root"
    root_techs = {t["name"]: t for t in by_val["https://example.com/"].details["technologies"]}
    assert root_techs["Nginx"]["version"] == "1.26.2"
    assert root_techs["WordPress"]["version"] == "6.5.2"
    app_techs = {t["name"]: t for t in by_val["https://app.example.com/"].details["technologies"]}
    assert app_techs["Nginx"]["version"] is None

    findings = db_session.scalars(scoped(Finding, org.id)).all()
    assert len(findings) == 1
    assert findings[0].rule_id == "web.disclosure.version_banner"
    assert findings[0].severity is Severity.INFO
    assert findings[0].asset_id == by_val["https://example.com/"].id
    ev = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == findings[0].id)
    ).one()
    assert ev.data["headers"]["server"] == "nginx/1.26.2"

    serves_edges = db_session.scalars(
        scoped(AssetRelation, org.id).where(AssetRelation.kind == RelationKind.SERVES)
    ).all()
    assert len(serves_edges) == 2

    # Mark first scan complete so we can run a second `web_active` scan where app URL is gone.
    first_scan = db_session.get_one(Scan, scan.id)
    first_scan.status = ScanStatus.COMPLETED
    db_session.commit()

    guard2, _ = _build_guard(
        db_session,
        {
            "https://example.com/": HttpBody(
                200,
                b"<title>Acme Root</title>",
                False,
                {"content-type": "text/html"},
                final_url="https://example.com/",
            ),
            "http://example.com/": _unreachable,
            "https://app.example.com/": _unreachable,
            "http://app.example.com/": _unreachable,
        },
    )
    queue2 = _Queue()
    scan2 = scans.start_scan(
        db_session,
        queue2,
        org_id=org.id,
        root_asset_id=root.id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans.dispatch_stage(
        db_session,
        queue2,
        org.id,
        queue2.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()

    # Discovery runs on root, subdomain, and previously discovered URL assets.
    assert len(queue2.header) == 4
    for task in queue2.header:
        run_check(
            db_session,
            org.id,
            task.job_id,
            registry=registry,
            gate=guard2,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )

    db_session.expire_all()
    refreshed = {
        u.value: u.is_active
        for u in db_session.scalars(scoped(Asset, org.id).where(Asset.type == AssetType.URL)).all()
    }
    assert refreshed == {
        "https://example.com/": True,
        "https://app.example.com/": False,
    }
    assert db_session.get(Scan, scan2.id) is not None


def test_web_active_skips_unverified_root_without_outbound_requests(
    db_session: Session,
) -> None:
    org, root = _setup_org_root(db_session, verified=False)
    guard, http = _build_guard(db_session, {})
    queue = _Queue()
    events = _Events()

    scan = scans.start_scan(
        db_session,
        queue,
        org_id=org.id,
        root_asset_id=root.id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans.dispatch_stage(
        db_session,
        queue,
        org.id,
        queue.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()

    for task in queue.header:
        run_check(
            db_session,
            org.id,
            task.job_id,
            registry=registry,
            gate=guard,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )

    assert http.requests == []
    jobs = db_session.scalars(
        scoped(Job, org.id).where(Job.scan_id == scan.id, Job.stage == "discovery")
    ).all()
    assert [j.status for j in jobs] == [JobStatus.SKIPPED, JobStatus.SKIPPED]
    assert db_session.scalars(scoped(Asset, org.id).where(Asset.type == AssetType.URL)).all() == []
    assert db_session.get(Scan, scan.id) is not None
    assert scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}
