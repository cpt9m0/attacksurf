"""End-to-end DB pipeline tests for `web.headers` and `web.cors` under `ScopeGuard` (#77)."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.events import DomainEvent
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import HttpBody
from attacksurf.domain.scans import ScanStatus
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import Asset, Evidence, Finding, Job, Org, Scan, Verification
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.scanners.web import components as _web_components  # noqa: F401
from attacksurf.scanners.web import exposures as _web_exposures  # noqa: F401
from attacksurf.scanners.web import headers as _web_headers  # noqa: F401
from attacksurf.scanners.web import probe as _web_probe  # noqa: F401
from attacksurf.scanners.web import tls as _web_tls  # noqa: F401
from attacksurf.scanners.web.headers import FOREIGN_ORIGIN
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


def _setup_org_and_root(db_session: Session, *, verified: bool) -> tuple[Org, Asset]:
    org = Org(name=f"Headers {verified}", slug=f"headers-{str(verified).lower()}")
    db_session.add(org)
    db_session.flush()
    root = assets_service.add_root_domain(db_session, org.id, "example.com", actor_id=None)
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


def _run_web_active(
    db_session: Session,
    org_id: UUID,
    root_id: UUID,
    http: FakeScopeHttp,
) -> Scan:
    dns = MutableDnsZone()
    dns.set_records("example.com", "A", ("93.184.216.34",))
    factory = sessionmaker(bind=db_session.get_bind())
    guard = ScopeGuard(
        dns=dns,
        http=http,
        ownership=DbOwnershipChecker(factory),
        classify=public_suffix.classify,
        active_scans_enabled=True,
    )
    events = _Events()
    q_disc = _Queue()
    scan = scans.start_scan(
        db_session,
        q_disc,
        org_id=org_id,
        root_asset_id=root_id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans.dispatch_stage(
        db_session,
        q_disc,
        org_id,
        q_disc.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    for task in q_disc.header:
        run_check(
            db_session,
            org_id,
            task.job_id,
            registry=registry,
            gate=guard,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )

    q_chk = _Queue()
    scans.dispatch_stage(
        db_session,
        q_chk,
        org_id,
        q_disc.tail[0].job_id,
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    selected_ids = {
        job.id
        for job in db_session.scalars(
            scoped(Job, org_id).where(Job.scanner.in_(("web.headers", "web.cors")))
        ).all()
    }
    for task in q_chk.header:
        if task.job_id in selected_ids:
            run_check(
                db_session,
                org_id,
                task.job_id,
                registry=registry,
                gate=guard,
                events=events,
                retry_allowed=False,
                profiles=PROFILES,
            )
    return db_session.get_one(Scan, scan.id)


def test_web_headers_and_cors_persist_findings_and_keep_suppressions(
    db_session: Session,
) -> None:
    org, root = _setup_org_and_root(db_session, verified=True)
    call_count = 0

    def _https_handler(_url: str) -> HttpBody:
        nonlocal call_count
        call_count += 1
        return HttpBody(
            status_code=200,
            content=b"<html><title>App</title></html>",
            headers={
                "Content-Type": "text/html",
                "Strict-Transport-Security": "max-age=3600",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
                "Set-Cookie": "sessionid=supersecretvalue999; Path=/",
                "Access-Control-Allow-Origin": FOREIGN_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
                "Date": f"Tue, 24 Nov 2026 00:0{call_count}:00 GMT",
            },
        )

    http = FakeScopeHttp(
        {
            "https://example.com/": _https_handler,
            "http://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>Plain</title></html>",
                headers={
                    "Content-Type": "text/html",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                },
            ),
        }
    )

    scan1 = _run_web_active(db_session, org.id, root.id, http)

    findings = db_session.scalars(scoped(Finding, org.id)).all()
    rule_ids = {f.rule_id for f in findings}
    assert {
        "web.headers.hsts_weak",
        "web.headers.csp_unsafe",
        "web.headers.clickjacking",
        "web.headers.nosniff_missing",
        "web.cookies.insecure_flags",
        "web.https.no_redirect",
        "web.cors.wildcard_credentials",
    } <= rule_ids
    cors_finding = next(f for f in findings if f.rule_id == "web.cors.wildcard_credentials")
    assert cors_finding.severity is Severity.MEDIUM
    cookie_finding = next(f for f in findings if f.rule_id == "web.cookies.insecure_flags")
    cookie_ev = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == cookie_finding.id)
    ).one()
    assert "supersecretvalue999" not in str(cookie_ev.data)
    assert ("https://example.com/", {"Origin": FOREIGN_ORIGIN}) in http.header_requests

    # Suppress one finding and re-scan with a different Date header: suppression must hold.
    cors_finding.status = FindingStatus.FALSE_POSITIVE
    cookie_finding.status = FindingStatus.FALSE_POSITIVE
    scan1.status = ScanStatus.COMPLETED
    db_session.commit()

    _run_web_active(db_session, org.id, root.id, http)
    db_session.expire_all()
    assert db_session.get_one(Finding, cors_finding.id).status is FindingStatus.FALSE_POSITIVE
    assert db_session.get_one(Finding, cookie_finding.id).status is FindingStatus.FALSE_POSITIVE


def test_web_cors_skips_unverified_root_and_hardened_site_is_clean(
    db_session: Session,
) -> None:
    unverified_org, unverified_root = _setup_org_and_root(db_session, verified=False)
    unverified_http = FakeScopeHttp({})
    _run_web_active(db_session, unverified_org.id, unverified_root.id, unverified_http)
    assert unverified_http.requests == []

    org, root = _setup_org_and_root(db_session, verified=True)
    hardened_http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>Hardened</title></html>",
                headers={
                    "Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": (
                        "default-src 'self'; script-src 'self' 'nonce-hardened'; "
                        "frame-ancestors 'none'"
                    ),
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Set-Cookie": "sessionid=sec; Path=/; Secure; HttpOnly; SameSite=Strict",
                },
            ),
            "http://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>Hardened</title></html>",
                final_url="https://example.com/",
                redirect_chain=(("http://example.com/", 301),),
                headers={
                    "Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": (
                        "default-src 'self'; script-src 'self' 'nonce-hardened'; "
                        "frame-ancestors 'none'"
                    ),
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            ),
        }
    )

    _run_web_active(db_session, org.id, root.id, hardened_http)

    findings = db_session.scalars(scoped(Finding, org.id)).all()
    assert findings == []
