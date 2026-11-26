"""End-to-end DB pipeline tests for `web.exposures` under `ScopeGuard` (#78)."""

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.events import DomainEvent
from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import HttpBody
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
    org = Org(name=f"Exposures {verified}", slug=f"exposures-{str(verified).lower()}")
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


def _run_web_exposures(
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
    exp_job_ids = {
        job.id
        for job in db_session.scalars(
            scoped(Job, org_id).where(Job.scanner == "web.exposures")
        ).all()
    }
    for task in q_chk.header:
        if task.job_id in exp_job_ids:
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


def test_web_exposures_redacts_env_secrets_across_db_and_logs(
    db_session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    org, root = _setup_org_and_root(db_session, verified=True)
    canary_secret = "CANARY_SECRET_TOKEN_987654"
    http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>App</title></html>",
                headers={"Content-Type": "text/html"},
            ),
            "http://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>App</title></html>",
                final_url="https://example.com/",
                redirect_chain=(("http://example.com/", 301),),
                headers={"Content-Type": "text/html"},
            ),
            "https://example.com/.env": HttpBody(
                status_code=200,
                content=f"APP_KEY=base64:{canary_secret}\nJWT_SECRET={canary_secret}\n".encode(),
                headers={"Content-Type": "text/plain"},
            ),
            "https://example.com/.git/HEAD": HttpBody(
                status_code=200,
                content=b"ref: refs/heads/main\n",
                headers={"Content-Type": "text/plain"},
            ),
            "https://example.com/backup.zip": HttpBody(
                status_code=200,
                content=b"PK\x03\x04",
                headers={"Content-Type": "application/zip", "Content-Length": "4096"},
            ),
            "https://example.com/.well-known/security.txt": HttpBody(
                status_code=200,
                content=b"Contact: mailto:sec@example.com\n",
                headers={"Content-Type": "text/plain"},
            ),
        }
    )

    with caplog.at_level(logging.DEBUG):
        _run_web_exposures(db_session, org.id, root.id, http)

    findings = db_session.scalars(scoped(Finding, org.id)).all()
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {
        "web.exposure.env_file",
        "web.exposure.git_repo",
        "web.exposure.backup_archive",
    }
    assert by_rule["web.exposure.env_file"].severity is Severity.CRITICAL

    all_evidence = db_session.scalars(scoped(Evidence, org.id)).all()
    env_ev = next(ev for ev in all_evidence if ev.finding_id == by_rule["web.exposure.env_file"].id)
    assert env_ev.data["key_names"] == ["APP_KEY", "JWT_SECRET"]
    for ev in all_evidence:
        assert canary_secret not in str(ev.data)
    for finding in findings:
        assert canary_secret not in finding.remediation
        assert canary_secret not in finding.location
    assert canary_secret not in caplog.text
    assert ("HEAD", "https://example.com/backup.zip") in http.method_requests
    assert ("GET", "https://example.com/backup.zip") not in http.method_requests


def test_web_exposures_soft_404_clean_and_unverified_root_skipped(
    db_session: Session,
) -> None:
    unverified_org, unverified_root = _setup_org_and_root(db_session, verified=False)
    unverified_http = FakeScopeHttp({})
    _run_web_exposures(db_session, unverified_org.id, unverified_root.id, unverified_http)
    assert unverified_http.requests == []

    org, root = _setup_org_and_root(db_session, verified=True)

    def _soft_404(url: str) -> HttpBody:
        if url.endswith("/.well-known/security.txt"):
            return HttpBody(
                status_code=200,
                content=b"Contact: https://example.com/.well-known/security\n",
                headers={"Content-Type": "text/plain"},
            )
        return HttpBody(
            status_code=200,
            content=b"<html><body>Not Found Catch-All</body></html>",
            headers={"Content-Type": "text/html", "Content-Length": "45"},
        )

    soft_http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>Home</title></html>",
                headers={"Content-Type": "text/html"},
            ),
            "http://example.com/": HttpBody(
                status_code=200,
                content=b"<html><title>Home</title></html>",
                final_url="https://example.com/",
                redirect_chain=(("http://example.com/", 301),),
                headers={"Content-Type": "text/html"},
            ),
            "https://example.com/.well-known/security.txt": _soft_404,
            **{
                f"https://example.com{path}": _soft_404
                for path in (
                    "/.git/HEAD",
                    "/.env",
                    "/backup.zip",
                    "/actuator/heapdump",
                    "/admin",
                )
            },
        }
    )

    class _CatchAllHttp(FakeScopeHttp):
        def _dispatch(
            self,
            url: str,
            *,
            limit: int,
            headers: object | None = None,  # type: ignore[override]
            method: str = "GET",
        ) -> HttpBody:
            if url not in self.routes and url.startswith("https://example.com/"):
                self.routes[url] = _soft_404
            return super()._dispatch(url, limit=limit, headers=None, method=method)

    catch_http = _CatchAllHttp(dict(soft_http.routes))
    _run_web_exposures(db_session, org.id, root.id, catch_http)

    exp_findings = db_session.scalars(
        scoped(Finding, org.id).where(Finding.rule_id.like("web.exposure.%"))
    ).all()
    sec_findings = db_session.scalars(
        scoped(Finding, org.id).where(Finding.rule_id == "web.security.security_txt_missing")
    ).all()
    assert exp_findings == []
    assert sec_findings == []
