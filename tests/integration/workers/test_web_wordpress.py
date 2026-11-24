"""End-to-end DB pipeline tests for `web.wordpress` under `ScopeGuard` (#79)."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.events import DomainEvent
from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import HttpBody
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import (
    Asset,
    Evidence,
    Finding,
    Job,
    Org,
    Scan,
    Verification,
    VulnCpeRange,
    VulnCve,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.scanners.web import components as _web_components  # noqa: F401
from attacksurf.scanners.web import exposures as _web_exposures  # noqa: F401
from attacksurf.scanners.web import headers as _web_headers  # noqa: F401
from attacksurf.scanners.web import probe as _web_probe  # noqa: F401
from attacksurf.scanners.web import tls as _web_tls  # noqa: F401
from attacksurf.scanners.web import wordpress as _web_wordpress  # noqa: F401
from attacksurf.services import assets as assets_service
from attacksurf.services import scans
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.services.scanner_jobs import run_check
from attacksurf.services.vulnintel import DbVulnIntelLookup
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


def _setup_org_and_root(db_session: Session, slug: str, *, verified: bool) -> tuple[Org, Asset]:
    org = Org(name=f"Org {slug}", slug=slug)
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


def _seed_wp_cves(db_session: Session) -> None:
    db_session.add_all(
        [
            VulnCve(
                cve_id="CVE-2024-8101",
                description="WordPress core vulnerability",
                cvss_v3_score=7.5,
                in_kev=False,
            ),
            VulnCve(
                cve_id="CVE-2024-8102",
                description="Contact Form 7 vulnerability",
                cvss_v3_score=6.8,
                in_kev=False,
            ),
        ]
    )
    db_session.flush()
    db_session.add_all(
        [
            VulnCpeRange(
                cve_id="CVE-2024-8101",
                vendor="wordpress",
                product="wordpress",
                version_end_excluding="6.5.0",
            ),
            VulnCpeRange(
                cve_id="CVE-2024-8102",
                vendor="rocklobster",
                product="contact_form_7",
                version_end_including="5.8.0",
            ),
        ]
    )
    db_session.commit()


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
        vuln_intel=DbVulnIntelLookup(factory),
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
    db_session.commit()
    checks = _Queue()
    scans.dispatch_stage(
        db_session,
        checks,
        org_id,
        q_disc.tail[0].job_id,
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    for task in checks.header:
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
    db_session.commit()
    return scan


def test_web_wordpress_end_to_end_pipeline_and_non_secret_evidence(db_session: Session) -> None:
    _seed_wp_cves(db_session)
    org, root = _setup_org_and_root(db_session, "wp-vuln", verified=True)
    landing_html = (
        b"<html><head><title>WP Blog</title>"
        b'<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/styles.css?ver=5.8.0" />'
        b"</head><body>Welcome</body></html>"
    )
    http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200, content=landing_html, headers={"Content-Type": "text/html"}
            ),
            "http://example.com/": HttpBody(
                status_code=301,
                content=b"",
                headers={"Location": "https://example.com/"},
                final_url="https://example.com/",
            ),
            "https://example.com/feed/": HttpBody(
                status_code=200,
                content=b"<rss><channel><generator>https://wordpress.org/?v=6.4.2</generator></channel></rss>",
                headers={"Content-Type": "application/rss+xml"},
            ),
            "https://example.com/xmlrpc.php": HttpBody(
                status_code=405,
                content=b"XML-RPC server accepts POST requests only.",
                headers={"Content-Type": "text/plain", "Allow": "POST"},
            ),
            "https://example.com/wp-json/wp/v2/users": HttpBody(
                status_code=200,
                content=b'[{"id": 1, "name": "Secret Admin", "slug": "secret-slug"}]',
                headers={"Content-Type": "application/json", "X-WP-Total": "3"},
            ),
            "https://example.com/wp-content/debug.log": HttpBody(
                status_code=200,
                content=b"[24-Nov-2026 10:00:00 UTC] PHP Warning: token=LeakCanary on line 9\n",
                headers={"Content-Type": "text/plain"},
            ),
            "https://example.com/wp-content/uploads/": HttpBody(
                status_code=200,
                content=(
                    b"<html><body><h1>Index of /wp-content/uploads/</h1><pre>"
                    b'<a href="../">Parent Directory</a><a href="file.pdf">file.pdf</a>'
                    b"</pre></body></html>"
                ),
                headers={"Content-Type": "text/html"},
            ),
        }
    )

    _run_web_active(db_session, org.id, root.id, http)

    findings = db_session.scalars(scoped(Finding, org.id)).all()
    wp_findings = [f for f in findings if f.scanner == "web.wordpress"]
    by_rule = {f.rule_id: f for f in wp_findings}
    assert "web.wordpress.xmlrpc_enabled" in by_rule
    assert "web.wordpress.user_listing" in by_rule
    assert "web.wordpress.debug_log" in by_rule
    assert "web.exposure.directory_listing" in by_rule
    assert by_rule["web.wordpress.debug_log"].severity is Severity.HIGH

    vuln_locs = {f.location for f in wp_findings if f.rule_id == "web.components.known_vulnerable"}
    assert vuln_locs == {"wordpress", "wordpress:plugin:contact-form-7"}

    user_listing_id = by_rule["web.wordpress.user_listing"].id
    user_ev = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == user_listing_id)
    ).one()
    assert user_ev.data["user_count"] == 3
    all_ev_text = str([ev.data for ev in db_session.scalars(scoped(Evidence, org.id)).all()])
    assert "secret-slug" not in all_ev_text
    assert "Secret Admin" not in all_ev_text
    assert "LeakCanary" not in all_ev_text


def test_web_wordpress_skips_non_wordpress_and_hardened_is_clean(db_session: Session) -> None:
    non_wp_org, non_wp_root = _setup_org_and_root(db_session, "non-wp", verified=True)
    non_wp_http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200,
                content=b"<html><head><title>Plain Static</title></head></html>",
                headers={"Content-Type": "text/html"},
            ),
            "http://example.com/": HttpBody(
                status_code=301,
                content=b"",
                headers={"Location": "https://example.com/"},
                final_url="https://example.com/",
            ),
        }
    )
    _run_web_active(db_session, non_wp_org.id, non_wp_root.id, non_wp_http)
    assert not any("/xmlrpc.php" in url for _, url in non_wp_http.method_requests)
    non_wp_job = db_session.scalars(
        scoped(Job, non_wp_org.id).where(Job.scanner == "web.wordpress")
    ).one()
    assert non_wp_job.status is JobStatus.COMPLETED

    hardened_org, hardened_root = _setup_org_and_root(db_session, "hardened-wp", verified=True)
    hardened_http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                status_code=200,
                content=(
                    b"<html><head><title>Hardened WP</title></head>"
                    b'<body><script src="/wp-includes/js/wp-embed.min.js"></script></body></html>'
                ),
                headers={"Content-Type": "text/html"},
            ),
            "http://example.com/": HttpBody(
                status_code=301,
                content=b"",
                headers={"Location": "https://example.com/"},
                final_url="https://example.com/",
            ),
            "https://example.com/xmlrpc.php": HttpBody(status_code=403, content=b"Forbidden"),
            "https://example.com/wp-json/wp/v2/users": HttpBody(
                status_code=401, content=b'{"code":"rest_not_logged_in"}'
            ),
            "https://example.com/wp-content/debug.log": HttpBody(
                status_code=404, content=b"Not Found"
            ),
            "https://example.com/wp-content/uploads/": HttpBody(
                status_code=403, content=b"Forbidden"
            ),
        }
    )
    _run_web_active(db_session, hardened_org.id, hardened_root.id, hardened_http)
    assert (
        db_session.scalars(
            scoped(Finding, hardened_org.id).where(Finding.scanner == "web.wordpress")
        ).all()
        == []
    )

    unverified_org, unverified_root = _setup_org_and_root(
        db_session, "unverified-wp", verified=False
    )
    unverified_http = FakeScopeHttp({})
    _run_web_active(db_session, unverified_org.id, unverified_root.id, unverified_http)
    assert unverified_http.method_requests == []
