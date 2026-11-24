"""End-to-end DB pipeline tests for `web.components` with NVD/KEV/EPSS intel (#75)."""

from datetime import UTC, date, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetType
from attacksurf.domain.events import DomainEvent, FindingReopened
from attacksurf.domain.findings import Confidence, FindingStatus, Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scans import ScanStatus
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import (
    Asset,
    Evidence,
    Finding,
    Org,
    Scan,
    Verification,
    VulnCpeRange,
    VulnCve,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.infra.tls import RawTlsHandshake
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


def _seed_vuln_intel(db_session: Session) -> VulnCve:
    now = datetime.now(UTC)
    high_cve = VulnCve(
        cve_id="CVE-2021-23017",
        description="Off-by-one DNS resolver bug in nginx.",
        published_at=datetime(2021, 5, 25, tzinfo=UTC),
        last_modified_at=now,
        cvss_v3_score=7.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        in_kev=False,
        epss_score=0.41,
        epss_percentile=0.92,
        created_at=now,
        updated_at=now,
    )
    kev_cve = VulnCve(
        cve_id="CVE-2021-3618",
        description="ALPACA TLS confusion affecting nginx.",
        published_at=datetime(2021, 6, 15, tzinfo=UTC),
        last_modified_at=now,
        cvss_v3_score=5.9,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        in_kev=True,
        kev_date_added=date(2022, 3, 15),
        epss_score=0.87,
        epss_percentile=0.98,
        created_at=now,
        updated_at=now,
    )
    db_session.add_all([high_cve, kev_cve])
    db_session.flush()
    db_session.add_all(
        [
            VulnCpeRange(
                cve_id="CVE-2021-23017",
                vendor="f5",
                product="nginx",
                version_start_including="0.6.18",
                version_end_excluding="1.20.1",
            ),
            VulnCpeRange(
                cve_id="CVE-2021-3618",
                vendor="nginx",
                product="nginx",
                version_start_including="1.0.0",
                version_end_excluding="1.20.0",
            ),
        ]
    )
    for idx in range(25):
        cid = f"CVE-2021-9{idx:03d}"
        db_session.add(
            VulnCve(
                cve_id=cid,
                description=f"Equal-CVSS nginx issue {idx}.",
                published_at=datetime(2021, 7, 1, tzinfo=UTC),
                last_modified_at=now,
                cvss_v3_score=7.5,
                in_kev=False,
                epss_score=0.40 - (idx * 0.01),
                epss_percentile=0.80,
                created_at=now,
                updated_at=now,
            )
        )
        db_session.flush()
        db_session.add(
            VulnCpeRange(
                cve_id=cid,
                vendor="f5",
                product="nginx",
                exact_version="1.18.0",
            )
        )
    db_session.commit()
    return kev_cve


class _NoOpTlsConnector:
    def handshake(self, **_kwargs: object) -> RawTlsHandshake:
        return RawTlsHandshake(
            protocol="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            chain_der=(),
            verified=True,
        )


def _build_guard(db_session: Session) -> tuple[ScopeGuard, FakeScopeHttp]:
    dns = MutableDnsZone()
    dns.set_records("example.com", "A", ("93.184.216.34",))
    http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(
                200,
                b"<title>Nginx Site</title>",
                False,
                {"content-type": "text/html", "server": "nginx/1.18.0"},
                final_url="https://example.com/",
            ),
            "http://example.com/": lambda _u: (_ for _ in ()).throw(DnsError("unreachable")),
        }
    )
    factory = sessionmaker(bind=db_session.get_bind())
    guard = ScopeGuard(
        dns=dns,
        http=http,
        ownership=DbOwnershipChecker(factory),
        classify=public_suffix.classify,
        active_scans_enabled=True,
        tls=_NoOpTlsConnector(),  # type: ignore[arg-type]
        vuln_intel=DbVulnIntelLookup(factory),
    )
    return guard, http


def _setup_verified_org(db_session: Session, now: datetime) -> tuple[Org, Asset]:
    org = Org(name="Acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    root = assets_service.add_root_domain(db_session, org.id, "example.com", actor_id=None)
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


def test_web_components_pipeline_flags_known_cves_and_tolerates_epss_updates(
    db_session: Session,
) -> None:
    kev_cve = _seed_vuln_intel(db_session)
    now = datetime.now(UTC)
    org, root = _setup_verified_org(db_session, now)

    guard, _ = _build_guard(db_session)
    events = _Events()

    def _run_web_active_cycle() -> tuple[Scan, Finding]:
        q_disc = _Queue()
        scan = scans.start_scan(
            db_session,
            q_disc,
            org_id=org.id,
            root_asset_id=root.id,
            profile="web_active",
            registry=registry,
            profiles=PROFILES,
        )
        scans.dispatch_stage(
            db_session,
            q_disc,
            org.id,
            q_disc.tasks[0][2],
            registry=registry,
            profiles=PROFILES,
        )
        db_session.commit()
        for task in q_disc.header:
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

        q_chk = _Queue()
        scans.dispatch_stage(
            db_session,
            q_chk,
            org.id,
            q_disc.tail[0].job_id,
            registry=registry,
            profiles=PROFILES,
        )
        db_session.commit()
        assert sorted(t.task_name for t in q_chk.header) == [
            "active.scan",
            "active.scan",
            "active.scan",
            "active.scan",
            "passive.scan",
            "passive.scan",
        ]
        for task in q_chk.header:
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
        comp_finding = db_session.scalars(
            scoped(Finding, org.id).where(Finding.rule_id == "web.components.known_vulnerable")
        ).one()
        return db_session.get_one(Scan, scan.id), comp_finding

    scan1, comp_finding = _run_web_active_cycle()
    url_asset = db_session.scalars(scoped(Asset, org.id).where(Asset.type == AssetType.URL)).one()
    assert comp_finding.asset_id == url_asset.id
    assert comp_finding.severity is Severity.CRITICAL
    assert comp_finding.confidence is Confidence.MEDIUM
    ev = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == comp_finding.id)
    ).one()
    assert ev.data["product"] == "Nginx"
    assert ev.data["version"] == "1.18.0"
    assert ev.data["kev_count"] == 1
    assert ev.data["cves_truncated"] is True
    assert ev.data["cves"][0]["cve_id"] == "CVE-2021-3618"

    # Suppress finding; EPSS updates that cross the top-20 display cutoff keep it suppressed.
    comp_finding.status = FindingStatus.FALSE_POSITIVE
    scan1.status = ScanStatus.COMPLETED
    kev_row = db_session.get_one(VulnCve, kev_cve.cve_id)
    kev_row.epss_score = 0.91
    promoted_row = db_session.get_one(VulnCve, "CVE-2021-9024")
    promoted_row.epss_score = 0.95
    db_session.commit()

    scan2, comp_after = _run_web_active_cycle()
    assert comp_after.status is FindingStatus.FALSE_POSITIVE
    evs = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == comp_finding.id)
    ).all()
    assert any(any(c["cve_id"] == "CVE-2021-9024" for c in row.data["cves"]) for row in evs)

    # Adding a new matching CVE changes the evidence digest and reopens the finding.
    scan2.status = ScanStatus.COMPLETED
    new_cve = VulnCve(
        cve_id="CVE-2022-41741",
        description="mp4 module memory corruption.",
        published_at=datetime(2022, 10, 19, tzinfo=UTC),
        last_modified_at=now,
        cvss_v3_score=7.8,
        in_kev=False,
        epss_score=0.22,
        created_at=now,
        updated_at=now,
    )
    db_session.add(new_cve)
    db_session.flush()
    db_session.add(
        VulnCpeRange(
            cve_id="CVE-2022-41741",
            vendor="f5",
            product="nginx",
            exact_version="1.18.0",
        )
    )
    db_session.commit()

    _, comp_reopened = _run_web_active_cycle()
    assert comp_reopened.status is FindingStatus.OPEN
    assert any(
        isinstance(e, FindingReopened) and e.finding_id == comp_finding.id for e in events.events
    )
