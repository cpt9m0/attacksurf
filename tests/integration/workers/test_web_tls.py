"""End-to-end DB pipeline tests for `web.tls` under `ScopeGuard` (#76)."""

import ssl
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.events import DomainEvent
from attacksurf.domain.findings import Severity
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import TlsError
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import Asset, Evidence, Finding, Job, Org, Verification
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.infra.tls import RawTlsHandshake
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.scanners.web import components as _web_components  # noqa: F401
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


def _der_cert(
    *,
    cn: str,
    san: str,
    days_offset_end: int,
    key_size: int = 2048,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=days_offset_end))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class _FakeTlsConnector:
    def __init__(self, certs_by_host: dict[str, bytes]) -> None:
        self._certs = certs_by_host
        self.calls: list[tuple[str, bool, ssl.TLSVersion | None]] = []

    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        verify: bool,
        check_hostname: bool = True,
        timeout: float,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> RawTlsHandshake:
        del address, port, check_hostname, timeout, max_version
        self.calls.append((server_hostname, verify, min_version))
        cert = self._certs[server_hostname]
        if min_version is ssl.TLSVersion.TLSv1:
            return RawTlsHandshake("TLSv1", "ECDHE-RSA-AES128-SHA", 128, (cert,), False)
        if min_version is ssl.TLSVersion.TLSv1_1:
            raise TlsError("TLS 1.1 rejected")
        if verify:
            return RawTlsHandshake(
                "", "", None, (), False, verify_code=18, verify_reason="self-signed certificate"
            )
        return RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (cert,), False)


def _setup_url(
    db_session: Session, *, verified: bool, host: str = "example.com"
) -> tuple[Org, Asset, Asset]:
    org = Org(name="Acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    root = assets_service.add_root_domain(db_session, org.id, host, actor_id=None)
    url_asset = assets_service.record_asset(
        db_session,
        org.id,
        AssetType.URL,
        f"https://{host}/",
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
    return org, root, url_asset


def _run_tls_check(
    db_session: Session,
    org_id: UUID,
    root_id: UUID,
    connector: _FakeTlsConnector,
) -> None:
    dns = MutableDnsZone()
    dns.set_records("example.com", "A", ("93.184.216.34",))
    factory = sessionmaker(bind=db_session.get_bind())
    guard = ScopeGuard(
        dns=dns,
        http=FakeScopeHttp({}),
        ownership=DbOwnershipChecker(factory),
        classify=public_suffix.classify,
        active_scans_enabled=True,
        tls=connector,
    )
    queue = _Queue()
    scan = scans.start_scan(
        db_session,
        queue,
        org_id=org_id,
        root_asset_id=root_id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans.dispatch_stage(
        db_session,
        queue,
        org_id,
        queue.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    checks_queue = _Queue()
    scans.dispatch_stage(
        db_session,
        checks_queue,
        org_id,
        queue.tail[0].job_id,
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    tls_jobs = [t for t in checks_queue.header if t.task_name == "active.scan"]
    events = _Events()
    for task in tls_jobs:
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
    assert scan.id is not None


def test_web_tls_persists_chain_findings_and_details_under_scope_guard(
    db_session: Session,
) -> None:
    org, root, url_asset = _setup_url(db_session, verified=True)
    connector = _FakeTlsConnector(
        {
            "example.com": _der_cert(
                cn="other.example", san="other.example", days_offset_end=5, key_size=1024
            )
        }
    )

    _run_tls_check(db_session, org.id, root.id, connector)

    db_session.expire_all()
    refreshed = db_session.get_one(Asset, url_asset.id)
    assert refreshed.details["tls"]["protocol"] == "TLSv1.3"
    assert refreshed.details["tls"]["legacy_protocols_accepted"] == ["TLSv1"]
    findings = db_session.scalars(scoped(Finding, org.id)).all()
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {
        "web.tls.cert_expiring",
        "web.tls.hostname_mismatch",
        "web.tls.untrusted_chain",
        "web.tls.weak_key",
        "web.tls.legacy_protocol",
    }
    assert by_rule["web.tls.cert_expiring"].severity is Severity.HIGH
    assert by_rule["web.tls.legacy_protocol"].severity is Severity.MEDIUM
    ev = db_session.scalars(
        scoped(Evidence, org.id).where(Evidence.finding_id == by_rule["web.tls.weak_key"].id)
    ).one()
    assert ev.data["chain"][0]["key_size"] == 1024


def test_web_tls_skips_unverified_url_without_handshakes(db_session: Session) -> None:
    org, root, _ = _setup_url(db_session, verified=False)
    connector = _FakeTlsConnector({})

    _run_tls_check(db_session, org.id, root.id, connector)

    assert connector.calls == []
    tls_job = db_session.scalars(scoped(Job, org.id).where(Job.scanner == "web.tls")).one()
    assert tls_job.status is JobStatus.SKIPPED
    assert db_session.scalars(scoped(Finding, org.id)).all() == []
