"""The real `dns.resolve` scanner through `run_check`, with fake adapters and no network."""

from collections.abc import Sequence
from datetime import timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.events import DomainEvent, FindingCreated
from attacksurf.domain.net import (
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpBody,
    IpInfo,
    ScannerRuntime,
)
from attacksurf.domain.scanners import AssetRef, ScanContext, Scanner
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Asset, AssetRelation, Finding, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.scanners.dns import resolve as _resolve  # noqa: F401
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services.assets import record_asset
from attacksurf.services.scanner_jobs import run_check
from tests.integration.factories import make_scan

ROOT = "acme.example"
ASSET = "www.acme.example"


class FakeDns:
    def __init__(
        self,
        answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] | None = None,
        *,
        errors: set[tuple[str, DnsRecordType]] | None = None,
        default_status: DnsStatus = DnsStatus.NO_ANSWER,
    ) -> None:
        self.answers = answers or {}
        self.errors = errors or set()
        self.default_status = default_status

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.resolve must use lookup_many")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.resolve must use lookup_many")

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        results = []
        for query in queries:
            key = (query.name, query.record_type)
            if key in self.errors:
                results.append(DnsLookup(query, (), DnsStatus.ERROR))
                continue
            outcome = self.answers.get(key, self.default_status)
            if isinstance(outcome, DnsStatus):
                results.append(DnsLookup(query, (), outcome))
            else:
                results.append(DnsLookup(query, outcome, DnsStatus.OK))
        return tuple(results)


class FakeHttp:
    def get(self, url: str, *, limit: int) -> HttpBody:
        raise AssertionError("dns.resolve must not use HTTP")

    def close(self) -> None:
        pass


class FakeIntel:
    def lookup(self, address: str) -> IpInfo | None:
        if address == "93.184.216.34":
            return IpInfo(asn=13335, org="CLOUDFLARENET", country="US")
        return None


class FakeGate:
    def __init__(self, runtime: ScannerRuntime) -> None:
        self.runtime = runtime

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        return self.runtime


class Events:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)


def _job(session: Session, scan: Scan, asset_id: UUID) -> Job:
    job = Job(
        org_id=scan.org_id,
        scan_id=scan.id,
        asset_id=asset_id,
        stage="check",
        scanner="dns.resolve",
        status=JobStatus.RUNNING,
    )
    session.add(job)
    session.commit()
    return job


def test_dns_resolve_persists_records_and_graph(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    job = _job(db_session, scan, root.id)
    runtime = ScannerRuntime(
        FakeDns(
            {
                (ROOT, DnsRecordType.CNAME): ("cdn.acme.example.",),
                ("cdn.acme.example", DnsRecordType.A): ("93.184.216.34",),
                (ROOT, DnsRecordType.TXT): ("v=spf1 -all",),
            }
        ),
        FakeHttp(),
        ip_intel=FakeIntel(),
    )
    events = Events()

    run_check(
        db_session,
        scan.org_id,
        job.id,
        registry=registry,
        gate=FakeGate(runtime),
        events=events,
        retry_allowed=False,
        profiles=PROFILES,
    )

    db_session.expire_all()
    assert job.status is JobStatus.COMPLETED
    assert root.details["dns"]["cname_chain"] == [ROOT, "cdn.acme.example"]
    assert root.details["dns"]["a"] == ["93.184.216.34"]
    assert root.details["dns"]["txt"] == ["v=spf1 -all"]
    assets = {row.value: row for row in db_session.scalars(scoped(Asset, scan.org_id))}
    assert set(assets) == {ROOT, "cdn.acme.example", "93.184.216.34"}
    assert assets["cdn.acme.example"].type is AssetType.SUBDOMAIN
    assert assets["93.184.216.34"].type is AssetType.IP
    relations = db_session.scalars(scoped(AssetRelation, scan.org_id)).all()
    assert {(rel.kind, rel.from_asset_id, rel.to_asset_id) for rel in relations} == {
        (RelationKind.CNAME_TO, root.id, assets["cdn.acme.example"].id),
        (RelationKind.RESOLVES_TO, root.id, assets["93.184.216.34"].id),
    }
    assert not any(isinstance(event, FindingCreated) for event in events.events)


def test_dns_resolve_deactivates_a_non_resolving_subdomain(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    subdomain = record_asset(
        db_session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        ASSET,
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    seen = subdomain.last_seen + timedelta(minutes=1)
    scan.started_at = seen
    db_session.flush()
    job = _job(db_session, scan, subdomain.id)
    runtime = ScannerRuntime(FakeDns(default_status=DnsStatus.NXDOMAIN), FakeHttp())
    events = Events()

    run_check(
        db_session,
        scan.org_id,
        job.id,
        registry=registry,
        gate=FakeGate(runtime),
        events=events,
        retry_allowed=False,
        profiles=PROFILES,
    )

    db_session.expire_all()
    assert job.status is JobStatus.COMPLETED
    assert (subdomain.is_active, subdomain.deactivated_at) == (False, seen)
    assert db_session.scalars(scoped(Finding, scan.org_id)).all() == []


def test_dns_resolve_preserves_details_when_a_record_query_fails(
    db_session: Session,
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    previous = {"dns": {"a": ["93.184.216.1"], "mx": ["10 mail.acme.example"]}}
    root.details = previous
    db_session.flush()
    job = _job(db_session, scan, root.id)
    runtime = ScannerRuntime(
        FakeDns(
            {(ROOT, DnsRecordType.A): ("93.184.216.34",)},
            errors={(ROOT, DnsRecordType.MX)},
            default_status=DnsStatus.NXDOMAIN,
        ),
        FakeHttp(),
    )

    run_check(
        db_session,
        scan.org_id,
        job.id,
        registry=registry,
        gate=FakeGate(runtime),
        events=Events(),
        retry_allowed=False,
        profiles=PROFILES,
    )

    db_session.expire_all()
    assert job.status is JobStatus.COMPLETED
    assert root.details == previous
