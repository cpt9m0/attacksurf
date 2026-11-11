"""The real CT scanner through `run_check`, with fixture sources and no network."""

import json
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.events import DomainEvent
from attacksurf.domain.net import HttpBody, ScannerRuntime
from attacksurf.domain.scanners import AssetRef, ScanContext, Scanner
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Asset, AssetRelation, Job
from attacksurf.infra.db.tenancy import scoped
from attacksurf.scanners.dns.discovery import CACHE_TTL_SECONDS
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services.scanner_jobs import run_check
from tests.fakes import FakeCache
from tests.integration.factories import make_scan

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dns" / "discovery"
ROOT = "acme.example"


class FakeDns:
    def __init__(self, wildcards: set[str]) -> None:
        self.wildcards = wildcards

    def resolve_name(self, host: str) -> tuple[str, ...]:
        _label, _, zone = host.partition(".")
        return ("93.184.216.34",) if zone in self.wildcards else ()

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return self.resolve_name(host)


class FakeHttp:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.calls.append(url)
        content = (FIXTURES / "crt_sh_example.json").read_bytes()
        return HttpBody(status_code=200, content=content)

    def close(self) -> None:
        pass


class FakeGate:
    def __init__(self, dns: FakeDns, http: FakeHttp, cache: FakeCache) -> None:
        self.runtime = ScannerRuntime(dns, http, cache=cache)

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        return self.runtime


class NoEvents:
    def publish(self, event: DomainEvent) -> None:
        raise AssertionError(f"unexpected event {event}")


@pytest.fixture
def ct_scan(db_session: Session) -> tuple[UUID, Job, UUID, FakeHttp, FakeCache]:
    scan = make_scan(db_session, name="acme")
    root = db_session.get_one(Asset, scan.root_asset_id)
    job = Job(
        org_id=scan.org_id,
        scan_id=scan.id,
        asset_id=root.id,
        stage="discovery",
        scanner="dns.discovery.ct",
        status=JobStatus.RUNNING,
    )
    db_session.add(job)
    db_session.commit()  # run_check rolls back to release locks before doing I/O
    http = FakeHttp()
    cache = FakeCache()
    return scan.org_id, job, root.id, http, cache


def test_ct_scan_persists_subdomains_relations_wildcards_and_cache(
    db_session: Session, ct_scan: tuple[UUID, Job, UUID, FakeHttp, FakeCache]
) -> None:
    org_id, job, root_id, http, cache = ct_scan
    gate = FakeGate(FakeDns({ROOT, "dev.acme.example"}), http, cache)
    job_id = job.id

    run_check(
        db_session,
        org_id,
        job_id,
        registry=registry,
        gate=gate,
        events=NoEvents(),  # type: ignore[arg-type]
        retry_allowed=False,
        profiles=PROFILES,
    )

    job = db_session.get_one(Job, job_id)
    assert job.status is JobStatus.COMPLETED
    assets = {
        row.value: row
        for row in db_session.scalars(
            scoped(Asset, org_id).where(Asset.source == AssetSource.DISCOVERED)
        )
    }
    assert set(assets) == {
        "api.acme.example",
        "certspotter.acme.example",
        "dev.acme.example",
        "mail.acme.example",
        "www.acme.example",
        "xn--bcher-kva.acme.example",
    }
    root = db_session.get_one(Asset, root_id)
    assert root.details == {"wildcard": True}
    assert assets["dev.acme.example"].details == {"wildcard": True}
    relations = db_session.scalars(scoped(AssetRelation, org_id)).all()
    assert len(relations) == len(assets)
    assert all(relation.kind is RelationKind.SUBDOMAIN_OF for relation in relations)
    assert len(http.calls) == 1
    cached = json.loads(cache.values[f"ct:v1:{ROOT}"])
    assert "www.acme.example" in cached["names"]
    assert cache.ttls[f"ct:v1:{ROOT}"] == CACHE_TTL_SECONDS
    assert assets["www.acme.example"].type is AssetType.SUBDOMAIN
