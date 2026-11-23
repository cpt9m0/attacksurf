"""Performance sanity (#30): a ~1k CT subdomain `dns_passive` scan completes within limits."""

import json
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest
from celery.backends.cache import CacheBackend
from sqlalchemy import Engine, delete
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.net import HttpBody
from attacksurf.domain.rules import RULES
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.infra.db.models import Asset, Finding, Job, Org, Scan
from attacksurf.infra.db.session import create_session_factory
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.events import InProcessDispatcher
from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.infra.rdap import IANA_BOOTSTRAP_URL
from attacksurf.infra.scope_guard import ScopeGuard, UnverifiedOwnership
from attacksurf.scanners.profiles import MAX_DISCOVERED_ASSETS, WORKER_PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services import scan_views, scans, summary
from attacksurf.services.assets import add_root_domain
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import pipeline
from tests.dns_fakes import FakeScopeHttp, MutableDnsZone, patch_dnspython_wire
from tests.fakes import FakeCache, FakeQueue
from tests.integration.factories import make_org

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dns" / "whois"
DOMAIN = "scale-test.example.com"
CT_ENTRIES = 1200  # above MAX_DISCOVERED_ASSETS (1000) to exercise the cap end to end
SCALE_BUDGET_SECONDS = 60.0


def _build_zone_and_http() -> tuple[MutableDnsZone, FakeScopeHttp]:
    zone = MutableDnsZone()
    zone.set_records(DOMAIN, "A", ["93.184.216.34"])
    zone.set_records(DOMAIN, "NS", [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"])
    zone.set_records(f"ns1.{DOMAIN}", "A", ["93.184.216.10"])
    zone.set_records(f"ns2.{DOMAIN}", "A", ["93.184.216.11"])
    soa = f"ns1.{DOMAIN}. hostmaster.{DOMAIN}. 2026112201 3600 600 604800 300"
    zone.set_records(DOMAIN, "SOA", [soa])
    zone.set_records(DOMAIN, "TXT", ["v=spf1 -all"])
    zone.set_records(f"_dmarc.{DOMAIN}", "TXT", [f"v=DMARC1; p=reject; rua=mailto:dmarc@{DOMAIN}"])
    zone.set_records(DOMAIN, "CAA", ['0 issue "letsencrypt.org"'])
    zone.set_records(f"default._domainkey.{DOMAIN}", "TXT", ["v=DKIM1; k=rsa; p=MIIBIjAN"])

    ct_payload = [
        {"name_value": f"h{i:04d}.{DOMAIN}", "common_name": f"h{i:04d}.{DOMAIN}"}
        for i in range(CT_ENTRIES)
    ]
    for i in range(MAX_DISCOVERED_ASSETS):
        sub = f"h{i:04d}.{DOMAIN}"
        # Every subdomain shares two backend IPs so IP asset rows stay bounded and realistic.
        zone.set_records(sub, "A", [f"93.184.216.{100 + (i % 4)}"])

    bootstrap = (FIXTURES / "iana_bootstrap.json").read_text(encoding="utf-8")
    rdap = json.dumps(
        {
            "objectClassName": "domain",
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
        }
    )
    http = FakeScopeHttp(
        {
            f"https://crt.sh/?q=%25.{DOMAIN}&output=json": HttpBody(
                200, json.dumps(ct_payload).encode()
            ),
            IANA_BOOTSTRAP_URL: HttpBody(200, bootstrap.encode()),
            "https://rdap.verisign.com/com/v1/domain/example.com": HttpBody(200, rdap.encode()),
        },
        resolver=zone,
    )
    zone.set_records("crt.sh", "A", ["93.184.216.50"])
    zone.set_records("data.iana.org", "A", ["93.184.216.51"])
    zone.set_records("rdap.verisign.com", "A", ["93.184.216.52"])
    return zone, http


@pytest.fixture
def scale_env(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[sessionmaker[Session], MutableDnsZone, list[str]]]:
    zone, http = _build_zone_and_http()
    patch_dnspython_wire(monkeypatch, zone)
    sent: list[str] = []

    class RecordingQueue(CeleryTaskQueue):
        def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
            sent.append(task_name)
            return "task-scale-1"

    # Real per-job sessions rather than a single-connection savepoint fixture: ~3k savepoints in one
    # Postgres transaction overflow PGPROC subxid caches and distort scale timing.
    factory = create_session_factory(db_engine)
    with db_engine.begin() as conn:
        conn.execute(delete(Org).where(Org.slug == "scale-org"))
    monkeypatch.setattr(pipeline, "CeleryTaskQueue", RecordingQueue)
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    monkeypatch.setattr(
        runtime,
        "scanner_gate",
        lambda: ScopeGuard(
            dns=zone,
            http=http,
            ownership=UnverifiedOwnership(),
            cache=FakeCache(),
        ),
    )
    monkeypatch.setattr(pipeline, "registry", registry)
    monkeypatch.setattr(pipeline, "WORKER_PROFILES", WORKER_PROFILES)
    monkeypatch.setattr(pipeline, "RULES", RULES)
    monkeypatch.setattr(pipeline, "dispatcher", InProcessDispatcher())
    monkeypatch.setitem(app.conf, "task_always_eager", True)
    monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    monkeypatch.setattr(
        app.__dict__["_local"], "backend", CacheBackend(app=app, backend="memory"), raising=False
    )
    try:
        yield factory, zone, sent
    finally:
        with db_engine.begin() as conn:
            conn.execute(delete(Org).where(Org.slug == "scale-org"))


def test_1k_subdomain_scan_completes_within_limits(
    scale_env: tuple[sessionmaker[Session], MutableDnsZone, list[str]],
) -> None:
    factory, _zone, sent = scale_env
    with factory() as session:
        org = make_org(session, "scale-org")
        org_id = org.id
        root = add_root_domain(session, org_id, DOMAIN, actor_id=None)
        started = time.monotonic()
        scan = scans.start_scan(
            session,
            FakeQueue(session),
            org_id=org_id,
            root_asset_id=root.id,
            profile="dns_passive",
            registry=registry,
            profiles=WORKER_PROFILES,
        )
        kickoff = session.scalars(scoped(Job, org_id).where(Job.scan_id == scan.id)).one()
        scan_id = scan.id
        root_id = root.id
        kickoff_id = kickoff.id
        session.commit()

    pipeline.discover.apply(kwargs={"org_id": str(org_id), "job_id": str(kickoff_id)})
    elapsed = time.monotonic() - started

    with factory() as session:
        stored_scan = session.get_one(Scan, scan_id)
        assert stored_scan.status is ScanStatus.COMPLETED
        assert elapsed < SCALE_BUDGET_SECONDS, f"1k subdomain scan took {elapsed:.2f}s"

        subdomains = session.scalars(
            scoped(Asset, org_id).where(
                Asset.parent_id == root_id,
                Asset.type == AssetType.SUBDOMAIN,
                Asset.source == AssetSource.DISCOVERED,
            )
        ).all()
        assert len(subdomains) == MAX_DISCOVERED_ASSETS

        failed_jobs = session.scalars(
            scoped(Job, org_id).where(Job.scan_id == scan_id, Job.status == JobStatus.FAILED)
        ).all()
        assert failed_jobs == []

        # Active checks (takeover.http, axfr) are cleanly skipped without verified ownership, and
        # finalize skips the unused pipeline `failure` sentinel job.
        skipped_jobs = session.scalars(
            scoped(Job, org_id).where(Job.scan_id == scan_id, Job.status == JobStatus.SKIPPED)
        ).all()
        skipped_checks = [j for j in skipped_jobs if j.stage == "check"]
        assert len(skipped_checks) == MAX_DISCOVERED_ASSETS + 2  # root+1000 takeover.http + axfr
        assert len(skipped_jobs) == MAX_DISCOVERED_ASSETS + 3

        assert stored_scan.stats["assets"]["new"]["total"] == MAX_DISCOVERED_ASSETS
        assert len(stored_scan.stats["assets"]["new"]["assets"]) == MAX_DISCOVERED_ASSETS

        detail = scan_views.get_scan_detail(session, org_id, scan_id)
        assert detail.jobs_total > scan_views.MAX_DETAIL_JOBS
        assert len(detail.jobs) == scan_views.MAX_DETAIL_JOBS
        assert detail.jobs_truncated is True
        assert detail.jobs_finished == detail.jobs_total
        assert detail.diff is not None
        assert detail.diff.new_assets.total == MAX_DISCOVERED_ASSETS
        assert len(detail.diff.new_assets.assets) == scan_views.MAX_DIFF_ASSETS
        assert detail.diff.new_assets.truncated is True

        summary_input = summary.build_summary_input(session, org_id, scan_id)
        assert len(summary_input.assets) == 200
        assert len(summary_input.findings) <= 25
        assert sent == ["ai.triage"]
        assert session.scalars(scoped(Finding, org_id)).all() is not None
