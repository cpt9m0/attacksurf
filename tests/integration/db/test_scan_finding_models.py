"""Database-level guarantees of scans, jobs, findings and evidence (independent of services)."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import (
    Confidence,
    EvidenceKind,
    FindingStatus,
    Severity,
    finding_fingerprint,
)
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Evidence, Finding, Job, Org, Scan
from attacksurf.infra.db.tenancy import scoped

NOW = datetime(2026, 10, 1, tzinfo=UTC)


@dataclass
class Tenant:
    org: Org
    root: Asset


def _tenant(session: Session, name: str) -> Tenant:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    root = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,
        value=f"{name}.example",
        source=AssetSource.USER,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(root)
    session.flush()
    return Tenant(org, root)


@pytest.fixture
def acme(db_session: Session) -> Tenant:
    return _tenant(db_session, "acme")


@pytest.fixture
def globex(db_session: Session) -> Tenant:
    return _tenant(db_session, "globex")


def _scan(t: Tenant, **kw: object) -> Scan:
    values: dict[str, object] = {
        "org_id": t.org.id,
        "root_asset_id": t.root.id,
        "profile": "dns_passive",
        "status": ScanStatus.QUEUED,
        "triggered_by": ScanTrigger.USER,
    }
    return Scan(**(values | kw))


def _job(t: Tenant, scan: Scan, **kw: object) -> Job:
    values: dict[str, object] = {
        "org_id": t.org.id,
        "scan_id": scan.id,
        "stage": "checks",
        "status": JobStatus.QUEUED,
    }
    return Job(**(values | kw))


def _finding(t: Tenant, rule_id: str = "dns.email.dmarc_missing", **kw: object) -> Finding:
    asset_id = kw.pop("asset_id", t.root.id)
    assert isinstance(asset_id, type(t.root.id))
    values: dict[str, object] = {
        "org_id": t.org.id,
        "asset_id": asset_id,
        "rule_id": rule_id,
        "fingerprint": finding_fingerprint(t.org.id, asset_id, rule_id),
        "title": "No DMARC record",
        "description": "The domain publishes no DMARC policy.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "first_seen": NOW,
        "last_seen": NOW,
    }
    return Finding(**(values | kw))


def _add(session: Session, *rows: object) -> None:
    session.add_all(rows)
    session.flush()


def test_full_scan_result_round_trips(db_session: Session, acme: Tenant) -> None:
    scan = _scan(acme)
    _add(db_session, scan)
    job = _job(acme, scan, asset_id=acme.root.id, scanner="dns.email", attempts=1)
    finding = _finding(
        acme,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
        references=["https://www.rfc-editor.org/rfc/rfc7489"],
        ai_triage={"priority": 1},
    )
    _add(db_session, job, finding)
    evidence = Evidence(
        org_id=acme.org.id,
        finding_id=finding.id,
        kind=EvidenceKind.DNS_RECORD,
        data={"name": "_dmarc.acme.example", "type": "TXT", "answers": []},
        captured_at=NOW,
    )
    _add(db_session, evidence)
    db_session.expire_all()

    stored = db_session.get_one(Finding, finding.id)
    assert (stored.status, stored.location, stored.remediation, stored.fixed_at) == (
        FindingStatus.OPEN,
        "",
        "",
        None,
    )
    assert stored.references == ["https://www.rfc-editor.org/rfc/rfc7489"]
    assert db_session.get_one(Scan, scan.id).stats == {}
    assert db_session.get_one(Job, job.id).status == JobStatus.QUEUED
    assert db_session.get_one(Evidence, evidence.id).data["type"] == "TXT"


def test_fingerprint_is_unique_per_org(db_session: Session, acme: Tenant) -> None:
    db_session.add_all([_finding(acme), _finding(acme)])

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_same_fingerprint_in_two_orgs_is_two_findings(
    db_session: Session, acme: Tenant, globex: Tenant
) -> None:
    shared = "f" * 64

    _add(db_session, _finding(acme, fingerprint=shared), _finding(globex, fingerprint=shared))

    assert len(db_session.scalars(select(Finding)).all()) == 2


def test_rediscovered_issue_maps_to_the_existing_finding(db_session: Session, acme: Tenant) -> None:
    first_scan, second_scan = _scan(acme), _scan(acme)
    _add(db_session, first_scan, second_scan)
    _add(db_session, _finding(acme, first_seen_scan_id=first_scan.id))
    fingerprint = finding_fingerprint(acme.org.id, acme.root.id, "dns.email.dmarc_missing")

    found = db_session.scalars(
        scoped(Finding, acme.org.id).where(Finding.fingerprint == fingerprint)
    ).one()

    assert found.first_seen_scan_id == first_scan.id


@pytest.mark.parametrize(
    "link", ["scan_root", "job_scan", "job_asset", "finding_asset", "finding_scan", "evidence"]
)
def test_links_to_another_orgs_rows_are_rejected(
    db_session: Session, acme: Tenant, globex: Tenant, link: str
) -> None:
    own_scan, foreign_scan = _scan(acme), _scan(globex)
    foreign_finding = _finding(globex)
    _add(db_session, own_scan, foreign_scan)
    _add(db_session, foreign_finding)
    rows: dict[str, object] = {
        "scan_root": _scan(acme, root_asset_id=globex.root.id),
        "job_scan": _job(acme, foreign_scan),
        "job_asset": _job(acme, own_scan, asset_id=globex.root.id),
        "finding_asset": _finding(acme, asset_id=globex.root.id),
        "finding_scan": _finding(acme, last_seen_scan_id=foreign_scan.id),
        "evidence": Evidence(
            org_id=acme.org.id,
            finding_id=foreign_finding.id,
            kind=EvidenceKind.RAW,
            data={},
            captured_at=NOW,
        ),
    }
    db_session.add(rows[link])

    with pytest.raises(IntegrityError):
        db_session.flush()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE findings SET status = 'fixed'",  # fixed without fixed_at
        "UPDATE findings SET fixed_at = now()",  # fixed_at while open
        "UPDATE findings SET last_seen = first_seen - interval '1 day'",
        "UPDATE findings SET severity = 'urgent'",
        "UPDATE findings SET confidence = 'certain'",
        "UPDATE findings SET status = 'ignored'",
        "UPDATE scans SET status = 'paused'",
        "UPDATE scans SET triggered_by = 'api'",
        "UPDATE scans SET started_at = now(), finished_at = now() - interval '1 hour'",
        "UPDATE jobs SET status = 'lost'",
        "UPDATE jobs SET attempts = -1",
        "UPDATE jobs SET started_at = now(), finished_at = now() - interval '1 hour'",
        "UPDATE evidence SET kind = 'screenshot'",
    ],
)
def test_invariants_are_enforced_by_database(
    db_session: Session, acme: Tenant, statement: str
) -> None:
    scan = _scan(acme)
    _add(db_session, scan)
    finding = _finding(acme)
    _add(db_session, _job(acme, scan), finding)
    _add(
        db_session,
        Evidence(
            org_id=acme.org.id,
            finding_id=finding.id,
            kind=EvidenceKind.RAW,
            data={},
            captured_at=NOW,
        ),
    )

    with pytest.raises(IntegrityError):
        db_session.execute(text(statement))


def test_fixed_finding_records_when(db_session: Session, acme: Tenant) -> None:
    finding = _finding(acme, status=FindingStatus.FIXED, fixed_at=NOW + timedelta(days=1))

    _add(db_session, finding)

    assert finding.fixed_at == NOW + timedelta(days=1)


def test_deleting_a_scan_keeps_findings_and_job_history_of_assets(
    db_session: Session, acme: Tenant
) -> None:
    scan = _scan(acme)
    _add(db_session, scan)
    finding = _finding(acme, first_seen_scan_id=scan.id, last_seen_scan_id=scan.id)
    _add(db_session, finding, _job(acme, scan))

    db_session.execute(delete(Scan).where(Scan.id == scan.id))
    db_session.expire_all()

    kept = db_session.get_one(Finding, finding.id)
    assert (kept.first_seen_scan_id, kept.last_seen_scan_id, kept.org_id) == (
        None,
        None,
        acme.org.id,
    )
    assert db_session.scalars(select(Job)).all() == []


def test_deleting_an_asset_keeps_jobs_but_drops_its_findings(
    db_session: Session, acme: Tenant
) -> None:
    child = Asset(
        org_id=acme.org.id,
        type=AssetType.SUBDOMAIN,
        value="www.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=acme.root.id,
        first_seen=NOW,
        last_seen=NOW,
    )
    scan = _scan(acme)
    _add(db_session, child, scan)
    job = _job(acme, scan, asset_id=child.id)
    finding = _finding(acme, asset_id=child.id)
    _add(db_session, job, finding)
    _add(
        db_session,
        Evidence(
            org_id=acme.org.id,
            finding_id=finding.id,
            kind=EvidenceKind.RAW,
            data={},
            captured_at=NOW,
        ),
    )

    db_session.execute(delete(Asset).where(Asset.id == child.id))
    db_session.expire_all()

    assert db_session.get_one(Job, job.id).asset_id is None
    assert db_session.scalars(select(Finding)).all() == []
    assert db_session.scalars(select(Evidence)).all() == []


def test_deleting_a_root_asset_removes_its_scans_and_jobs(
    db_session: Session, acme: Tenant
) -> None:
    scan = _scan(acme)
    _add(db_session, scan)
    _add(db_session, _job(acme, scan))

    db_session.execute(delete(Asset).where(Asset.id == acme.root.id))
    db_session.expunge_all()

    assert db_session.scalars(select(Scan)).all() == []
    assert db_session.scalars(select(Job)).all() == []


def test_scan_results_are_tenant_isolated(
    db_session: Session, acme: Tenant, globex: Tenant
) -> None:
    acme_scan, globex_scan = _scan(acme), _scan(globex)
    _add(db_session, acme_scan, globex_scan)
    _add(
        db_session,
        _finding(acme),
        _finding(globex),
        _job(acme, acme_scan),
        _job(globex, globex_scan),
    )

    for model in (Scan, Job, Finding):
        rows = db_session.scalars(scoped(model, acme.org.id)).all()
        assert {row.org_id for row in rows} == {acme.org.id}
