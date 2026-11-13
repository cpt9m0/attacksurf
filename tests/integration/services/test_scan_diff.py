"""Finding lifecycle and asset diffing: fixed, regressed, stats (issue #20, ADR 0027)."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.events import FindingCreated, FindingFixed, FindingRegressed, FindingReopened
from attacksurf.domain.findings import Confidence, FindingStatus, Severity
from attacksurf.domain.jobs import JobNotFound
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import RawFinding, ScanOutput
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Finding, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.events import InProcessDispatcher
from attacksurf.services import assets as assets_service
from attacksurf.services.scan_diff import diff_scan
from attacksurf.services.scan_results import persist_scan_output
from tests.integration.factories import make_scan

BASE = datetime(2026, 11, 1, tzinfo=UTC)
SCANNER = "test.scanner"
OTHER_SCANNER = "test.other"
DISCOVERY = "test.discovery"
RULE_A = Rule("test.fixture.alpha", "Alpha", "Alpha description", Severity.MEDIUM, "Fix $domain")
RULE_B = Rule("test.fixture.beta", "Beta", "Beta description", Severity.HIGH, "Fix $domain")
CATALOG = {RULE_A.id: RULE_A, RULE_B.id: RULE_B}


def _scan(
    session: Session,
    tenant: Scan,
    hours: int,
    *,
    status: ScanStatus = ScanStatus.RUNNING,
) -> Scan:
    scan = Scan(
        org_id=tenant.org_id,
        root_asset_id=tenant.root_asset_id,
        profile="dns_passive",
        status=status,
        triggered_by=ScanTrigger.USER,
        started_at=BASE + timedelta(hours=hours),
    )
    session.add(scan)
    session.flush()
    return scan


def _complete(session: Session, scan: Scan) -> None:
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = scan.started_at
    session.flush()


def _job(
    session: Session,
    scan: Scan,
    *,
    scanner: str = SCANNER,
    stage: str = "check",
    status: JobStatus = JobStatus.COMPLETED,
    asset_id: UUID | None = None,
) -> Job:
    job = Job(
        org_id=scan.org_id,
        scan_id=scan.id,
        stage=stage,
        scanner=scanner,
        asset_id=asset_id or scan.root_asset_id,
        status=status,
    )
    session.add(job)
    session.flush()
    return job


def _observe(
    session: Session,
    scan: Scan,
    *,
    rule: Rule = RULE_A,
    scanner: str = SCANNER,
    confidence: Confidence = Confidence.HIGH,
    severity: Severity | None = None,
) -> list[FindingCreated | FindingReopened]:
    raw = RawFinding(
        rule_id=rule.id, severity=severity, confidence=confidence, location=f"loc-{rule.id}"
    )
    return persist_scan_output(
        session,
        scan,
        scan.root_asset_id,
        ScanOutput(findings=(raw,)),
        catalog=CATALOG,
        scanner=scanner,
    )


def _diff(session: Session, scan: Scan) -> list[object]:
    # The `persist` barrier commits every scanner result before this stage runs.
    session.commit()
    dispatcher = InProcessDispatcher()
    received: list[object] = []
    dispatcher.handlers.append(received.append)
    job = _job(session, scan, stage="diff")
    diff_scan(session, scan.org_id, job.id, dispatcher)
    return received


def _bucket(total: int, **by_severity: int) -> dict[str, object]:
    severities = {severity.value: 0 for severity in Severity}
    severities.update(by_severity)
    return {"total": total, "by_severity": severities}


def _finding(session: Session, org_id: UUID, rule: Rule) -> Finding:
    return session.scalars(scoped(Finding, org_id).where(Finding.rule_id == rule.id)).one()


def test_diff_fixes_a_finding_its_scanner_did_not_reobserve(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)

    events = _diff(db_session, second)

    finding = _finding(db_session, tenant.org_id, RULE_A)
    assert finding.status is FindingStatus.FIXED
    assert finding.fixed_at is not None
    assert [type(event) for event in events] == [FindingFixed]
    assert second.stats["findings"]["fixed"] == _bucket(1, medium=1)
    assert second.stats["findings"]["new"] == _bucket(0)


@pytest.mark.parametrize(
    "coverage",
    ["failed", "skipped", "other_scanner", "no_job", "other_asset"],
    ids=["failed", "skipped", "different-scanner", "no-job", "different-asset"],
)
def test_diff_never_fixes_without_its_own_scanner_completing(
    db_session: Session, coverage: str
) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    if coverage == "failed":
        _job(db_session, second, status=JobStatus.FAILED)
    elif coverage == "skipped":
        _job(db_session, second, status=JobStatus.SKIPPED)
    elif coverage == "other_scanner":
        _job(db_session, second, scanner=OTHER_SCANNER)
    elif coverage == "other_asset":
        child = assets_service.record_asset(
            db_session,
            tenant.org_id,
            AssetType.SUBDOMAIN,
            "www.acme.example",
            source=AssetSource.DISCOVERED,
            parent_id=tenant.root_asset_id,
        )
        _job(db_session, second, asset_id=child.id)

    events = _diff(db_session, second)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.OPEN
    assert events == []
    assert second.stats["findings"]["fixed"] == _bucket(0)


def test_diff_never_fixes_a_finding_without_provenance(db_session: Session) -> None:
    """Rows written before #20 (or by a caller that names no scanner) have unknown coverage."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    persist_scan_output(
        db_session,
        first,
        first.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE_A.id),)),
        catalog=CATALOG,
    )
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)

    _diff(db_session, second)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.OPEN


def test_consecutive_scans_report_new_fixed_and_regressed_sets(db_session: Session) -> None:
    """Acceptance criterion: two consecutive fixture scans produce the right sets."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first, rule=RULE_A)
    _complete(db_session, first)

    second = _scan(db_session, tenant, 1)
    _job(db_session, second, scanner=SCANNER)
    _job(db_session, second, scanner=OTHER_SCANNER)
    _observe(db_session, second, rule=RULE_B, scanner=OTHER_SCANNER)
    _diff(db_session, second)
    _complete(db_session, second)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.FIXED
    assert _finding(db_session, tenant.org_id, RULE_B).status is FindingStatus.OPEN
    assert second.stats["findings"]["new"] == _bucket(1, high=1)
    assert second.stats["findings"]["fixed"] == _bucket(1, medium=1)
    assert second.stats["findings"]["regressed"] == _bucket(0)
    assert second.stats["findings"]["total"] == _bucket(1, high=1)

    third = _scan(db_session, tenant, 2)
    _job(db_session, third, scanner=SCANNER)
    _job(db_session, third, scanner=OTHER_SCANNER)
    _observe(db_session, third, rule=RULE_A)
    events = _diff(db_session, third)
    _complete(db_session, third)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.REGRESSED
    assert _finding(db_session, tenant.org_id, RULE_A).fixed_at is None
    assert _finding(db_session, tenant.org_id, RULE_B).status is FindingStatus.FIXED
    assert [type(event) for event in events] == [FindingFixed, FindingRegressed]
    assert third.stats["findings"]["new"] == _bucket(0)
    assert third.stats["findings"]["fixed"] == _bucket(1, high=1)
    assert third.stats["findings"]["regressed"] == _bucket(1, medium=1)
    assert third.stats["findings"]["total"] == _bucket(1, medium=1)


def test_diff_counts_a_finding_observed_after_a_later_scan_moved_the_pointer(
    db_session: Session,
) -> None:
    """Overlapping scans: the stats come from this scan's observations, not `last_seen_scan_id`."""
    tenant = make_scan(db_session)
    earlier = _scan(db_session, tenant, 1)
    _observe(db_session, earlier)
    later = _scan(db_session, tenant, 2)
    _observe(db_session, later)
    assert _finding(db_session, tenant.org_id, RULE_A).last_seen_scan_id == later.id

    _diff(db_session, earlier)

    assert earlier.stats["findings"]["new"] == _bucket(1, medium=1)
    assert earlier.stats["findings"]["total"] == _bucket(1, medium=1)


def test_a_regressed_finding_is_fixed_again_when_it_disappears(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)
    _diff(db_session, second)
    fixed_at = _finding(db_session, tenant.org_id, RULE_A).fixed_at

    third = _scan(db_session, tenant, 2)
    _job(db_session, third)
    _observe(db_session, third)
    _diff(db_session, third)
    _complete(db_session, third)
    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.REGRESSED

    fourth = _scan(db_session, tenant, 3)
    _job(db_session, fourth)
    _diff(db_session, fourth)

    finding = _finding(db_session, tenant.org_id, RULE_A)
    assert finding.status is FindingStatus.FIXED
    assert fixed_at is not None
    assert finding.fixed_at is not None


@pytest.mark.parametrize("status", [FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE])
def test_diff_never_fixes_suppressed_findings(db_session: Session, status: FindingStatus) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    finding = _finding(db_session, tenant.org_id, RULE_A)
    finding.status = status
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)

    events = _diff(db_session, second)

    assert finding.status is status
    assert events == []
    assert second.stats["findings"]["fixed"] == _bucket(0)


def test_diff_does_not_fix_a_finding_a_newer_scan_just_observed(db_session: Session) -> None:
    """A delayed older scan's diff must not fix what a newer scan already saw."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    newer = _scan(db_session, tenant, 5)
    _job(db_session, newer)
    _observe(db_session, newer)
    _complete(db_session, newer)
    older = _scan(db_session, tenant, 1)
    _job(db_session, older)

    _diff(db_session, older)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.OPEN


def test_diff_does_not_regress_a_fix_established_by_a_newer_scan(
    db_session: Session,
) -> None:
    """A delayed positive from an older scan must not undo a newer scan's fix."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    newer = _scan(db_session, tenant, 2)
    _job(db_session, newer)
    _diff(db_session, newer)
    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.FIXED

    older = _scan(db_session, tenant, 1)
    _job(db_session, older)
    _observe(db_session, older)
    events = _diff(db_session, older)

    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.FIXED
    assert events == []


def test_diff_does_not_report_disappeared_ips(db_session: Session) -> None:
    """IPs are excluded: a failed resolution leaves their last_seen stale without deactivating."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _job(db_session, first, scanner=DISCOVERY, stage="discovery")
    address = _child(db_session, tenant, "203.0.113.10", BASE, AssetType.IP)
    gone = _child(db_session, tenant, "a.acme.example", BASE)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second, scanner=DISCOVERY, stage="discovery")
    for asset in (address, gone):
        asset.is_active = False
        asset.deactivated_at = BASE + timedelta(hours=1)
    db_session.flush()

    _diff(db_session, second)

    disappeared = second.stats["assets"]["disappeared"]
    assert disappeared["total"] == 1
    assert [item["value"] for item in disappeared["assets"]] == ["a.acme.example"]


def _child(
    session: Session,
    tenant: Scan,
    value: str,
    seen: datetime,
    asset_type: AssetType = AssetType.SUBDOMAIN,
) -> Asset:
    return assets_service.record_asset(
        session,
        tenant.org_id,
        asset_type,
        value,
        source=AssetSource.DISCOVERED,
        parent_id=tenant.root_asset_id,
        seen_at=seen,
    )


def test_diff_reports_new_and_disappeared_assets(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _job(db_session, first, scanner=DISCOVERY, stage="discovery")
    gone = _child(db_session, tenant, "a.acme.example", BASE)
    _child(db_session, tenant, "b.acme.example", BASE)
    _complete(db_session, first)

    second = _scan(db_session, tenant, 1)
    _job(db_session, second, scanner=DISCOVERY, stage="discovery")
    _child(db_session, tenant, "c.acme.example", BASE + timedelta(hours=1))
    _child(db_session, tenant, "b.acme.example", BASE + timedelta(hours=1))
    _child(db_session, tenant, "203.0.113.10", BASE + timedelta(hours=1), AssetType.IP)
    # This scan's resolver found `a` no longer resolves; that is the disappearance verdict.
    gone.is_active = False
    gone.deactivated_at = BASE + timedelta(hours=1)
    db_session.flush()
    _diff(db_session, second)

    assets = second.stats["assets"]
    assert assets["new"]["total"] == 2
    assert [(item["type"], item["value"]) for item in assets["new"]["assets"]] == [
        ("ip", "203.0.113.10"),
        ("subdomain", "c.acme.example"),
    ]
    assert assets["disappeared"]["total"] == 1
    assert [item["value"] for item in assets["disappeared"]["assets"]] == ["a.acme.example"]
    assert all(set(item) == {"id", "type", "value"} for item in assets["new"]["assets"])


def test_first_scan_reports_no_disappeared_assets(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _job(db_session, first, scanner=DISCOVERY, stage="discovery")
    _child(db_session, tenant, "a.acme.example", BASE)

    _diff(db_session, first)

    assert first.stats["assets"]["new"]["total"] == 1
    assert first.stats["assets"]["disappeared"] == {"total": 0, "assets": []}


def test_diff_does_not_report_assets_that_still_resolve(db_session: Session) -> None:
    """Stale `last_seen` alone is not evidence: only a resolution verdict deactivates an asset."""
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _job(db_session, first, scanner=DISCOVERY, stage="discovery")
    _child(db_session, tenant, "a.acme.example", BASE)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second, scanner=DISCOVERY, stage="discovery")

    _diff(db_session, second)

    assert second.stats["assets"]["disappeared"] == {"total": 0, "assets": []}


def test_redelivered_diff_changes_nothing(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)
    _diff(db_session, second)
    stats = dict(second.stats)
    fixed_at = _finding(db_session, tenant.org_id, RULE_A).fixed_at

    events = _diff(db_session, second)

    assert events == []
    assert second.stats == stats
    assert _finding(db_session, tenant.org_id, RULE_A).fixed_at == fixed_at


def test_diff_skips_a_terminal_scan(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    cancelled = _scan(db_session, tenant, 1, status=ScanStatus.CANCELLED)
    _job(db_session, cancelled)

    events = _diff(db_session, cancelled)

    assert events == []
    assert cancelled.stats == {}
    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.OPEN


def test_diff_skips_an_archived_root(db_session: Session) -> None:
    tenant = make_scan(db_session)
    first = _scan(db_session, tenant, 0)
    _observe(db_session, first)
    _complete(db_session, first)
    second = _scan(db_session, tenant, 1)
    _job(db_session, second)
    assets_service.archive_root_domain(
        db_session, tenant.org_id, tenant.root_asset_id, actor_id=None
    )
    second.status = ScanStatus.RUNNING  # the archive's cancellation was missed (ADR 0021)

    events = _diff(db_session, second)

    assert events == []
    assert second.stats == {}
    assert _finding(db_session, tenant.org_id, RULE_A).status is FindingStatus.OPEN


def test_diff_rejects_another_tenants_job(db_session: Session) -> None:
    acme = make_scan(db_session, "acme")
    globex = make_scan(db_session, "globex")
    globex_scan = _scan(db_session, globex, 0)
    job = _job(db_session, globex_scan, stage="diff")

    with pytest.raises(JobNotFound):
        diff_scan(db_session, acme.org_id, job.id, InProcessDispatcher())


def test_diff_never_touches_another_tenants_findings(db_session: Session) -> None:
    acme = make_scan(db_session, "acme")
    globex = make_scan(db_session, "globex")
    acme_first = _scan(db_session, acme, 0)
    _observe(db_session, acme_first)
    _complete(db_session, acme_first)
    globex_scan = _scan(db_session, globex, 0)
    _observe(db_session, globex_scan)
    _complete(db_session, globex_scan)
    acme_second = _scan(db_session, acme, 1)
    _job(db_session, acme_second)

    _diff(db_session, acme_second)

    assert _finding(db_session, acme.org_id, RULE_A).status is FindingStatus.FIXED
    assert _finding(db_session, globex.org_id, RULE_A).status is FindingStatus.OPEN
