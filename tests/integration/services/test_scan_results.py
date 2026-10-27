from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import AssetRef, RawEvidence, RawFinding, ScanOutput
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Evidence, Finding, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services.scan_results import persist_scan_output
from tests.integration.factories import make_scan

RULE = Rule("test.fixture.issue", "Fixture issue", "Description", Severity.LOW, "Fix $domain")


@pytest.fixture
def catalog() -> dict[str, Rule]:
    return {RULE.id: RULE}


def test_persist_upserts_findings_and_does_not_duplicate_evidence_on_replay(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"x": 1}),)),)
    )

    first = persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)
    second = persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert len(first) == 1
    assert second == []
    assert len(db_session.scalars(scoped(Finding, scan.org_id)).all()) == 1
    assert len(db_session.scalars(scoped(Evidence, scan.org_id)).all()) == 1


def test_persist_preserves_user_states(db_session: Session, catalog: dict[str, Rule]) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))
    persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()

    persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert finding.status == FindingStatus.ACCEPTED_RISK


def test_persist_rejects_references_not_in_the_output_or_input(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        findings=(
            RawFinding(
                rule_id=RULE.id, asset=AssetRef(type=AssetType.DOMAIN, value="other.example")
            ),
        )
    )
    with pytest.raises(ValueError, match="reference"):
        persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)


@pytest.mark.parametrize("hours", [0, 1])
def test_findings_survive_rescans_and_out_of_order_results(
    db_session: Session,
    catalog: dict[str, Rule],
    hours: int,
) -> None:
    first_scan = make_scan(db_session)
    first_started = first_scan.created_at
    first_scan.started_at = first_started
    second_scan = Scan(
        org_id=first_scan.org_id,
        root_asset_id=first_scan.root_asset_id,
        profile="fixture",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
        started_at=first_started + timedelta(hours=hours),
    )
    db_session.add(second_scan)
    db_session.flush()
    output = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"x": 1}),)),)
    )
    persist_scan_output(db_session, first_scan, first_scan.root_asset_id, output, catalog=catalog)
    persist_scan_output(db_session, second_scan, first_scan.root_asset_id, output, catalog=catalog)
    persist_scan_output(db_session, first_scan, first_scan.root_asset_id, output, catalog=catalog)

    finding = db_session.scalars(scoped(Finding, first_scan.org_id)).one()
    assert finding.first_seen_scan_id == (
        min(first_scan.id, second_scan.id) if hours == 0 else first_scan.id
    )
    assert finding.last_seen_scan_id == (
        max(first_scan.id, second_scan.id) if hours == 0 else second_scan.id
    )
    assert finding.last_seen == second_scan.started_at
    assert len(db_session.scalars(scoped(Evidence, first_scan.org_id)).all()) == 2
