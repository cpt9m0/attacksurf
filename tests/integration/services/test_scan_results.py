import threading
from datetime import timedelta

import pytest
from sqlalchemy import Engine, delete
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import AssetRef, RawEvidence, RawFinding, ScanOutput
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Evidence, Finding, Job, Org, Scan
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


def test_discovered_limit_drops_overflow_and_their_findings(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        assets=(
            AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example"),
            AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example"),
        ),
        findings=(
            RawFinding(
                rule_id=RULE.id, asset=AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example")
            ),
        ),
    )

    created = persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=1
    )

    assert created == []
    assert [row.value for row in db_session.scalars(scoped(Asset, scan.org_id)).all()][1:] == [
        "a.acme.example"
    ]
    assert db_session.scalars(scoped(Finding, scan.org_id)).all() == []


def test_discovered_limit_still_rejects_names_the_plugin_never_reported(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        findings=(
            RawFinding(
                rule_id=RULE.id,
                asset=AssetRef(type=AssetType.SUBDOMAIN, value="ghost.acme.example"),
            ),
        )
    )
    with pytest.raises(ValueError, match="reference"):
        persist_scan_output(
            db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=0
        )


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


def test_discovered_limit_counts_against_the_scan_root_for_subdomain_checks(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    """A check on a discovered name must not get a fresh allowance of its own."""
    scan = make_scan(db_session)
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example"),)),
        catalog=catalog,
        discovered_limit=1,
    )
    subdomain = db_session.scalars(
        scoped(Asset, scan.org_id).where(Asset.value == "a.acme.example")
    ).one()

    created = persist_scan_output(
        db_session,
        scan,
        subdomain.id,
        ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example"),)),
        catalog=catalog,
        discovered_limit=1,
    )

    assert created == []
    assert not db_session.scalars(
        scoped(Asset, scan.org_id).where(Asset.value == "b.acme.example")
    ).all()


def test_admission_locks_the_root_so_overlapping_scans_cannot_overspend(
    db_engine: Engine, catalog: dict[str, Rule]
) -> None:
    """Regression: two scans of one root could each read the same count and admit the cap.

    Uses two real connections: the second admission must block while the first holds the root
    lock, then see the first run's asset and admit nothing.
    """
    with Session(db_engine) as setup:
        scan = make_scan(setup)
        setup.commit()
        org_id, root_id = scan.org_id, scan.root_asset_id

    first = Session(db_engine)
    second = Session(db_engine)
    try:
        first_scan = first.get(Scan, scan.id)
        assert first_scan is not None
        persist_scan_output(
            first,
            first_scan,
            root_id,
            ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example"),)),
            catalog=catalog,
            discovered_limit=1,
        )
        # The first transaction still holds the root row lock: the second must wait for it.
        waiting = threading.Event()
        done = threading.Event()
        admitted: list[int] = []

        def second_run() -> None:
            waiting.set()
            other = second.get(Scan, scan.id)
            assert other is not None
            result = persist_scan_output(
                second,
                other,
                root_id,
                ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example"),)),
                catalog=catalog,
                discovered_limit=1,
            )
            admitted.extend([len(result)])
            done.set()

        thread = threading.Thread(target=second_run, daemon=True)
        thread.start()
        waiting.wait(timeout=5)
        assert not done.wait(timeout=0.5), "admission must serialize on the root"
        first.commit()  # release the lock: the second run now sees the first one's asset
        assert done.wait(timeout=5), "the waiting admission never completed"
        thread.join(timeout=5)
        assert admitted == [0]
        assert not second.scalars(
            scoped(Asset, org_id).where(Asset.value == "b.acme.example")
        ).all()
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()
        # These rows were committed to the real engine: delete them so no later test sees them.
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(Finding).where(Finding.org_id == org_id))
            cleanup.execute(delete(Evidence).where(Evidence.org_id == org_id))
            cleanup.execute(delete(Job).where(Job.org_id == org_id))
            cleanup.execute(delete(Scan).where(Scan.org_id == org_id))
            cleanup.execute(delete(Asset).where(Asset.org_id == org_id))
            cleanup.execute(delete(Org).where(Org.id == org_id))
            cleanup.commit()
