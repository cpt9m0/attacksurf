import contextlib
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType, RelationKind
from attacksurf.domain.events import FindingReopened
from attacksurf.domain.findings import Confidence, EvidenceKind, FindingStatus, Severity
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import (
    AssetObservation,
    AssetRef,
    DiscoveredRelation,
    RawEvidence,
    RawFinding,
    ScanOutput,
)
from attacksurf.domain.scans import JobStatus, ScanCancelled, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, AssetRelation, Evidence, Finding, Job, Org, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import assets as assets_service
from attacksurf.services import scan_results as scan_results_service
from attacksurf.services.assets import archive_root_domain
from attacksurf.services.scan_results import persist_scan_output
from tests.integration.factories import make_scan

RULE = Rule("test.fixture.issue", "Fixture issue", "Description", Severity.LOW, "Fix $domain")


@pytest.fixture
def catalog() -> dict[str, Rule]:
    return {RULE.id: RULE}


def _forget(engine: Engine, org_id: object) -> None:
    """Rows committed to the real engine stay: delete them so no later test sees them."""
    with Session(engine) as cleanup:
        for model in (Finding, Evidence, Job, Scan, Asset):
            cleanup.execute(delete(model).where(model.org_id == org_id))
        cleanup.execute(delete(Org).where(Org.id == org_id))
        cleanup.commit()


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

    events = persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert finding.status == FindingStatus.ACCEPTED_RISK
    assert events == []


def _later_scan(session: Session, first: Scan, *, hours: int = 1) -> Scan:
    later = Scan(
        org_id=first.org_id,
        root_asset_id=first.root_asset_id,
        profile="fixture",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
        started_at=(first.started_at or first.created_at) + timedelta(hours=hours),
    )
    session.add(later)
    session.flush()
    return later


def test_persist_stamps_and_updates_the_observing_scanner(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))

    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, scanner="dns.email"
    )
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    assert finding.scanner == "dns.email"

    later = _later_scan(db_session, scan)
    persist_scan_output(
        db_session, later, scan.root_asset_id, output, catalog=catalog, scanner="dns.other"
    )

    assert finding.scanner == "dns.other"


def test_persist_does_not_reopen_from_a_delayed_older_scan(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    newer = _later_scan(db_session, scan, hours=2)
    persist_scan_output(
        db_session,
        newer,
        newer.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 1}),)),)),
        catalog=catalog,
    )
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()
    older = _later_scan(db_session, newer, hours=-1)
    changed = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 2}),)),)
    )

    events = persist_scan_output(db_session, older, scan.root_asset_id, changed, catalog=catalog)

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []


def test_persist_treats_an_empty_evidence_batch_as_a_batch(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    with_evidence = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 1}),)),)
    )
    persist_scan_output(db_session, scan, scan.root_asset_id, with_evidence, catalog=catalog)
    second = _later_scan(db_session, scan, hours=1)
    empty = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))
    persist_scan_output(db_session, second, scan.root_asset_id, empty, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()

    # The latest observation carried no evidence; another empty one is not a change.
    third = _later_scan(db_session, second, hours=1)
    events = persist_scan_output(db_session, third, scan.root_asset_id, empty, catalog=catalog)
    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []

    # Returning to the older evidence differs from the empty batch and reopens.
    fourth = _later_scan(db_session, third, hours=1)
    events = persist_scan_output(
        db_session, fourth, scan.root_asset_id, with_evidence, catalog=catalog
    )
    assert finding.status is FindingStatus.OPEN
    assert [type(event) for event in events] == [FindingReopened]


def test_persist_initializes_a_missing_evidence_baseline_without_reopening(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    """A row migrated without a digest must not lose a suppression on its first observation."""
    scan = make_scan(db_session)
    unchanged = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 1}),)),)
    )
    persist_scan_output(db_session, scan, scan.root_asset_id, unchanged, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.evidence_digest = None  # as migration 0008 leaves a pre-#20 row
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()
    later = _later_scan(db_session, scan)

    events = persist_scan_output(db_session, later, scan.root_asset_id, unchanged, catalog=catalog)

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []
    assert finding.evidence_digest is not None  # the baseline is recorded now

    changed = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 2}),)),)
    )
    events = persist_scan_output(
        db_session,
        _later_scan(db_session, later),
        scan.root_asset_id,
        changed,
        catalog=catalog,
    )

    assert finding.status is FindingStatus.OPEN
    assert [type(event) for event in events] == [FindingReopened]


def test_persist_compares_only_the_latest_evidence_batch(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    first = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 1}),)),)
    )
    persist_scan_output(db_session, scan, scan.root_asset_id, first, catalog=catalog)
    second = _later_scan(db_session, scan, hours=1)
    latest = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"v": 2}),)),)
    )
    persist_scan_output(db_session, second, scan.root_asset_id, latest, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()

    # v1 is an older batch, not the latest one: it must count as a material change.
    events = persist_scan_output(
        db_session,
        _later_scan(db_session, second, hours=1),
        scan.root_asset_id,
        first,
        catalog=catalog,
    )

    assert finding.status is FindingStatus.OPEN
    assert [type(event) for event in events] == [FindingReopened]


def test_persist_does_not_erase_known_scanner_provenance(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))
    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, scanner="dns.email"
    )

    persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert db_session.scalars(scoped(Finding, scan.org_id)).one().scanner == "dns.email"


def test_persist_reopens_a_suppressed_finding_when_evidence_changes(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    first = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"record": "v1"}),)),)
    )
    persist_scan_output(db_session, scan, scan.root_asset_id, first, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()
    changed = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"record": "v2"}),)),)
    )

    events = persist_scan_output(
        db_session, _later_scan(db_session, scan), scan.root_asset_id, changed, catalog=catalog
    )

    assert finding.status is FindingStatus.OPEN
    assert [type(event) for event in events] == [FindingReopened]


@pytest.mark.parametrize("change", ["severity", "confidence"])
def test_persist_reopens_a_suppressed_finding_when_its_assessment_changes(
    db_session: Session, catalog: dict[str, Rule], change: str
) -> None:
    scan = make_scan(db_session)
    first = ScanOutput(
        findings=(
            RawFinding(rule_id=RULE.id, severity=Severity.MEDIUM, confidence=Confidence.HIGH),
        )
    )
    persist_scan_output(db_session, scan, scan.root_asset_id, first, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.FALSE_POSITIVE
    db_session.flush()
    changed = ScanOutput(
        findings=(
            RawFinding(
                rule_id=RULE.id,
                severity=Severity.HIGH if change == "severity" else Severity.MEDIUM,
                confidence=Confidence.LOW if change == "confidence" else Confidence.HIGH,
            ),
        )
    )

    events = persist_scan_output(
        db_session, _later_scan(db_session, scan), scan.root_asset_id, changed, catalog=catalog
    )

    assert finding.status is FindingStatus.OPEN
    assert [type(event) for event in events] == [FindingReopened]


def test_persist_ignores_reordered_dns_record_values_for_material_change(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)

    def output(values: tuple[str, ...]) -> ScanOutput:
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id=RULE.id,
                    evidence=(
                        RawEvidence(
                            kind=EvidenceKind.DNS_RECORD,
                            data={
                                "record": "TXT",
                                "name": "_dmarc.example",
                                "values": list(values),
                            },
                        ),
                    ),
                ),
            )
        )

    persist_scan_output(db_session, scan, scan.root_asset_id, output(("a", "b")), catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()

    events = persist_scan_output(
        db_session,
        _later_scan(db_session, scan),
        scan.root_asset_id,
        output(("b", "a")),
        catalog=catalog,
    )

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []


def test_persist_ignores_reordered_rdap_statuses_for_material_change(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)

    def output(statuses: tuple[str, ...]) -> ScanOutput:
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id=RULE.id,
                    evidence=(
                        RawEvidence(
                            kind=EvidenceKind.RAW,
                            data={"source": "rdap", "statuses": list(statuses)},
                        ),
                    ),
                ),
            )
        )

    statuses = ("clientTransferProhibited", "active")
    persist_scan_output(db_session, scan, scan.root_asset_id, output(statuses), catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()

    events = persist_scan_output(
        db_session,
        _later_scan(db_session, scan),
        scan.root_asset_id,
        output(tuple(reversed(statuses))),
        catalog=catalog,
    )

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []


def test_persist_ignores_evidence_order_for_material_change(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    one = RawEvidence(data={"record": "a"})
    two = RawEvidence(data={"record": "b"})
    first = ScanOutput(findings=(RawFinding(rule_id=RULE.id, evidence=(one, two)),))
    persist_scan_output(db_session, scan, scan.root_asset_id, first, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()
    reordered = ScanOutput(findings=(RawFinding(rule_id=RULE.id, evidence=(two, one)),))

    events = persist_scan_output(
        db_session, _later_scan(db_session, scan), scan.root_asset_id, reordered, catalog=catalog
    )

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert events == []


def test_persist_replay_does_not_reopen_twice(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    first = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))
    persist_scan_output(db_session, scan, scan.root_asset_id, first, catalog=catalog)
    finding = db_session.scalars(scoped(Finding, scan.org_id)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    db_session.flush()
    changed = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"x": 1}),)),)
    )
    later = _later_scan(db_session, scan)
    persist_scan_output(db_session, later, scan.root_asset_id, changed, catalog=catalog)

    events = persist_scan_output(db_session, later, scan.root_asset_id, changed, catalog=catalog)

    assert finding.status is FindingStatus.OPEN
    assert events == []


def test_persist_does_not_reopen_an_open_finding(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))
    persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)
    changed = ScanOutput(
        findings=(RawFinding(rule_id=RULE.id, evidence=(RawEvidence(data={"x": 1}),)),)
    )

    events = persist_scan_output(
        db_session, _later_scan(db_session, scan), scan.root_asset_id, changed, catalog=catalog
    )

    assert events == []


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
        _forget(db_engine, org_id)


def test_persist_refuses_output_for_a_cancelled_scan(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    scan.status = ScanStatus.CANCELLED
    output = ScanOutput(findings=(RawFinding(rule_id=RULE.id),))

    with pytest.raises(ScanCancelled):
        persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert db_session.scalars(scoped(Finding, scan.org_id)).all() == []


def test_persist_refuses_output_under_an_archived_root(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    archive_root_domain(db_session, scan.org_id, scan.root_asset_id, actor_id=None)
    # The root's state alone must stop the write, even if this scan's cancellation was missed.
    db_session.refresh(scan)
    scan.status = ScanStatus.RUNNING
    output = ScanOutput(
        assets=(AssetRef(type=AssetType.SUBDOMAIN, value="www.acme.example"),),
        findings=(RawFinding(rule_id=RULE.id),),
    )

    with pytest.raises(AssetNotFound):
        persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)

    assert db_session.scalars(scoped(Finding, scan.org_id)).all() == []
    assert len(db_session.scalars(scoped(Asset, scan.org_id)).all()) == 1  # just the root


def test_archive_locks_scan_rows_before_the_root(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the archive took the root before the scan rows. Persistence takes the scan
    rows first (`load_job_scan`) and then the root, so the opposite order deadlocks (ADR 0021).
    """
    order: list[str] = []
    real_scans = assets_service._cancel_scans
    real_root = assets_service._lock_root

    def record_scans(*args: object, **kwargs: object) -> object:
        order.append("scans")
        return real_scans(*args, **kwargs)  # type: ignore[arg-type]

    def record_root(*args: object, **kwargs: object) -> object:
        order.append("root")
        return real_root(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(assets_service, "_cancel_scans", record_scans)
    monkeypatch.setattr(assets_service, "_lock_root", record_root)
    scan = make_scan(db_session)

    archive_root_domain(db_session, scan.org_id, scan.root_asset_id, actor_id=None)

    assert order == ["scans", "root"]


def test_archive_started_before_a_persist_deadlocks_neither(
    db_engine: Engine, tmp_path: Path, catalog: dict[str, Rule]
) -> None:
    """Regression: an archive that took the root before a worker took the scan deadlocked.

    The archive request begins first; the worker then takes the scan row and its job. Both
    proceed in their real lock orders, and whichever loses simply waits.
    """
    worker_holds = tmp_path / "worker-holds"
    go = tmp_path / "go"

    with Session(db_engine) as setup:
        scan = make_scan(setup)
        job = Job(
            org_id=scan.org_id,
            scan_id=scan.id,
            asset_id=scan.root_asset_id,
            stage="check",
            status=JobStatus.RUNNING,
        )
        setup.add(job)
        setup.commit()
        org_id, scan_id, root_id, job_id = scan.org_id, scan.id, scan.root_asset_id, job.id

    archive = Session(db_engine)
    worker = Session(db_engine)
    failure: list[BaseException] = []
    deadline = time.monotonic() + 15

    def run_worker() -> None:
        try:
            worker_scan = worker.get(Scan, scan_id)
            assert worker_scan is not None
            worker.execute(select(Scan.id).where(Scan.id == scan_id).with_for_update())
            worker.execute(select(Job.id).where(Job.id == job_id).with_for_update())
            worker_holds.touch()
            while not go.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            persist_scan_output(
                worker,
                worker_scan,
                root_id,
                ScanOutput(findings=(RawFinding(rule_id=RULE.id),)),
                catalog=catalog,
            )
            worker.commit()
        except BaseException as exc:
            failure.append(exc)
            worker_holds.touch()

    try:
        # The archive request begins (and reads its root) before the worker starts.
        assert archive.get(Asset, root_id) is not None
        thread = threading.Thread(target=run_worker, daemon=True)
        thread.start()
        while not worker_holds.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        go.touch()  # the worker now persists while the archive is under way

        archive_root_domain(archive, org_id, root_id, actor_id=None)
        thread.join(timeout=15)
        assert not thread.is_alive()
        assert failure == [], f"deadlock: {failure}"
    finally:
        go.touch()
        worker.rollback()
        archive.rollback()
        worker.close()
        archive.close()
        _forget(db_engine, org_id)


def test_concurrent_capped_persists_do_not_deadlock_on_the_root(
    db_engine: Engine, catalog: dict[str, Rule]
) -> None:
    """Regression: a key-share read of the root followed by `FOR UPDATE` deadlocked persists.

    Every persist took the root key-share and then tried to upgrade it for the cap, so each
    waited on the others' key-share and Postgres aborted some. The cap path must lock once.
    """
    with Session(db_engine) as setup:
        scan = make_scan(setup, "capped")
        setup.commit()
        org_id, scan_id, root_id = scan.org_id, scan.id, scan.root_asset_id

    loads = threading.Barrier(3)  # every worker has its scan row before anyone locks the root
    errors: list[BaseException] = []
    admitted: list[int] = []

    def persist(name: str) -> None:
        session = Session(db_engine)
        try:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            loads.wait(timeout=10)
            persist_scan_output(
                session,
                scan,
                root_id,
                ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value=name),)),
                catalog=catalog,
                discovered_limit=1,
            )
            session.commit()
            admitted.append(1)
        except BaseException as exc:
            errors.append(exc)
            with contextlib.suppress(threading.BrokenBarrierError):
                loads.abort()
            session.rollback()
        finally:
            session.close()

    try:
        threads = [
            threading.Thread(target=persist, args=("www.capped.example",), daemon=True)
            for _ in range(3)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
            assert not thread.is_alive()

        assert errors == [], f"deadlock or failure: {errors}"
        with Session(db_engine) as check:
            children = check.scalars(select(Asset.value).where(Asset.parent_id == root_id)).all()
        assert children == ["www.capped.example"]  # inserted once, cap respected
    finally:
        _forget(db_engine, org_id)


def test_persist_marks_discovered_wildcard_zones_in_asset_details(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    zone = AssetRef(type=AssetType.SUBDOMAIN, value="dev.acme.example")
    output = ScanOutput(assets=(zone,), wildcard_zones=(zone,))

    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=10
    )
    db_session.flush()

    row = db_session.scalars(scoped(Asset, scan.org_id).where(Asset.value == zone.value)).one()
    assert row.details == {"wildcard": True}


def test_persist_marks_the_root_wildcard_without_discovered_assets(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    output = ScanOutput(wildcard_zones=(AssetRef(type=AssetType.DOMAIN, value=root.value),))

    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=10
    )
    db_session.flush()

    assert root.details == {"wildcard": True}


def test_persist_merges_the_wildcard_marker_with_existing_details(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    root.details = {"owner": "security"}
    db_session.flush()
    output = ScanOutput(wildcard_zones=(AssetRef(type=AssetType.DOMAIN, value=root.value),))

    persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)
    db_session.flush()

    assert root.details == {"owner": "security", "wildcard": True}


def test_persist_skips_a_wildcard_zone_dropped_by_the_cap(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    kept = AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example")
    dropped = AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example")
    output = ScanOutput(assets=(kept, dropped), wildcard_zones=(dropped,))

    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=1
    )
    db_session.flush()

    values = {row.value: row.details for row in db_session.scalars(scoped(Asset, scan.org_id))}
    assert values[kept.value] == {}
    assert dropped.value not in values


def test_persist_rejects_a_wildcard_zone_it_never_reported(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        wildcard_zones=(AssetRef(type=AssetType.SUBDOMAIN, value="ghost.acme.example"),)
    )

    with pytest.raises(ValueError, match="reference"):
        persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)


def _subdomain(session: Session, scan: Scan, value: str = "www.acme.example") -> Asset:
    return assets_service.record_asset(
        session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        value,
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )


def test_persist_merges_observation_details_and_keeps_existing_keys(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    root.details = {"wildcard": True}
    db_session.flush()
    output = ScanOutput(
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.DOMAIN, value=root.value),
                details={"dns": {"a": ["93.184.216.34"]}},
                active=True,
            ),
        )
    )

    persist_scan_output(db_session, scan, root.id, output, catalog=catalog)

    assert root.details["wildcard"] is True
    assert root.details["dns"] == {"a": ["93.184.216.34"]}
    assert "observed_at" in root.details


def test_persist_deactivates_a_non_resolving_discovered_subdomain(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    subdomain = _subdomain(db_session, scan)
    seen = subdomain.last_seen + timedelta(minutes=1)
    scan.started_at = seen
    db_session.flush()
    output = ScanOutput(
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value),
                active=False,
            ),
        )
    )

    persist_scan_output(db_session, scan, subdomain.id, output, catalog=catalog)

    assert (subdomain.is_active, subdomain.deactivated_at) == (False, seen)


def test_persist_records_which_scan_discovered_and_deactivated_an_asset(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    ref = AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example")
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(assets=(ref,)),
        catalog=catalog,
        discovered_limit=10,
    )
    asset = db_session.scalars(scoped(Asset, scan.org_id).where(Asset.value == ref.value)).one()
    assert asset.first_seen_scan_id == scan.id

    later = _later_scan(db_session, scan)
    persist_scan_output(
        db_session,
        later,
        asset.id,
        ScanOutput(observations=(AssetObservation(asset=ref, active=False),)),
        catalog=catalog,
    )
    assert (asset.is_active, asset.deactivated_by_scan_id) == (False, later.id)

    reactivated = _later_scan(db_session, later)
    persist_scan_output(
        db_session,
        reactivated,
        asset.id,
        ScanOutput(observations=(AssetObservation(asset=ref, active=True),)),
        catalog=catalog,
    )
    assert (asset.is_active, asset.deactivated_by_scan_id) == (True, None)


def test_persist_never_deactivates_a_root_domain(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    output = ScanOutput(
        observations=(
            AssetObservation(asset=AssetRef(type=AssetType.DOMAIN, value=root.value), active=False),
        )
    )

    persist_scan_output(db_session, scan, root.id, output, catalog=catalog)

    assert root.is_active is True


def test_persist_reactivates_a_subdomain_seen_after_its_deactivation(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    subdomain = _subdomain(db_session, scan)
    gone_at = subdomain.last_seen - timedelta(hours=1)
    subdomain.is_active, subdomain.deactivated_at = False, gone_at
    scan.started_at = subdomain.last_seen
    db_session.flush()
    output = ScanOutput(
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value), active=True
            ),
        )
    )

    persist_scan_output(db_session, scan, subdomain.id, output, catalog=catalog)

    assert (subdomain.is_active, subdomain.deactivated_at) == (True, None)


def test_persist_ignores_an_older_deactivation_result(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    subdomain = _subdomain(db_session, scan)
    previous = {
        "dns": {"a": ["93.184.216.34"]},
        "observed_at": (subdomain.last_seen + timedelta(hours=1)).isoformat(),
    }
    subdomain.details = previous
    scan.started_at = subdomain.last_seen - timedelta(hours=1)
    db_session.flush()
    output = ScanOutput(
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value),
                details={"dns": {}},
                active=False,
            ),
        )
    )

    persist_scan_output(db_session, scan, subdomain.id, output, catalog=catalog)

    assert subdomain.is_active is True
    assert subdomain.details == previous


def test_observation_for_a_cap_dropped_asset_is_skipped(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    persist_scan_output(
        db_session,
        scan,
        scan.root_asset_id,
        ScanOutput(assets=(AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example"),)),
        catalog=catalog,
        discovered_limit=1,
    )
    output = ScanOutput(
        assets=(AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example"),),
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.SUBDOMAIN, value="b.acme.example"),
                details={"dns": {"a": ["93.184.216.34"]}},
                active=False,
            ),
        ),
    )

    persist_scan_output(
        db_session, scan, scan.root_asset_id, output, catalog=catalog, discovered_limit=1
    )

    assert not db_session.scalars(
        scoped(Asset, scan.org_id).where(Asset.value == "b.acme.example")
    ).all()


def test_observation_for_an_unknown_asset_is_rejected(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    output = ScanOutput(
        observations=(
            AssetObservation(
                asset=AssetRef(type=AssetType.SUBDOMAIN, value="ghost.acme.example"),
                active=False,
            ),
        )
    )

    with pytest.raises(ValueError, match="reference"):
        persist_scan_output(db_session, scan, scan.root_asset_id, output, catalog=catalog)


def test_persist_allows_a_subdomain_cname_to_its_root(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    root = db_session.get_one(Asset, scan.root_asset_id)
    subdomain = _subdomain(db_session, scan)
    output = ScanOutput(
        relations=(
            DiscoveredRelation(
                from_asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value),
                to_asset=AssetRef(type=AssetType.DOMAIN, value=root.value),
                kind=RelationKind.CNAME_TO,
            ),
        )
    )

    persist_scan_output(
        db_session, scan, subdomain.id, output, catalog=catalog, discovered_limit=1000
    )

    relation = db_session.scalars(scoped(AssetRelation, scan.org_id)).one()
    assert (relation.from_asset_id, relation.to_asset_id, relation.kind) == (
        subdomain.id,
        root.id,
        RelationKind.CNAME_TO,
    )


def test_later_negative_observation_outranks_a_delayed_positive(
    db_session: Session, catalog: dict[str, Rule]
) -> None:
    scan = make_scan(db_session)
    subdomain = _subdomain(db_session, scan)
    base = datetime.now(UTC)
    first_negative = base + timedelta(hours=1)
    delayed_positive = base + timedelta(hours=2)
    latest_negative = base + timedelta(hours=3)

    for seen, active in ((first_negative, False), (latest_negative, False)):
        scan.started_at = seen
        persist_scan_output(
            db_session,
            scan,
            subdomain.id,
            ScanOutput(
                observations=(
                    AssetObservation(
                        asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value),
                        details={"dns": {}},
                        active=active,
                    ),
                )
            ),
            catalog=catalog,
        )

    scan.started_at = delayed_positive
    persist_scan_output(
        db_session,
        scan,
        subdomain.id,
        ScanOutput(
            observations=(
                AssetObservation(
                    asset=AssetRef(type=AssetType.SUBDOMAIN, value=subdomain.value),
                    details={"dns": {"a": ["93.184.216.34"]}},
                    active=True,
                ),
            )
        ),
        catalog=catalog,
    )

    assert subdomain.is_active is False
    assert subdomain.deactivated_at == latest_negative
    assert subdomain.details["dns"] == {}


def test_persist_refreshes_the_input_after_locking_the_root(  # noqa: PLR0915
    db_engine: Engine, catalog: dict[str, Rule]
) -> None:
    """A stale input row must not overwrite a newer result after waiting for the root lock."""
    with Session(db_engine) as setup:
        scan = make_scan(setup, name="refresh")
        root = setup.get_one(Asset, scan.root_asset_id)
        subdomain = assets_service.record_asset(
            setup,
            scan.org_id,
            AssetType.SUBDOMAIN,
            "www.refresh.example",
            source=AssetSource.DISCOVERED,
            parent_id=root.id,
        )
        base = datetime.now(UTC)
        scan.started_at = base + timedelta(hours=1)
        newer_scan = Scan(
            org_id=scan.org_id,
            root_asset_id=root.id,
            profile="dns_passive",
            status=ScanStatus.RUNNING,
            triggered_by=ScanTrigger.USER,
            started_at=base + timedelta(hours=2),
        )
        setup.add(newer_scan)
        setup.commit()
        org_id, subdomain_id = scan.org_id, subdomain.id
        older_scan_id, newer_scan_id = scan.id, newer_scan.id
        older_seen, newer_seen = scan.started_at, newer_scan.started_at
        assert older_seen is not None
        assert newer_seen is not None

    newer_ready = threading.Event()
    release_newer = threading.Event()
    older_loaded = threading.Event()
    errors: list[BaseException] = []

    def newer_result() -> None:
        try:
            with Session(db_engine) as session:
                newer = session.get(Scan, newer_scan_id)
                assert newer is not None
                persist_scan_output(
                    session,
                    newer,
                    subdomain_id,
                    ScanOutput(
                        observations=(
                            AssetObservation(
                                asset=AssetRef(
                                    type=AssetType.SUBDOMAIN, value="www.refresh.example"
                                ),
                                details={"dns": {"a": ["93.184.216.34"]}},
                                active=False,
                            ),
                        )
                    ),
                    catalog=catalog,
                    discovered_limit=1000,
                )
                newer_ready.set()
                assert release_newer.wait(timeout=5)
                session.commit()
        except BaseException as exc:
            errors.append(exc)
            newer_ready.set()

    def older_result() -> None:
        try:
            with Session(db_engine) as session:
                older = session.get(Scan, older_scan_id)
                assert older is not None
                # Read the input before blocking on the root, as the real persistence path does.
                stale = session.get(Asset, subdomain_id)
                assert stale is not None
                older_loaded.set()
                assert newer_ready.wait(timeout=5)
                persist_scan_output(
                    session,
                    older,
                    subdomain_id,
                    ScanOutput(
                        observations=(
                            AssetObservation(
                                asset=AssetRef(
                                    type=AssetType.SUBDOMAIN, value="www.refresh.example"
                                ),
                                details={"dns": {"a": ["198.51.100.1"]}},
                                active=True,
                            ),
                        )
                    ),
                    catalog=catalog,
                    discovered_limit=1000,
                )
                session.commit()
        except BaseException as exc:
            errors.append(exc)

    newer_thread = threading.Thread(target=newer_result, daemon=True)
    older_thread = threading.Thread(target=older_result, daemon=True)
    try:
        newer_thread.start()
        assert newer_ready.wait(timeout=5)
        older_thread.start()
        assert older_loaded.wait(timeout=5)
        release_newer.set()
        older_thread.join(timeout=5)
        newer_thread.join(timeout=5)
        assert not older_thread.is_alive()
        assert not newer_thread.is_alive()
        assert errors == []

        with Session(db_engine) as check:
            final = check.get_one(Asset, subdomain_id)
            assert final.details["dns"] == {"a": ["93.184.216.34"]}
            assert final.is_active is False
            assert final.deactivated_at == newer_seen
            assert final.last_seen < newer_seen
            assert older_seen < newer_seen
    finally:
        _forget(db_engine, org_id)


def test_persist_locks_input_and_discovered_assets_in_one_order(
    db_session: Session, catalog: dict[str, Rule], monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan(db_session)
    input_asset = _subdomain(db_session, scan, "z.acme.example")
    calls: list[str] = []
    real_record = scan_results_service.record_asset
    real_lock = scan_results_service._lock_input

    def record(
        session: Session, org_id: UUID, asset_type: AssetType, value: str, **kwargs: object
    ) -> Asset:
        calls.append(f"upsert:{value}")
        return real_record(session, org_id, asset_type, value, **kwargs)  # type: ignore[arg-type]

    def lock(session: Session, owner: Scan, asset_id: UUID) -> Asset:
        calls.append("input")
        return real_lock(session, owner, asset_id)

    monkeypatch.setattr(scan_results_service, "record_asset", record)
    monkeypatch.setattr(scan_results_service, "_lock_input", lock)

    persist_scan_output(
        db_session,
        scan,
        input_asset.id,
        ScanOutput(
            assets=(AssetRef(type=AssetType.SUBDOMAIN, value="a.acme.example"),),
        ),
        catalog=catalog,
        discovered_limit=1000,
    )

    assert calls == ["upsert:a.acme.example", "input"]
