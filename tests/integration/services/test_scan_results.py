import contextlib
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetType
from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import AssetRef, RawEvidence, RawFinding, ScanOutput
from attacksurf.domain.scans import JobStatus, ScanCancelled, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Evidence, Finding, Job, Org, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import assets as assets_service
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
