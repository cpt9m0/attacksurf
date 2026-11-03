"""Database-level guarantees of ownership verifications (#14)."""

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.domain.verification import VerificationMethod, VerificationStatus, new_token
from attacksurf.infra.db.models import Asset, Job, Org, Scan, Verification

NOW = datetime(2026, 11, 1, tzinfo=UTC)


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


def _verification(t: Tenant, **kw: object) -> Verification:
    values: dict[str, object] = {
        "org_id": t.org.id,
        "asset_id": t.root.id,
        "method": VerificationMethod.DNS_TXT,
        "token": new_token(),
        "status": VerificationStatus.PENDING,
    }
    return Verification(**(values | kw))


@pytest.fixture
def acme(db_session: Session) -> Tenant:
    return _tenant(db_session, "acme")


def test_a_root_can_only_have_one_verification(db_session: Session, acme: Tenant) -> None:
    db_session.add(_verification(acme))
    db_session.flush()
    db_session.add(_verification(acme, token=new_token()))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_a_verified_proof_records_when_it_was_verified(db_session: Session, acme: Tenant) -> None:
    # The services always set both together; the row shape stays consistent whichever way it
    # was reached (checked now, or revoked after a check).
    db_session.add(_verification(acme, status=VerificationStatus.VERIFIED, verified_at=NOW))

    db_session.flush()

    assert db_session.scalar(select(Verification.verified_at)) == NOW


def test_a_pending_proof_cannot_carry_a_verified_at(db_session: Session, acme: Tenant) -> None:
    db_session.add(_verification(acme, status=VerificationStatus.PENDING, verified_at=NOW))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_a_revoked_proof_keeps_its_verified_at(db_session: Session, acme: Tenant) -> None:
    proof = _verification(acme, status=VerificationStatus.REVOKED, verified_at=NOW)
    db_session.add(proof)

    db_session.flush()

    assert db_session.get_one(Verification, proof.id).verified_at == NOW


def test_deleting_the_root_deletes_its_verification(db_session: Session, acme: Tenant) -> None:
    db_session.add(_verification(acme, status=VerificationStatus.VERIFIED, verified_at=NOW))
    db_session.flush()

    db_session.execute(delete(Asset).where(Asset.id == acme.root.id))
    db_session.expire_all()

    assert db_session.scalars(select(Verification)).all() == []


def test_a_verification_cannot_point_at_another_orgs_asset(db_session: Session) -> None:
    acme, globex = _tenant(db_session, "acme"), _tenant(db_session, "globex")

    db_session.add(
        Verification(
            org_id=globex.org.id,
            asset_id=acme.root.id,
            method=VerificationMethod.DNS_TXT,
            token=new_token(),
            status=VerificationStatus.PENDING,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_a_job_can_exist_without_a_scan(db_session: Session, acme: Tenant) -> None:
    job = Job(org_id=acme.org.id, scan_id=None, stage="verify", status=JobStatus.QUEUED)
    db_session.add(job)

    db_session.flush()

    assert db_session.get_one(Job, job.id).scan_id is None


def test_a_scan_cascades_but_its_jobs_are_kept_without_a_scan(
    db_session: Session, acme: Tenant
) -> None:
    scan = Scan(
        org_id=acme.org.id,
        root_asset_id=acme.root.id,
        profile="dns_passive",
        status=ScanStatus.QUEUED,
        triggered_by=ScanTrigger.USER,
    )
    db_session.add(scan)
    db_session.flush()
    db_session.add(
        Job(org_id=acme.org.id, scan_id=scan.id, stage="checks", status=JobStatus.QUEUED)
    )
    db_session.flush()

    db_session.execute(delete(Scan).where(Scan.id == scan.id))
    db_session.expire_all()

    assert [job.scan_id for job in db_session.scalars(select(Job)).all()] == [None]
