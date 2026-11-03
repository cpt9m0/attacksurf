"""The worker-side ownership check: authoritative lookup, then the recorded outcome."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import TxtError
from attacksurf.domain.verification import VerificationStatus, record_value
from attacksurf.infra.db.models import Asset, AuditLog, Org, Verification
from attacksurf.services import ownership, verifications
from attacksurf.services.assets import record_asset
from tests.fakes import FakeQueue

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


class FakeLookup:
    def __init__(self, values: tuple[str, ...] = (), *, error: Exception | None = None) -> None:
        self.values = values
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        self.calls.append((host, name))
        if self.error is not None:
            raise self.error
        return self.values


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def root(db_session: Session, org: Org) -> Asset:
    return record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )


@pytest.fixture
def proof(db_session: Session, org: Org, root: Asset) -> Verification:
    return verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=org.id, asset_id=root.id, actor_id=None
    )


def test_the_lookup_asks_the_roots_zone_for_the_documented_record(
    db_session: Session, org: Org, proof: Verification
) -> None:
    lookup = FakeLookup((record_value(proof.token),))

    ownership.check_ownership(db_session, lookup, org_id=org.id, verification_id=proof.id, now=NOW)

    assert lookup.calls == [("example.com", "_attacksurf-verify.example.com")]


def test_a_found_record_verifies_and_audits(
    db_session: Session, org: Org, proof: Verification
) -> None:
    status = ownership.check_ownership(
        db_session,
        FakeLookup((record_value(proof.token),)),
        org_id=org.id,
        verification_id=proof.id,
        now=NOW,
    )

    assert status is VerificationStatus.VERIFIED
    assert db_session.get_one(Verification, proof.id).status is VerificationStatus.VERIFIED
    entry = db_session.query(AuditLog).filter(AuditLog.action == "asset.ownership_verified").one()
    assert entry.details == {"value": "example.com"}


def test_a_missing_record_keeps_a_fresh_proof_pending(
    db_session: Session, org: Org, proof: Verification
) -> None:
    status = ownership.check_ownership(
        db_session, FakeLookup(()), org_id=org.id, verification_id=proof.id, now=NOW
    )

    assert status is VerificationStatus.PENDING
    assert db_session.get_one(Verification, proof.id).last_checked_at == NOW


def test_a_proof_lost_after_the_grace_is_revoked_and_audited(
    db_session: Session, org: Org, proof: Verification
) -> None:
    ownership.check_ownership(
        db_session,
        FakeLookup((record_value(proof.token),)),
        org_id=org.id,
        verification_id=proof.id,
        now=NOW,
    )

    status = ownership.check_ownership(
        db_session,
        FakeLookup(()),
        org_id=org.id,
        verification_id=proof.id,
        now=NOW + timedelta(days=2),
    )

    assert status is VerificationStatus.REVOKED
    assert db_session.query(AuditLog).filter(AuditLog.action == "asset.ownership_revoked").count()


def test_a_lookup_failure_is_transient_so_the_job_retries(
    db_session: Session, org: Org, proof: Verification
) -> None:
    with pytest.raises(TransientJobError):
        ownership.check_ownership(
            db_session,
            FakeLookup(error=TxtError()),
            org_id=org.id,
            verification_id=proof.id,
            now=NOW,
        )

    assert db_session.get_one(Verification, proof.id).status is VerificationStatus.PENDING


def test_another_org_cannot_run_someone_elses_check(
    db_session: Session, org: Org, proof: Verification
) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    with pytest.raises(ownership.VerificationNotFound):
        ownership.check_ownership(
            db_session,
            FakeLookup(()),
            org_id=other.id,
            verification_id=proof.id,
            now=NOW,
        )


def test_an_archived_root_is_not_checked(
    db_session: Session, org: Org, root: Asset, proof: Verification
) -> None:
    root.is_active = False
    root.deactivated_at = NOW
    db_session.flush()

    with pytest.raises(ownership.VerificationNotFound):
        ownership.check_ownership(
            db_session,
            FakeLookup(()),
            org_id=org.id,
            verification_id=proof.id,
            now=NOW,
        )
