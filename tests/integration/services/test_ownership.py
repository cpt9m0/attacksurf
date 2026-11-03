"""The gate's ownership checker: proofs are read per run and fail closed."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scanners import AssetRef
from attacksurf.domain.verification import (
    VerificationMethod,
    VerificationStatus,
    new_token,
)
from attacksurf.infra.db.models import Asset, Org, Verification
from attacksurf.services.assets import record_asset
from attacksurf.services.ownership import DbOwnershipChecker

NOW = datetime.now(UTC)


def _verified(session: Session, org_id: UUID, asset_id: UUID, **kw: object) -> Verification:
    values: dict[str, object] = {
        "org_id": org_id,
        "asset_id": asset_id,
        "method": VerificationMethod.DNS_TXT,
        "token": new_token(),
        "status": VerificationStatus.VERIFIED,
        "verified_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=23),
    }
    proof = Verification(**(values | kw))
    session.add(proof)
    session.flush()
    return proof


@pytest.fixture
def checker(db_session: Session) -> DbOwnershipChecker:
    # The gate opens its own sessions; the test's transaction is visible to them through bind.
    return DbOwnershipChecker(sessionmaker(bind=db_session.get_bind()))


@pytest.fixture
def acme(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def root(db_session: Session, acme: Org) -> Asset:
    return record_asset(
        db_session, acme.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )


def test_a_verified_root_is_verified(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(db_session, acme.id, root.id)

    assert checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_a_subdomain_inherits_its_roots_proof(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(db_session, acme.id, root.id)
    record_asset(
        db_session,
        acme.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )

    assert checker.is_verified(acme.id, AssetRef(type=AssetType.SUBDOMAIN, value="www.example.com"))


def test_a_pending_proof_does_not_verify(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(
        db_session,
        acme.id,
        root.id,
        status=VerificationStatus.PENDING,
        verified_at=None,
        expires_at=None,
    )

    assert not checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_a_revoked_proof_does_not_verify(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    # A revoked proof keeps its verified_at (it proved ownership once, then lost it) but its
    # status is what the gate reads, so the domain drops back to passive checks only.
    _verified(db_session, acme.id, root.id, status=VerificationStatus.REVOKED)

    assert not checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_an_expired_proof_does_not_verify(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(db_session, acme.id, root.id, expires_at=NOW - timedelta(minutes=1))

    assert not checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_an_archived_asset_does_not_verify(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(db_session, acme.id, root.id)
    root.is_active = False
    root.deactivated_at = NOW
    db_session.flush()

    assert not checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_another_orgs_proof_does_not_verify(
    checker: DbOwnershipChecker, db_session: Session, acme: Org, root: Asset
) -> None:
    _verified(db_session, acme.id, root.id)
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    assert not checker.is_verified(other.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


def test_an_unknown_asset_does_not_verify(checker: DbOwnershipChecker, acme: Org) -> None:
    assert not checker.is_verified(acme.id, AssetRef(type=AssetType.DOMAIN, value="example.com"))


class BrokenFactory:
    """A session factory whose database is unreachable."""

    def __call__(self) -> Session:
        raise OperationalError("BEGIN", {}, Exception("connection refused"))


def test_a_database_failure_denies() -> None:
    broken = DbOwnershipChecker(BrokenFactory())  # type: ignore[arg-type]

    assert not broken.is_verified(uuid4(), AssetRef(type=AssetType.DOMAIN, value="example.com"))
