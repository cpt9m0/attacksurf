from unittest.mock import Mock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import InvalidCredentials, Role
from attacksurf.infra.db.models import AuditLog, Membership, Org, User
from attacksurf.services.accounts import Registration, register_user
from attacksurf.services.auth import (
    SessionUser,
    authenticate,
    has_users,
    load_session_user,
    record_logout,
)
from tests.fakes import FakePasswordHasher

PASSWORD = "correct horse battery"


@pytest.fixture
def alice(db_session: Session) -> Registration:
    return register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD, "Acme")


def _actions(session: Session) -> list[str]:
    return [e.action for e in session.scalars(select(AuditLog).order_by(AuditLog.id))]


def _failed_login(session: Session) -> AuditLog:
    return session.scalars(select(AuditLog).where(AuditLog.action == "user.login_failed")).one()


def test_authenticate_returns_session_user_and_records_login(
    db_session: Session, alice: Registration
) -> None:
    user = authenticate(db_session, FakePasswordHasher(), "Alice@Example.com ", PASSWORD)

    assert user == SessionUser(alice.user.id, "alice@example.com", alice.org.id, "Acme", Role.OWNER)
    db_session.refresh(alice.user)
    assert alice.user.last_login_at is not None
    assert _actions(db_session)[-1] == "user.login"


def test_wrong_password_is_rejected_and_audited(db_session: Session, alice: Registration) -> None:
    with pytest.raises(InvalidCredentials):
        authenticate(db_session, FakePasswordHasher(), "alice@example.com", "nope")

    failed = db_session.scalars(
        select(AuditLog).where(AuditLog.action == "user.login_failed")
    ).one()
    assert (failed.org_id, failed.actor_user_id, failed.details) == (
        alice.org.id,
        alice.user.id,
        {"reason": "bad_password"},
    )
    db_session.refresh(alice.user)
    assert alice.user.last_login_at is None


@pytest.mark.parametrize("email", ["nobody@example.com", "not an email", ""])
def test_unknown_email_is_rejected_after_equal_hashing_work(
    db_session: Session, alice: Registration, email: str
) -> None:
    hasher = FakePasswordHasher()
    hasher.hash = Mock(wraps=hasher.hash)  # type: ignore[method-assign]

    with pytest.raises(InvalidCredentials):
        authenticate(db_session, hasher, email, PASSWORD)

    hasher.hash.assert_called_once_with(PASSWORD)
    assert "user.login_failed" not in _actions(db_session)


def test_inactive_user_cannot_log_in_even_with_right_password(
    db_session: Session, alice: Registration
) -> None:
    alice.user.is_active = False
    db_session.flush()

    with pytest.raises(InvalidCredentials):
        authenticate(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)

    failed = db_session.scalars(
        select(AuditLog).where(AuditLog.action == "user.login_failed")
    ).one()
    assert failed.details == {"reason": "inactive"}


def test_user_without_membership_cannot_log_in(db_session: Session) -> None:
    hasher = FakePasswordHasher()
    db_session.add(User(email="orphan@example.com", password_hash=hasher.hash(PASSWORD)))
    db_session.flush()

    with pytest.raises(InvalidCredentials):
        authenticate(db_session, hasher, "orphan@example.com", PASSWORD)


class _LegacyHasher(FakePasswordHasher):
    """Accepts an old-format hash and asks for it to be upgraded."""

    def verify(self, password_hash: str, password: str) -> bool:
        return password_hash == "legacy" or super().verify(password_hash, password)

    def needs_rehash(self, password_hash: str) -> bool:
        return password_hash == "legacy"


def test_login_upgrades_outdated_hash(db_session: Session, alice: Registration) -> None:
    alice.user.password_hash = "legacy"
    db_session.flush()

    authenticate(db_session, _LegacyHasher(), "alice@example.com", PASSWORD)

    db_session.refresh(alice.user)
    assert alice.user.password_hash == FakePasswordHasher().hash(PASSWORD)


def test_record_logout_audits(db_session: Session, alice: Registration) -> None:
    user = authenticate(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)

    record_logout(db_session, user)

    assert _actions(db_session)[-1] == "user.logout"


def test_load_session_user(db_session: Session, alice: Registration) -> None:
    loaded = load_session_user(db_session, alice.user.id)

    assert loaded is not None
    assert (loaded.org_id, loaded.role) == (alice.org.id, Role.OWNER)


def test_load_session_user_rejects_inactive_or_missing(
    db_session: Session, alice: Registration
) -> None:
    alice.user.is_active = False
    db_session.flush()

    assert load_session_user(db_session, alice.user.id) is None
    assert load_session_user(db_session, alice.org.id) is None  # not a user id


def test_session_user_acts_in_first_org(db_session: Session, alice: Registration) -> None:
    other = Org(name="Later", slug="later")
    db_session.add(other)
    db_session.flush()
    db_session.add(Membership(org_id=other.id, user_id=alice.user.id, role=Role.MEMBER))
    db_session.flush()

    loaded = load_session_user(db_session, alice.user.id)

    assert loaded is not None
    assert loaded.org_id == alice.org.id


def test_has_users(db_session: Session) -> None:
    assert has_users(db_session) is False
    register_user(db_session, FakePasswordHasher(), "a@example.com", PASSWORD)
    assert has_users(db_session) is True
