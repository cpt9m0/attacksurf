import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import EmailAlreadyRegistered, InvalidSignup, Role
from attacksurf.infra.db.models import AuditLog, Membership, Org, User
from attacksurf.services import accounts
from attacksurf.services.accounts import register_user
from tests.fakes import FakePasswordHasher

PASSWORD = "correct horse battery"


def _count(session: Session, model: type) -> int:
    # Not session.scalar: one test monkeypatches it.
    return len(session.scalars(select(model)).all())


def test_register_user_creates_user_org_owner_membership_and_audit(db_session: Session) -> None:
    result = register_user(db_session, FakePasswordHasher(), "Alice@Example.com", PASSWORD)

    assert result.user.email == "alice@example.com"
    assert FakePasswordHasher().verify(result.user.password_hash, PASSWORD)
    assert result.org.name == "alice"
    assert result.org.slug == "alice"
    assert result.org.plan == "free"
    membership = db_session.scalars(select(Membership)).one()
    assert (membership.org_id, membership.user_id, membership.role) == (
        result.org.id,
        result.user.id,
        Role.OWNER,
    )
    entry = db_session.scalars(select(AuditLog)).one()
    assert (entry.org_id, entry.actor_user_id, entry.action, entry.target_id) == (
        result.org.id,
        result.user.id,
        "user.registered",
        str(result.user.id),
    )


def test_register_user_never_stores_plaintext_password(db_session: Session) -> None:
    result = register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)

    assert PASSWORD not in result.user.password_hash


def test_register_user_uses_given_org_name(db_session: Session) -> None:
    result = register_user(
        db_session, FakePasswordHasher(), "alice@example.com", PASSWORD, org_name="Acme Inc"
    )

    assert (result.org.name, result.org.slug) == ("Acme Inc", "acme-inc")


def test_register_user_suffixes_taken_slug(db_session: Session) -> None:
    hasher = FakePasswordHasher()
    register_user(db_session, hasher, "a@example.com", PASSWORD, org_name="Acme")
    register_user(db_session, hasher, "b@example.com", PASSWORD, org_name="ACME")

    third = register_user(db_session, hasher, "c@example.com", PASSWORD, org_name="acme")

    assert third.org.slug == "acme-3"


def test_register_user_rejects_duplicate_email_case_insensitively(db_session: Session) -> None:
    register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)

    with pytest.raises(EmailAlreadyRegistered):
        register_user(db_session, FakePasswordHasher(), "ALICE@example.com", PASSWORD)
    assert _count(db_session, User) == 1


def test_register_user_maps_concurrent_duplicate_to_email_error(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)
    # Simulate the race: the pre-check sees no user, the unique constraint still catches it.
    monkeypatch.setattr(db_session, "scalar", lambda *_a, **_k: None)

    with pytest.raises(EmailAlreadyRegistered):
        register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)
    assert _count(db_session, User) == 1


@pytest.mark.parametrize(
    ("email", "password", "org_name"),
    [
        ("not-an-email", PASSWORD, None),
        ("a@example.com", "short", None),
        ("a@example.com", PASSWORD, " "),
    ],
)
def test_register_user_rejects_invalid_input(
    db_session: Session, email: str, password: str, org_name: str | None
) -> None:
    with pytest.raises(InvalidSignup):
        register_user(db_session, FakePasswordHasher(), email, password, org_name=org_name)
    assert _count(db_session, User) == 0


def test_register_user_is_atomic_when_a_step_fails(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_audit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit failed")

    monkeypatch.setattr(accounts, "audit", failing_audit)

    with pytest.raises(RuntimeError):
        register_user(db_session, FakePasswordHasher(), "alice@example.com", PASSWORD)
    assert (_count(db_session, User), _count(db_session, Org), _count(db_session, Membership)) == (
        0,
        0,
        0,
    )


def test_register_user_reraises_other_integrity_errors(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    register_user(db_session, FakePasswordHasher(), "a@example.com", PASSWORD, org_name="acme")
    # A concurrent signup took the slug between the lookup and the insert.
    monkeypatch.setattr(accounts, "_unique_slug", lambda *_a: "acme")

    with pytest.raises(IntegrityError):
        register_user(db_session, FakePasswordHasher(), "b@example.com", PASSWORD, org_name="acme")
    assert _count(db_session, User) == 1
