import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import Role
from attacksurf.infra.db.models import AuditLog, Membership, Org, User
from attacksurf.infra.db.tenancy import scoped


@pytest.fixture
def two_orgs(db_session: Session) -> tuple[Org, Org, User]:
    acme, globex = Org(name="acme", slug="acme"), Org(name="globex", slug="globex")
    user = User(email="alice@example.com", password_hash="x")
    db_session.add_all([acme, globex, user])
    db_session.flush()
    db_session.add_all(
        [
            Membership(org_id=acme.id, user_id=user.id, role=Role.OWNER),
            Membership(org_id=globex.id, user_id=user.id, role=Role.MEMBER),
            AuditLog(org_id=acme.id, action="acme.thing"),
            AuditLog(org_id=globex.id, action="globex.thing"),
        ]
    )
    db_session.flush()
    return acme, globex, user


def test_memberships_are_tenant_isolated(
    db_session: Session, two_orgs: tuple[Org, Org, User]
) -> None:
    acme, _, _ = two_orgs

    roles = [m.role for m in db_session.scalars(scoped(Membership, acme.id))]

    assert roles == [Role.OWNER]


def test_audit_log_is_tenant_isolated(db_session: Session, two_orgs: tuple[Org, Org, User]) -> None:
    _, globex, _ = two_orgs

    actions = [e.action for e in db_session.scalars(scoped(AuditLog, globex.id))]

    assert actions == ["globex.thing"]


def test_membership_is_unique_per_org_and_user(
    db_session: Session, two_orgs: tuple[Org, Org, User]
) -> None:
    acme, _, user = two_orgs
    db_session.add(Membership(org_id=acme.id, user_id=user.id, role=Role.ADMIN))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_role_column_rejects_unknown_values(
    db_session: Session, two_orgs: tuple[Org, Org, User]
) -> None:
    acme, _, user = two_orgs

    with pytest.raises(IntegrityError):
        db_session.execute(
            text("UPDATE memberships SET role = 'superuser' WHERE org_id = :org"),
            {"org": acme.id},
        )
    assert user.id is not None


def test_email_is_unique(db_session: Session) -> None:
    db_session.add_all(
        [
            User(email="a@example.com", password_hash="x"),
            User(email="a@example.com", password_hash="y"),
        ]
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_org_slug_is_unique(db_session: Session) -> None:
    db_session.add_all([Org(name="a", slug="same"), Org(name="b", slug="same")])

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_deleting_user_removes_memberships_and_keeps_audit_trail(
    db_session: Session, two_orgs: tuple[Org, Org, User]
) -> None:
    acme, _, user = two_orgs
    db_session.add(AuditLog(org_id=acme.id, action="user.did", actor_user_id=user.id))
    db_session.flush()

    db_session.delete(user)
    db_session.flush()
    db_session.expunge_all()

    assert db_session.scalars(select(Membership)).all() == []
    entry = db_session.scalars(select(AuditLog).where(AuditLog.action == "user.did")).one()
    assert entry.actor_user_id is None
