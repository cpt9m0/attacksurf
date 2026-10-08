from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import AuditLog, Org
from attacksurf.services.audit import audit


def test_audit_adds_entry_without_committing(db_session: Session) -> None:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()

    entry = audit(db_session, org.id, "asset.added", target_type="asset", details={"n": 1})
    db_session.rollback()

    assert entry not in db_session
    assert db_session.scalars(select(AuditLog)).all() == []


def test_audit_entry_defaults(db_session: Session) -> None:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()

    audit(db_session, org.id, "org.updated")
    db_session.flush()

    entry = db_session.scalars(select(AuditLog)).one()
    db_session.refresh(entry)
    assert (entry.actor_user_id, entry.details) == (None, {})
    assert entry.created_at is not None
