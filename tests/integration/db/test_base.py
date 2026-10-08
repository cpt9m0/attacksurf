from datetime import timedelta

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import Org


def test_new_row_gets_uuid7_primary_key(db_session: Session) -> None:
    org = Org(name="acme")
    db_session.add(org)
    db_session.flush()

    assert org.id.version == 7


def test_timestamps_are_set_by_database_and_timezone_aware(db_session: Session) -> None:
    org = Org(name="acme")
    db_session.add(org)
    db_session.flush()
    db_session.refresh(org)

    assert org.created_at.utcoffset() == timedelta(0)
    assert org.updated_at == org.created_at


def test_constraint_names_follow_naming_convention(db_session: Session) -> None:
    pk = inspect(db_session.connection()).get_pk_constraint("orgs")

    assert pk["name"] == "pk_orgs"
