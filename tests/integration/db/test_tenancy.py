import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import Org
from attacksurf.infra.db.tenancy import get_scoped, scoped
from tests.integration.db.models import Widget, create_test_tables


@pytest.fixture
def session(db_session: Session) -> Session:
    # DDL is transactional in Postgres: the table disappears with the test's rollback.
    create_test_tables(db_session.connection())
    return db_session


@pytest.fixture
def orgs(session: Session) -> tuple[Org, Org]:
    acme, globex = Org(name="acme", slug="acme"), Org(name="globex", slug="globex")
    session.add_all([acme, globex])
    session.flush()
    session.add_all(
        [
            Widget(org_id=acme.id, name="acme-1"),
            Widget(org_id=acme.id, name="acme-2"),
            Widget(org_id=globex.id, name="globex-1"),
        ]
    )
    session.flush()
    return acme, globex


def test_scoped_returns_only_own_org_rows(session: Session, orgs: tuple[Org, Org]) -> None:
    acme, globex = orgs

    acme_names = session.scalars(scoped(Widget, acme.id)).all()
    globex_names = session.scalars(scoped(Widget, globex.id)).all()

    assert sorted(w.name for w in acme_names) == ["acme-1", "acme-2"]
    assert [w.name for w in globex_names] == ["globex-1"]


def test_scoped_keeps_org_filter_when_more_filters_are_added(
    session: Session, orgs: tuple[Org, Org]
) -> None:
    acme, _ = orgs

    rows = session.scalars(scoped(Widget, acme.id).where(Widget.name == "globex-1")).all()

    assert rows == []


def test_get_scoped_returns_own_row(session: Session, orgs: tuple[Org, Org]) -> None:
    acme, _ = orgs
    widget = session.scalars(select(Widget).where(Widget.name == "acme-1")).one()

    assert get_scoped(session, Widget, widget.id, acme.id) is widget


def test_get_scoped_hides_other_orgs_row_even_with_known_id(
    session: Session, orgs: tuple[Org, Org]
) -> None:
    acme, _ = orgs
    foreign = session.scalars(select(Widget).where(Widget.name == "globex-1")).one()

    assert get_scoped(session, Widget, foreign.id, acme.id) is None


def test_tenant_row_requires_org(session: Session) -> None:
    session.add(Widget(name="orphan"))

    with pytest.raises(IntegrityError):
        session.flush()


def test_deleting_org_deletes_its_rows(session: Session, orgs: tuple[Org, Org]) -> None:
    acme, globex = orgs

    session.delete(acme)
    session.flush()
    session.expunge_all()

    assert [w.name for w in session.scalars(select(Widget))] == ["globex-1"]
    assert globex.id is not None
