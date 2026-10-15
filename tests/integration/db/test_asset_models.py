"""Database-level guarantees of the asset tables (independent of the services)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.infra.db.models import Asset, AssetRelation, Org
from attacksurf.infra.db.tenancy import scoped

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def _asset(
    org: Org,
    value: str,
    asset_type: AssetType = AssetType.DOMAIN,
    source: AssetSource = AssetSource.USER,
    **kw: object,
) -> Asset:
    return Asset(
        org_id=org.id,
        type=asset_type,
        value=value,
        source=source,
        first_seen=NOW,
        last_seen=NOW,
        **kw,
    )


@pytest.fixture
def two_orgs(db_session: Session) -> tuple[Org, Org]:
    acme, globex = Org(name="acme", slug="acme"), Org(name="globex", slug="globex")
    db_session.add_all([acme, globex])
    db_session.flush()
    return acme, globex


def test_value_is_unique_per_org_and_type(db_session: Session, two_orgs: tuple[Org, Org]) -> None:
    acme, _ = two_orgs
    db_session.add_all([_asset(acme, "example.com"), _asset(acme, "example.com")])

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_parent_must_belong_to_the_same_org(db_session: Session, two_orgs: tuple[Org, Org]) -> None:
    acme, globex = two_orgs
    foreign_root = _asset(globex, "globex.example")
    db_session.add(foreign_root)
    db_session.flush()

    db_session.add(
        _asset(
            acme,
            "www.globex.example",
            AssetType.SUBDOMAIN,
            AssetSource.DISCOVERED,
            parent_id=foreign_root.id,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_relation_endpoints_must_belong_to_the_same_org(
    db_session: Session, two_orgs: tuple[Org, Org]
) -> None:
    acme, globex = two_orgs
    mine, theirs = _asset(acme, "acme.example"), _asset(globex, "globex.example")
    db_session.add_all([mine, theirs])
    db_session.flush()

    db_session.add(
        AssetRelation(
            org_id=acme.id,
            from_asset_id=mine.id,
            to_asset_id=theirs.id,
            kind=RelationKind.CNAME_TO,
            first_seen=NOW,
            last_seen=NOW,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_self_relation_is_rejected_by_database(
    db_session: Session, two_orgs: tuple[Org, Org]
) -> None:
    acme, _ = two_orgs
    host = _asset(acme, "acme.example")
    db_session.add(host)
    db_session.flush()

    db_session.add(
        AssetRelation(
            org_id=acme.id,
            from_asset_id=host.id,
            to_asset_id=host.id,
            kind=RelationKind.CNAME_TO,
            first_seen=NOW,
            last_seen=NOW,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_unknown_type_is_rejected_by_database(
    db_session: Session, two_orgs: tuple[Org, Org]
) -> None:
    acme, _ = two_orgs
    db_session.add(_asset(acme, "example.com"))
    db_session.flush()

    with pytest.raises(IntegrityError):
        db_session.execute(text("UPDATE assets SET type = 'mainframe'"))


def test_deleting_root_cascades_to_children_and_relations(
    db_session: Session, two_orgs: tuple[Org, Org]
) -> None:
    acme, _ = two_orgs
    root = _asset(acme, "example.com")
    db_session.add(root)
    db_session.flush()
    child = _asset(
        acme, "www.example.com", AssetType.SUBDOMAIN, AssetSource.DISCOVERED, parent_id=root.id
    )
    ip = _asset(acme, "192.0.2.1", AssetType.IP)
    db_session.add_all([child, ip])
    db_session.flush()
    db_session.add(
        AssetRelation(
            org_id=acme.id,
            from_asset_id=child.id,
            to_asset_id=ip.id,
            kind=RelationKind.RESOLVES_TO,
            first_seen=NOW,
            last_seen=NOW,
        )
    )
    db_session.flush()

    db_session.execute(text("DELETE FROM assets WHERE id = :id"), {"id": root.id})
    db_session.expunge_all()

    assert [a.value for a in db_session.scalars(select(Asset))] == ["192.0.2.1"]
    assert db_session.scalars(select(AssetRelation)).all() == []


@pytest.mark.parametrize(
    "update",
    [
        "UPDATE assets SET parent_id = id, source = 'discovered'",
        "UPDATE assets SET parent_id = (SELECT id FROM assets WHERE value = 'example.org')"
        " WHERE value = 'example.com'",
        "UPDATE assets SET is_active = false",
        "UPDATE assets SET deactivated_at = now()",
    ],
    ids=["self_parent", "user_asset_with_parent", "inactive_without_time", "time_while_active"],
)
def test_parent_and_status_invariants_are_enforced(
    db_session: Session, two_orgs: tuple[Org, Org], update: str
) -> None:
    acme, _ = two_orgs
    db_session.add_all([_asset(acme, "example.com"), _asset(acme, "example.org")])
    db_session.flush()

    with pytest.raises(IntegrityError):
        db_session.execute(text(update))


def test_assets_are_tenant_isolated(db_session: Session, two_orgs: tuple[Org, Org]) -> None:
    acme, globex = two_orgs
    db_session.add_all([_asset(acme, "acme.example"), _asset(globex, "globex.example")])
    db_session.flush()

    values = [a.value for a in db_session.scalars(scoped(Asset, acme.id))]

    assert values == ["acme.example"]
