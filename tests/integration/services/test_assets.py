from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType, InvalidAssetValue, RelationKind
from attacksurf.infra.db.models import Asset, AssetRelation, Org
from attacksurf.services.assets import record_asset, record_relation

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_record_asset_stores_normalized_value(db_session: Session, org: Org) -> None:
    asset = record_asset(
        db_session, org.id, AssetType.DOMAIN, " Example.COM. ", source=AssetSource.USER, seen_at=T0
    )

    assert (asset.value, asset.type, asset.source) == ("example.com", "domain", "user")
    assert (asset.first_seen, asset.last_seen) == (T0, T0)
    assert asset.is_active
    assert (asset.tags, asset.details) == ([], {})


def test_rediscovering_asset_updates_last_seen_without_duplicating(
    db_session: Session, org: Org
) -> None:
    first = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        seen_at=T0,
    )
    first_id = first.id
    first.is_active = False
    db_session.flush()

    again = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "WWW.example.com",
        source=AssetSource.DISCOVERED,
        seen_at=T0 + timedelta(days=1),
    )

    assert again.id == first_id
    assert _count(db_session, Asset) == 1
    assert (again.first_seen, again.last_seen) == (T0, T0 + timedelta(days=1))
    assert again.is_active


def test_out_of_order_sighting_never_moves_last_seen_back(db_session: Session, org: Org) -> None:
    record_asset(
        db_session, org.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED, seen_at=T0
    )

    asset = record_asset(
        db_session,
        org.id,
        AssetType.IP,
        "192.0.2.1",
        source=AssetSource.DISCOVERED,
        seen_at=T0 - timedelta(hours=1),
    )

    assert (asset.first_seen, asset.last_seen) == (T0 - timedelta(hours=1), T0)


def test_rediscovery_keeps_user_source_and_first_parent(db_session: Session, org: Org) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    other_root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.org", source=AssetSource.USER
    )
    user_added = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "app.example.com",
        source=AssetSource.USER,
        parent_id=root.id,
    )

    again = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "app.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=other_root.id,
    )

    assert again.id == user_added.id
    assert (again.source, again.parent_id) == (AssetSource.USER, root.id)


def test_user_adding_a_discovered_asset_promotes_it(db_session: Session, org: Org) -> None:
    record_asset(db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.DISCOVERED)

    asset = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )

    assert asset.source == AssetSource.USER


def test_same_value_in_two_orgs_is_two_assets(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()

    a = record_asset(
        db_session, org.id, AssetType.DOMAIN, "shared.example", source=AssetSource.USER
    )
    b = record_asset(
        db_session, other.id, AssetType.DOMAIN, "shared.example", source=AssetSource.USER
    )

    assert a.id != b.id
    assert _count(db_session, Asset) == 2


def test_invalid_value_is_rejected_before_writing(db_session: Session, org: Org) -> None:
    with pytest.raises(InvalidAssetValue):
        record_asset(
            db_session, org.id, AssetType.URL, "https://u:p@example.com/", source=AssetSource.USER
        )

    assert _count(db_session, Asset) == 0


def test_record_relation_upserts_edge(db_session: Session, org: Org) -> None:
    host = record_asset(
        db_session, org.id, AssetType.SUBDOMAIN, "www.example.com", source=AssetSource.DISCOVERED
    )
    ip = record_asset(db_session, org.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED)

    first = record_relation(
        db_session, org.id, host.id, ip.id, RelationKind.RESOLVES_TO, seen_at=T0
    )
    again = record_relation(
        db_session,
        org.id,
        host.id,
        ip.id,
        RelationKind.RESOLVES_TO,
        seen_at=T0 + timedelta(hours=2),
    )

    assert again.id == first.id
    assert _count(db_session, AssetRelation) == 1
    assert (again.first_seen, again.last_seen) == (T0, T0 + timedelta(hours=2))


def test_relation_to_itself_is_rejected(db_session: Session, org: Org) -> None:
    host = record_asset(
        db_session, org.id, AssetType.SUBDOMAIN, "www.example.com", source=AssetSource.DISCOVERED
    )

    with pytest.raises(InvalidAssetValue):
        record_relation(db_session, org.id, host.id, host.id, RelationKind.CNAME_TO)
