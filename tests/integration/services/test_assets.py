from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import (
    AssetNotFound,
    AssetSource,
    AssetType,
    InvalidAssetValue,
    RelationKind,
    UrlAlreadyAdded,
)
from attacksurf.domain.scanners import AssetRef
from attacksurf.domain.verification import OwnershipState, VerificationMethod, VerificationStatus
from attacksurf.infra.db.models import Asset, AssetRelation, AuditLog, Org, Verification
from attacksurf.services.asset_views import get_asset
from attacksurf.services.assets import (
    add_root_domain,
    add_url_asset,
    archive_root_domain,
    record_asset,
    record_assets,
    record_relation,
    record_relations,
)
from attacksurf.services.ownership import DbOwnershipChecker

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
    first.is_active, first.deactivated_at = False, T0 + timedelta(hours=1)
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
    assert (again.is_active, again.deactivated_at) == (True, None)


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


def test_sighting_before_deactivation_does_not_reactivate_asset(
    db_session: Session, org: Org
) -> None:
    asset = record_asset(
        db_session, org.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED, seen_at=T0
    )
    gone_at = T0 + timedelta(hours=2)  # a newer scan found it gone
    asset.is_active, asset.deactivated_at = False, gone_at
    db_session.flush()

    late = record_asset(
        db_session,
        org.id,
        AssetType.IP,
        "192.0.2.1",
        source=AssetSource.DISCOVERED,
        seen_at=T0 + timedelta(hours=1),  # newer than last_seen, older than the deactivation
    )

    assert (late.is_active, late.deactivated_at) == (False, gone_at)
    assert late.last_seen == T0 + timedelta(hours=1)


def test_rediscovery_keeps_user_source_and_first_parent(db_session: Session, org: Org) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    other_root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.org", source=AssetSource.USER
    )
    user_added = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.net", source=AssetSource.USER
    )
    found = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )

    user_again = record_asset(
        db_session,
        org.id,
        AssetType.DOMAIN,
        "example.net",
        source=AssetSource.DISCOVERED,
        parent_id=other_root.id,
    )
    found_again = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=other_root.id,
    )

    assert (user_again.id, user_again.source, user_again.parent_id) == (
        user_added.id,
        AssetSource.USER,
        None,
    )
    assert (found_again.id, found_again.parent_id) == (found.id, root.id)


def test_parent_is_not_set_after_first_sighting(db_session: Session, org: Org) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    child = record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )
    orphan = record_asset(
        db_session, org.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED
    )

    # Would otherwise make a self-loop or a cycle (child -> root -> child).
    again = record_asset(
        db_session,
        org.id,
        AssetType.IP,
        "192.0.2.1",
        source=AssetSource.DISCOVERED,
        parent_id=orphan.id,
    )
    root_again = record_asset(
        db_session,
        org.id,
        AssetType.DOMAIN,
        "example.com",
        source=AssetSource.DISCOVERED,
        parent_id=child.id,
    )

    assert (again.parent_id, root_again.parent_id) == (None, None)


def test_user_assets_cannot_have_a_parent(db_session: Session, org: Org) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )

    with pytest.raises(InvalidAssetValue, match="roots"):
        record_asset(
            db_session,
            org.id,
            AssetType.SUBDOMAIN,
            "app.example.com",
            source=AssetSource.USER,
            parent_id=root.id,
        )


def test_unknown_parent_raises_not_found(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    foreign = record_asset(
        db_session, other.id, AssetType.DOMAIN, "globex.example", source=AssetSource.USER
    )

    with pytest.raises(AssetNotFound):
        record_asset(
            db_session,
            org.id,
            AssetType.SUBDOMAIN,
            "www.globex.example",
            source=AssetSource.DISCOVERED,
            parent_id=foreign.id,
        )

    assert _count(db_session, Asset) == 1  # session still usable


def test_user_adding_a_discovered_asset_promotes_it(db_session: Session, org: Org) -> None:
    record_asset(db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.DISCOVERED)

    asset = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )

    assert asset.source == AssetSource.USER


def test_promoted_asset_is_detached_and_survives_deleting_its_parent(
    db_session: Session, org: Org
) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    record_asset(
        db_session,
        org.id,
        AssetType.SUBDOMAIN,
        "app.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )
    promoted = record_asset(
        db_session, org.id, AssetType.SUBDOMAIN, "app.example.com", source=AssetSource.USER
    )

    db_session.execute(delete(Asset).where(Asset.id == root.id))
    db_session.expunge_all()

    assert promoted.parent_id is None
    assert db_session.scalars(select(Asset.value)).all() == ["app.example.com"]


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


def test_relation_to_another_orgs_asset_raises_not_found(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    host = record_asset(
        db_session, org.id, AssetType.SUBDOMAIN, "www.example.com", source=AssetSource.DISCOVERED
    )
    foreign_ip = record_asset(
        db_session, other.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED
    )

    with pytest.raises(AssetNotFound):
        record_relation(db_session, org.id, host.id, foreign_ip.id, RelationKind.RESOLVES_TO)

    assert _count(db_session, AssetRelation) == 0  # session still usable


def test_existence_check_takes_a_key_share_lock(db_session: Session, org: Org) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    statements: list[str] = []

    @event.listens_for(db_session.bind, "before_cursor_execute")
    def capture(_conn, _cursor, statement, *_args) -> None:
        statements.append(statement)

    try:
        record_asset(
            db_session,
            org.id,
            AssetType.SUBDOMAIN,
            "www.example.com",
            source=AssetSource.DISCOVERED,
            parent_id=root.id,
        )
    finally:
        event.remove(db_session.bind, "before_cursor_execute", capture)

    # FOR KEY SHARE locks don't conflict with each other, so concurrent scans don't serialize.
    assert any(s.rstrip().endswith("FOR KEY SHARE") for s in statements)


def test_record_assets_batches_deduplicates_and_preserves_order(
    db_session: Session, org: Org
) -> None:
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER, seen_at=T0
    )

    rows = record_assets(
        db_session,
        org.id,
        [
            (AssetType.SUBDOMAIN, "A.example.com"),
            (AssetType.SUBDOMAIN, "a.example.com."),
            (AssetType.SUBDOMAIN, "b.example.com"),
        ],
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
        seen_at=T0,
    )

    assert [(row.value, row.parent_id) for row in rows] == [
        ("a.example.com", root.id),
        ("b.example.com", root.id),
    ]
    assert _count(db_session, Asset) == 3


def test_record_relations_batches_deduplicates_and_rejects_foreign_assets(
    db_session: Session, org: Org
) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    host = record_asset(
        db_session, org.id, AssetType.SUBDOMAIN, "www.example.com", source=AssetSource.DISCOVERED
    )
    ip1 = record_asset(db_session, org.id, AssetType.IP, "192.0.2.1", source=AssetSource.DISCOVERED)
    ip2 = record_asset(db_session, org.id, AssetType.IP, "192.0.2.2", source=AssetSource.DISCOVERED)
    foreign = record_asset(
        db_session, other.id, AssetType.IP, "192.0.2.99", source=AssetSource.DISCOVERED
    )

    edges = record_relations(
        db_session,
        org.id,
        [
            (host.id, ip1.id, RelationKind.RESOLVES_TO),
            (host.id, ip1.id, RelationKind.RESOLVES_TO),
            (host.id, ip2.id, RelationKind.RESOLVES_TO),
        ],
        seen_at=T0,
    )

    assert len(edges) == 2
    assert _count(db_session, AssetRelation) == 2
    with pytest.raises(AssetNotFound):
        record_relations(
            db_session,
            org.id,
            [(host.id, foreign.id, RelationKind.RESOLVES_TO)],
            seen_at=T0,
        )


def _mark_verified(db_session: Session, org: Org, root: Asset) -> None:
    now = datetime.now(UTC)
    db_session.add(
        Verification(
            org_id=org.id,
            asset_id=root.id,
            method=VerificationMethod.DNS_TXT,
            token="tok-123",
            status=VerificationStatus.VERIFIED,
            verified_at=now,
            last_checked_at=now,
            recheck_at=now + timedelta(hours=20),
            expires_at=now + timedelta(hours=24),
        )
    )
    db_session.flush()


def test_add_url_asset_links_verified_root_saves_unverified_and_enforces_rules(
    db_session: Session, org: Org
) -> None:
    verified_root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    _mark_verified(db_session, org, verified_root)
    unverified_root = add_root_domain(db_session, org.id, "pending.org", actor_id=None)

    verified_url = add_url_asset(
        db_session, org.id, "https://app.example.com/login?next=1", actor_id=None
    )
    unverified_url = add_url_asset(db_session, org.id, "https://pending.org/", actor_id=None)
    orphan_url = add_url_asset(db_session, org.id, "https://unowned.net/portal", actor_id=None)

    assert verified_url.type is AssetType.URL
    assert verified_url.source is AssetSource.USER
    assert verified_url.parent_id == verified_root.id
    assert get_asset(db_session, org.id, verified_url.id).verification is OwnershipState.VERIFIED

    assert unverified_url.parent_id == unverified_root.id
    assert get_asset(db_session, org.id, unverified_url.id).verification is OwnershipState.NONE
    assert orphan_url.parent_id is None
    assert get_asset(db_session, org.id, orphan_url.id).verification is OwnershipState.NONE

    checker = DbOwnershipChecker(sessionmaker(bind=db_session.get_bind()))
    assert checker.is_verified(org.id, AssetRef(type=AssetType.URL, value=verified_url.value))
    assert not checker.is_verified(org.id, AssetRef(type=AssetType.URL, value=unverified_url.value))
    assert not checker.is_verified(org.id, AssetRef(type=AssetType.URL, value=orphan_url.value))

    audits = db_session.scalars(select(AuditLog).where(AuditLog.action == "asset.url_added")).all()
    assert len(audits) == 3

    with pytest.raises(UrlAlreadyAdded):
        add_url_asset(db_session, org.id, "https://app.example.com/login?next=1", actor_id=None)
    with pytest.raises(InvalidAssetValue, match="ports"):
        add_url_asset(db_session, org.id, "https://app.example.com:9443/", actor_id=None)
    with pytest.raises(InvalidAssetValue, match=r"Internal-only|public"):
        add_url_asset(db_session, org.id, "https://printer.corp/", actor_id=None)
    with pytest.raises(InvalidAssetValue, match="credentials"):
        add_url_asset(db_session, org.id, "https://user:pass@app.example.com/", actor_id=None)

    # Archiving the root deactivates verified_url; adding it again restores it.
    archive_root_domain(db_session, org.id, verified_root.id, actor_id=None)
    restored = add_url_asset(
        db_session, org.id, "https://app.example.com/login?next=1", actor_id=None
    )
    assert restored.id == verified_url.id
    assert restored.is_active is True
    assert restored.parent_id is None
    restored_log = db_session.scalars(
        select(AuditLog).where(AuditLog.action == "asset.url_restored")
    ).one()
    assert restored_log.target_id == str(verified_url.id)


def test_add_root_domain_attaches_existing_orphan_user_urls(db_session: Session, org: Org) -> None:
    orphan = add_url_asset(db_session, org.id, "https://later.example.org/app", actor_id=None)
    unrelated = add_url_asset(db_session, org.id, "https://elsewhere.net/", actor_id=None)
    assert orphan.parent_id is None
    assert get_asset(db_session, org.id, orphan.id).verification is OwnershipState.NONE

    root = add_root_domain(db_session, org.id, "example.org", actor_id=None)
    db_session.refresh(orphan)
    db_session.refresh(unrelated)
    assert orphan.parent_id == root.id
    assert unrelated.parent_id is None

    _mark_verified(db_session, org, root)
    assert get_asset(db_session, org.id, orphan.id).verification is OwnershipState.VERIFIED
