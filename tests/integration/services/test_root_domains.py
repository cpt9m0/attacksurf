"""Use cases: adding and archiving root domains."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import (
    AssetNotFound,
    AssetSource,
    AssetType,
    DomainAlreadyAdded,
    InvalidAssetValue,
)
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.models import Asset, AuditLog, Org, User
from attacksurf.services.assets import add_root_domain, archive_root_domain, record_asset


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def user(db_session: Session) -> User:
    user = User(email="alice@example.com", password_hash="not-a-real-hash")
    db_session.add(user)
    db_session.flush()
    return user


def _audit(session: Session, org: Org) -> list[tuple[str, str | None, dict[str, object]]]:
    entries = session.scalars(
        select(AuditLog).where(AuditLog.org_id == org.id).order_by(AuditLog.id)
    )
    return [(e.action, e.target_id, e.details) for e in entries]


def _child(session: Session, org: Org, root: Asset, value: str) -> Asset:
    return record_asset(
        session,
        org.id,
        AssetType.SUBDOMAIN,
        value,
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )


def test_add_root_domain_stores_normalized_user_root(db_session: Session, org: Org) -> None:
    asset = add_root_domain(db_session, org.id, " ExAmple.COM. ", actor_id=None)

    assert (asset.type, asset.value, asset.source) == ("domain", "example.com", "user")
    assert (asset.parent_id, asset.is_active) == (None, True)
    assert _audit(db_session, org) == [
        ("asset.root_added", str(asset.id), {"value": "example.com"})
    ]


def test_root_domain_use_cases_record_the_actor(db_session: Session, org: Org, user: User) -> None:
    asset = add_root_domain(db_session, org.id, "example.com", actor_id=user.id)
    archive_root_domain(db_session, org.id, asset.id, actor_id=user.id)

    entries = db_session.scalars(select(AuditLog).where(AuditLog.org_id == org.id)).all()
    assert [e.actor_user_id for e in entries] == [user.id, user.id]


def test_add_root_domain_accepts_a_subdomain_the_org_controls(
    db_session: Session, org: Org
) -> None:
    asset = add_root_domain(db_session, org.id, "eng.example.co.uk", actor_id=None)

    assert (asset.type, asset.value, asset.parent_id) == ("domain", "eng.example.co.uk", None)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "Enter a domain name."),
        ("192.0.2.1", "is an IP address"),
        ("localhost", "is not a valid domain name"),
        ("printer.corp", "Internal-only domain names"),
        ("app.internal", "Internal-only domain names"),
        ("co.uk", "known public suffix"),
        ("example.notatld", "known public suffix"),
        ("exa mple.com", "is not a valid domain name"),
    ],
)
def test_add_root_domain_rejects_names_that_cannot_be_scanned(
    db_session: Session, org: Org, raw: str, message: str
) -> None:
    with pytest.raises(InvalidAssetValue, match=message):
        add_root_domain(db_session, org.id, raw, actor_id=None)

    assert db_session.scalars(select(Asset)).all() == []


def test_adding_an_active_root_twice_is_rejected(db_session: Session, org: Org) -> None:
    add_root_domain(db_session, org.id, "example.com", actor_id=None)

    with pytest.raises(DomainAlreadyAdded, match=r"example\.com is already in your assets"):
        add_root_domain(db_session, org.id, "EXAMPLE.com", actor_id=None)


def test_same_domain_in_another_org_is_independent(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    add_root_domain(db_session, org.id, "example.com", actor_id=None)

    asset = add_root_domain(db_session, other.id, "example.com", actor_id=None)

    assert asset.org_id == other.id


def test_archive_deactivates_root_and_its_discovered_assets_only(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")
    other_root = add_root_domain(db_session, org.id, "example.org", actor_id=None)
    other_child = _child(db_session, org, other_root, "www.example.org")

    archived = archive_root_domain(db_session, org.id, root.id, actor_id=None)

    assert archived.id == root.id
    for asset in (root, www):
        db_session.refresh(asset)
        assert not asset.is_active
        assert asset.deactivated_at is not None
    for asset in (other_root, other_child):
        db_session.refresh(asset)
        assert asset.is_active
    assert _audit(db_session, org)[-1] == (
        "asset.root_archived",
        str(root.id),
        {"value": "example.com", "children": 1},
    )


def test_archive_keeps_already_inactive_children_deactivation_time(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    gone = _child(db_session, org, root, "old.example.com")
    gone.is_active, gone.deactivated_at = False, gone.last_seen
    db_session.flush()

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.refresh(gone)
    assert gone.deactivated_at == gone.last_seen
    assert _audit(db_session, org)[-1][2] == {"value": "example.com", "children": 0}


def test_archiving_an_archived_root_changes_nothing(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    archive_root_domain(db_session, org.id, root.id, actor_id=None)
    db_session.refresh(root)
    deactivated_at = root.deactivated_at

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.refresh(root)
    assert root.deactivated_at == deactivated_at
    assert [a for a, *_ in _audit(db_session, org)].count("asset.root_archived") == 1


def test_readding_an_archived_root_restores_it_but_not_its_children(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")
    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    restored = add_root_domain(db_session, org.id, "example.com", actor_id=None)

    db_session.refresh(www)
    assert restored.id == root.id
    assert (restored.is_active, restored.deactivated_at) == (True, None)
    assert not www.is_active  # comes back when a scan sees it again
    assert _audit(db_session, org)[-1][0] == "asset.root_restored"


def test_archive_rejects_discovered_assets(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")

    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, www.id, actor_id=None)


def test_archive_rejects_another_orgs_root(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    theirs = add_root_domain(db_session, other.id, "globex.com", actor_id=None)

    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, theirs.id, actor_id=None)

    db_session.refresh(theirs)
    assert theirs.is_active


def test_archive_rejects_unknown_ids(db_session: Session, org: Org) -> None:
    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, uuid7(), actor_id=None)
