"""Database-level guarantees of stored artifacts (#85, ADR 0028)."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import ArtifactKind
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.infra.db.models import Artifact, Asset, Org
from attacksurf.infra.db.tenancy import get_scoped, scoped

NOW = datetime(2026, 11, 1, tzinfo=UTC)
ENVELOPE = b"\x01" + b"e" * 60


def _asset(session: Session, name: str) -> Asset:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    asset = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,
        value=f"{name}.example",
        source=AssetSource.USER,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(asset)
    session.flush()
    return asset


def _artifact(asset: Asset, **kw: object) -> Artifact:
    artifact_id = uuid4()
    values: dict[str, object] = {
        "id": artifact_id,
        "org_id": asset.org_id,
        "asset_id": asset.id,
        "kind": ArtifactKind.REPO,
        "sha256": "0" * 64,
        "size_bytes": 10,
        "storage_key": f"{asset.org_id}/{artifact_id}",
        "key_envelope": ENVELOPE,
        "delete_after": NOW,
    }
    return Artifact(**(values | kw))


@pytest.fixture
def acme(db_session: Session) -> Asset:
    return _asset(db_session, "acme")


def test_artifact_persists_its_columns(db_session: Session, acme: Asset) -> None:
    artifact = _artifact(acme, kind=ArtifactKind.BINARY, size_bytes=5 * 1024**3)
    db_session.add(artifact)
    db_session.flush()
    db_session.expire_all()

    row = db_session.get_one(Artifact, artifact.id)

    assert row.kind is ArtifactKind.BINARY
    assert row.size_bytes == 5 * 1024**3  # BIGINT: past 32 bits
    assert row.key_envelope == ENVELOPE
    assert (row.delete_after, row.deleted_at) == (NOW, None)


@pytest.mark.parametrize(
    "overrides",
    [
        {"size_bytes": -1},
        {"key_envelope": None},  # live without a key
        {"deleted_at": NOW},  # deleted but still holding its key
    ],
)
def test_invalid_artifact_rows_are_rejected(
    db_session: Session, acme: Asset, overrides: dict[str, object]
) -> None:
    db_session.add(_artifact(acme, **overrides))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_a_deleted_artifact_keeps_its_row_without_a_key(db_session: Session, acme: Asset) -> None:
    artifact = _artifact(acme, key_envelope=None, deleted_at=NOW)
    db_session.add(artifact)

    db_session.flush()

    assert db_session.get_one(Artifact, artifact.id).key_envelope is None


def test_unknown_kind_is_rejected_by_the_database(db_session: Session, acme: Asset) -> None:
    artifact = _artifact(acme)
    db_session.add(artifact)
    db_session.flush()

    with pytest.raises(IntegrityError):
        db_session.execute(
            text("UPDATE artifacts SET kind = 'archive' WHERE id = :id"), {"id": artifact.id}
        )


def test_storage_key_is_unique(db_session: Session, acme: Asset) -> None:
    db_session.add(_artifact(acme, storage_key="same"))
    db_session.flush()
    db_session.add(_artifact(acme, storage_key="same"))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_artifact_cannot_point_at_another_orgs_asset(db_session: Session, acme: Asset) -> None:
    globex = _asset(db_session, "globex")
    db_session.add(_artifact(acme, asset_id=globex.id))

    with pytest.raises(IntegrityError):
        db_session.flush()


@pytest.mark.parametrize("parent", [Asset, Org])
def test_deleting_the_asset_or_org_deletes_the_row_and_its_key(
    db_session: Session, acme: Asset, parent: type[Asset] | type[Org]
) -> None:
    # Crypto-erase by cascade: with the row goes the only copy of the wrapped key.
    artifact_id: UUID = uuid4()
    db_session.add(_artifact(acme, id=artifact_id))
    db_session.flush()
    parent_id = acme.id if parent is Asset else acme.org_id

    db_session.execute(delete(parent).where(parent.id == parent_id))

    assert db_session.scalar(select(Artifact.id).where(Artifact.id == artifact_id)) is None


def test_artifacts_are_tenant_scoped(db_session: Session, acme: Asset) -> None:
    globex = _asset(db_session, "globex")
    mine, theirs = _artifact(acme), _artifact(globex)
    db_session.add_all([mine, theirs])
    db_session.flush()

    assert db_session.scalars(scoped(Artifact, acme.org_id)).all() == [mine]
    assert get_scoped(db_session, Artifact, theirs.id, acme.org_id) is None
