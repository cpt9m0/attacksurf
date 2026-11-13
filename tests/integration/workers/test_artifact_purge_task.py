"""The retention beat task: deletes expired artifacts with whatever store the worker has."""

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.artifacts import ArtifactKind, ArtifactPolicy
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.infra.crypto import EnvelopeCipher
from attacksurf.infra.db.models import Artifact, Asset, Org
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.services import artifacts
from attacksurf.workers import runtime
from attacksurf.workers.tasks import system

NOW = datetime.now(UTC)
POLICY = ArtifactPolicy(max_bytes=1024, org_quota_bytes=4096, retention_hours=1)


def test_purge_task_deletes_expired_artifacts_even_without_a_key(
    db_session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "run").mkdir()
    store = LocalArtifactStore(
        tmp_path / "store", tmp_path / "run", EnvelopeCipher(b"k" * 32, purpose=b"artifact")
    )
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    asset = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,
        value="acme.example",
        source=AssetSource.USER,
        first_seen=NOW,
        last_seen=NOW,
    )
    db_session.add(asset)
    db_session.commit()
    stored = {
        age: artifacts.store_artifact(
            db_session,
            store,
            POLICY,
            org_id=org.id,
            asset_id=asset.id,
            kind=ArtifactKind.BINARY,
            source=io.BytesIO(b"payload"),
            actor_id=None,
            now=NOW - timedelta(hours=age),
        ).id
        for age in (2, 0)
    }
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    # The worker has no APP_ENCRYPTION_KEY: it can't read artifacts, but must still purge them.
    keyless = LocalArtifactStore(tmp_path / "store", tmp_path / "run", None)
    monkeypatch.setattr(runtime, "artifact_store", lambda: keyless)

    system.purge_expired_artifacts()
    db_session.expire_all()

    expired, fresh = (
        db_session.get_one(Artifact, stored[2]),
        db_session.get_one(Artifact, stored[0]),
    )
    assert expired.deleted_at is not None
    assert expired.key_envelope is None
    assert fresh.deleted_at is None
    assert [path.name for path in (tmp_path / "store" / str(org.id)).iterdir()] == [str(fresh.id)]
