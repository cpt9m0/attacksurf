"""Artifact use cases (#85): encrypted round-trip, quota, retention, tenant isolation."""

import hashlib
import io
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, event, select, update
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    STAGE_MAX_AGE_SECONDS,
    STAGED_NAME,
    ArtifactKind,
    ArtifactNotFound,
    ArtifactPolicy,
    ArtifactQuotaExceeded,
    ArtifactStorageUnavailable,
    ArtifactStore,
    ArtifactTooLarge,
)
from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType
from attacksurf.infra.crypto import CHUNK_BYTES, EnvelopeCipher
from attacksurf.infra.db.models import Artifact, Asset, AuditLog, Org, User
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.services import artifacts
from tests.fakes import FakeArtifactStore

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
POLICY = ArtifactPolicy(max_bytes=1024 * 1024, org_quota_bytes=4 * 1024 * 1024, retention_hours=0)


@dataclass
class Tenant:
    org_id: UUID
    asset_id: UUID


def _tenant(session: Session, name: str) -> Tenant:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    asset = Asset(
        org_id=org.id,
        type=AssetType.DOMAIN,  # repo/binary assets arrive with #87/#101; any asset can own one
        value=f"{name}.example",
        source=AssetSource.USER,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(asset)
    # Committed (inside the test's outer transaction): the use cases roll back between steps.
    session.commit()
    return Tenant(org.id, asset.id)


@pytest.fixture(autouse=True)
def _expire_loaded_rows(db_session: Session) -> Iterator[None]:
    """Use cases roll back and reload rows; a stale instance here would mask what they wrote."""
    yield
    db_session.expire_all()


@pytest.fixture
def acme(db_session: Session) -> Tenant:
    return _tenant(db_session, "acme")


@pytest.fixture
def globex(db_session: Session) -> Tenant:
    return _tenant(db_session, "globex")


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    store_root, run_root = tmp_path / "store", tmp_path / "run"
    store_root.mkdir()
    run_root.mkdir()
    return store_root, run_root


@pytest.fixture
def store(roots: tuple[Path, Path]) -> LocalArtifactStore:
    return LocalArtifactStore(*roots, EnvelopeCipher(b"k" * 32, purpose=b"artifact"))


def _store(
    session: Session,
    store: ArtifactStore,
    tenant: Tenant,
    payload: bytes = b"payload",
    *,
    policy: ArtifactPolicy = POLICY,
    now: datetime = NOW,
    actor_id: UUID | None = None,
) -> Artifact:
    return artifacts.store_artifact(
        session,
        store,
        policy,
        org_id=tenant.org_id,
        asset_id=tenant.asset_id,
        kind=ArtifactKind.REPO,
        source=io.BytesIO(payload),
        actor_id=actor_id,
        now=now,
    )


def _files(root: Path) -> list[Path]:
    """Files under `root`, without the store's per-artifact lock files."""
    return [path for path in root.rglob("*") if path.is_file() and path.suffix != ".lock"]


def _actions(session: Session, org_id: UUID) -> list[tuple[str, dict[str, object]]]:
    rows = session.scalars(
        select(AuditLog).where(AuditLog.org_id == org_id).order_by(AuditLog.created_at, AuditLog.id)
    )
    return [(row.action, row.details) for row in rows]


def test_stored_artifact_round_trips_as_a_stream(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    payload = secrets.token_bytes(2 * CHUNK_BYTES + 99)

    artifact = _store(db_session, store, acme, payload)
    chunks = list(artifacts.open_artifact(db_session, store, acme.org_id, artifact.id))

    assert b"".join(chunks) == payload
    assert len(chunks) == 3
    assert artifact.sha256 == hashlib.sha256(payload).hexdigest()
    assert artifact.size_bytes == len(payload)
    assert artifact.kind is ArtifactKind.REPO
    assert artifact.storage_key == f"{acme.org_id}/{artifact.id}"
    assert artifact.deleted_at is None
    assert payload[:64] not in (roots[0] / artifact.storage_key).read_bytes()


def test_store_commits_the_row_with_an_audit_entry(
    db_session: Session, store: LocalArtifactStore, acme: Tenant
) -> None:
    user = User(email="alice@example.com", password_hash="x")
    db_session.add(user)
    db_session.commit()

    artifact = _store(db_session, store, acme, b"payload", actor_id=user.id)

    assert not db_session.in_transaction()
    entry = db_session.scalars(select(AuditLog).where(AuditLog.org_id == acme.org_id)).one()
    assert (entry.action, entry.target_type, entry.target_id) == (
        "artifact.stored",
        "artifact",
        str(artifact.id),
    )
    assert entry.actor_user_id == user.id
    assert entry.details == {
        "kind": "repo",
        "size_bytes": 7,
        "sha256": hashlib.sha256(b"payload").hexdigest(),
    }


@pytest.mark.parametrize(("retention_hours", "expected_hours"), [(0, 24), (72, 72)])
def test_delete_after_follows_retention_with_a_24_hour_backstop(
    db_session: Session, acme: Tenant, retention_hours: int, expected_hours: int
) -> None:
    policy = ArtifactPolicy(max_bytes=1024, org_quota_bytes=4096, retention_hours=retention_hours)

    artifact = _store(db_session, FakeArtifactStore(), acme, policy=policy)

    assert artifact.delete_after == NOW + timedelta(hours=expected_hours)


def test_store_refuses_an_asset_of_another_org(
    db_session: Session, acme: Tenant, globex: Tenant
) -> None:
    store = FakeArtifactStore()

    with pytest.raises(AssetNotFound):
        artifacts.store_artifact(
            db_session,
            store,
            POLICY,
            org_id=acme.org_id,
            asset_id=globex.asset_id,
            kind=ArtifactKind.BINARY,
            source=io.BytesIO(b"payload"),
            actor_id=None,
        )

    assert store.blobs == {}


def test_store_rejects_an_oversized_stream_and_leaves_nothing(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    policy = ArtifactPolicy(
        max_bytes=CHUNK_BYTES, org_quota_bytes=10 * CHUNK_BYTES, retention_hours=0
    )

    with pytest.raises(ArtifactTooLarge):
        _store(db_session, store, acme, b"x" * (3 * CHUNK_BYTES), policy=policy)

    assert _files(roots[0]) == []
    assert db_session.scalars(select(Artifact)).all() == []
    assert _actions(db_session, acme.org_id) == []


def test_store_caps_the_stream_at_the_remaining_quota(db_session: Session, acme: Tenant) -> None:
    policy = ArtifactPolicy(max_bytes=100, org_quota_bytes=150, retention_hours=0)
    store = FakeArtifactStore()
    _store(db_session, store, acme, b"x" * 100, policy=policy)

    with pytest.raises(ArtifactQuotaExceeded):
        _store(db_session, store, acme, b"x" * 60, policy=policy)

    assert store.put_limits == [100, 50]
    assert len(store.blobs) == 1


def test_store_refuses_when_the_quota_is_already_used_up(db_session: Session, acme: Tenant) -> None:
    policy = ArtifactPolicy(max_bytes=100, org_quota_bytes=100, retention_hours=0)
    store = FakeArtifactStore()
    _store(db_session, store, acme, b"x" * 100, policy=policy)

    with pytest.raises(ArtifactQuotaExceeded):
        _store(db_session, store, acme, b"x", policy=policy)

    assert store.put_limits == [100]  # the second upload was never read


def test_quota_is_per_org_and_ignores_deleted_artifacts(
    db_session: Session, acme: Tenant, globex: Tenant
) -> None:
    policy = ArtifactPolicy(max_bytes=100, org_quota_bytes=100, retention_hours=0)
    store = FakeArtifactStore()
    first = _store(db_session, store, acme, b"x" * 100, policy=policy)

    _store(db_session, store, globex, b"x" * 100, policy=policy)
    artifacts.delete_artifact(db_session, store, acme.org_id, first.id, actor_id=None)
    again = _store(db_session, store, acme, b"x" * 100, policy=policy)

    assert again.size_bytes == 100


def test_quota_is_rechecked_after_the_upload_and_the_file_removed(
    db_session: Session, acme: Tenant
) -> None:
    # A concurrent upload that committed while this one was streaming.
    policy = ArtifactPolicy(max_bytes=100, org_quota_bytes=150, retention_hours=0)
    store = FakeArtifactStore()

    class Racing(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            _store(db_session, FakeArtifactStore(), acme, b"y" * 100, policy=policy)
            return super().read(size)

    with pytest.raises(ArtifactQuotaExceeded):
        artifacts.store_artifact(
            db_session,
            store,
            policy,
            org_id=acme.org_id,
            asset_id=acme.asset_id,
            kind=ArtifactKind.REPO,
            source=Racing(b"x" * 100),
            actor_id=None,
        )

    assert store.blobs == {}
    assert len(store.deleted) == 1
    assert len(db_session.scalars(select(Artifact)).all()) == 1


def test_store_removes_the_file_when_the_commit_fails(
    db_session: Session, acme: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FakeArtifactStore()

    def broken_audit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("database went away")

    monkeypatch.setattr(artifacts, "audit", broken_audit)

    with pytest.raises(RuntimeError):
        _store(db_session, store, acme)

    assert store.blobs == {}
    assert db_session.scalars(select(Artifact)).all() == []


def test_store_keeps_the_original_error_when_the_cleanup_fails_too(
    db_session: Session,
    store: LocalArtifactStore,
    acme: Tenant,
    roots: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_audit(*_args: object, **_kwargs: object) -> None:
        # Make the stored file undeletable (a non-empty directory), then fail the use case.
        (blob,) = _files(roots[0])
        blob.unlink()
        (blob / "child").mkdir(parents=True)
        raise RuntimeError("database went away")

    monkeypatch.setattr(artifacts, "audit", broken_audit)

    with pytest.raises(RuntimeError, match="database went away"):
        _store(db_session, store, acme)

    assert not db_session.in_transaction()
    assert db_session.scalars(select(Artifact)).all() == []


def test_store_holds_no_transaction_while_the_upload_streams(
    db_session: Session, acme: Tenant
) -> None:
    open_during_read: list[bool] = []

    class Watching(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            open_during_read.append(db_session.in_transaction())
            return super().read(size)

    artifacts.store_artifact(
        db_session,
        FakeArtifactStore(),
        POLICY,
        org_id=acme.org_id,
        asset_id=acme.asset_id,
        kind=ArtifactKind.REPO,
        source=Watching(b"payload"),
        actor_id=None,
    )

    assert open_during_read == [False]


def test_store_locks_the_org_row_before_it_rechecks_the_quota_and_inserts(
    db_session: Session, acme: Tenant
) -> None:
    statements: list[str] = []

    def record(_conn: object, _cursor: object, statement: str, *_rest: object) -> None:
        statements.append(" ".join(statement.split()))

    connection = db_session.get_bind()
    event.listen(connection, "before_cursor_execute", record)
    try:
        _store(db_session, FakeArtifactStore(), acme)
    finally:
        event.remove(connection, "before_cursor_execute", record)

    lock = next(
        index
        for index, sql in enumerate(statements)
        if "FROM orgs" in sql and sql.endswith("FOR UPDATE")
    )
    usage_checks = [index for index, sql in enumerate(statements) if "sum(artifacts.size" in sql]
    insert = next(i for i, sql in enumerate(statements) if sql.startswith("INSERT INTO artifacts"))
    assert len(usage_checks) == 2
    assert usage_checks[0] < lock < usage_checks[1] < insert


def test_store_without_an_encryption_key_fails_closed(
    db_session: Session, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    keyless = LocalArtifactStore(*roots, None)

    with pytest.raises(ArtifactStorageUnavailable):
        _store(db_session, keyless, acme)

    assert _files(roots[0]) == []
    assert db_session.scalars(select(Artifact)).all() == []


def test_another_org_cannot_read_stage_or_delete_an_artifact(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, globex: Tenant
) -> None:
    artifact = _store(db_session, store, acme)

    with pytest.raises(ArtifactNotFound):
        artifacts.open_artifact(db_session, store, globex.org_id, artifact.id)
    with pytest.raises(ArtifactNotFound):
        artifacts.stage_artifact(db_session, store, globex.org_id, artifact.id)
    with pytest.raises(ArtifactNotFound):
        artifacts.delete_artifact(db_session, store, globex.org_id, artifact.id, actor_id=None)

    assert b"".join(artifacts.open_artifact(db_session, store, acme.org_id, artifact.id)) == (
        b"payload"
    )
    assert _actions(db_session, globex.org_id) == []


def test_unknown_artifact_reads_like_another_orgs(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, globex: Tenant
) -> None:
    artifact = _store(db_session, store, acme)

    with pytest.raises(ArtifactNotFound) as foreign:
        artifacts.open_artifact(db_session, store, globex.org_id, artifact.id)
    with pytest.raises(ArtifactNotFound) as unknown:
        artifacts.open_artifact(db_session, store, globex.org_id, uuid4())

    assert str(foreign.value) == str(unknown.value) == "Artifact not found."


def test_stage_writes_the_plaintext_for_one_run(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    artifact = _store(db_session, store, acme, b"plaintext for the sandbox")

    artifacts.stage_artifact(db_session, store, acme.org_id, artifact.id)

    staged = roots[1] / str(artifact.id) / STAGED_NAME
    assert staged.read_bytes() == b"plaintext for the sandbox"
    store.unstage(artifact.id)
    assert list(roots[1].iterdir()) == []


def test_delete_removes_the_file_erases_the_key_and_keeps_the_row(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    artifact = _store(db_session, store, acme)
    artifacts.stage_artifact(db_session, store, acme.org_id, artifact.id)

    artifacts.delete_artifact(
        db_session, store, acme.org_id, artifact.id, actor_id=None, reason="analysis_complete"
    )

    row = db_session.get_one(Artifact, artifact.id)
    assert row.deleted_at is not None
    assert row.key_envelope is None
    assert _files(roots[0]) == []
    assert list(roots[1].iterdir()) == []
    assert _actions(db_session, acme.org_id)[-1] == (
        "artifact.deleted",
        {"reason": "analysis_complete"},
    )
    for use in (artifacts.open_artifact, artifacts.stage_artifact):
        with pytest.raises(ArtifactNotFound):
            use(db_session, store, acme.org_id, artifact.id)


def test_delete_twice_is_a_no_op(db_session: Session, acme: Tenant) -> None:
    store = FakeArtifactStore()
    artifact = _store(db_session, store, acme)
    artifacts.delete_artifact(db_session, store, acme.org_id, artifact.id, actor_id=None, now=NOW)

    artifacts.delete_artifact(db_session, store, acme.org_id, artifact.id, actor_id=None)

    assert not db_session.in_transaction()  # the row lock is released
    assert len(store.deleted) == 1
    assert db_session.get_one(Artifact, artifact.id).deleted_at == NOW
    assert [action for action, _ in _actions(db_session, acme.org_id)] == [
        "artifact.stored",
        "artifact.deleted",
    ]


def test_delete_is_a_no_op_when_another_transaction_deleted_a_row_this_session_holds(
    db_session: Session, acme: Tenant
) -> None:
    store = FakeArtifactStore()
    artifact_id = _store(db_session, store, acme).id
    held = db_session.get_one(Artifact, artifact_id)
    assert held.deleted_at is None
    # Stands in for a concurrent purge: the row changes underneath the loaded instance.
    db_session.execute(
        update(Artifact)
        .where(Artifact.id == artifact_id)
        .values(deleted_at=NOW, key_envelope=None)
        .execution_options(synchronize_session=False)
    )

    artifacts.delete_artifact(
        db_session,
        store,
        acme.org_id,
        artifact_id,
        actor_id=None,
        reason="analysis_complete",
        now=NOW + timedelta(hours=5),
    )

    assert store.deleted == []
    assert [action for action, _ in _actions(db_session, acme.org_id)] == ["artifact.stored"]


def test_delete_changes_nothing_and_releases_the_lock_when_the_file_cannot_be_removed(
    db_session: Session, acme: Tenant
) -> None:
    store = FakeArtifactStore()
    artifact = _store(db_session, store, acme)
    store.undeletable.add(artifact.id)

    with pytest.raises(ArtifactStorageUnavailable):
        artifacts.delete_artifact(db_session, store, acme.org_id, artifact.id, actor_id=None)

    assert not db_session.in_transaction()
    row = db_session.get_one(Artifact, artifact.id)
    assert (row.deleted_at is None, row.key_envelope is None) == (True, False)
    assert [action for action, _ in _actions(db_session, acme.org_id)] == ["artifact.stored"]


def test_purge_deletes_the_file_and_marks_the_row_once_retention_passes(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    policy = ArtifactPolicy(max_bytes=1024, org_quota_bytes=4096, retention_hours=48)
    expired = _store(db_session, store, acme, b"old", policy=policy, now=NOW - timedelta(hours=49))
    kept = _store(db_session, store, acme, b"new", policy=policy, now=NOW - timedelta(hours=47))

    purged = artifacts.purge_expired(db_session, store, now=NOW)

    assert purged == 1
    row = db_session.get_one(Artifact, expired.id)
    assert (row.deleted_at, row.key_envelope) == (NOW, None)
    assert db_session.get_one(Artifact, kept.id).deleted_at is None
    assert _files(roots[0]) == [roots[0] / str(acme.org_id) / str(kept.id)]
    assert _actions(db_session, acme.org_id)[-1] == ("artifact.deleted", {"reason": "expired"})


def test_purge_works_without_an_encryption_key(
    db_session: Session, store: LocalArtifactStore, acme: Tenant, roots: tuple[Path, Path]
) -> None:
    artifact = _store(db_session, store, acme, now=NOW - timedelta(days=2))
    keyless = LocalArtifactStore(*roots, None)

    assert artifacts.purge_expired(db_session, keyless, now=NOW) == 1

    assert _files(roots[0]) == []
    assert db_session.get_one(Artifact, artifact.id).deleted_at == NOW


def test_purge_covers_every_org_and_skips_already_deleted_rows(
    db_session: Session, acme: Tenant, globex: Tenant
) -> None:
    store = FakeArtifactStore()
    past = NOW - timedelta(days=2)
    one = _store(db_session, store, acme, now=past)
    two = _store(db_session, store, globex, now=past)
    gone = _store(db_session, store, acme, now=past)
    artifacts.delete_artifact(db_session, store, acme.org_id, gone.id, actor_id=None)
    store.deleted.clear()

    assert artifacts.purge_expired(db_session, store, now=NOW) == 2

    assert set(store.deleted) == {(acme.org_id, one.id), (globex.org_id, two.id)}
    assert artifacts.purge_expired(db_session, store, now=NOW) == 0


def test_purge_is_bounded_and_takes_the_oldest_first(db_session: Session, acme: Tenant) -> None:
    store = FakeArtifactStore()
    newer = _store(db_session, store, acme, now=NOW - timedelta(days=2))
    older = _store(db_session, store, acme, now=NOW - timedelta(days=3))

    assert artifacts.purge_expired(db_session, store, now=NOW, limit=1) == 1

    assert db_session.get_one(Artifact, older.id).deleted_at is not None
    assert db_session.get_one(Artifact, newer.id).deleted_at is None


def test_purge_continues_past_a_file_it_cannot_delete(db_session: Session, acme: Tenant) -> None:
    store = FakeArtifactStore()
    stuck = _store(db_session, store, acme, now=NOW - timedelta(days=3))  # sorts first
    later = _store(db_session, store, acme, now=NOW - timedelta(days=2))
    store.undeletable.add(stuck.id)

    assert artifacts.purge_expired(db_session, store, now=NOW) == 1

    assert not db_session.in_transaction()
    row = db_session.get_one(Artifact, stuck.id)
    assert row.deleted_at is None  # still live, so the next run retries it
    assert row.key_envelope is not None
    purged = db_session.get_one(Artifact, later.id)
    assert (purged.deleted_at, purged.key_envelope) == (NOW, None)
    assert store.swept == [STAGE_MAX_AGE_SECONDS]


def test_purge_continues_when_a_row_was_cascaded_away_after_the_scan(
    db_session: Session, acme: Tenant, globex: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FakeArtifactStore()
    orphan = _store(db_session, store, acme, now=NOW - timedelta(days=3))  # sorts first
    later = _store(db_session, store, globex, now=NOW - timedelta(days=2))
    orphan_id, real_delete = orphan.id, artifacts.delete_artifact

    def asset_deleted_first(session: Session, *args: object, **kwargs: object) -> None:
        if args[2] == orphan_id:
            session.execute(delete(Asset).where(Asset.id == acme.asset_id))
            session.commit()
        real_delete(session, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(artifacts, "delete_artifact", asset_deleted_first)

    assert artifacts.purge_expired(db_session, store, now=NOW) == 1

    assert not db_session.in_transaction()
    assert db_session.get_one(Artifact, later.id).deleted_at == NOW
    # The row is gone; its file is removed as well.
    assert store.deleted == [(acme.org_id, orphan_id), (globex.org_id, later.id)]
    assert store.swept == [STAGE_MAX_AGE_SECONDS]


def test_purge_sweeps_staged_plaintext_even_when_an_item_fails_unexpectedly(
    db_session: Session, acme: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FakeArtifactStore()
    _store(db_session, store, acme, now=NOW - timedelta(days=2))

    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("database went away")

    monkeypatch.setattr(artifacts, "delete_artifact", broken)

    with pytest.raises(RuntimeError):
        artifacts.purge_expired(db_session, store, now=NOW)

    assert store.swept == [STAGE_MAX_AGE_SECONDS]


def test_purge_sweeps_stale_staged_plaintext(db_session: Session) -> None:
    store = FakeArtifactStore()

    artifacts.purge_expired(db_session, store, now=NOW)

    assert store.swept == [STAGE_MAX_AGE_SECONDS]


def _move_deadline(session: Session, artifact: Artifact, deadline: datetime) -> None:
    """Pin an artifact's retention deadline (storing one leaves 24 h when retention is 0)."""
    session.execute(
        update(Artifact).where(Artifact.id == artifact.id).values(delete_after=deadline)
    )
    session.commit()


def test_purge_retries_an_undeletable_artifact_after_the_retry_delay(
    db_session: Session, acme: Tenant
) -> None:
    # A failed item must not be skipped by the next run, or fixing its cause would never recover
    # it: it stays due, just later than anything still waiting.
    store = FakeArtifactStore()
    blocked = _store(db_session, store, acme)
    _move_deadline(db_session, blocked, NOW - timedelta(days=3))
    store.undeletable.add(blocked.id)

    assert artifacts.purge_expired(db_session, store, now=NOW) == 0
    deferred = db_session.get_one(Artifact, blocked.id)
    assert deferred.deleted_at is None
    assert deferred.key_envelope is not None  # the file is still there, so the key must stay
    assert deferred.delete_after == NOW + timedelta(minutes=1)

    store.undeletable.clear()

    assert artifacts.purge_expired(db_session, store, now=deferred.delete_after + timedelta(0)) == 1
    assert db_session.get_one(Artifact, blocked.id).deleted_at == deferred.delete_after


def test_purge_does_not_defer_a_row_whose_deadline_moved_since_selection(
    db_session: Session, acme: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A request that sets a newer deadline between selection and the attempt wins: the failed
    # attempt's retry rule must not pull it back to the top of the queue.
    store = FakeArtifactStore()
    artifact = _store(db_session, store, acme)
    _move_deadline(db_session, artifact, NOW - timedelta(days=3))
    store.undeletable.add(artifact.id)
    moved = NOW + timedelta(days=10)
    real_locked = artifacts._locked
    calls = iter([False, True])

    def moved_before_the_retry(
        session: Session, org_id: UUID, artifact_id: UUID
    ) -> Artifact | None:
        if next(calls, False):  # the second lookup is the one `_defer_retry` makes
            session.execute(
                update(Artifact).where(Artifact.id == artifact_id).values(delete_after=moved)
            )
            session.commit()
        return real_locked(session, org_id, artifact_id)

    monkeypatch.setattr(artifacts, "_locked", moved_before_the_retry)

    assert artifacts.purge_expired(db_session, store, now=NOW) == 0

    assert db_session.get_one(Artifact, artifact.id).delete_after == moved


def test_purge_does_not_starve_newer_artifacts_behind_a_full_failing_batch(
    db_session: Session, acme: Tenant
) -> None:
    # The reported bug: when the batch is full of undeletable rows, the rows behind them (other
    # orgs' included) were never reached, so they stayed past retention indefinitely.
    store = FakeArtifactStore()
    stuck = [_store(db_session, store, acme) for _ in range(3)]
    for index, artifact in enumerate(stuck):
        _move_deadline(db_session, artifact, NOW - timedelta(days=5, hours=index))
    store.undeletable.update(artifact.id for artifact in stuck)
    later = _store(db_session, store, acme)
    _move_deadline(db_session, later, NOW - timedelta(days=4))

    # A batch exactly full of failures must still end with the artifacts behind them reached in
    # a later run, not starved by the same full batch forever.
    assert artifacts.purge_expired(db_session, store, now=NOW, limit=len(stuck)) == 0
    assert db_session.get_one(Artifact, later.id).deleted_at is None  # not selected this run

    assert artifacts.purge_expired(db_session, store, now=NOW + timedelta(minutes=1)) == 1
    assert db_session.get_one(Artifact, later.id).deleted_at == NOW + timedelta(minutes=1)
    assert all(db_session.get_one(Artifact, artifact.id).deleted_at is None for artifact in stuck)


def test_purge_prefers_artifacts_whose_last_attempt_failed_least_recently(
    db_session: Session, acme: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic tie-break: with more failing rows than the batch size, the ones attempted
    # most recently go last, so every artifact eventually gets its turn.
    store = FakeArtifactStore()
    first, second = _store(db_session, store, acme), _store(db_session, store, acme)
    _move_deadline(db_session, first, NOW - timedelta(days=4))
    _move_deadline(db_session, second, NOW - timedelta(days=3))
    store.undeletable.update({first.id, second.id})
    attempted: list[UUID] = []
    real_delete = artifacts.delete_artifact

    def record_delete(session: Session, *args: object, **kwargs: object) -> None:
        attempted.append(args[2])  # type: ignore[arg-type]  # (session, store, org_id, artifact_id)
        real_delete(session, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(artifacts, "delete_artifact", record_delete)

    retry = NOW
    for _ in range(3):
        artifacts.purge_expired(db_session, store, now=retry, limit=1)
        retry += timedelta(minutes=1)

    assert attempted == [first.id, second.id, first.id]
