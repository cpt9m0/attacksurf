"""Repo archive upload (#87): asset + artifact + queued code scan, cleanup, tenant isolation."""

import hashlib
import io
from pathlib import Path
from typing import IO
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    ArtifactPolicy,
    ArtifactTooLarge,
    StoredArtifact,
    UnsupportedArtifactFormat,
)
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import JobStatus, ScanNotQueued, ScanStatus
from attacksurf.infra.db.models import Artifact, Asset, AuditLog, Job, Org, Scan
from attacksurf.scanners.profiles import CODE_PROFILE, PROFILES
from attacksurf.services.repos import CODE_SCAN_TASK, RepoUpload, upload_repo_archive
from tests.fakes import FakeArtifactStore, FakeQueue

ZIP = (Path(__file__).resolve().parents[2] / "fixtures" / "archives" / "ok.zip").read_bytes()
POLICY = ArtifactPolicy(max_bytes=1024 * 1024, org_quota_bytes=4 * 1024 * 1024, retention_hours=0)


def _org(session: Session, name: str = "acme") -> UUID:
    org = Org(name=name, slug=name)
    session.add(org)
    session.commit()  # the use case rolls back between steps
    return org.id


def _upload(
    session: Session,
    store: FakeArtifactStore,
    org_id: UUID,
    *,
    data: bytes = ZIP,
    filename: str = "My App.zip",
    queue: FakeQueue | None = None,
    policy: ArtifactPolicy = POLICY,
) -> RepoUpload:
    return upload_repo_archive(
        session,
        store,
        policy,
        queue or FakeQueue(session),
        org_id=org_id,
        filename=filename,
        source=io.BytesIO(data),
        actor_id=None,
    )


def test_upload_creates_repo_asset_artifact_and_queued_code_scan(db_session: Session) -> None:
    org_id, store, queue = _org(db_session), FakeArtifactStore(), FakeQueue(db_session)

    upload = _upload(db_session, store, org_id, queue=queue)

    asset = db_session.get_one(Asset, upload.asset_id)
    artifact = db_session.get_one(Artifact, upload.artifact_id)
    scan = db_session.get_one(Scan, upload.scan_id)
    job = db_session.scalars(select(Job).where(Job.scan_id == scan.id)).one()
    digest = hashlib.sha256(ZIP).hexdigest()
    assert (asset.type, asset.value, asset.source) == (
        AssetType.REPO,
        "upload/my-app",
        AssetSource.USER,
    )
    assert asset.details["upload"] == {"filename": "My App.zip"}
    assert (artifact.asset_id, artifact.sha256, artifact.size_bytes) == (asset.id, digest, len(ZIP))
    assert store.blobs[org_id, artifact.id] == ZIP
    assert (scan.root_asset_id, scan.profile, scan.status) == (
        asset.id,
        CODE_PROFILE,
        ScanStatus.QUEUED,
    )
    assert scan.stats == {"revision": digest, "artifact_id": str(artifact.id)}
    assert (job.stage, job.status, job.asset_id) == ("analysis", JobStatus.QUEUED, asset.id)
    # Sent only after everything was committed: a worker must find the rows.
    assert queue.sent == [(CODE_SCAN_TASK, org_id, job.id, True)]


def test_code_profile_selects_no_scanner_until_an_analyzer_ships() -> None:
    assert CODE_PROFILE not in PROFILES
    assert CODE_SCAN_TASK.startswith("analysis.")


def test_upload_is_audited_with_ids_digest_and_size(db_session: Session) -> None:
    org_id = _org(db_session)

    upload = _upload(db_session, FakeArtifactStore(), org_id)

    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.action == "repo.archive_uploaded")
    ).one()
    assert (entry.org_id, entry.target_type, entry.target_id) == (
        org_id,
        "asset",
        str(upload.asset_id),
    )
    assert entry.details == {
        "artifact_id": str(upload.artifact_id),
        "scan_id": str(upload.scan_id),
        "sha256": hashlib.sha256(ZIP).hexdigest(),
        "size_bytes": len(ZIP),
    }


def test_uploading_the_same_name_again_adds_a_version_to_the_same_asset(
    db_session: Session,
) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    first = _upload(db_session, store, org_id)
    second = _upload(db_session, store, org_id, filename="my-app.tar.gz")

    assert second.asset_id == first.asset_id
    assert second.artifact_id != first.artifact_id
    assert len(db_session.scalars(select(Scan)).all()) == 2


@pytest.mark.parametrize("data", [b"", b"MZ\x90\x00 not an archive", b"plain text"])
def test_upload_that_is_not_an_archive_is_rejected_before_anything_is_stored(
    db_session: Session, data: bytes
) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    with pytest.raises(UnsupportedArtifactFormat):
        _upload(db_session, store, org_id, data=data)

    assert store.put_limits == []
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_that_fails_in_storage_stores_nothing(db_session: Session) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()
    tiny = ArtifactPolicy(max_bytes=8, org_quota_bytes=1024, retention_hours=0)

    with pytest.raises(ArtifactTooLarge):
        _upload(db_session, store, org_id, policy=tiny)

    assert db_session.scalars(select(Artifact)).all() == []
    assert db_session.scalars(select(Scan)).all() == []
    assert store.blobs == {}


def test_failed_upload_never_removes_a_concurrent_upload_of_the_same_name(
    db_session: Session,
) -> None:
    """Regression: the failed upload used to delete "its" asset, and with it the other
    upload's artifact row and scan, leaving that upload's file orphaned in the store."""
    org_id = _org(db_session)
    finished: list[RepoUpload] = []
    calls: list[UUID] = []

    class Interleaved(FakeArtifactStore):
        def put(
            self, org_id: UUID, artifact_id: UUID, source: IO[bytes], *, max_bytes: int
        ) -> StoredArtifact:
            calls.append(artifact_id)
            if len(calls) == 1:  # while the first upload streams, a second one completes
                finished.append(_upload(db_session, self, org_id))
                raise ArtifactTooLarge("The artifact is larger than the allowed size.")
            return super().put(org_id, artifact_id, source, max_bytes=max_bytes)

    store = Interleaved()

    with pytest.raises(ArtifactTooLarge):
        _upload(db_session, store, org_id)

    (other,) = finished
    assert db_session.get(Asset, other.asset_id) is not None
    assert db_session.get(Artifact, other.artifact_id) is not None
    assert db_session.get_one(Scan, other.scan_id).status == ScanStatus.QUEUED
    assert set(store.blobs) == {(org_id, other.artifact_id)}


def test_failed_upload_in_one_org_leaves_the_same_name_in_another_org_alone(
    db_session: Session,
) -> None:
    store = FakeArtifactStore()
    acme, other = _org(db_session, "acme"), _org(db_session, "other")
    mine = _upload(db_session, store, acme)
    tiny = ArtifactPolicy(max_bytes=8, org_quota_bytes=1024, retention_hours=0)

    with pytest.raises(ArtifactTooLarge):
        _upload(db_session, store, other, policy=tiny)

    assert db_session.get_one(Asset, mine.asset_id).org_id == acme
    assert db_session.get(Artifact, mine.artifact_id) is not None
    assert db_session.scalars(select(Artifact).where(Artifact.org_id == other)).all() == []


@pytest.mark.parametrize(
    ("filename", "shown"),
    [
        ("a\x00b\x1f.zip", "ab.zip"),  # Postgres rejects NUL in JSONB: this used to be a 500
        ("C:\\Users\\me\\src/../My App.zip", "My App.zip"),
        ("n" * 300 + ".zip", "n" * 255),
    ],
)
def test_original_file_name_is_kept_without_path_or_control_characters_and_bounded(
    db_session: Session, filename: str, shown: str
) -> None:
    org_id = _org(db_session)

    upload = _upload(db_session, FakeArtifactStore(), org_id, filename=filename)

    assert db_session.get_one(Asset, upload.asset_id).details["upload"] == {"filename": shown}


def test_enqueue_failure_fails_the_scan_and_deletes_the_artifact(db_session: Session) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    with pytest.raises(ScanNotQueued):
        _upload(db_session, store, org_id, queue=FakeQueue(db_session, fail=True))

    scan = db_session.scalars(select(Scan)).one()
    artifact = db_session.scalars(select(Artifact)).one()
    assert scan.status == ScanStatus.FAILED
    assert db_session.scalars(select(Job)).one().status == JobStatus.FAILED
    assert artifact.deleted_at is not None
    assert store.blobs == {}


def test_uploads_of_the_same_name_in_two_orgs_stay_separate(db_session: Session) -> None:
    store = FakeArtifactStore()
    acme, other = _org(db_session, "acme"), _org(db_session, "other")

    mine = _upload(db_session, store, acme)
    theirs = _upload(db_session, store, other)

    assert mine.asset_id != theirs.asset_id
    for org_id, upload in ((acme, mine), (other, theirs)):
        assert db_session.get_one(Asset, upload.asset_id).org_id == org_id
        assert db_session.get_one(Artifact, upload.artifact_id).org_id == org_id
        assert db_session.get_one(Scan, upload.scan_id).org_id == org_id
        assert set(store.blobs) >= {(org_id, upload.artifact_id)}
