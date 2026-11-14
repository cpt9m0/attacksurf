"""Binary upload (#101): sha256-named asset + artifact + queued binary_static scan."""

import hashlib
import io
from typing import IO
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    ArtifactCorrupt,
    ArtifactPolicy,
    ArtifactQuotaExceeded,
    ArtifactTooLarge,
    StoredArtifact,
    UnsupportedArtifactFormat,
)
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import JobStatus, ScanNotQueued, ScanStatus
from attacksurf.infra.db.models import Artifact, Asset, AuditLog, Job, Org, Scan
from attacksurf.scanners.profiles import BINARY_STATIC_PROFILE, PROFILES
from attacksurf.services.binaries import BINARY_SCAN_TASK, upload_binary
from attacksurf.services.uploads import AssetUpload
from tests.binary_fixtures import CORPUS, DETECTED
from tests.fakes import FakeArtifactStore, FakeQueue

ELF = CORPUS["elf64-le"]
DIGEST = hashlib.sha256(ELF).hexdigest()
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
    data: bytes = ELF,
    filename: str = "My Tool",
    queue: FakeQueue | None = None,
    policy: ArtifactPolicy = POLICY,
) -> AssetUpload:
    return upload_binary(
        session,
        store,
        policy,
        queue or FakeQueue(session),
        org_id=org_id,
        filename=filename,
        source=io.BytesIO(data),
        actor_id=None,
    )


def test_upload_creates_binary_asset_artifact_and_queued_static_scan(db_session: Session) -> None:
    org_id, store, queue = _org(db_session), FakeArtifactStore(), FakeQueue(db_session)

    upload = _upload(db_session, store, org_id, queue=queue)

    asset = db_session.get_one(Asset, upload.asset_id)
    artifact = db_session.get_one(Artifact, upload.artifact_id)
    scan = db_session.get_one(Scan, upload.scan_id)
    job = db_session.scalars(select(Job).where(Job.scan_id == scan.id)).one()
    assert (asset.type, asset.value, asset.source) == (
        AssetType.BINARY,
        f"sha256:{DIGEST}",
        AssetSource.USER,
    )
    assert upload.asset_value == asset.value
    assert asset.details["upload"] == {"filename": "My Tool", "format_hint": "elf"}
    assert (artifact.asset_id, artifact.kind, artifact.sha256) == (asset.id, "binary", DIGEST)
    assert store.blobs[org_id, artifact.id] == ELF
    assert (scan.root_asset_id, scan.profile, scan.status) == (
        asset.id,
        BINARY_STATIC_PROFILE,
        ScanStatus.QUEUED,
    )
    assert scan.stats == {"revision": DIGEST, "artifact_id": str(artifact.id)}
    assert (job.stage, job.status, job.asset_id) == ("analysis", JobStatus.QUEUED, asset.id)
    # Sent only after everything was committed: a worker must find the rows.
    assert queue.sent == [(BINARY_SCAN_TASK, org_id, job.id, True)]


def test_binary_static_profile_selects_no_scanner_until_an_analyzer_ships() -> None:
    assert BINARY_STATIC_PROFILE == "binary_static"
    assert BINARY_STATIC_PROFILE not in PROFILES
    assert BINARY_SCAN_TASK == "analysis.binary_static"


@pytest.mark.parametrize("name", sorted(DETECTED))
def test_every_supported_fixture_passes_the_upload_gate(db_session: Session, name: str) -> None:
    org_id = _org(db_session)

    upload = _upload(db_session, FakeArtifactStore(), org_id, data=CORPUS[name])

    assert upload.asset_value == "sha256:" + hashlib.sha256(CORPUS[name]).hexdigest()


def test_upload_is_audited_with_ids_digest_size_and_format_hint(db_session: Session) -> None:
    org_id = _org(db_session)

    upload = _upload(db_session, FakeArtifactStore(), org_id)

    entry = db_session.scalars(select(AuditLog).where(AuditLog.action == "binary.uploaded")).one()
    assert (entry.org_id, entry.target_type, entry.target_id) == (
        org_id,
        "asset",
        str(upload.asset_id),
    )
    assert entry.details == {
        "artifact_id": str(upload.artifact_id),
        "scan_id": str(upload.scan_id),
        "sha256": DIGEST,
        "size_bytes": len(ELF),
        "format_hint": "elf",
    }


def test_uploading_the_same_bytes_again_reuses_the_asset_and_adds_a_scan(
    db_session: Session,
) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    first = _upload(db_session, store, org_id)
    second = _upload(db_session, store, org_id, filename="renamed.bin")

    assert second.asset_id == first.asset_id
    assert second.artifact_id != first.artifact_id
    assert len(db_session.scalars(select(Scan)).all()) == 2
    assert db_session.get_one(Asset, first.asset_id).details["upload"]["filename"] == "renamed.bin"


@pytest.mark.parametrize("data", [b"", CORPUS["text.txt"], b"#!/bin/sh\nrm -rf /\n"])
def test_upload_that_is_not_a_binary_is_rejected_before_anything_is_stored(
    db_session: Session, data: bytes
) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    with pytest.raises(UnsupportedArtifactFormat):
        _upload(db_session, store, org_id, data=data)

    assert store.put_limits == []
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_over_the_size_cap_is_refused_while_hashing_and_leaves_no_asset(
    db_session: Session,
) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()
    tiny = ArtifactPolicy(max_bytes=8, org_quota_bytes=1024, retention_hours=0)

    with pytest.raises(ArtifactTooLarge):
        _upload(db_session, store, org_id, policy=tiny)

    assert store.put_limits == []
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_that_does_not_fit_the_org_quota_is_refused_and_leaves_no_asset(
    db_session: Session,
) -> None:
    """Regression: every distinct file refused for quota left a `sha256:` asset behind."""
    org_id, store = _org(db_session), FakeArtifactStore()
    full = ArtifactPolicy(max_bytes=1024, org_quota_bytes=len(ELF) + 1, retention_hours=0)
    first = _upload(db_session, store, org_id, policy=full)

    with pytest.raises(ArtifactQuotaExceeded):
        _upload(db_session, store, org_id, data=CORPUS["pe64.exe"], policy=full)
    with pytest.raises(ArtifactQuotaExceeded):
        _upload(db_session, store, org_id, filename="again.bin", policy=full)

    asset = db_session.scalars(select(Asset)).one()
    assert asset.id == first.asset_id
    assert asset.details["upload"]["filename"] == "My Tool"  # a refused re-upload renames nothing
    assert len(store.put_limits) == 1
    assert db_session.scalars(select(Scan)).one().id == first.scan_id


def test_upload_that_exactly_fills_the_org_quota_is_accepted(db_session: Session) -> None:
    exact = ArtifactPolicy(max_bytes=1024, org_quota_bytes=len(ELF), retention_hours=0)

    upload = _upload(db_session, FakeArtifactStore(), _org(db_session), policy=exact)

    assert upload.asset_value == f"sha256:{DIGEST}"


def test_upload_exactly_at_the_size_cap_is_accepted(db_session: Session) -> None:
    exact = ArtifactPolicy(max_bytes=len(ELF), org_quota_bytes=1024, retention_hours=0)

    upload = _upload(db_session, FakeArtifactStore(), _org(db_session), policy=exact)

    assert upload.asset_value == f"sha256:{DIGEST}"


def test_stored_bytes_that_differ_from_the_hashed_ones_are_deleted_not_scanned(
    db_session: Session,
) -> None:
    class Swapping(FakeArtifactStore):
        def put(
            self, org_id: UUID, artifact_id: UUID, source: IO[bytes], *, max_bytes: int
        ) -> StoredArtifact:
            return super().put(org_id, artifact_id, io.BytesIO(b"other"), max_bytes=max_bytes)

    org_id, store = _org(db_session), Swapping()

    with pytest.raises(ArtifactCorrupt):
        _upload(db_session, store, org_id)

    assert store.blobs == {}
    assert db_session.scalars(select(Artifact)).one().deleted_at is not None
    assert db_session.scalars(select(Scan)).all() == []


def test_file_name_is_kept_for_display_without_path_or_control_characters(
    db_session: Session,
) -> None:
    org_id = _org(db_session)

    upload = _upload(db_session, FakeArtifactStore(), org_id, filename="C:\\x\\..\\a\x00<b>.exe")

    details = db_session.get_one(Asset, upload.asset_id).details
    assert details["upload"]["filename"] == "a<b>.exe"


def test_enqueue_failure_fails_the_scan_and_deletes_the_artifact(db_session: Session) -> None:
    org_id, store = _org(db_session), FakeArtifactStore()

    with pytest.raises(ScanNotQueued):
        _upload(db_session, store, org_id, queue=FakeQueue(db_session, fail=True))

    assert db_session.scalars(select(Scan)).one().status == ScanStatus.FAILED
    assert db_session.scalars(select(Artifact)).one().deleted_at is not None
    assert store.blobs == {}


def test_the_same_binary_in_two_orgs_is_two_separate_assets(db_session: Session) -> None:
    store = FakeArtifactStore()
    acme, other = _org(db_session, "acme"), _org(db_session, "other")

    mine = _upload(db_session, store, acme)
    theirs = _upload(db_session, store, other)

    assert mine.asset_value == theirs.asset_value
    assert mine.asset_id != theirs.asset_id
    for org_id, upload in ((acme, mine), (other, theirs)):
        assert db_session.get_one(Asset, upload.asset_id).org_id == org_id
        assert db_session.get_one(Artifact, upload.artifact_id).org_id == org_id
        assert db_session.get_one(Scan, upload.scan_id).org_id == org_id
        assert (org_id, upload.artifact_id) in store.blobs
    audited = db_session.scalars(select(AuditLog).where(AuditLog.action == "binary.uploaded"))
    assert sorted(entry.org_id for entry in audited) == sorted([acme, other])
