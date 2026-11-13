"""`LocalArtifactStore` (ADR 0028): encrypted blobs in one root, per-run plaintext in another."""

import hashlib
import io
import os
import secrets
import shutil
import stat
import time
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from attacksurf.domain.artifacts import (
    STAGED_NAME,
    ArtifactCorrupt,
    ArtifactNotFound,
    ArtifactStorageUnavailable,
    ArtifactStore,
    ArtifactTooLarge,
    StoredArtifact,
)
from attacksurf.infra import storage
from attacksurf.infra.crypto import CHUNK_BYTES, EnvelopeCipher
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.sandbox_launcher.artifacts import resolve_artifact

ORG, OTHER_ORG = uuid4(), uuid4()
MAX = 10 * 1024 * 1024


class Roots:
    def __init__(self, base: Path) -> None:
        self.store, self.run = base / "store", base / "run"
        self.store.mkdir()
        self.run.mkdir()

    def blob(self, artifact_id: UUID, org_id: UUID = ORG) -> Path:
        return self.store / str(org_id) / str(artifact_id)

    def staged(self, artifact_id: UUID) -> Path:
        return self.run / str(artifact_id)

    def files(self) -> list[Path]:
        return [path for path in self.store.rglob("*") if path.is_file()]


@pytest.fixture
def roots(tmp_path: Path) -> Roots:
    return Roots(tmp_path)


@pytest.fixture
def store(roots: Roots) -> LocalArtifactStore:
    cipher = EnvelopeCipher(b"k" * 32, purpose=b"artifact")
    return LocalArtifactStore(roots.store, roots.run, cipher)


def _put(store: ArtifactStore, payload: bytes, org_id: UUID = ORG) -> tuple[UUID, StoredArtifact]:
    artifact_id = uuid4()
    return artifact_id, store.put(org_id, artifact_id, io.BytesIO(payload), max_bytes=MAX)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_put_then_open_round_trips_a_multi_chunk_stream(store: LocalArtifactStore) -> None:
    payload = secrets.token_bytes(3 * CHUNK_BYTES + 17)

    artifact_id, stored = _put(store, payload)

    chunks = list(store.open(ORG, artifact_id, stored.key_envelope))
    assert b"".join(chunks) == payload
    assert len(chunks) == 4  # streamed, never one whole-file read
    assert stored.sha256 == hashlib.sha256(payload).hexdigest()
    assert stored.size_bytes == len(payload)
    assert stored.storage_key == f"{ORG}/{artifact_id}"


def test_put_writes_only_ciphertext_with_owner_only_modes(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, _stored = _put(store, b"SECRET-SOURCE-CODE" * 50)

    blob = roots.blob(artifact_id)
    assert b"SECRET-SOURCE-CODE" not in blob.read_bytes()
    assert _mode(blob) == 0o600
    assert _mode(blob.parent) == 0o700
    assert roots.files() == [blob]  # no temp file left behind
    assert list(roots.run.iterdir()) == []  # nothing in the sandbox-mounted root


def test_put_never_reads_the_whole_upload_at_once(store: LocalArtifactStore) -> None:
    reads: list[int] = []

    class Recording(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            reads.append(size or -1)
            return super().read(size)

    store.put(ORG, uuid4(), Recording(b"x" * (2 * CHUNK_BYTES)), max_bytes=MAX)

    assert min(reads) > 0
    assert max(reads) <= CHUNK_BYTES


def test_put_enforces_max_bytes_while_reading_and_removes_the_partial_file(
    store: LocalArtifactStore, roots: Roots
) -> None:
    class Endless(io.RawIOBase):
        served = 0

        def read(self, size: int = -1) -> bytes:
            self.served += size
            return b"\x00" * size

    source = Endless()

    with pytest.raises(ArtifactTooLarge):
        store.put(ORG, uuid4(), source, max_bytes=3 * CHUNK_BYTES)  # type: ignore[arg-type]

    assert source.served <= 5 * CHUNK_BYTES  # stopped at the cap, not at end of input
    assert roots.files() == []


def test_put_accepts_exactly_max_bytes(store: LocalArtifactStore) -> None:
    stored = store.put(ORG, uuid4(), io.BytesIO(b"x" * 100), max_bytes=100)

    assert stored.size_bytes == 100


def test_put_removes_the_partial_file_when_the_source_fails(
    store: LocalArtifactStore, roots: Roots
) -> None:
    class Broken(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise RuntimeError("client went away")

    with pytest.raises(RuntimeError):
        store.put(ORG, uuid4(), Broken(), max_bytes=MAX)

    assert roots.files() == []


def test_put_reports_an_unusable_store_root_without_naming_it(tmp_path: Path) -> None:
    # A path component that is a file: both the write and the temp-file cleanup fail.
    (tmp_path / "afile").write_bytes(b"")
    cipher = EnvelopeCipher(b"k" * 32, purpose=b"artifact")
    store = LocalArtifactStore(tmp_path / "afile" / "store", tmp_path / "run", cipher)

    with pytest.raises(ArtifactStorageUnavailable) as error:
        store.put(ORG, uuid4(), io.BytesIO(b"payload"), max_bytes=MAX)

    assert str(error.value) == "Artifact storage is unavailable."


def test_open_fails_for_another_orgs_envelope(store: LocalArtifactStore, roots: Roots) -> None:
    # The wrapped key is bound to (org, artifact): moving a blob and its row's key to another
    # org's namespace does not make it readable there.
    artifact_id, stored = _put(store, b"payload")
    roots.blob(artifact_id, OTHER_ORG).parent.mkdir()
    roots.blob(artifact_id).rename(roots.blob(artifact_id, OTHER_ORG))

    with pytest.raises(ArtifactCorrupt):
        store.open(OTHER_ORG, artifact_id, stored.key_envelope)


def test_open_fails_with_another_artifacts_envelope(store: LocalArtifactStore) -> None:
    first, _stored = _put(store, b"one")
    _second, other = _put(store, b"two")

    with pytest.raises(ArtifactCorrupt):
        store.open(ORG, first, other.key_envelope)


def test_open_reports_a_tampered_blob_as_corrupt(store: LocalArtifactStore, roots: Roots) -> None:
    artifact_id, stored = _put(store, b"payload" * 100)
    blob = roots.blob(artifact_id)
    data = bytearray(blob.read_bytes())
    data[40] ^= 0x01
    blob.write_bytes(bytes(data))

    with pytest.raises(ArtifactCorrupt) as error:
        list(store.open(ORG, artifact_id, stored.key_envelope))

    assert str(artifact_id) not in str(error.value)
    assert str(roots.store) not in str(error.value)


def test_open_reports_a_missing_blob_as_not_found(store: LocalArtifactStore, roots: Roots) -> None:
    artifact_id, stored = _put(store, b"payload")
    roots.blob(artifact_id).unlink()

    with pytest.raises(ArtifactNotFound):
        list(store.open(ORG, artifact_id, stored.key_envelope))


def test_delete_removes_ciphertext_and_staged_plaintext_and_is_idempotent(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload")
    store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)

    store.delete(ORG, artifact_id)
    store.delete(ORG, artifact_id)

    assert not roots.blob(artifact_id).exists()
    assert not roots.staged(artifact_id).exists()


def test_delete_removes_staged_plaintext_even_when_the_ciphertext_cannot_be_removed(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload")
    store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)
    # Something `unlink` can't remove, whatever user runs the tests.
    roots.blob(artifact_id).unlink()
    (roots.blob(artifact_id) / "child").mkdir(parents=True)

    with pytest.raises(ArtifactStorageUnavailable) as error:
        store.delete(ORG, artifact_id)

    assert str(error.value) == "Artifact storage is unavailable."
    assert not roots.staged(artifact_id).exists()


def test_stage_writes_sandbox_readable_plaintext_the_launcher_can_resolve(
    store: LocalArtifactStore, roots: Roots
) -> None:
    payload = secrets.token_bytes(CHUNK_BYTES + 5)
    artifact_id, stored = _put(store, payload)

    old_umask = os.umask(0o077)  # a restrictive worker umask must not hide it from the sandbox
    try:
        store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)
    finally:
        os.umask(old_umask)

    staged = resolve_artifact(roots.run, artifact_id)
    assert (staged / STAGED_NAME).read_bytes() == payload
    assert _mode(staged) == 0o755  # the sandbox runs as another uid
    assert _mode(staged / STAGED_NAME) == 0o644
    assert [entry.name for entry in roots.run.iterdir()] == [str(artifact_id)]


def test_stage_refuses_content_that_does_not_match_the_recorded_digest(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload")

    with pytest.raises(ArtifactCorrupt):
        store.stage(ORG, artifact_id, stored.key_envelope, sha256="0" * 64)

    assert list(roots.run.iterdir()) == []


def test_stage_leaves_nothing_behind_when_the_blob_is_corrupt(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload" * 10)
    roots.blob(artifact_id).write_bytes(roots.blob(artifact_id).read_bytes()[:-1])

    with pytest.raises(ArtifactCorrupt):
        store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)

    assert list(roots.run.iterdir()) == []


def test_stage_reports_an_unusable_run_root_without_naming_it(roots: Roots, tmp_path: Path) -> None:
    missing = tmp_path / "not-mounted"
    store = LocalArtifactStore(roots.store, missing, EnvelopeCipher(b"k" * 32, purpose=b"artifact"))
    artifact_id, stored = _put(store, b"payload")

    with pytest.raises(ArtifactStorageUnavailable) as error:
        store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)

    assert "not-mounted" not in str(error.value)


def test_unstage_removes_the_plaintext_and_is_idempotent(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload")
    store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)

    store.unstage(artifact_id)
    store.unstage(artifact_id)

    assert list(roots.run.iterdir()) == []
    assert roots.blob(artifact_id).exists()


def test_sweep_staged_removes_only_old_staging_entries(
    store: LocalArtifactStore, roots: Roots
) -> None:
    old = time.time() - 7200
    stale_run, stale_build, fresh = uuid4(), roots.run / ".stage-0011223344556677", uuid4()
    for path in (roots.staged(stale_run), stale_build, roots.staged(fresh)):
        path.mkdir()
        (path / STAGED_NAME).write_bytes(b"plaintext")
    unrelated = roots.run / "operator-notes"
    unrelated.mkdir()
    for path in (roots.staged(stale_run), stale_build, unrelated):
        os.utime(path, (old, old))

    removed = store.sweep_staged(older_than_seconds=3600)

    assert removed == 2
    assert sorted(entry.name for entry in roots.run.iterdir()) == sorted(
        [str(fresh), "operator-notes"]
    )


def test_sweep_staged_tolerates_a_missing_run_root(roots: Roots, tmp_path: Path) -> None:
    store = LocalArtifactStore(roots.store, tmp_path / "not-mounted", None)

    assert store.sweep_staged(older_than_seconds=0) == 0


def test_sweep_staged_tolerates_a_run_root_that_is_not_a_directory(
    roots: Roots, tmp_path: Path
) -> None:
    (tmp_path / "afile").write_bytes(b"")
    store = LocalArtifactStore(roots.store, tmp_path / "afile", None)

    assert store.sweep_staged(older_than_seconds=0) == 0


def _aged_staging_dirs(roots: Roots, count: int) -> list[Path]:
    old = time.time() - 7200
    paths = [roots.staged(uuid4()) for _ in range(count)]
    for path in paths:
        path.mkdir()
        os.utime(path, (old, old))
    return paths


def test_sweep_staged_skips_an_entry_removed_by_a_concurrent_unstage(
    store: LocalArtifactStore, roots: Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, real_rmtree = _aged_staging_dirs(roots, 2), shutil.rmtree

    def remove_all(_path: str, **_kwargs: object) -> None:
        # While one entry is swept, another worker unstages the rest.
        for path in paths:
            real_rmtree(path, ignore_errors=True)

    monkeypatch.setattr(storage.shutil, "rmtree", remove_all)

    assert store.sweep_staged(older_than_seconds=3600) == 1

    assert list(roots.run.iterdir()) == []


def test_sweep_staged_counts_only_what_it_removed(
    store: LocalArtifactStore, roots: Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _aged_staging_dirs(roots, 1)
    monkeypatch.setattr(storage.shutil, "rmtree", lambda _path, **_kwargs: None)

    assert store.sweep_staged(older_than_seconds=3600) == 0

    assert paths[0].exists()


def test_store_without_a_key_fails_closed_but_still_deletes(
    store: LocalArtifactStore, roots: Roots
) -> None:
    artifact_id, stored = _put(store, b"payload")
    store.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)
    keyless = LocalArtifactStore(roots.store, roots.run, None)

    with pytest.raises(ArtifactStorageUnavailable):
        keyless.put(ORG, uuid4(), io.BytesIO(b"x"), max_bytes=MAX)
    with pytest.raises(ArtifactStorageUnavailable):
        keyless.open(ORG, artifact_id, stored.key_envelope)
    with pytest.raises(ArtifactStorageUnavailable):
        keyless.stage(ORG, artifact_id, stored.key_envelope, sha256=stored.sha256)
    keyless.delete(ORG, artifact_id)

    assert roots.files() == []
    assert list(roots.run.iterdir()) == []


def test_another_app_key_cannot_open_the_artifact(store: LocalArtifactStore, roots: Roots) -> None:
    artifact_id, stored = _put(store, b"payload")
    other = LocalArtifactStore(
        roots.store, roots.run, EnvelopeCipher(b"z" * 32, purpose=b"artifact")
    )

    with pytest.raises(ArtifactCorrupt):
        other.open(ORG, artifact_id, stored.key_envelope)
