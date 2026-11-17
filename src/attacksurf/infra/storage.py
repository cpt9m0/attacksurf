"""`ArtifactStore` on the local filesystem (ADR 0028).

Two roots that never overlap. Ciphertext lives under `store_root`; `run_root` is the directory
the sandbox launcher mounts from (`SANDBOX_ARTIFACT_ROOT`), and holds plaintext only while an
artifact is staged for a run. Every path is built from UUIDs, never from caller text.
"""

import fcntl
import hashlib
import hmac
import os
import secrets
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import IO
from uuid import UUID

from attacksurf.domain.artifacts import (
    STAGED_NAME,
    ArtifactCorrupt,
    ArtifactNotFound,
    ArtifactStorageUnavailable,
    ArtifactTooLarge,
    StoredArtifact,
)
from attacksurf.infra.crypto import (
    KEY_BYTES,
    ByteSource,
    DecryptionError,
    EnvelopeCipher,
    decrypt_stream,
    encrypt_stream,
)

_KEY_AAD = b"attacksurf.artifact.dek.v1"
_BUILD_PREFIX = ".stage-"  # not a UUID, so the launcher can never resolve a half-written dir
_LOCK_SUFFIX = ".lock"  # `<artifact_id>.lock` in the store root; never a UUID
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_LOCK_FILE = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW  # reused across processes: no O_EXCL


@contextmanager
def _fixed_errors() -> Iterator[None]:
    """Filesystem and crypto errors carry paths and details; callers get fixed messages."""
    try:
        yield
    except DecryptionError:
        raise ArtifactCorrupt("The stored artifact failed its integrity check.") from None
    except OSError:
        raise ArtifactStorageUnavailable("Artifact storage is unavailable.") from None


class _Metered:
    """Counts and hashes what is read, and stops the stream once it passes `max_bytes`."""

    def __init__(self, source: ByteSource, max_bytes: int) -> None:
        self._source, self._max_bytes = source, max_bytes
        self.size, self.digest = 0, hashlib.sha256()

    def read(self, size: int = -1, /) -> bytes:
        data = self._source.read(size)
        self.size += len(data)
        if self.size > self._max_bytes:
            raise ArtifactTooLarge("The artifact is larger than the allowed size.")
        self.digest.update(data)
        return data


class LocalArtifactStore:
    """Implements `attacksurf.domain.artifacts.ArtifactStore`.

    Without a `cipher` (no `APP_ENCRYPTION_KEY`) it fails closed: nothing is written or read,
    but deletion and sweeping still work, since they need no key.
    """

    def __init__(self, store_root: Path, run_root: Path, cipher: EnvelopeCipher | None) -> None:
        self._store_root, self._run_root, self._cipher = store_root, run_root, cipher

    def put(
        self, org_id: UUID, artifact_id: UUID, source: IO[bytes], *, max_bytes: int
    ) -> StoredArtifact:
        cipher = self._require_cipher()
        directory = self._store_root / str(org_id)
        tmp = directory / f".tmp-{secrets.token_hex(8)}"
        dek, metered = secrets.token_bytes(KEY_BYTES), _Metered(source, max_bytes)
        try:
            with _fixed_errors():
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                with os.fdopen(os.open(tmp, _NEW_FILE, 0o600), "wb") as out:
                    for block in encrypt_stream(dek, metered):
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(tmp, directory / str(artifact_id))
        except BaseException:
            # Must not raise: an unusable directory would replace the error with a raw path.
            with suppress(OSError):
                tmp.unlink()
            raise
        return StoredArtifact(
            storage_key=f"{org_id}/{artifact_id}",
            sha256=metered.digest.hexdigest(),
            size_bytes=metered.size,
            key_envelope=cipher.wrap(dek, aad=_key_aad(org_id, artifact_id)),
        )

    def open(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes) -> Iterator[bytes]:
        # The key is unwrapped here, not on first iteration, so a wrong key fails at the call.
        return self._decrypt(org_id, artifact_id, self._unwrap(org_id, artifact_id, key_envelope))

    def delete(self, org_id: UUID, artifact_id: UUID) -> None:
        with _artifact_lock(self._store_root, artifact_id):
            try:
                with _fixed_errors():
                    (self._store_root / str(org_id) / str(artifact_id)).unlink(missing_ok=True)
            finally:
                # Whatever happens to the ciphertext, the plaintext never outlives a delete.
                self.unstage(artifact_id)

    def stage(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes, *, sha256: str) -> None:
        dek = self._unwrap(org_id, artifact_id, key_envelope)
        with _artifact_lock(self._store_root, artifact_id):
            build = self._run_root / f"{_BUILD_PREFIX}{secrets.token_hex(8)}"
            digest = hashlib.sha256()
            try:
                with _fixed_errors():
                    build.mkdir()
                    # Explicit modes (umask-proof): the sandbox reads this as another uid.
                    build.chmod(0o755)
                    with os.fdopen(os.open(build / STAGED_NAME, _NEW_FILE, 0o644), "wb") as out:
                        os.fchmod(out.fileno(), 0o644)
                        for chunk in self._decrypt(org_id, artifact_id, dek):
                            digest.update(chunk)
                            out.write(chunk)
                    if not hmac.compare_digest(digest.hexdigest(), sha256):
                        raise DecryptionError
                    # Taken under the lock, so a delete either unlinked the ciphertext before
                    # the first chunk was read or waits until this directory is in place.
                    if not (self._store_root / str(org_id) / str(artifact_id)).exists():
                        raise ArtifactNotFound("Artifact not found.")
                    # Atomic: the launcher sees either nothing or the complete directory.
                    os.rename(build, self._run_root / str(artifact_id))
            except BaseException:
                shutil.rmtree(build, ignore_errors=True)
                raise

    def unstage(self, artifact_id: UUID) -> None:
        shutil.rmtree(self._run_root / str(artifact_id), ignore_errors=True)

    def sweep_staged(self, *, older_than_seconds: int) -> int:
        cutoff = time.time() - older_than_seconds
        try:
            entries = list(os.scandir(self._run_root))
        except OSError:
            return 0  # no usable run root, so nothing is staged
        removed = 0
        for entry in entries:
            if not (entry.name.startswith(_BUILD_PREFIX) or _is_uuid(entry.name)):
                continue  # only what this store creates
            try:
                stale = entry.is_dir(follow_symlinks=False) and (
                    entry.stat(follow_symlinks=False).st_mtime < cutoff
                )
            except OSError:
                continue  # a concurrent unstage already removed it
            if stale:
                shutil.rmtree(entry.path, ignore_errors=True)
                if not os.path.lexists(entry.path):  # count only what is really gone
                    removed += 1
        return removed

    def _require_cipher(self) -> EnvelopeCipher:
        if self._cipher is None:
            raise ArtifactStorageUnavailable("Artifact storage is not configured.")
        return self._cipher

    def _unwrap(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes) -> bytes:
        with _fixed_errors():
            return self._require_cipher().unwrap(key_envelope, aad=_key_aad(org_id, artifact_id))

    def _decrypt(self, org_id: UUID, artifact_id: UUID, dek: bytes) -> Iterator[bytes]:
        with _fixed_errors():
            try:
                blob = (self._store_root / str(org_id) / str(artifact_id)).open("rb")
            except FileNotFoundError:
                raise ArtifactNotFound("Artifact not found.") from None
            with blob:
                yield from decrypt_stream(dek, blob)


@contextmanager
def _artifact_lock(lock_root: Path, artifact_id: UUID) -> Iterator[None]:
    """Serialise staging and deletion of one artifact across processes.

    `flock` releases on process death, so a killed stager can't wedge a delete, and the lock file
    is never removed: unlinking it would hand "the" lock to two processes at once. The lock lives
    in the ciphertext root, which `put` already creates, never in the sandbox-visible run root.
    """
    with _fixed_errors():
        lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with os.fdopen(
            os.open(lock_root / f"{artifact_id}{_LOCK_SUFFIX}", _LOCK_FILE, 0o600), "w"
        ) as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


def _key_aad(org_id: UUID, artifact_id: UUID) -> bytes:
    # Binds the wrapped key to its row: it can't be replayed for another org or artifact.
    return _KEY_AAD + org_id.bytes + artifact_id.bytes


def _is_uuid(name: str) -> bool:
    try:
        return str(UUID(name)) == name
    except ValueError:
        return False
