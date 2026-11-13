"""Uploaded and fetched artifacts: the storage port and its limits (#85, ADR 0028).

Artifacts are untrusted bytes. They are encrypted at rest and exist as plaintext only while
staged for one sandbox run. Error messages are fixed: never a path, an ID or content.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import IO, Protocol
from uuid import UUID

# File name of the staged plaintext inside its run directory: the sandbox reads `/input/artifact`.
STAGED_NAME = "artifact"
# Above the launcher's longest run (840 s) plus time queued, so a sweep never hits a live run.
STAGE_MAX_AGE_SECONDS = 3600


class ArtifactKind(StrEnum):
    REPO = "repo"
    BINARY = "binary"


class ArtifactError(Exception):
    """Base for artifact errors that `web/` maps to user-facing messages."""


class ArtifactNotFound(ArtifactError):
    """Missing, deleted or another org's artifact (never says which)."""


class ArtifactTooLarge(ArtifactError):
    """The stream went over the per-artifact size limit."""


class ArtifactQuotaExceeded(ArtifactError):
    """The org's stored artifacts would go over its quota."""


class ArtifactCorrupt(ArtifactError):
    """The stored bytes or their key failed authentication."""


class ArtifactStorageUnavailable(ArtifactError):
    """No encryption key is configured, or the storage directory can't be used."""


@dataclass(frozen=True)
class ArtifactPolicy:
    max_bytes: int
    org_quota_bytes: int
    retention_hours: int  # 0: delete as soon as analysis completes


@dataclass(frozen=True)
class StoredArtifact:
    """What `put` wrote. `sha256` and `size_bytes` describe the plaintext."""

    storage_key: str
    sha256: str
    size_bytes: int
    key_envelope: bytes = field(repr=False)  # the wrapped per-artifact key, kept in the row


class ArtifactStore(Protocol):
    def put(
        self, org_id: UUID, artifact_id: UUID, source: IO[bytes], *, max_bytes: int
    ) -> StoredArtifact:
        """Encrypt `source` to storage in chunks. Raises `ArtifactTooLarge` past `max_bytes`."""
        ...

    def open(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes) -> Iterator[bytes]:
        """Decrypted chunks. Raises `ArtifactCorrupt` as soon as a chunk fails authentication."""
        ...

    def delete(self, org_id: UUID, artifact_id: UUID) -> None:
        """Remove the ciphertext and any staged plaintext. Idempotent; needs no key.

        Raises `ArtifactStorageUnavailable` if the ciphertext can't be removed; the staged
        plaintext is removed either way.
        """
        ...

    def stage(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes, *, sha256: str) -> None:
        """Write the plaintext where one sandbox run can mount it, after re-checking `sha256`."""
        ...

    def unstage(self, artifact_id: UUID) -> None:
        """Remove the staged plaintext. Idempotent."""
        ...

    def sweep_staged(self, *, older_than_seconds: int) -> int:
        """Remove staged plaintext a crashed run left behind; returns how many entries went."""
        ...
