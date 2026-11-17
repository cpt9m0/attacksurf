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
# Enough leading bytes to tell the formats apart: tar's magic sits at offset 257.
SNIFF_BYTES = 262
_ARCHIVE_MAGIC = (
    (0, b"PK\x03\x04", "zip"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (257, b"ustar", "tar"),
)
# Leading bytes of what the binary analyzers take. Universal Mach-O shares 0xCAFEBABE with Java
# class files and a zip may be an APK, an IPA or neither: the sandbox detector tells them apart.
_BINARY_MAGIC = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"\xca\xfe\xba\xbf", "macho_fat"),
    (b"PK\x03\x04", "zip"),
)


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


class UnsupportedArtifactFormat(ArtifactError):
    """The upload's leading bytes are not a format we analyse."""


def sniff_archive(head: bytes) -> str | None:
    """The archive format the first `SNIFF_BYTES` announce, or None.

    A cheap gate on uploads, never a parse: the archive is only opened inside the sandbox
    (ADR 0017), which decides for itself whether it is valid.
    """
    for offset, magic, name in _ARCHIVE_MAGIC:
        if head[offset : offset + len(magic)] == magic:
            return name
    return None


def sniff_binary(head: bytes) -> str | None:
    """What an uploaded binary's leading bytes look like (a hint, stored as such), or None.

    The same kind of gate as `sniff_archive`: the authoritative detection is
    `sandbox_tools.detect`, run on the artifact inside the sandbox (#101).
    """
    return next((name for magic, name in _BINARY_MAGIC if head.startswith(magic)), None)


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

        Raises `ArtifactStorageUnavailable` if the ciphertext or the staged plaintext can't be
        removed; a failure to remove the staged plaintext fails the delete (nothing is marked
        deleted) so it is retried instead of leaving mountable plaintext behind.
        """
        ...

    def stage(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes, *, sha256: str) -> None:
        """Write the plaintext where one sandbox run can mount it, after re-checking `sha256`."""
        ...

    def unstage(self, artifact_id: UUID) -> None:
        """Remove the staged plaintext. Idempotent; a missing directory is not an error.

        Raises `ArtifactStorageUnavailable` if removal fails, so callers never treat leftover
        plaintext as gone.
        """
        ...

    def sweep_staged(self, *, older_than_seconds: int) -> int:
        """Remove staged plaintext a crashed run left behind; returns how many entries went."""
        ...
