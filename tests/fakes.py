"""Test doubles for domain interfaces."""

import hashlib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import IO
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy.orm import Session

from attacksurf.ai.structured import complete_structured
from attacksurf.domain.artifacts import (
    ArtifactStorageUnavailable,
    ArtifactTooLarge,
    StoredArtifact,
)
from attacksurf.domain.llm import Completion, LLMResult, Message, TokenUsage


class FakePasswordHasher:
    """Fast, deterministic stand-in for argon2 in service tests."""

    def hash(self, password: str) -> str:
        return f"fake${password[::-1]}"

    def verify(self, password_hash: str, password: str) -> bool:
        return password_hash == self.hash(password)

    def needs_rehash(self, password_hash: str) -> bool:
        return not password_hash.startswith("fake$")


class FakeQueue:
    """Records what was enqueued and whether the job row was committed at that moment."""

    def __init__(self, session: Session, *, fail: bool = False) -> None:
        self.session = session
        self.fail = fail
        self.sent: list[tuple[str, UUID, UUID, bool]] = []

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        committed = not self.session.in_transaction()
        self.sent.append((task_name, org_id, job_id, committed))
        if self.fail:
            raise ConnectionError("broker unreachable")
        return "task-1"


class FakeCache:
    """In-memory `ScanCache` that records keys, values and TTLs."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = dict(values or {})
        self.ttls: dict[str, int] = {}
        self.gets: list[str] = []

    def get(self, key: str) -> str | None:
        self.gets.append(key)
        return self.values.get(key)

    def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        self.values[key] = value
        self.ttls[key] = ttl_seconds


@dataclass(frozen=True)
class FakeLLMCall:
    messages: tuple[Message, ...]
    schema: type[BaseModel]
    max_tokens: int


class FakeLLMProvider:
    """`LLMProvider` with queued replies (text, `Completion`, or an error to raise).

    Runs the shared schema validation like the real providers, so a queued invalid reply is
    retried once, exactly as in production. Every API call is recorded in `calls`.
    """

    def __init__(self, *replies: str | Completion | Exception) -> None:
        self.replies: list[str | Completion | Exception] = list(replies)
        self.calls: list[FakeLLMCall] = []

    def complete[T: BaseModel](
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        max_tokens: int,
    ) -> LLMResult[T]:
        def send(conversation: Sequence[Message]) -> Completion:
            self.calls.append(FakeLLMCall(tuple(conversation), schema, max_tokens))
            assert self.replies, "FakeLLMProvider: no reply queued for this call"
            reply = self.replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            if isinstance(reply, str):
                return Completion(reply, TokenUsage(input_tokens=10, output_tokens=5))
            return reply

        return complete_structured(send, messages, schema)


class FakeArtifactStore:
    """In-memory `ArtifactStore`: no disk, no crypto. Records deletes and staging."""

    def __init__(self) -> None:
        self.blobs: dict[tuple[UUID, UUID], bytes] = {}
        self.staged: set[UUID] = set()
        self.deleted: list[tuple[UUID, UUID]] = []
        self.put_limits: list[int] = []
        self.swept: list[int] = []
        self.undeletable: set[UUID] = set()

    def put(
        self, org_id: UUID, artifact_id: UUID, source: IO[bytes], *, max_bytes: int
    ) -> StoredArtifact:
        self.put_limits.append(max_bytes)
        data = source.read()
        if len(data) > max_bytes:
            raise ArtifactTooLarge("The artifact is larger than the allowed size.")
        self.blobs[org_id, artifact_id] = data
        return StoredArtifact(
            storage_key=f"{org_id}/{artifact_id}",
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            key_envelope=b"\x01" + b"e" * 60,
        )

    def open(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes) -> Iterator[bytes]:
        return iter([self.blobs[org_id, artifact_id]])

    def delete(self, org_id: UUID, artifact_id: UUID) -> None:
        self.staged.discard(artifact_id)
        if artifact_id in self.undeletable:
            raise ArtifactStorageUnavailable("Artifact storage is unavailable.")
        self.deleted.append((org_id, artifact_id))
        self.blobs.pop((org_id, artifact_id), None)

    def stage(self, org_id: UUID, artifact_id: UUID, key_envelope: bytes, *, sha256: str) -> None:
        self.staged.add(artifact_id)

    def unstage(self, artifact_id: UUID) -> None:
        self.staged.discard(artifact_id)

    def sweep_staged(self, *, older_than_seconds: int) -> int:
        self.swept.append(older_than_seconds)
        return 0
