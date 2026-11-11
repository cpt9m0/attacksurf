"""Test doubles for domain interfaces."""

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy.orm import Session

from attacksurf.ai.structured import complete_structured
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
