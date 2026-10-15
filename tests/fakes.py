"""Test doubles for domain interfaces."""

from uuid import UUID

from sqlalchemy.orm import Session


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
