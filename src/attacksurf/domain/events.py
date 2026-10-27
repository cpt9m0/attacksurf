"""Tenant-scoped facts, carrying identifiers only (never scan evidence)."""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class FindingCreated:
    org_id: UUID
    scan_id: UUID
    finding_id: UUID


@dataclass(frozen=True)
class FindingFixed:
    org_id: UUID
    scan_id: UUID
    finding_id: UUID


@dataclass(frozen=True)
class ScanCompleted:
    org_id: UUID
    scan_id: UUID


type DomainEvent = FindingCreated | FindingFixed | ScanCompleted


class EventDispatcher(Protocol):
    def publish(self, event: DomainEvent) -> None: ...
