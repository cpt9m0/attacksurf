"""Scans and their jobs: one scan run per root asset, split into per-stage/per-scanner jobs."""

from enum import StrEnum
from typing import Literal
from uuid import UUID


class ScanError(ValueError):
    """Invalid scan request, safe for the web layer to display."""


class ScanCancelled(ScanError):
    """Output arrived for a scan that was cancelled: it is dropped, never written."""


class ScanNotFound(LookupError):
    """No such scan in this org (or another org's scan: never says which)."""


class ScanAlreadyActive(ScanError):
    """A scan of the same root is already queued or running. Carries its id."""

    def __init__(self, scan_id: UUID) -> None:
        super().__init__("A scan of this domain is already running.")
        self.scan_id = scan_id


class ScanRateLimited(ScanError):
    """The org started too many scans recently (per-org hourly quota)."""


class ScanNotQueued(ScanError):
    """The scan's task could not be sent to the queue; the scan was marked failed."""


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTrigger(StrEnum):
    USER = "user"
    SCHEDULE = "schedule"


class ScheduleFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"


# "off" is a creation-time default only: a saved schedule is either daily or weekly.
ScanScheduleDefault = Literal["off", "daily", "weekly"]


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"  # not run, e.g. ScopeGuard denied it; the reason goes in `error`
