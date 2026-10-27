"""Scans and their jobs: one scan run per root asset, split into per-stage/per-scanner jobs."""

from enum import StrEnum


class ScanError(ValueError):
    """Invalid scan request, safe for the web layer to display."""


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTrigger(StrEnum):
    USER = "user"
    SCHEDULE = "schedule"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"  # not run, e.g. ScopeGuard denied it; the reason goes in `error`
