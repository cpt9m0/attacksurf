"""A small key/value cache scanners may use for public source data (implemented in `infra`).

The cache is not a scanner permission: it never reaches a target and the gate does not guard it.
Adapters therefore keep their own namespace, bounds and deadlines, and treat every failure as a
miss, so a Redis outage slows a scan down instead of failing it.
"""

from typing import Protocol


class ScanCache(Protocol):
    """Run-available cache for public source data. Implementations must never raise."""

    def get(self, key: str) -> str | None:
        """The stored value, or None when absent, expired or unavailable."""
        ...

    def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        """Store `value` for at most `ttl_seconds`; failures are ignored."""
        ...


class NullCache:
    """No cache: every read misses and every write is dropped (the safe default)."""

    def get(self, key: str) -> str | None:
        return None

    def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        return None
