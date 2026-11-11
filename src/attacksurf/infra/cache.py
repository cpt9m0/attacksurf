"""Redis-backed scan cache for public source data (CT logs now, RDAP later).

Celery and Flask-Limiter also use `REDIS_URL`, so keys are namespaced and bounded, and every
Redis failure is a miss: a cache outage must never fail a scan. Values are public source data,
never findings, evidence or tenant data (ADR 0022).
"""

import re
from typing import Any, Protocol

import redis
import structlog

from attacksurf.domain.cache import ScanCache

CACHE_PREFIX = "attacksurf:scan-cache:v1:"
MAX_KEY_LENGTH = 300
MAX_VALUE_BYTES = 256 * 1024
MAX_TTL_SECONDS = 7 * 24 * 3600
_KEY = re.compile(r"[a-z0-9][a-z0-9.:-]*")

log = structlog.get_logger(__name__)


class RedisLike(Protocol):
    """The two client calls the cache needs; `redis.Redis` implements them."""

    def get(self, name: str) -> Any: ...

    def set(self, name: str, value: str, ex: int) -> Any: ...


class RedisScanCache(ScanCache):
    def __init__(
        self,
        client: RedisLike,
        *,
        prefix: str = CACHE_PREFIX,
        max_value_bytes: int = MAX_VALUE_BYTES,
        max_ttl_seconds: int = MAX_TTL_SECONDS,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._max_value_bytes = max_value_bytes
        self._max_ttl_seconds = max_ttl_seconds

    def get(self, key: str) -> str | None:
        name = self._name(key)
        try:
            value = self._client.get(name)
        except redis.RedisError as exc:
            log.warning("scan cache unavailable", operation="get", error=type(exc).__name__)
            return None
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if not isinstance(value, str) or len(value.encode()) > self._max_value_bytes:
            return None
        return value

    def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        if ttl_seconds <= 0 or ttl_seconds > self._max_ttl_seconds:
            raise ValueError("invalid cache ttl")
        if len(value.encode()) > self._max_value_bytes:
            return  # a source result that large is not worth caching; the scanner caps first
        try:
            self._client.set(self._name(key), value, ex=ttl_seconds)
        except redis.RedisError as exc:
            log.warning("scan cache unavailable", operation="set", error=type(exc).__name__)

    def _name(self, key: str) -> str:
        if not key or len(key) > MAX_KEY_LENGTH or _KEY.fullmatch(key) is None:
            raise ValueError("invalid cache key")
        return f"{self._prefix}{key}"
