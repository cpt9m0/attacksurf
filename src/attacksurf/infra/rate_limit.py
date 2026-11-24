"""Per-(org, target host) rate limiting and concurrency control for active checks (#70)."""

import math
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID, uuid4

import redis
import structlog

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import TargetRateLimiter

KEY_PREFIX = "attacksurf:active-rl:v1:"
MAX_HOST_LENGTH = 255
_MIN_SLEEP_SECONDS = 0.01
_MAX_CONC_POLL_SECONDS = 0.25
_ASCII_PRINTABLE_MIN = 0x20
_ASCII_DEL = 0x7F

log = structlog.get_logger(__name__)

# Atomic token-bucket + expiring sorted-set concurrency lease per (org, host).
# KEYS: [1] = bucket hash key, [2] = concurrency zset key.
# ARGV: [1] = now (float seconds), [2] = rps, [3] = burst, [4] = max_concurrency,
#       [5] = lease_ttl_seconds, [6] = lease_id, [7] = bucket_ttl_seconds.
# Floating-point wait durations are returned with tostring() so RESP2 does not truncate them.
ACQUIRE_LUA = """
local bucket_key = KEYS[1]
local conc_key = KEYS[2]
local now = tonumber(ARGV[1])
local rps = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local max_conc = tonumber(ARGV[4])
local lease_ttl = tonumber(ARGV[5])
local lease_id = ARGV[6]
local bucket_ttl = tonumber(ARGV[7])

redis.call('ZREMRANGEBYSCORE', conc_key, '-inf', now)
local active = redis.call('ZCARD', conc_key)
if active >= max_conc then
    local earliest = redis.call('ZRANGE', conc_key, 0, 0, 'WITHSCORES')
    local wait = 0.05
    if earliest[2] then
        wait = math.max(0.01, math.min(0.25, tonumber(earliest[2]) - now))
    end
    return {0, tostring(wait), 'conc'}
end

local vals = redis.call('HMGET', bucket_key, 'tokens', 'ts')
local tokens = tonumber(vals[1])
local ts = tonumber(vals[2])
if tokens == nil or ts == nil then
    tokens = burst
    ts = now
else
    tokens = math.min(burst, tokens + math.max(0, now - ts) * rps)
    ts = now
end

if tokens < 1.0 then
    local wait = (1.0 - tokens) / rps
    return {0, tostring(wait), 'rate'}
end

tokens = tokens - 1.0
redis.call('HSET', bucket_key, 'tokens', tostring(tokens), 'ts', tostring(ts))
redis.call('EXPIRE', bucket_key, bucket_ttl)
redis.call('ZADD', conc_key, now + lease_ttl, lease_id)
redis.call('EXPIRE', conc_key, math.max(1, math.ceil(lease_ttl * 2)))
return {1, '0', 'ok'}
"""


class Clock(Protocol):
    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def now(self) -> float:
        # Epoch seconds: Redis keys are shared across workers and container restarts.
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


@dataclass(frozen=True)
class TargetRateLimitPolicy:
    rps: float = 2.0
    burst: int = 5
    max_concurrency: int = 2
    lease_ttl_seconds: float = 30.0
    max_wait_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.rps) or self.rps <= 0:
            raise ValueError("rps must be positive")
        if self.burst < 1:
            raise ValueError("burst must be at least 1")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if not math.isfinite(self.lease_ttl_seconds) or self.lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be positive")
        if not math.isfinite(self.max_wait_seconds) or self.max_wait_seconds < 0:
            raise ValueError("max_wait_seconds must be non-negative")


class RedisRateLimitClient(Protocol):
    def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> Any: ...

    def zrem(self, name: str, *values: Any) -> Any: ...


def _normalize_host(host: str) -> str:
    cleaned = host.strip().lower().rstrip(".")
    if (
        not cleaned
        or len(cleaned) > MAX_HOST_LENGTH
        or any(
            ch.isspace() or ord(ch) < _ASCII_PRINTABLE_MIN or ord(ch) == _ASCII_DEL
            for ch in cleaned
        )
    ):
        raise ValueError("invalid target host for rate limit")
    return cleaned


def _bucket_ttl_seconds(policy: TargetRateLimitPolicy) -> int:
    return max(60, math.ceil((policy.burst / policy.rps) * 2))


def _exhausted_error(reason: str) -> TransientJobError:
    if reason == "conc":
        return TransientJobError("Target concurrency limit reached.")
    return TransientJobError("Target rate limit reached.")


class RedisTargetRateLimiter(TargetRateLimiter):
    """Redis-backed per-(org, host) token bucket and expiring concurrency lease."""

    def __init__(
        self,
        client: RedisRateLimitClient,
        policy: TargetRateLimitPolicy | None = None,
        *,
        clock: Clock | None = None,
        prefix: str = KEY_PREFIX,
    ) -> None:
        self._client = client
        self._policy = policy or TargetRateLimitPolicy()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._prefix = prefix

    @contextmanager
    def acquire(self, org_id: UUID, host: str) -> Iterator[None]:
        norm_host = _normalize_host(host)
        bucket_key = f"{self._prefix}bucket:{org_id}:{norm_host}"
        conc_key = f"{self._prefix}conc:{org_id}:{norm_host}"
        lease_id = uuid4().hex
        deadline = self._clock.now() + self._policy.max_wait_seconds
        bucket_ttl = _bucket_ttl_seconds(self._policy)

        while True:
            now = self._clock.now()
            try:
                raw = self._client.eval(
                    ACQUIRE_LUA,
                    2,
                    bucket_key,
                    conc_key,
                    now,
                    self._policy.rps,
                    self._policy.burst,
                    self._policy.max_concurrency,
                    self._policy.lease_ttl_seconds,
                    lease_id,
                    bucket_ttl,
                )
            except redis.RedisError as exc:
                log.warning(
                    "target rate limiter unavailable",
                    operation="acquire",
                    error=type(exc).__name__,
                )
                raise TransientJobError("Target rate limiter unavailable.") from None

            acquired = int(raw[0]) == 1
            wait = float(raw[1])
            reason = raw[2].decode("utf-8") if isinstance(raw[2], bytes) else str(raw[2])
            if acquired:
                break

            remaining = deadline - now
            if reason == "rate" and wait > remaining:
                raise _exhausted_error(reason)
            if remaining <= 0:
                raise _exhausted_error(reason)
            self._clock.sleep(max(_MIN_SLEEP_SECONDS, min(wait, remaining)))

        try:
            yield
        finally:
            try:
                self._client.zrem(conc_key, lease_id)
            except redis.RedisError as exc:
                log.warning(
                    "target rate limiter release failed",
                    operation="release",
                    error=type(exc).__name__,
                )


class InMemoryTargetRateLimiter(TargetRateLimiter):
    """Thread-safe in-memory equivalent for unit tests and zero-Redis harnesses."""

    def __init__(
        self,
        policy: TargetRateLimitPolicy | None = None,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._policy = policy or TargetRateLimitPolicy()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.Lock()
        self._buckets: dict[tuple[UUID, str], tuple[float, float]] = {}
        self._leases: dict[tuple[UUID, str], dict[str, float]] = {}

    @contextmanager
    def acquire(self, org_id: UUID, host: str) -> Iterator[None]:
        key = (org_id, _normalize_host(host))
        lease_id = uuid4().hex
        deadline = self._clock.now() + self._policy.max_wait_seconds

        while True:
            now = self._clock.now()
            acquired, wait, reason = self._try_acquire(key, lease_id, now)
            if acquired:
                break
            remaining = deadline - now
            if reason == "rate" and wait > remaining:
                raise _exhausted_error(reason)
            if remaining <= 0:
                raise _exhausted_error(reason)
            self._clock.sleep(max(_MIN_SLEEP_SECONDS, min(wait, remaining)))

        try:
            yield
        finally:
            with self._lock:
                leases = self._leases.get(key)
                if leases is not None:
                    leases.pop(lease_id, None)
                    if not leases:
                        self._leases.pop(key, None)

    def _try_acquire(
        self, key: tuple[UUID, str], lease_id: str, now: float
    ) -> tuple[bool, float, str]:
        with self._lock:
            leases = self._leases.setdefault(key, {})
            expired = [lid for lid, exp in leases.items() if exp <= now]
            for lid in expired:
                del leases[lid]
            if len(leases) >= self._policy.max_concurrency:
                earliest = min(leases.values())
                wait = max(_MIN_SLEEP_SECONDS, min(_MAX_CONC_POLL_SECONDS, earliest - now))
                return False, wait, "conc"

            prev = self._buckets.get(key)
            if prev is None:
                tokens = float(self._policy.burst)
            else:
                prev_tokens, prev_ts = prev
                tokens = min(
                    float(self._policy.burst),
                    prev_tokens + max(0.0, now - prev_ts) * self._policy.rps,
                )
            if tokens < 1.0:
                return False, (1.0 - tokens) / self._policy.rps, "rate"

            self._buckets[key] = (tokens - 1.0, now)
            leases[lease_id] = now + self._policy.lease_ttl_seconds
            return True, 0.0, "ok"
