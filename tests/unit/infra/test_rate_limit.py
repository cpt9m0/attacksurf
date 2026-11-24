"""Target rate limiting and concurrency control tests with a deterministic fake clock (#70)."""

from __future__ import annotations

import math
from typing import Any
from uuid import uuid4

import pytest
import redis

from attacksurf.domain.jobs import TransientJobError
from attacksurf.infra.rate_limit import (
    ACQUIRE_LUA,
    InMemoryTargetRateLimiter,
    RedisTargetRateLimiter,
    SystemClock,
    TargetRateLimitPolicy,
)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.current = start
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += seconds

    def advance(self, seconds: float) -> None:
        self.current += seconds


class FakeEvalRedis:
    """In-memory simulation of Redis `EVAL ACQUIRE_LUA` + `ZREM` using FakeClock."""

    def __init__(self) -> None:
        self.buckets: dict[str, tuple[float, float]] = {}
        self.concs: dict[str, dict[str, float]] = {}
        self.eval_calls: list[tuple[str, int, tuple[Any, ...]]] = []
        self.zrem_calls: list[tuple[str, tuple[Any, ...]]] = []
        self.fail_acquire: Exception | None = None
        self.fail_release: Exception | None = None

    def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> Any:
        assert script is ACQUIRE_LUA
        assert numkeys == 2
        self.eval_calls.append((script, numkeys, keys_and_args))
        if self.fail_acquire is not None:
            raise self.fail_acquire

        bucket_key, conc_key = str(keys_and_args[0]), str(keys_and_args[1])
        now = float(keys_and_args[2])
        rps = float(keys_and_args[3])
        burst = float(keys_and_args[4])
        max_conc = int(keys_and_args[5])
        lease_ttl = float(keys_and_args[6])
        lease_id = str(keys_and_args[7])

        leases = self.concs.setdefault(conc_key, {})
        for expired in [lid for lid, exp in leases.items() if exp <= now]:
            del leases[expired]
        if len(leases) >= max_conc:
            earliest = min(leases.values())
            wait = max(0.01, min(0.25, earliest - now))
            return [0, str(wait), "conc"]

        prev = self.buckets.get(bucket_key)
        if prev is None:
            tokens = burst
        else:
            prev_tokens, prev_ts = prev
            tokens = min(burst, prev_tokens + max(0.0, now - prev_ts) * rps)
        if tokens < 1.0:
            return [0, str((1.0 - tokens) / rps), "rate"]

        self.buckets[bucket_key] = (tokens - 1.0, now)
        leases[lease_id] = now + lease_ttl
        return [1, "0", "ok"]

    def zrem(self, name: str, *values: Any) -> int:
        self.zrem_calls.append((name, values))
        if self.fail_release is not None:
            raise self.fail_release
        leases = self.concs.get(name, {})
        removed = 0
        for val in values:
            if str(val) in leases:
                del leases[str(val)]
                removed += 1
        return removed


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_burst_and_token_refill_use_clock_without_real_waiting(backend: str) -> None:
    clock = FakeClock()
    policy = TargetRateLimitPolicy(rps=2.0, burst=3, max_concurrency=2, max_wait_seconds=2.0)
    limiter = (
        InMemoryTargetRateLimiter(policy, clock=clock)
        if backend == "memory"
        else RedisTargetRateLimiter(FakeEvalRedis(), policy, clock=clock)
    )
    org = uuid4()

    # First 3 requests consume the burst immediately.
    for _ in range(3):
        with limiter.acquire(org, "Example.COM."):
            pass
    assert clock.sleeps == []

    # Next request needs 1 token at 2 rps -> waits 0.5 s on the fake clock.
    with limiter.acquire(org, "example.com"):
        pass
    assert len(clock.sleeps) == 1
    assert math.isclose(clock.sleeps[0], 0.5, rel_tol=1e-6)


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_rate_exhaustion_beyond_max_wait_raises_transient_error(backend: str) -> None:
    clock = FakeClock()
    policy = TargetRateLimitPolicy(rps=1.0, burst=1, max_concurrency=2, max_wait_seconds=0.4)
    limiter = (
        InMemoryTargetRateLimiter(policy, clock=clock)
        if backend == "memory"
        else RedisTargetRateLimiter(FakeEvalRedis(), policy, clock=clock)
    )
    org = uuid4()

    with limiter.acquire(org, "example.com"):
        pass

    with pytest.raises(TransientJobError, match="rate limit"), limiter.acquire(org, "example.com"):
        pass
    assert clock.sleeps == []


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_concurrency_limit_blocks_until_lease_expires_or_releases(backend: str) -> None:
    clock = FakeClock()
    policy = TargetRateLimitPolicy(
        rps=10.0, burst=10, max_concurrency=1, lease_ttl_seconds=1.0, max_wait_seconds=2.0
    )
    limiter = (
        InMemoryTargetRateLimiter(policy, clock=clock)
        if backend == "memory"
        else RedisTargetRateLimiter(FakeEvalRedis(), policy, clock=clock)
    )
    org = uuid4()

    # Simulate a leaked lease by entering the context manager without exiting yet.
    cm = limiter.acquire(org, "example.com")
    cm.__enter__()
    try:
        # While held, a second acquisition polls up to lease_ttl_seconds and succeeds once expired.
        with limiter.acquire(org, "example.com"):
            assert sum(clock.sleeps) >= 1.0
    finally:
        cm.__exit__(None, None, None)


def test_concurrency_limit_raises_when_wait_budget_exhausted() -> None:
    clock = FakeClock()
    policy = TargetRateLimitPolicy(
        rps=10.0, burst=10, max_concurrency=1, lease_ttl_seconds=5.0, max_wait_seconds=0.3
    )
    limiter = InMemoryTargetRateLimiter(policy, clock=clock)
    org = uuid4()

    cm = limiter.acquire(org, "example.com")
    cm.__enter__()
    try:
        with (
            pytest.raises(TransientJobError, match="concurrency limit"),
            limiter.acquire(org, "example.com"),
        ):
            pass
    finally:
        cm.__exit__(None, None, None)


def test_rate_limits_are_isolated_per_org_and_host() -> None:
    clock = FakeClock()
    policy = TargetRateLimitPolicy(rps=1.0, burst=1, max_concurrency=1, max_wait_seconds=0.0)
    limiter = RedisTargetRateLimiter(FakeEvalRedis(), policy, clock=clock)
    org_a, org_b = uuid4(), uuid4()

    with limiter.acquire(org_a, "a.example.com"):
        pass
    # Same org + same host is exhausted immediately.
    with pytest.raises(TransientJobError), limiter.acquire(org_a, "a.example.com"):
        pass
    # Different host or different org still has its own full burst.
    with limiter.acquire(org_a, "b.example.com"):
        pass
    with limiter.acquire(org_b, "a.example.com"):
        pass


def test_redis_errors_fail_closed_on_acquire_and_do_not_break_release() -> None:
    clock = FakeClock()
    fake = FakeEvalRedis()
    limiter = RedisTargetRateLimiter(fake, TargetRateLimitPolicy(), clock=clock)
    org = uuid4()

    fake.fail_acquire = redis.ConnectionError("down")
    with pytest.raises(TransientJobError, match="unavailable"), limiter.acquire(org, "example.com"):
        pass

    fake.fail_acquire = None
    fake.fail_release = redis.TimeoutError("slow")
    with limiter.acquire(org, "example.com"):
        pass
    assert len(fake.zrem_calls) == 1


@pytest.mark.parametrize("bad_host", ["", "   ", "bad host", "bad\nhost", "a" * 256])
def test_invalid_hosts_are_rejected(bad_host: str) -> None:
    limiter = InMemoryTargetRateLimiter()
    with pytest.raises(ValueError, match="invalid target host"), limiter.acquire(uuid4(), bad_host):
        pass


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rps": 0.0},
        {"rps": float("nan")},
        {"burst": 0},
        {"max_concurrency": 0},
        {"lease_ttl_seconds": 0.0},
        {"max_wait_seconds": -0.1},
    ],
)
def test_policy_rejects_invalid_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be"):
        TargetRateLimitPolicy(**kwargs)


def test_system_clock_uses_unix_epoch_seconds() -> None:
    assert SystemClock().now() > 1_700_000_000
