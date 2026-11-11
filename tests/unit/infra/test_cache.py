"""Redis scan cache: namespacing, bounds, TTLs and fail-open behavior (no Redis needed)."""

from typing import Any

import pytest
import redis

from attacksurf.infra.cache import CACHE_PREFIX, MAX_KEY_LENGTH, RedisScanCache


class StubRedis:
    def __init__(
        self, values: dict[str, Any] | None = None, *, error: Exception | None = None
    ) -> None:
        self.values = values or {}
        self.error = error
        self.names: list[str] = []
        self.ttls: dict[str, int] = {}

    def get(self, name: str) -> Any:
        if self.error is not None:
            raise self.error
        self.names.append(name)
        return self.values.get(name)

    def set(self, name: str, value: str, ex: int) -> Any:
        if self.error is not None:
            raise self.error
        self.names.append(name)
        self.values[name] = value
        self.ttls[name] = ex
        return True


KEY = "ct:v1:acme.example"


def test_cache_round_trips_a_value_with_the_namespace_and_ttl() -> None:
    redis_client = StubRedis()
    cache = RedisScanCache(redis_client)

    cache.set(KEY, '{"names":[]}', ttl_seconds=3600)

    name = f"{CACHE_PREFIX}{KEY}"
    assert redis_client.names == [name]
    assert redis_client.ttls[name] == 3600
    assert cache.get(KEY) == '{"names":[]}'


def test_cache_decodes_byte_values() -> None:
    redis_client = StubRedis({f"{CACHE_PREFIX}{KEY}": b"value"})

    assert RedisScanCache(redis_client).get(KEY) == "value"


def test_cache_treats_non_utf8_and_non_string_values_as_misses() -> None:
    for value in (b"\xff", 42, None):
        redis_client = StubRedis({f"{CACHE_PREFIX}{KEY}": value})
        assert RedisScanCache(redis_client).get(KEY) is None


def test_cache_is_fail_open_when_redis_is_down() -> None:
    error = redis.ConnectionError("down")
    redis_client = StubRedis(error=error)
    cache = RedisScanCache(redis_client)

    assert cache.get(KEY) is None
    cache.set(KEY, "value", ttl_seconds=60)


def test_cache_skips_values_above_the_bound() -> None:
    redis_client = StubRedis()
    cache = RedisScanCache(redis_client, max_value_bytes=4)

    cache.set(KEY, "too long", ttl_seconds=60)
    assert redis_client.values == {}
    assert cache.get(KEY) is None


def test_cache_reads_above_the_bound_as_a_miss() -> None:
    redis_client = StubRedis({f"{CACHE_PREFIX}{KEY}": "too long"})

    assert RedisScanCache(redis_client, max_value_bytes=4).get(KEY) is None


@pytest.mark.parametrize(
    "key",
    ["", "UPPER", "has space", "a" * (MAX_KEY_LENGTH + 1), "ct/v1/acme.example"],
)
def test_cache_rejects_invalid_keys(key: str) -> None:
    cache = RedisScanCache(StubRedis())

    with pytest.raises(ValueError, match="cache key"):
        cache.get(key)
    with pytest.raises(ValueError, match="cache key"):
        cache.set(key, "value", ttl_seconds=60)


@pytest.mark.parametrize("ttl", [0, -1, 11])
def test_cache_rejects_out_of_range_ttls(ttl: int) -> None:
    cache = RedisScanCache(StubRedis(), max_ttl_seconds=10)

    with pytest.raises(ValueError, match="cache ttl"):
        cache.set(KEY, "value", ttl_seconds=ttl)
