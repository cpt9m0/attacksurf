"""The default runtime cache is a safe no-op."""

from attacksurf.domain.cache import NullCache


def test_null_cache_never_stores_or_returns_anything() -> None:
    cache = NullCache()

    cache.set("ct:v1:example.com", "value", ttl_seconds=60)

    assert cache.get("ct:v1:example.com") is None
