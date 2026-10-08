import time

from attacksurf.domain.ids import uuid7


def test_uuid7_sets_version_and_variant() -> None:
    value = uuid7()

    assert value.version == 7
    assert value.variant == "specified in RFC 4122"


def test_uuid7_embeds_unix_ms_timestamp() -> None:
    value = uuid7(unix_ms=1_700_000_000_123)

    assert value.int >> 80 == 1_700_000_000_123


def test_uuid7_defaults_to_current_time() -> None:
    before = time.time_ns() // 1_000_000
    value = uuid7()
    after = time.time_ns() // 1_000_000

    assert before <= value.int >> 80 <= after


def test_uuid7_sorts_by_creation_time() -> None:
    ids = [uuid7(unix_ms=ms) for ms in (3, 1, 2)]

    assert sorted(ids) == [ids[1], ids[2], ids[0]]


def test_uuid7_is_random_within_same_millisecond() -> None:
    assert uuid7(unix_ms=5) != uuid7(unix_ms=5)
