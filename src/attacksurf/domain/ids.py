"""Identifier generation."""

import secrets
import time
from uuid import UUID

_TIMESTAMP_MASK = (1 << 48) - 1


def uuid7(unix_ms: int | None = None) -> UUID:
    """RFC 9562 UUIDv7: 48-bit Unix-ms timestamp + random bits.

    Time-ordered IDs keep B-tree indexes compact (inserts append) and sort by creation time.
    The stdlib only gains `uuid.uuid7` in Python 3.14; we support 3.12.
    """
    ms = time.time_ns() // 1_000_000 if unix_ms is None else unix_ms
    value = ((ms & _TIMESTAMP_MASK) << 80) | secrets.randbits(80)
    value = (value & ~(0xF << 76)) | (0x7 << 76)  # version 7
    value = (value & ~(0x3 << 62)) | (0x2 << 62)  # RFC 4122/9562 variant
    return UUID(int=value)
