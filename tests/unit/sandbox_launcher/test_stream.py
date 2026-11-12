"""The attach-stream reader: Docker's multiplexed frames in, capped stdout bytes out."""

import struct
from collections.abc import Iterable, Iterator

import pytest

from attacksurf.domain.scanners import MAX_OUTPUT_BYTES
from attacksurf.sandbox_launcher.stream import (
    MAX_STDOUT_BYTES,
    MalformedStream,
    OutputLimitExceeded,
    StreamError,
    read_stdout,
)

STDOUT = 1
STDERR = 2
MARKER = b"SECRET-MARKER-9f3a"


def frame(stream_type: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream_type, len(payload)) + payload


def header(stream_type: int, size: int) -> bytes:
    return struct.pack(">BxxxI", stream_type, size)


def chunked(data: bytes, size: int) -> Iterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def counting(pieces: list[bytes], pulled: list[int]) -> Iterator[bytes]:
    for piece in pieces:
        pulled.append(1)
        yield piece


MULTI_FRAME = (
    frame(STDOUT, b"alpha ")
    + frame(STDERR, b"warning")
    + frame(STDOUT, b"beta ")
    + frame(STDOUT, b"")
    + frame(STDOUT, b"gamma")
)
MULTI_FRAME_STDOUT = b"alpha beta gamma"


# --- A. Happy path -------------------------------------------------------------------------


def test_read_stdout_returns_a_single_stdout_frame() -> None:
    assert read_stdout([frame(STDOUT, b"hello")]) == b"hello"


def test_read_stdout_joins_stdout_frames_in_order() -> None:
    data = frame(STDOUT, b"one ") + frame(STDOUT, b"two ") + frame(STDOUT, b"three")

    assert read_stdout([data]) == b"one two three"


def test_read_stdout_drops_stderr_frames() -> None:
    data = frame(STDOUT, b"a") + frame(STDERR, b"error text") + frame(STDOUT, b"b")

    assert read_stdout([data]) == b"ab"


def test_read_stdout_returns_empty_bytes_for_an_empty_stream() -> None:
    assert read_stdout(iter(())) == b""


def test_read_stdout_returns_empty_bytes_for_stderr_only() -> None:
    assert read_stdout([frame(STDERR, b"only errors")]) == b""


def test_read_stdout_accepts_zero_length_frames() -> None:
    data = frame(STDOUT, b"") + frame(STDERR, b"") + frame(STDOUT, b"real") + frame(STDERR, b"")

    assert read_stdout([data]) == b"real"


@pytest.mark.parametrize("size", [1, 3, 7, 8, 9, len(MULTI_FRAME)])
def test_read_stdout_handles_any_chunking(size: int) -> None:
    assert read_stdout(chunked(MULTI_FRAME, size)) == MULTI_FRAME_STDOUT


def test_read_stdout_ignores_empty_chunks() -> None:
    pieces: Iterable[bytes] = [b"", MULTI_FRAME[:5], b"", b"", MULTI_FRAME[5:], b""]

    assert read_stdout(pieces) == MULTI_FRAME_STDOUT


def test_read_stdout_reads_the_size_as_big_endian() -> None:
    payload = bytes(range(256))
    assert header(STDOUT, 256) == b"\x01\x00\x00\x00\x00\x00\x01\x00"

    assert read_stdout([header(STDOUT, 256) + payload]) == payload


def test_read_stdout_does_not_decode_the_payload() -> None:
    payload = b"\xff\xfe\x00\x80not utf-8"

    result = read_stdout([frame(STDOUT, payload)])

    assert result == payload
    assert type(result) is bytes


# --- B. Boundary cases ---------------------------------------------------------------------


def test_read_stdout_accepts_exactly_the_cap_in_one_frame() -> None:
    payload = b"x" * MAX_STDOUT_BYTES

    assert read_stdout([frame(STDOUT, payload)]) == payload


def test_read_stdout_accepts_exactly_the_cap_across_frames() -> None:
    part = b"y" * (MAX_STDOUT_BYTES // 1024)
    data = frame(STDOUT, part) * 1024

    assert read_stdout(chunked(data, 64 * 1024)) == part * 1024


def test_read_stdout_does_not_count_stderr_toward_the_cap() -> None:
    data = frame(STDERR, b"e" * (3 * 1024 * 1024)) + frame(STDOUT, b"s" * 1024)

    assert read_stdout(chunked(data, 64 * 1024)) == b"s" * 1024


def test_read_stdout_does_not_count_stderr_before_a_full_cap_of_stdout() -> None:
    payload = b"z" * MAX_STDOUT_BYTES
    data = frame(STDERR, b"e" * 1024) + frame(STDOUT, payload)

    assert read_stdout([data]) == payload


# --- C. Cap exceeded and malformed streams -------------------------------------------------


def test_read_stdout_rejects_one_byte_over_the_cap_in_one_frame() -> None:
    with pytest.raises(OutputLimitExceeded):
        read_stdout([frame(STDOUT, b"x" * (MAX_STDOUT_BYTES + 1))])


def test_read_stdout_rejects_one_byte_over_the_cap_across_frames() -> None:
    data = frame(STDOUT, b"x" * MAX_STDOUT_BYTES) + frame(STDOUT, b"y")

    with pytest.raises(OutputLimitExceeded):
        read_stdout(chunked(data, 64 * 1024))


def test_read_stdout_rejects_an_oversized_header_before_its_payload_arrives() -> None:
    with pytest.raises(OutputLimitExceeded):
        read_stdout([header(STDOUT, 0xFFFFFFFF)])


def test_read_stdout_stops_pulling_chunks_once_the_cap_trips() -> None:
    pulled: list[int] = []
    pieces = [header(STDOUT, MAX_STDOUT_BYTES + 1), b"later", b"more"]

    with pytest.raises(OutputLimitExceeded):
        read_stdout(counting(pieces, pulled))

    assert len(pulled) == 1


@pytest.mark.parametrize("kept", [1, 7])
def test_read_stdout_rejects_a_cut_off_header(kept: int) -> None:
    with pytest.raises(MalformedStream):
        read_stdout([frame(STDOUT, b"ok") + header(STDOUT, 5)[:kept]])


def test_read_stdout_rejects_a_cut_off_payload() -> None:
    with pytest.raises(MalformedStream):
        read_stdout([header(STDOUT, 10), b"four"])


@pytest.mark.parametrize("stream_type", [0, 3, 255])
def test_read_stdout_rejects_an_unknown_stream_type(stream_type: int) -> None:
    data = frame(STDOUT, b"fine") + frame(stream_type, b"x")

    with pytest.raises(MalformedStream):
        read_stdout([data])


@pytest.mark.parametrize("position", [1, 2, 3])
def test_read_stdout_rejects_non_zero_header_padding(position: int) -> None:
    bad = bytearray(frame(STDOUT, b"x"))
    bad[position] = 1

    with pytest.raises(MalformedStream):
        read_stdout([frame(STDOUT, b"fine") + bytes(bad)])


def test_read_stdout_never_returns_partial_output_on_error() -> None:
    result: list[bytes] = []

    with pytest.raises(MalformedStream):
        result.append(read_stdout([frame(STDOUT, b"good"), frame(9, b"bad")]))

    assert result == []


def test_malformed_stream_stops_pulling_chunks() -> None:
    pulled: list[int] = []
    pieces = [frame(7, b"x"), b"later", b"more"]

    with pytest.raises(MalformedStream):
        read_stdout(counting(pieces, pulled))

    assert len(pulled) == 1


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        (header(STDOUT, MAX_STDOUT_BYTES), OutputLimitExceeded),
        (header(9, 1), MalformedStream),
        (header(STDOUT, 5) + b"abc", MalformedStream),
        (header(STDOUT, 5)[:3], MalformedStream),
    ],
)
def test_error_messages_do_not_echo_output(tail: bytes, expected: type[StreamError]) -> None:
    data = frame(STDOUT, MARKER) + tail

    with pytest.raises(expected) as caught:
        read_stdout([data])

    assert MARKER.decode() not in str(caught.value)
    assert str(MAX_STDOUT_BYTES) not in str(caught.value)


# --- D. Drift guard ------------------------------------------------------------------------


def test_max_stdout_bytes_matches_the_adr_0011_output_cap() -> None:
    assert MAX_STDOUT_BYTES == MAX_OUTPUT_BYTES == 2 * 1024 * 1024


def test_exception_types_share_a_base() -> None:
    assert issubclass(OutputLimitExceeded, StreamError)
    assert issubclass(MalformedStream, StreamError)
