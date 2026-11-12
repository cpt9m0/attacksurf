"""Read the stdout of a sandboxed analyzer from Docker's attach stream.

A container without a TTY (ADR 0016) answers `attach` with Docker's multiplexed format: a series
of frames, each an 8-byte header `[type, 0, 0, 0, size]` (`size` a big-endian uint32) followed by
`size` payload bytes. Type 1 is stdout and type 2 is stderr.

`read_stdout` keeps the stdout payloads and drops stderr, which can echo secrets the analyzer
found. It refuses a stream that is cut short or not shaped like Docker's, so half a result is
never taken for a whole one, and it gives up once stdout would pass the ADR 0011 output cap. The
cap is checked on the size a header declares, before the payload is read, so a hostile header
cannot make the launcher buffer toward it. `MAX_STDOUT_BYTES` is a copy of
`domain.scanners.MAX_OUTPUT_BYTES` because the launcher imports nothing from the app; a unit test
keeps the two equal.

Pure: it consumes the iterable lazily and does no I/O. Exception messages are fixed text, since
the stream may carry scanned secrets and exceptions get logged.
"""

from collections.abc import Iterable

MAX_STDOUT_BYTES = 2 * 1024 * 1024

_HEADER_SIZE = 8
_STDOUT = 1
_STDERR = 2


class StreamError(Exception):
    """Base for every reason the attach stream could not be turned into stdout."""


class OutputLimitExceeded(StreamError):
    """Stdout would pass `MAX_STDOUT_BYTES`; the analyzer printed more than the cap allows."""


class MalformedStream(StreamError):
    """The stream was cut off, or a frame header is not one Docker would send."""


def _parse_header(header: bytes | bytearray) -> tuple[int, int]:
    """Return `(stream type, payload size)` for a full 8-byte header, or raise."""
    stream_type = header[0]
    if stream_type not in (_STDOUT, _STDERR) or any(header[1:4]):
        raise MalformedStream("the attach stream has an invalid frame header")
    return stream_type, int.from_bytes(header[4:8], "big")


def read_stdout(chunks: Iterable[bytes]) -> bytes:
    """Concatenate the stdout payloads of a Docker attach stream, dropping stderr.

    Frames may be split across `chunks` at any byte. Raises `OutputLimitExceeded` as soon as a
    stdout frame would take the total past `MAX_STDOUT_BYTES` (exactly the cap is accepted), and
    `MalformedStream` for an unknown stream type, non-zero header padding, or a stream that ends
    inside a header or payload. After either, no further chunk is pulled and nothing is returned.
    """
    out = bytearray()
    header = bytearray()
    stream_type = _STDOUT
    remaining = 0  # payload bytes still owed by the current frame
    for chunk in chunks:
        pos = 0
        while pos < len(chunk):
            if remaining == 0:
                take = min(_HEADER_SIZE - len(header), len(chunk) - pos)
                header += chunk[pos : pos + take]
                pos += take
                if len(header) < _HEADER_SIZE:
                    break
                stream_type, remaining = _parse_header(header)
                header.clear()
                if stream_type == _STDOUT and len(out) + remaining > MAX_STDOUT_BYTES:
                    raise OutputLimitExceeded("the analyzer's stdout passed the output cap")
            else:
                take = min(remaining, len(chunk) - pos)
                if stream_type == _STDOUT:
                    out += chunk[pos : pos + take]
                pos += take
                remaining -= take
    if header or remaining:
        raise MalformedStream("the attach stream ended inside a frame")
    return bytes(out)
