# Plan: PR 3b, commit 4: `feat(infra): read capped stdout from docker attach streams`

Branch `84-sandbox-launcher-core` · `Refs #84` · follows `d9bfc8e feat(infra): build sandbox create
bodies the proxy accepts` (commit 3 of PR 3b; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** An analysis tool in the sandbox reports its findings by printing them. Docker
hands that printout back as one long stream of small labelled pieces: each piece says "this is
normal output" or "this is error output" and how long it is. This commit writes the reader that
sorts those pieces. It keeps the normal output, throws the error output away (error text can leak
secrets the tool found), and gives up the moment the normal output grows past 2 MiB, so a tool
that prints forever cannot fill the launcher's memory. It also refuses a stream that looks broken
or cut short, because half a result must never be mistaken for a whole one. It only reads bytes
it is given; it starts nothing and talks to nothing.

**Technical.** Adds `sandbox_launcher/stream.py` with the pure function
`read_stdout(chunks: Iterable[bytes]) -> bytes`, which demultiplexes Docker's attach stream for a
container without a TTY (ADR 0016): 8-byte header `[type, 0, 0, 0, size:uint32 big-endian]`
followed by `size` payload bytes. It returns the concatenated stdout payloads, discards stderr,
and raises `OutputLimitExceeded` as soon as stdout would pass `MAX_STDOUT_BYTES` (2 MiB, the
ADR 0011 output cap) or `MalformedStream` for a cut-off, unknown or inconsistent frame. It is
stdlib only, does no I/O, and imports nothing from the app, the proxy or Docker. It pulls from the
iterable lazily, so a caller that feeds it socket reads stops reading the moment the cap trips
(commit 7 of the split plan, `runner.py`, then kills the container). Frame parsing is proven with
byte fixtures; a parity test pins the 2 MiB cap to `domain.scanners.MAX_OUTPUT_BYTES`.

## Context
Commit 3 produced `build_create_body`, which sets `AttachStdout: true` and leaves `Tty`,
`AttachStderr` and `AttachStdin` off (the proxy requires it), and the proxy's `attach` call is
stdout-only. So the stream is Docker's *multiplexed* (non-TTY) format and stderr frames should
not appear; the reader still drops them, because the launcher must not depend on that being
true. Nothing yet turns the attach stream into a result; `runner.py` (commit 3c of the split
plan) needs this as its last step. It is a separate commit because it is pure bytes-in/bytes-out,
so every frame edge case is tested here with fixtures, with no HTTP, socket, thread or Docker
involved.

## Decisions
1. **A lazy function over `Iterable[bytes]`, not a class or a `bytes` argument.** The split plan
   said "a pure function"; taking an iterable lets the runner pass `iter(lambda: sock.recv(n), b"")`
   and lets the reader stop pulling the instant the cap trips, which a whole-`bytes` argument
   cannot (the bytes would already be in memory). Signature:
   `read_stdout(chunks: Iterable[bytes]) -> bytes`.
2. **The cap is checked against the *declared* frame size, before the payload is read.** A header
   that says "4 GiB of stdout" trips `OutputLimitExceeded` immediately instead of buffering toward
   it. Total stdout after the frame is `len(out) + size`; the cap is inclusive (exactly
   `MAX_STDOUT_BYTES` is accepted, one more byte is not). Stderr is skipped as it arrives (never
   buffered) and does **not** count toward the cap; wall time bounds how much of it there can be.
3. **Fixed constant, no parameter.** `MAX_STDOUT_BYTES = 2 * 1024 * 1024` is copied here because
   the launcher stays decoupled from app code (the stdlib-only module needs no import), and a
   parity test compares it with `domain.scanners.MAX_OUTPUT_BYTES`. The worker client's reply cap
   (~3 MiB, base64 of 2 MiB) in PR 3d depends on this value, so a caller must not be able to
   raise it.
4. **Two exception types under one base.** `StreamError` is the base; `OutputLimitExceeded` maps
   to `output_exceeded` in the launcher result, `MalformedStream` to a proxy/Docker failure (503
   in commit 3c). Callers can tell a chatty tool from a broken stream.
5. **Strict framing; fail closed.** Only stream types `1` (stdout) and `2` (stderr) are valid.
   Type `0` (stdin), `3` and anything else raise `MalformedStream`, as does any non-zero byte in
   header positions 1 to 3. A stream that ends inside a header or inside a payload also raises:
   a truncated result is never returned as partial stdout. Zero-length frames are legal.
6. **Messages never carry output.** Both exceptions use fixed messages; they do not include
   payload bytes, sizes or offsets, since stdout may contain scanned secrets and exceptions get
   logged.
7. **Left out: HTTP and process concerns.** The proxy relays the daemon's raw hijacked response,
   so the HTTP status line and headers precede the frames. Stripping them, the socket, timeouts,
   killing and cleanup are commit 3c's `runner.py`. This reader only sees frame bytes. It also
   does not decode text or parse JSON; `bytes` out, so ADR 0011 validation stays with the worker.
8. **No docs in this commit.** Commit 5 of PR 3b carries `AGENTS.md`, `docs/architecture.md`,
   `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/sandbox_launcher/stream.py` exists, pure (no I/O, no threads, no sockets),
      stdlib only (`collections.abc`, `struct`), with a module docstring that names the frame
      format and ADR 0016.
- [ ] `MAX_STDOUT_BYTES == 2 * 1024 * 1024`.
- [ ] `class StreamError(Exception)`, `class OutputLimitExceeded(StreamError)` and
      `class MalformedStream(StreamError)`, each with a docstring.
- [ ] `read_stdout(chunks: Iterable[bytes]) -> bytes` returns the stdout payloads in order,
      concatenated, as `bytes` (no decoding); `b""` for an empty iterable or only-stderr stream.
- [ ] Frames may be split across chunks at any byte, including inside the 8-byte header; empty
      chunks are ignored; one chunk may hold several frames.
- [ ] Header layout is read as `[type][3 zero bytes][size big-endian uint32]` (`struct` format
      `>BxxxI`-equivalent, with the three padding bytes required to be zero).
- [ ] Stream type `2` payloads are discarded without being buffered; types other than `1` or `2`
      raise `MalformedStream`.
- [ ] `OutputLimitExceeded` when `len(stdout so far) + declared size` exceeds `MAX_STDOUT_BYTES`,
      raised at the header, before the payload bytes are pulled.
- [ ] After either exception the reader pulls **no further** chunks from the iterable.
- [ ] `MalformedStream` for: end of stream inside a header, end of stream inside a payload, an
      unknown stream type, a non-zero padding byte. Partial stdout is never returned.
- [ ] Fixed exception messages that contain no payload, size or offset.
- [ ] Memory held is bounded by the cap plus one chunk (stderr and skipped bytes are not kept).
- [ ] No change to `container.py`, `catalog.py`, `artifacts.py`, `config.py`, `sandbox_proxy` or
      `pyproject.toml` (the existing launcher isolation contract already covers the new module).

## Acceptance criteria
- [ ] **Happy path:** byte fixtures built with a test-local `frame(type, payload)` helper decode
      to the exact stdout, for one frame, many frames, interleaved stdout/stderr, and every
      chunking of the same bytes (1, 3, 7, 8, 9 bytes at a time and in one piece).
- [ ] **Stderr:** stderr frames never appear in the result and never count toward the cap, even
      when larger than the cap.
- [ ] **Cap boundary:** exactly 2 MiB (one frame, and spread over many frames) is returned in
      full; 2 MiB + 1 byte (one frame, spread over many, and declared-only with no payload sent)
      raises `OutputLimitExceeded`.
- [ ] **Early stop:** with a counting generator, no chunk after the tripping header is pulled, for
      both exceptions.
- [ ] **Malformed:** cut-off header (1 and 7 bytes), cut-off payload, unknown stream types
      (`0`, `3`, `255`) and non-zero padding all raise `MalformedStream`, including after earlier
      valid stdout frames.
- [ ] **No leakage:** exception text contains no payload bytes (a stdout payload containing a
      marker string is not in `str(exc)`).
- [ ] **Drift guard:** `MAX_STDOUT_BYTES` equals `domain.scanners.MAX_OUTPUT_BYTES` (tests only).
- [ ] **Isolation:** `uv run lint-imports` passes; `stream.py` imports only the stdlib.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `src/attacksurf/sandbox_launcher/stream.py` (~65 lines)
- Module docstring: Docker's non-TTY attach framing (8-byte header, types 1/2), why stderr is
  dropped (can echo found secrets, ADR 0016/`docs/security.md`), why the cap is checked on the
  declared size, and that the constant is a copy of the ADR 0011 cap.
- Constants: `MAX_STDOUT_BYTES`, `_HEADER_SIZE = 8`, `_STDOUT = 1`, `_STDERR = 2`.
- `StreamError`, `OutputLimitExceeded`, `MalformedStream`.
- `read_stdout(chunks)`: a small state machine (waiting for a header, or `remaining` payload
  bytes of a frame of kind stdout/stderr) over a `bytearray` buffer. Helpers `_parse_header(buf)
  -> tuple[int, int]` (validates type and padding) keep `read_stdout` short. At the end of the
  iterable, a non-empty header buffer or `remaining > 0` raises `MalformedStream`. No new
  dataclasses.

### 2. Tests, `tests/unit/sandbox_launcher/test_stream.py` (written first)
Style follows `tests/unit/sandbox_launcher/test_container.py` and `test_artifacts.py` (plain
functions, `pytest.mark.parametrize`). A module-level `frame(stream_type, payload)` helper builds
bytes with `struct.pack(">BxxxI", ...)`, and a `chunked(data, size)` helper yields fixed-size
slices. The file has four sections under comment banners.

#### A. Happy path (frames in → exact stdout out)
| Test | Given | Expect |
|---|---|---|
| `test_read_stdout_returns_a_single_stdout_frame` | one stdout frame | the payload |
| `test_read_stdout_joins_stdout_frames_in_order` | three stdout frames | payloads concatenated in order |
| `test_read_stdout_drops_stderr_frames` | stdout, stderr, stdout interleaved | only the stdout payloads |
| `test_read_stdout_returns_empty_bytes_for_an_empty_stream` | `iter(())` | `b""` |
| `test_read_stdout_returns_empty_bytes_for_stderr_only` | one stderr frame | `b""` |
| `test_read_stdout_accepts_zero_length_frames` | empty stdout and stderr frames around real ones | the real payload only |
| `test_read_stdout_handles_any_chunking` (param chunk size 1, 3, 7, 8, 9, whole) | same multi-frame bytes split every way | identical result for all |
| `test_read_stdout_ignores_empty_chunks` | `b""` chunks between pieces | same result |
| `test_read_stdout_reads_the_size_as_big_endian` | a 256-byte payload (`0x00000100`) | all 256 bytes (a little-endian misread would fail) |
| `test_read_stdout_does_not_decode_the_payload` | non-UTF-8 bytes in the payload | returned byte-for-byte, type `bytes` |

#### B. Boundary cases (edges of the cap)
| Test | Given | Expect |
|---|---|---|
| `test_read_stdout_accepts_exactly_the_cap_in_one_frame` | one frame of `MAX_STDOUT_BYTES` | returned in full |
| `test_read_stdout_accepts_exactly_the_cap_across_frames` | 2 MiB split into many frames | returned in full |
| `test_read_stdout_does_not_count_stderr_toward_the_cap` | 3 MiB stderr plus 1 KiB stdout | the stdout |
| `test_read_stdout_does_not_count_stderr_before_a_full_cap_of_stdout` | stderr frame then exactly 2 MiB stdout | the stdout |

One above the cap is covered in section C; a stderr frame is never buffered, so "huge stderr" is a
boundary case here, not an error.

#### C. Cap exceeded and malformed streams (must raise, message never echoes output)
| Test | Given | Expect |
|---|---|---|
| `test_read_stdout_rejects_one_byte_over_the_cap_in_one_frame` | one frame of cap + 1 | `OutputLimitExceeded` |
| `test_read_stdout_rejects_one_byte_over_the_cap_across_frames` | frames totalling cap + 1 | `OutputLimitExceeded` |
| `test_read_stdout_rejects_an_oversized_header_before_its_payload_arrives` | header declaring `0xFFFFFFFF`, no payload | `OutputLimitExceeded` (not `MalformedStream`) |
| `test_read_stdout_stops_pulling_chunks_once_the_cap_trips` | counting generator, header over cap then more chunks | later chunks never requested |
| `test_read_stdout_rejects_a_cut_off_header` (param 1 byte, 7 bytes) | stream ends mid-header | `MalformedStream` |
| `test_read_stdout_rejects_a_cut_off_payload` | header says 10, 4 bytes follow, stream ends | `MalformedStream` |
| `test_read_stdout_rejects_an_unknown_stream_type` (param `0`, `3`, `255`) | header with that type | `MalformedStream` |
| `test_read_stdout_rejects_non_zero_header_padding` (param byte 1, 2, 3) | non-zero padding byte | `MalformedStream` |
| `test_read_stdout_never_returns_partial_output_on_error` | valid stdout frame, then a bad one | raises; nothing returned |
| `test_malformed_stream_stops_pulling_chunks` | counting generator, bad type then more chunks | later chunks never requested |
| `test_error_messages_do_not_echo_output` | stdout containing a marker, then a violation of each kind | `str(exc)` lacks the marker |

#### D. Drift guard
| Test | Given | Expect |
|---|---|---|
| `test_max_stdout_bytes_matches_the_adr_0011_output_cap` | `MAX_STDOUT_BYTES` vs `domain.scanners.MAX_OUTPUT_BYTES` | equal, and equal to 2 MiB |
| `test_exception_types_share_a_base` | both exceptions | `issubclass(..., StreamError)` |

Section D keeps the launcher's copied cap honest: if ADR 0011 changes the limit, this test fails
until `stream.py` follows. The test may import `domain.scanners` while the source module stays
stdlib only.

## Order of work (red → green)
1. Write `tests/unit/sandbox_launcher/test_stream.py`; run
   `uv run pytest tests/unit/sandbox_launcher/test_stream.py`. Confirm it fails because
   `attacksurf.sandbox_launcher.stream` does not exist yet, not because of a typo in a helper.
2. Implement `stream.py` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. Run the `finish-task` sync (docs are deferred to commit 5 of PR 3b, see Decisions) and the
   `pre-pr-check` self-review.
5. Commit on `84-sandbox-launcher-core` with subject
   `feat(infra): read capped stdout from docker attach streams`, a body explaining *why* (stdout
   must be bounded and stderr dropped before `runner.py` exists), footer `Refs #84`, and the
   Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `src/attacksurf/domain/scanners.py`: `MAX_OUTPUT_BYTES` (in the parity test only; never
  imported by `stream.py`).
- `tests/unit/sandbox_launcher/test_container.py` and `test_artifacts.py`: style reference.
- No existing source module is changed.

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage >= 80%.
- `uv run lint-imports` passes. Scratch-only negative check (revert afterwards): add
  `import httpx` to `stream.py` and confirm the "sandbox launcher stays isolated" contract fails.
- Mutation check (scratch only): change `>` to `>=` in the cap comparison and confirm the
  exactly-2-MiB test fails; change the byte order to little-endian and confirm the big-endian
  test fails; drop the stderr branch (buffer it) and confirm the stderr tests fail.
- Optional manual smoke: none. This commit has no I/O; the reader first sees a real stream in
  commit 3c (against `FakeDocker`) and under `runsc` in PR 5.

## Notes for later commits
- **Commit 5 (docs):** document `stream.py` in the `AGENTS.md` layout and
  `docs/architecture.md`, with the 2 MiB / stderr-dropped behaviour, in `CHANGELOG.md` and
  `STATE.md`.
- **PR 3c, `runner.py`:** strips the HTTP response head from the proxy's relayed attach reply,
  passes `iter(lambda: sock.recv(64 * 1024), b"")` to `read_stdout`, and maps
  `OutputLimitExceeded` to `output_exceeded=True` (kill the container, drop stdout) and
  `MalformedStream` to a proxy failure (503). A wall-time or output-cap kill that cuts the
  stream mid-frame arrives as `MalformedStream`, so the runner decides the outcome from its own
  flags (`timed_out`, cap tripped) before the stream error. `tests/docker_fakes.py` must be able
  to script frames split across writes.
- **PR 3d, worker client:** its ~3 MiB reply cap assumes stdout is at most 2 MiB (base64 ~2.67
  MiB); changing `MAX_STDOUT_BYTES` means changing that cap.
- **PR 5 (`runsc` CI):** the real container run is the end-to-end proof that Docker's framing
  matches what this reader accepts.
