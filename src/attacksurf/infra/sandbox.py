"""The worker's client for `sandbox-launcher` (ADR 0016): "run analyzer X on artifact Y".

This is a plain `httpx.Client`, not the SSRF-guarded `SafeHttpClient`, on purpose: the launcher
lives on the internal network, which the guarded client would refuse. That is safe because the
URL comes from operator config, never from a scanner or a user. `trust_env=False` keeps proxy
variables and `.netrc` out of the request, and a redirect is an error, never a hop.

The reply comes from a separate service and is checked like any other untrusted input: it is
read with a size cap, must have exactly the expected keys and types, and its stdout is decoded
strictly. Only "busy" and "unreachable" are worth retrying. Every message here is fixed text:
the reply body is never copied into an error, a log line or a `JobError` shown to users.

The launcher has no notion of orgs, so the caller must confirm the artifact belongs to the org
before calling `run`.
"""

import base64
import json
from http import HTTPStatus
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import structlog

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.sandbox import SandboxError, SandboxResult
from attacksurf.domain.scanners import MAX_OUTPUT_BYTES

# Base64 of a full 2 MiB stdout is about 2.67 MiB, plus a few dozen bytes of JSON.
MAX_REPLY_BYTES = 3 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 5.0

_REPLY_KEYS = {"exit_code", "stdout_b64", "timed_out", "output_exceeded"}
_BUSY = "The sandbox is busy; the run will be retried."
_UNREACHABLE = "The sandbox could not be reached; the run will be retried."
_FAILED = "The sandbox run failed."
_INVALID = "The sandbox returned an invalid reply."
_BAD_URL = "the sandbox launcher URL must be http://host[:port] only"

log = structlog.get_logger(__name__)


class _InvalidReply(Exception):
    """The launcher answered 200 with something we won't trust. Carries no detail on purpose."""


class LauncherSandboxRunner:
    """Implements `domain.sandbox.SandboxRunner` over the launcher's HTTP API."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 900.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=_require_plain_http_url(base_url),
            timeout=httpx.Timeout(timeout_seconds, connect=CONNECT_TIMEOUT_SECONDS),
            trust_env=False,
            follow_redirects=False,
            # The reply is never inflated: a small compressed body must not grow past the cap.
            headers={"Accept-Encoding": "identity"},
            transport=transport,
        )

    def run(self, analyzer: str, artifact_id: UUID) -> SandboxResult:
        """Run `analyzer` on the artifact. 503 and network failures raise `TransientJobError`."""
        body = {"analyzer": analyzer, "artifact_id": str(artifact_id)}
        reply = b""
        try:
            with self._client.stream("POST", "/runs", json=body) as response:
                status = response.status_code
                if status == HTTPStatus.OK:
                    reply = _read_capped(response)
        except httpx.TransportError as error:
            # The type name only: the message can carry the host and port.
            log.warning("sandbox_client_error", analyzer=analyzer, error_type=type(error).__name__)
            raise TransientJobError(_UNREACHABLE) from None
        except _InvalidReply:
            log.warning("sandbox_client_error", analyzer=analyzer, status=HTTPStatus.OK.value)
            raise SandboxError(_INVALID) from None

        if status == HTTPStatus.OK:
            try:
                return _decode_result(reply)
            except _InvalidReply:
                log.warning("sandbox_client_error", analyzer=analyzer, status=status)
                raise SandboxError(_INVALID) from None
        log.warning("sandbox_client_error", analyzer=analyzer, status=status)
        if status == HTTPStatus.SERVICE_UNAVAILABLE:
            raise TransientJobError(_BUSY)
        # A 404 is a missing analyzer or artifact and a 500 is a launcher bug: retrying fixes
        # neither.
        raise SandboxError(_FAILED)


def _require_plain_http_url(url: str) -> str:
    """Accept `http://host[:port]` only, so a configured value is never silently dropped.

    Same rule as the launcher's proxy client, copied because the layers may not import each
    other. The launcher has no authentication, so userinfo has nowhere to go, and a path, query
    or fragment would be ignored. The error never echoes the value.
    """
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a bad port; the value isn't needed
    except ValueError:
        raise ValueError(_BAD_URL) from None
    plain = (
        parts.scheme == "http"
        and parts.hostname
        and parts.username is None
        and parts.password is None
        and parts.path in ("", "/")
        and not parts.query
        and not parts.fragment
    )
    if not plain:
        raise ValueError(_BAD_URL)
    return url.rstrip("/")


def _read_capped(response: httpx.Response) -> bytes:
    """Read the body, never holding more than `MAX_REPLY_BYTES` of it.

    A declared length over the cap is refused before any body is read, and a body that lies
    about its length is still stopped by the running count. `iter_raw` skips content decoding.
    """
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError:
            raise _InvalidReply from None
        if not 0 <= length <= MAX_REPLY_BYTES:
            raise _InvalidReply
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_raw():
        total += len(chunk)
        if total > MAX_REPLY_BYTES:
            raise _InvalidReply
        chunks.append(chunk)
    return b"".join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key")
    return result


def _decode_result(raw: bytes) -> SandboxResult:
    """Exactly the four keys with the right types; stdout strictly base64, at most the cap."""
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError):
        raise _InvalidReply from None
    if not isinstance(parsed, dict) or set(parsed) != _REPLY_KEYS:
        raise _InvalidReply
    exit_code, stdout_b64 = parsed["exit_code"], parsed["stdout_b64"]
    timed_out, output_exceeded = parsed["timed_out"], parsed["output_exceeded"]
    # `bool` is an `int`, so `true` would pass a plain isinstance check.
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        raise _InvalidReply
    if not isinstance(timed_out, bool) or not isinstance(output_exceeded, bool):
        raise _InvalidReply
    if not isinstance(stdout_b64, str):
        raise _InvalidReply
    try:
        stdout = base64.b64decode(stdout_b64, validate=True)
    except ValueError:
        raise _InvalidReply from None
    if len(stdout) > MAX_OUTPUT_BYTES:  # the launcher enforces this too; defense in depth
        raise _InvalidReply
    return SandboxResult(exit_code, stdout, timed_out, output_exceeded)
