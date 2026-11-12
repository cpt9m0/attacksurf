"""What may reach Docker: pure allowlist checks, with no I/O beyond reading the images lock.

Everything is deny by default. Unknown fields are refused rather than ignored because Docker
matches JSON field names case-insensitively and gains new options over time, so anything this
module doesn't recognise could widen the sandbox. Violation messages never echo request values.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

SANDBOX_USER = "65532:65532"
OSV_BIND = "attacksurf_osv:/data/osv:ro"
OSV_ANALYZER = "osv-scanner"

# Hard ceilings, deliberately not settings: the launcher's configured limits must fit under them.
MAX_NANO_CPUS = 4_000_000_000
MAX_MEMORY_BYTES = 8 * 1024**3
MAX_PIDS = 1024
MAX_SCRATCH_BYTES = 8 * 1024**3
MAX_OPEN_FILES = 4096
MAX_FILE_BYTES = 8 * 1024**3

_DIGEST = re.compile(r"([^@\s:]+(:\d+)?(/[^@\s:]+)*@)?sha256:[0-9a-f]{64}")
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")
_SCRATCH_SIZE = re.compile(r"size=([1-9][0-9]{0,18})")
# Before API 1.30 Docker ignores the removed-wait condition; before 1.25 it disables
# AutoRemove. Accept only canonical modern v1 versions (unversioned uses daemon defaults).
_API_VERSION = r"(?:/v1\.(?:3[0-9]|[4-9][0-9]))?"
_CONTAINER_PATH = re.compile(
    _API_VERSION + r"/containers/"
    r"(?:create|(?P<id>[0-9a-f]{64})(?:/(?P<verb>start|wait|attach|kill))?)"
)
# The launcher's startup check that `runsc` is registered (ADR 0023); the server relays
# runtime names only, never the rest of the daemon's info.
_INFO_PATH = re.compile(_API_VERSION + r"/info")

_TOP_REQUIRED = frozenset({"Image", "User", "HostConfig"})
_TOP_OPTIONAL = frozenset(
    {"Cmd", "Entrypoint", "AttachStdout", "AttachStderr", "AttachStdin"}
    | {"Tty", "OpenStdin", "StdinOnce"}
)
_MUST_BE_OFF = ("AttachStderr", "AttachStdin", "Tty", "OpenStdin", "StdinOnce")
_HOST_FIELDS = frozenset(
    {"Runtime", "NetworkMode", "ReadonlyRootfs", "AutoRemove", "CapDrop", "SecurityOpt"}
    | {"Binds", "Tmpfs", "NanoCpus", "Memory", "MemorySwap", "PidsLimit", "Ulimits", "LogConfig"}
)
_SCRATCH_FLAGS = frozenset({"rw", "noexec", "nosuid", "nodev"})
_ULIMIT_CEILINGS = {"nofile": MAX_OPEN_FILES, "fsize": MAX_FILE_BYTES}
_ALLOWED_QUERIES: dict[str, tuple[dict[str, str], ...]] = {
    "create": ({},),
    "start": ({},),
    "wait": (
        {},
        {"condition": "not-running"},
        {"condition": "next-exit"},
        {"condition": "removed"},
    ),
    "attach": ({"stream": "1", "stdout": "1"},),
    "kill": ({}, {"signal": "SIGKILL"}),
    "remove": ({}, {"force": "1"}, {"force": "true"}),
    "info": ({},),
}


class PolicyViolation(Exception):
    """A request is outside the sandbox policy. The message is safe to log and return."""


@dataclass(frozen=True)
class SandboxPolicy:
    images: frozenset[str]
    runtimes: frozenset[str]
    artifact_root: PurePosixPath
    osv_image: str | None


@dataclass(frozen=True)
class Route:
    action: str
    container_id: str | None
    target: str  # rebuilt from validated parts, never the client's raw string


def load_images(lock_path: Path) -> tuple[frozenset[str], str | None]:
    """Allowed image digests and the OSV image. An empty lock allows nothing."""
    try:
        entries = json.loads(lock_path.read_text())
    except ValueError:
        raise ValueError("invalid images lock") from None
    if not isinstance(entries, dict):
        raise ValueError("invalid images lock")
    for digest in entries.values():
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("invalid images lock")
    return frozenset(entries.values()), entries.get(OSV_ANALYZER)


def classify_request(method: str, raw_target: str) -> Route:
    """Map a request to one allowed Docker call, or raise `PolicyViolation`."""
    parts = urlsplit(raw_target)
    if parts.fragment:
        raise PolicyViolation("Docker call not allowed.")
    action, container_id = _action(method, parts.path)
    query = _single_valued_query(parts.query)
    if query not in _ALLOWED_QUERIES[action]:
        raise PolicyViolation("Docker call options not allowed.")
    target = parts.path + (f"?{urlencode(sorted(query.items()))}" if query else "")
    return Route(action, container_id, target)


def _action(method: str, path: str) -> tuple[str, str | None]:
    if _INFO_PATH.fullmatch(path):
        if method == "GET":
            return "info", None
        raise PolicyViolation("Docker call not allowed.")
    match = _CONTAINER_PATH.fullmatch(path)
    if match is None:
        raise PolicyViolation("Docker call not allowed.")
    container_id, verb = match["id"], match["verb"]
    if method == "DELETE" and container_id and not verb:
        return "remove", container_id
    if method == "POST" and container_id and verb:
        return verb, container_id
    if method == "POST" and not container_id:
        return "create", None
    raise PolicyViolation("Docker call not allowed.")


def _single_valued_query(raw: str) -> dict[str, str]:
    pairs = parse_qsl(raw, keep_blank_values=True)
    query = dict(pairs)
    if len(query) != len(pairs):
        raise PolicyViolation("Docker call options not allowed.")
    return query


def validate_create(body: object, policy: SandboxPolicy) -> None:
    """Raise `PolicyViolation` unless `body` is exactly the ADR 0016 sandbox."""
    config = _object(body)
    host = _object(config.get("HostConfig"))
    _check_fields(config, required=_TOP_REQUIRED, allowed=_TOP_REQUIRED | _TOP_OPTIONAL)
    _check_fields(host, required=_HOST_FIELDS, allowed=_HOST_FIELDS)
    image = config["Image"]
    _require(isinstance(image, str) and image in policy.images, "Image is not allowlisted.")
    _require(config["User"] == SANDBOX_USER, "Sandbox user is not allowed.")
    _require(
        all(config.get(field, False) is False for field in _MUST_BE_OFF), "Stream not allowed."
    )
    _require(config.get("AttachStdout", True) is True, "Stdout must stay attached.")
    for field in ("Cmd", "Entrypoint"):
        _require(_is_string_list(config.get(field, [])), "Command must be a list of strings.")
    _check_isolation(host, policy)
    _check_limits(host)
    _check_scratch(host["Tmpfs"])
    _check_binds(host["Binds"], image, policy)


def _check_isolation(host: dict[str, Any], policy: SandboxPolicy) -> None:
    runtime = host["Runtime"]
    _require(isinstance(runtime, str) and runtime in policy.runtimes, "Runtime is not allowed.")
    _require(host["NetworkMode"] == "none", "Sandboxes have no network.")
    _require(host["ReadonlyRootfs"] is True, "The root filesystem must be read-only.")
    _require(host["AutoRemove"] is True, "Sandboxes must be removed after use.")
    _require(host["CapDrop"] == ["ALL"], "All capabilities must be dropped.")
    _require(host["SecurityOpt"] == ["no-new-privileges"], "Security options are not allowed.")
    # A log driver would copy unbounded tool output, which may contain secrets, onto the host.
    _require(host["LogConfig"] == {"Type": "none"}, "Container logging must be off.")


def _check_limits(host: dict[str, Any]) -> None:
    _require(_within(host["NanoCpus"], MAX_NANO_CPUS), "CPU limit is out of bounds.")
    _require(_within(host["Memory"], MAX_MEMORY_BYTES), "Memory limit is out of bounds.")
    _require(host["MemorySwap"] == host["Memory"], "Swap is not allowed.")
    _require(_within(host["PidsLimit"], MAX_PIDS), "Process limit is out of bounds.")
    ulimits = host["Ulimits"]
    _require(isinstance(ulimits, list), "Ulimits are required.")
    seen: set[str] = set()
    for entry in ulimits:
        limit = _object(entry)
        _require(set(limit) == {"Name", "Soft", "Hard"}, "Ulimit is malformed.")
        name = limit["Name"]
        _require(name in _ULIMIT_CEILINGS and name not in seen, "Ulimit is not allowed.")
        _require(
            _within(limit["Hard"], _ULIMIT_CEILINGS[name])
            and _within(limit["Soft"], limit["Hard"]),
            "Ulimit is out of bounds.",
        )
        seen.add(name)
    _require(seen == set(_ULIMIT_CEILINGS), "Ulimits are required.")


def _check_scratch(tmpfs: object) -> None:
    mounts = _object(tmpfs)
    _require(set(mounts) == {"/scratch"}, "Only /scratch may be a tmpfs.")
    options = mounts["/scratch"]
    _require(isinstance(options, str), "Scratch options are malformed.")
    flags = set(options.split(","))
    sizes = [flag for flag in flags if flag.startswith("size=")]
    _require(
        flags - set(sizes) == _SCRATCH_FLAGS and len(sizes) == 1, "Scratch options not allowed."
    )
    size = _SCRATCH_SIZE.fullmatch(sizes[0])
    _require(size is not None and int(size[1]) <= MAX_SCRATCH_BYTES, "Scratch size out of bounds.")


def _check_binds(binds: object, image: str, policy: SandboxPolicy) -> None:
    _require(_is_string_list(binds), "Binds are malformed.")
    remaining = list(binds)  # type: ignore[call-overload]
    if image == policy.osv_image and OSV_BIND in remaining:
        remaining.remove(OSV_BIND)
    _require(len(remaining) == 1, "Exactly one input mount is allowed.")
    source, *rest = remaining[0].split(":")
    _require(rest == ["/input", "ro"], "Input must be read-only at /input.")
    _check_artifact_source(source, policy.artifact_root)


def _check_artifact_source(source: str, root: PurePosixPath) -> None:
    prefix = f"{root}/"
    _require(source.startswith(prefix), "Input is outside the artifact root.")
    segments = source[len(prefix) :].split("/")
    _require(all(_SEGMENT.fullmatch(segment) for segment in segments), "Input path is not allowed.")


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyViolation("Request is malformed.")
    return value


def _check_fields(
    value: dict[str, Any], *, required: frozenset[str], allowed: frozenset[str]
) -> None:
    _require(required <= set(value), "A required field is missing.")
    _require(set(value) <= allowed, "A field is not allowed.")


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _within(value: object, ceiling: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and isinstance(ceiling, int)
        and 0 < value <= ceiling
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyViolation(message)
