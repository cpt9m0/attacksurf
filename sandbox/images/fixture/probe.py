"""A harmless fixture for the sandbox runtime tests (ADR 0016). Never a real analyzer.

Standard library only: the image holds this one file. One mode per run, chosen by the launcher's
fixed command:

  ok     print one JSON object and exit 0
  probe  print what the sandbox lets this process do, as facts (the tests judge them)
  sleep  never exit, so the wall-time kill is what ends it
  flood  print more than the 2 MiB stdout cap, so the output-cap kill is what ends it

The probe reports `*_allowed` booleans (did the attempt succeed?) and raw values. It prints
environment variable names but never their values, so a secret that wrongly reached the sandbox
cannot end up in a CI log. Every file it creates is removed again.
"""

import json
import os
import socket
import subprocess
import sys
import time

INPUT_DIR = "/input"
SCRATCH_DIR = "/scratch"
ROOT_PROBE_PATH = "/etc/.attacksurf-probe"
DOCKER_SOCKET = "/var/run/docker.sock"
PROC_STATUS = "/proc/self/status"

_PROBE_FILE = ".attacksurf-probe"
_MAX_INPUT_FILES = 1000
_FLOOD_BYTES = 3 * 1024 * 1024
_CHUNK = 64 * 1024
_USAGE_EXIT = 2


def _can_connect() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
    except OSError:
        return False
    return True


def _can_resolve() -> bool:
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        return False
    return True


def _input_files() -> list[str]:
    found: list[str] = []
    for directory, _dirs, names in os.walk(INPUT_DIR):
        for name in names:
            found.append(os.path.join(directory, name))
            if len(found) >= _MAX_INPUT_FILES:
                return found
    return found


def _can_open_for_writing(path: str) -> bool:
    try:
        os.close(os.open(path, os.O_WRONLY))
    except OSError:
        return False
    return True


def _can_create(path: str) -> bool:
    """Create `path` exclusively; remove it again when that worked."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except OSError:
        return False
    os.unlink(path)
    return True


def _can_execute_in_scratch() -> bool:
    path = os.path.join(SCRATCH_DIR, _PROBE_FILE)
    try:
        with open(path, "x") as script:
            script.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)  # noqa: S103 (a throwaway script: it is the exec bit being tested)
        try:
            ran = subprocess.run([path], check=False, capture_output=True, timeout=10)  # noqa: S603
            return ran.returncode == 0
        finally:
            os.unlink(path)
    except (OSError, subprocess.SubprocessError):
        return False


def _status_field(name: str) -> str | None:
    try:
        with open(PROC_STATUS) as status:
            for line in status:
                key, _, value = line.partition(":")
                if key == name:
                    return value.strip()
    except OSError:
        return None
    return None


def probe() -> dict[str, object]:
    inputs = _input_files()
    no_new_privs = _status_field("NoNewPrivs")
    return {
        "network_connect_allowed": _can_connect(),
        "dns_resolve_allowed": _can_resolve(),
        "input_files": len(inputs),
        "input_write_allowed": _can_open_for_writing(inputs[0]) if inputs else None,
        "input_create_allowed": _can_create(os.path.join(INPUT_DIR, _PROBE_FILE)),
        "root_write_allowed": _can_create(ROOT_PROBE_PATH),
        "scratch_write_allowed": _can_create(os.path.join(SCRATCH_DIR, _PROBE_FILE)),
        "scratch_exec_allowed": _can_execute_in_scratch(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cap_eff": _status_field("CapEff"),
        "no_new_privs": int(no_new_privs) if no_new_privs is not None else None,
        "docker_socket_present": os.path.exists(DOCKER_SOCKET),
        "env_names": sorted(os.environ),
        "kernel_release": os.uname().release,
    }


def _flood() -> None:
    chunk = b"A" * _CHUNK
    try:
        for _ in range(_FLOOD_BYTES // _CHUNK):
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        pass  # the launcher stopped reading: that is the point


def main(argv: list[str]) -> int:
    modes = {"ok", "probe", "sleep", "flood"}
    if len(argv) != 1 or argv[0] not in modes:
        print(f"usage: probe.py {{{'|'.join(sorted(modes))}}}", file=sys.stderr)
        return _USAGE_EXIT
    mode = argv[0]
    if mode == "ok":
        print(json.dumps({"status": "ok"}))
    elif mode == "probe":
        print(json.dumps(probe()))
    elif mode == "flood":
        _flood()
    else:
        while True:
            time.sleep(60)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
