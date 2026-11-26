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

`probe` is meant for the container only: it tries to create a file, and run a script, in every
directory it can reach.
"""

import errno
import json
import os
import socket
import subprocess
import sys
import time

INPUT_DIR = "/input"
SCRATCH_DIR = "/scratch"
# World-writable in the Debian base and not a mount of its own, so only a read-only root can
# refuse a write here. (`/etc` is closed to the sandbox user whatever the root is.)
ROOT_PROBE_PATH = "/var/tmp/.attacksurf-probe"  # noqa: S108 (probed, never relied on)
WALK_ROOT = "/"
# Kernel interfaces, not places a tool can keep a file.
SKIPPED_DIRS = ("/proc", "/sys")
MAX_WALKED_DIRS = 20_000
DOCKER_SOCKET = "/var/run/docker.sock"
PROC_STATUS = "/proc/self/status"

_PROBE_FILE = ".attacksurf-probe"
_MAX_INPUT_FILES = 1000
_FLOOD_BYTES = 3 * 1024 * 1024
_CHUNK = 64 * 1024
_USAGE_EXIT = 2


def _connect_error() -> str | None:
    """None when the connect worked, else the errno name (or the error's type name). The name
    tells "there is no route" apart from "nothing answered"."""
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
    except OSError as error:
        return errno.errorcode.get(error.errno or 0, type(error).__name__)
    return None


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


def _can_execute_in(directory: str) -> bool:
    path = os.path.join(directory, _PROBE_FILE)
    try:
        script = open(path, "x")  # noqa: SIM115 (the file must be closed before it can be run)
    except OSError:
        return False
    try:
        with script:
            script.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)  # noqa: S103 (a throwaway script: it is the exec bit being tested)
        ran = subprocess.run([path], check=False, capture_output=True, timeout=10)  # noqa: S603
        return ran.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        os.unlink(path)


def _writable_dirs() -> tuple[dict[str, bool], bool]:
    """Every directory a file can be created in, with whether a script there runs; the second
    value says the walk was cut short, so the list can't pass for complete. Links aren't
    followed. A closed directory is still searched: something inside it may be open."""
    found: dict[str, bool] = {}
    for walked, (directory, subdirs, _names) in enumerate(os.walk(WALK_ROOT)):
        if walked >= MAX_WALKED_DIRS:
            return found, True
        subdirs[:] = [name for name in subdirs if os.path.join(directory, name) not in SKIPPED_DIRS]
        if _can_create(os.path.join(directory, _PROBE_FILE)):
            found[directory] = _can_execute_in(directory)
    return found, False


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
    network_error = _connect_error()
    writable_dirs, walk_truncated = _writable_dirs()
    return {
        "network_connect_allowed": network_error is None,
        "network_error": network_error,
        "dns_resolve_allowed": _can_resolve(),
        "input_files": len(inputs),
        "input_write_allowed": _can_open_for_writing(inputs[0]) if inputs else None,
        "input_create_allowed": _can_create(os.path.join(INPUT_DIR, _PROBE_FILE)),
        "root_write_allowed": _can_create(ROOT_PROBE_PATH),
        "scratch_write_allowed": _can_create(os.path.join(SCRATCH_DIR, _PROBE_FILE)),
        "scratch_exec_allowed": _can_execute_in(SCRATCH_DIR),
        "writable_dirs": writable_dirs,
        "walk_truncated": walk_truncated,
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
