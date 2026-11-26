"""The sandbox fixture image (ADR 0016) and the script that builds it, without a Docker daemon.

The fixture's behavior inside a real sandbox is checked by the runtime tests; here the probe runs on
the host with its paths pointed at `tmp_path` and the network stubbed, so nothing is written
outside the test directory and no connection is attempted.
"""

import ast
import errno
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from attacksurf.sandbox_launcher.container import SANDBOX_USER
from attacksurf.sandbox_launcher.stream import MAX_STDOUT_BYTES

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ROOT / "sandbox" / "images"
FIXTURE = IMAGES / "fixture"
PROBE = FIXTURE / "probe.py"
BUILD_SCRIPT = ROOT / "scripts" / "build-sandbox-images.sh"
BASH = shutil.which("bash") or "/bin/bash"
IMAGE_ID = "sha256:" + "ab" * 32
PROBE_KEYS = {
    "network_connect_allowed",
    "dns_resolve_allowed",
    "input_files",
    "input_write_allowed",
    "input_create_allowed",
    "root_write_allowed",
    "scratch_write_allowed",
    "scratch_exec_allowed",
    "uid",
    "gid",
    "cap_eff",
    "no_new_privs",
    "docker_socket_present",
    "env_names",
    "kernel_release",
    "network_error",
    "writable_dirs",
    "walk_truncated",
}
FROM_LINE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)


def run_fixture(*argv: str) -> subprocess.CompletedProcess[bytes]:
    # -I -S: no site-packages and no environment, like the image holding only this file.
    command = [sys.executable, "-I", "-S", str(PROBE), *argv]
    return subprocess.run(command, check=False, capture_output=True)  # noqa: S603


def load_probe() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fixture_probe", PROBE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _refuse(*_args: object, **_kwargs: object) -> None:
    raise OSError("network is unreachable")


@pytest.fixture
def probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The probe with every path under `tmp_path` and both network calls refused."""
    module = load_probe()
    for name in ("input", "scratch", "root"):
        (tmp_path / name).mkdir()
    (tmp_path / "input" / "hello.txt").write_text("hello\n")
    monkeypatch.setattr(module, "INPUT_DIR", str(tmp_path / "input"))
    monkeypatch.setattr(module, "SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr(module, "ROOT_PROBE_PATH", str(tmp_path / "root" / ".attacksurf-probe"))
    monkeypatch.setattr(module, "DOCKER_SOCKET", str(tmp_path / "docker.sock"))
    # Without this the probe would walk, and try to write all over, the host's filesystem.
    monkeypatch.setattr(module, "WALK_ROOT", str(tmp_path))
    monkeypatch.setattr(module.socket, "create_connection", _refuse)
    monkeypatch.setattr(module.socket, "getaddrinfo", _refuse)
    return module


def run_build(
    tmp_path: Path, *names: str, image_id: str = IMAGE_ID, build_status: int = 0
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the build script against a `docker` stub that logs its arguments."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\n"
        f"echo \"$*\" >> '{log}'\n"
        'case "$1" in\n'
        f"  build) exit {build_status} ;;\n"
        f"  image) echo '{image_id}' ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
    result = subprocess.run(  # noqa: S603 (fixed local script, stubbed docker)
        [BASH, str(BUILD_SCRIPT), *names],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, log


# Happy path


def test_fixture_ok_prints_one_json_line() -> None:
    result = run_fixture("ok")

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [b'{"status": "ok"}']


def test_fixture_flood_prints_more_than_the_output_cap() -> None:
    result = run_fixture("flood")

    assert result.returncode == 0, result.stderr
    assert len(result.stdout) > MAX_STDOUT_BYTES


def test_fixture_probe_reports_every_key(probe: ModuleType) -> None:
    facts = probe.probe()

    assert set(facts) == PROBE_KEYS
    assert json.loads(json.dumps(facts)) == facts
    assert facts["network_connect_allowed"] is False
    assert facts["network_error"] == "OSError"
    assert facts["walk_truncated"] is False
    assert facts["dns_resolve_allowed"] is False
    assert facts["input_files"] == 1
    assert facts["docker_socket_present"] is False
    assert facts["uid"] == os.getuid()


def test_fixture_probe_names_the_connect_error(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unreachable(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(probe.socket, "create_connection", unreachable)

    facts = probe.probe()

    assert facts["network_connect_allowed"] is False
    assert facts["network_error"] == "ENETUNREACH"


def test_fixture_probe_reports_a_connect_that_worked(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Connection:
        def close(self) -> None:
            pass

    monkeypatch.setattr(probe.socket, "create_connection", lambda *_a, **_kw: Connection())

    facts = probe.probe()

    assert facts["network_connect_allowed"] is True
    assert facts["network_error"] is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_fixture_probe_lists_only_writable_directories_and_whether_they_run_files(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    walk = tmp_path / "walk"
    (walk / "open").mkdir(parents=True)
    (walk / "locked" / "nested-open").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (walk / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    (walk / "locked").chmod(0o555)
    monkeypatch.setattr(probe, "WALK_ROOT", str(walk))
    try:
        facts = probe.probe()
    finally:
        (walk / "locked").chmod(0o755)

    # `locked` is closed, but what is inside it is still searched; the link is not followed.
    assert set(facts["writable_dirs"]) == {
        str(walk),
        str(walk / "open"),
        str(walk / "locked" / "nested-open"),
    }
    assert facts["writable_dirs"][str(walk / "open")] is True
    assert list(walk.rglob(".attacksurf-probe")) == []


def test_fixture_probe_does_not_walk_the_skipped_directories(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "walk" / "proc" / "inner").mkdir(parents=True)
    monkeypatch.setattr(probe, "WALK_ROOT", str(tmp_path / "walk"))
    monkeypatch.setattr(probe, "SKIPPED_DIRS", (str(tmp_path / "walk" / "proc"),))

    facts = probe.probe()

    assert set(facts["writable_dirs"]) == {str(tmp_path / "walk")}


def test_fixture_probe_says_when_the_walk_was_cut_short(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "MAX_WALKED_DIRS", 1)

    facts = probe.probe()

    assert facts["walk_truncated"] is True


def test_fixture_probe_removes_its_script_when_it_cannot_run_it(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse_mode(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("not permitted")

    monkeypatch.setattr(probe.os, "chmod", refuse_mode)

    facts = probe.probe()

    assert facts["scratch_exec_allowed"] is False
    assert list((tmp_path / "scratch").iterdir()) == []


def test_fixture_probe_tests_the_root_where_only_a_read_only_root_can_block_it() -> None:
    # `/etc` is closed to the sandbox user anyway, and `/tmp` is its own mount (ADR 0034).
    assert load_probe().ROOT_PROBE_PATH == "/var/tmp/.attacksurf-probe"  # noqa: S108


def test_build_script_builds_each_image_and_prints_its_id(tmp_path: Path) -> None:
    result, log = run_build(tmp_path)

    names = sorted(d.name for d in IMAGES.iterdir() if (d / "Dockerfile").is_file())
    assert result.returncode == 0, result.stderr
    assert sorted(result.stdout.splitlines()) == [f"{name} {IMAGE_ID}" for name in names]
    calls = log.read_text().splitlines()
    assert "build --tag attacksurf-sandbox-fixture:ci sandbox/images/fixture" in calls
    assert "image inspect --format {{.Id}} attacksurf-sandbox-fixture:ci" in calls


def test_build_script_builds_only_the_named_image(tmp_path: Path) -> None:
    result, _log = run_build(tmp_path, "fixture")

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"fixture {IMAGE_ID}\n"


# Boundary cases


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_fixture_probe_reports_scratch_writable_and_input_blocked_by_permissions(
    probe: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "input" / "hello.txt").chmod(0o444)
    (tmp_path / "input").chmod(0o555)
    try:
        facts = probe.probe()
    finally:
        (tmp_path / "input").chmod(0o755)

    assert facts["input_write_allowed"] is False
    assert facts["input_create_allowed"] is False
    assert facts["scratch_write_allowed"] is True
    assert facts["root_write_allowed"] is True


def test_fixture_probe_reports_no_input_write_without_an_input_file(
    probe: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "input" / "hello.txt").unlink()

    facts = probe.probe()

    assert facts["input_files"] == 0
    assert facts["input_write_allowed"] is None


def test_fixture_probe_reports_missing_process_status_as_null(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "PROC_STATUS", str(tmp_path / "no-such-status"))

    facts = probe.probe()

    assert facts["cap_eff"] is None
    assert facts["no_new_privs"] is None


def test_fixture_probe_never_prints_environment_values(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PROBE_SECRET", "s3cr3t-value")

    facts = probe.probe()

    assert "PROBE_SECRET" in facts["env_names"]
    assert "s3cr3t-value" not in json.dumps(facts)


def test_fixture_probe_cleans_up_what_it_created(probe: ModuleType, tmp_path: Path) -> None:
    probe.probe()

    assert list((tmp_path / "scratch").iterdir()) == []
    assert list((tmp_path / "root").iterdir()) == []
    assert [p.name for p in (tmp_path / "input").iterdir()] == ["hello.txt"]
    assert (tmp_path / "input" / "hello.txt").read_text() == "hello\n"


# Invalid inputs


@pytest.mark.parametrize("argv", [("nope",), (), ("ok", "extra")], ids=["unknown", "none", "two"])
def test_fixture_rejects_a_bad_mode(argv: tuple[str, ...]) -> None:
    result = run_fixture(*argv)

    assert result.returncode == 2
    assert result.stdout == b""
    assert b"usage" in result.stderr


@pytest.mark.parametrize("name", ["nope", "../fixture", "Fixture"])
def test_build_script_rejects_an_unknown_image_name(tmp_path: Path, name: str) -> None:
    result, log = run_build(tmp_path, name)

    assert result.returncode != 0
    assert result.stdout == ""
    assert not log.exists(), "docker must not be called for a bad name"


def test_build_script_fails_when_the_image_id_is_malformed(tmp_path: Path) -> None:
    result, _log = run_build(tmp_path, "fixture", image_id="abc")

    assert result.returncode != 0
    assert result.stdout == ""


def test_build_script_fails_when_docker_build_fails(tmp_path: Path) -> None:
    result, log = run_build(tmp_path, "fixture", build_status=1)

    assert result.returncode != 0
    assert result.stdout == ""
    assert not any(call.startswith("image") for call in log.read_text().splitlines())


# Neighbor rejection and drift guards


def test_fixture_base_image_matches_the_app_base() -> None:
    app_base = FROM_LINE.findall((ROOT / "Dockerfile").read_text())[0]
    fixture_bases = FROM_LINE.findall((FIXTURE / "Dockerfile").read_text())

    assert fixture_bases == [app_base]


def test_every_sandbox_image_pins_its_base_by_digest() -> None:
    dockerfiles = sorted(IMAGES.glob("*/Dockerfile"))

    assert dockerfiles
    for dockerfile in dockerfiles:
        for base in FROM_LINE.findall(dockerfile.read_text()):
            assert re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", base), dockerfile


def test_fixture_probe_imports_only_the_standard_library() -> None:
    tree = ast.parse(PROBE.read_text())

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the probe is a single file"
            imported.add((node.module or "").split(".")[0])
    assert imported
    assert imported <= sys.stdlib_module_names


def test_fixture_image_runs_as_the_sandbox_user() -> None:
    users = re.findall(r"^USER\s+(\S+)", (FIXTURE / "Dockerfile").read_text(), re.MULTILINE)

    assert users == [SANDBOX_USER]


def test_fixture_image_lets_the_sandbox_user_reach_the_probe() -> None:
    copies = re.findall(r"^COPY\s+--chmod=(\d+)\s", (FIXTURE / "Dockerfile").read_text(), re.M)

    # BuildKit applies the mode to the directories COPY creates, so a mode without the
    # search bit for "other" leaves /opt/fixture closed to the non-root sandbox user.
    assert copies
    assert all(int(mode, 8) & 0o005 == 0o005 for mode in copies)


def test_build_script_is_executable() -> None:
    assert os.access(BUILD_SCRIPT, os.X_OK), "the Makefile runs it directly"


def test_dependabot_watches_the_sandbox_images() -> None:
    config = (ROOT / ".github" / "dependabot.yml").read_text()

    entries = config.split("- package-ecosystem:")
    docker = next(entry for entry in entries if entry.split("\n", 1)[0].strip() == "docker")
    assert '"/sandbox/images/*"' in docker
