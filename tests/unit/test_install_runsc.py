"""The gVisor install script (#84), run against stub commands: nothing is downloaded, installed
or restarted here."""

import os
import re
import shutil
import subprocess
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "install-runsc.sh"
BASH = shutil.which("bash") or "/bin/bash"
# Commands that would change or reach the machine. Stubs come first on PATH, so the real ones
# are never run.
LOGGED_STUBS = ("sudo", "docker", "systemctl", "zstd")

# On the folder, not the script: a missing or renamed script must fail, not skip.
pytestmark = pytest.mark.skipif(not SCRIPT.parent.is_dir(), reason="needs the checkout's scripts/")


def write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def run_with_stubs(tmp_path: Path, *, arch: str) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run the script with a `curl` that "downloads" junk; returns the result and the call log."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    log.touch()
    for name in LOGGED_STUBS:
        write_executable(bin_dir / name, f'echo "{name} $*" >> "{log}"')
    write_executable(bin_dir / "uname", f"echo {arch}")
    write_executable(
        bin_dir / "curl",
        f"""echo "curl $*" >> "{log}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then echo junk > "$2"; fi
  shift
done""",
    )
    work = tmp_path / "work"
    work.mkdir()
    env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin", "TMPDIR": str(work)}
    command = [BASH, str(SCRIPT)]
    result = subprocess.run(command, capture_output=True, text=True, check=False, env=env)  # noqa: S603
    assert list(work.iterdir()) == [], "the download folder must be removed"
    return result, log.read_text()


def script_text() -> str:
    return SCRIPT.read_text()


def test_install_script_is_valid_bash() -> None:
    command = [BASH, "-n", str(SCRIPT)]

    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603

    assert result.returncode == 0, result.stderr
    assert os.access(SCRIPT, os.X_OK)


def test_install_script_pins_a_release_at_least_two_weeks_old() -> None:
    release = re.search(r"^GVISOR_RELEASE=(\d{8})$", script_text(), re.MULTILINE)
    published = re.search(r"published (\d{4}-\d{2}-\d{2})", script_text())

    assert release is not None
    assert published is not None
    assert datetime.strptime(release[1], "%Y%m%d").replace(tzinfo=UTC).date() <= date.fromisoformat(
        published[1]
    )
    assert datetime.now(UTC).date() - date.fromisoformat(published[1]) >= timedelta(days=14)


def test_install_script_pins_the_checksum() -> None:
    assert re.search(r"^GVISOR_SHA512=[0-9a-f]{128}$", script_text(), re.MULTILINE)


def test_install_script_runs_nothing_it_pipes_from_the_network() -> None:
    assert not re.search(r"\|\s*(sudo\s+)?(ba)?sh\b", script_text())
    assert "latest" not in script_text()


def test_install_script_stops_runsc_from_downloading_by_itself() -> None:
    (install,) = [line for line in script_text().splitlines() if 'runsc" install' in line]

    assert "--download-sidecars=NEVER" in install
    assert "--require-sidecars=ALWAYS" in install


def test_install_refuses_a_download_with_the_wrong_checksum(tmp_path: Path) -> None:
    result, calls = run_with_stubs(tmp_path, arch="x86_64")

    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert re.search(r"^curl .*/release/\d{8}/x86_64/gvisor\.tar\.zstd$", calls, re.MULTILINE)
    assert not re.search(r"^(sudo|docker|systemctl) ", calls, re.MULTILINE), calls


def test_install_refuses_an_architecture_without_a_pinned_checksum(tmp_path: Path) -> None:
    result, calls = run_with_stubs(tmp_path, arch="aarch64")

    assert result.returncode != 0
    assert "only x86_64" in result.stderr
    assert calls == ""
