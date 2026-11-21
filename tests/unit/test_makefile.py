"""Exercise startup orchestration without a Docker daemon or network access."""

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKE = shutil.which("make")
pytestmark = pytest.mark.skipif(
    MAKE is None or not (ROOT / "Makefile").is_file(),
    reason="host-side startup tests need GNU Make and the checkout's Makefile",
)
STARTUP_COMMANDS = [
    ["build"],
    ["up", "-d", "--wait", "postgres", "redis"],
    ["run", "--rm", "web", "alembic", "upgrade", "head"],
    ["up", "-d", "--wait"],
]


def _run_make(
    tmp_path: Path, target: str, fail_command: list[str] | None = None
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    log = tmp_path / "commands.jsonl"
    compose = tmp_path / "compose.py"
    compose.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "with Path(sys.argv[1]).open('a') as log:\n"
        "    log.write(json.dumps(sys.argv[2:]) + '\\n')\n"
        f"if sys.argv[2:] == {fail_command!r}:\n"
        "    sys.exit(1)\n"
    )
    command = shlex.join([sys.executable, str(compose), str(log)])
    assert MAKE is not None
    result = subprocess.run(  # noqa: S603 (fixed make target, local Compose stub)
        [MAKE, "--no-print-directory", target, f"COMPOSE={command}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    return result, commands


def test_make_up_migrates_before_starting_application_services(tmp_path: Path) -> None:
    result, commands = _run_make(tmp_path, "up")

    assert result.returncode == 0, result.stderr
    assert commands == STARTUP_COMMANDS


def test_make_down_also_stops_opt_in_sandbox_services(tmp_path: Path) -> None:
    result, commands = _run_make(tmp_path, "down")

    assert result.returncode == 0, result.stderr
    assert commands == [["--profile", "sandbox", "down"]]


@pytest.mark.parametrize("failed_step", [0, 1, 2], ids=["build", "dependencies", "migration"])
def test_make_up_stops_when_a_prerequisite_fails(tmp_path: Path, failed_step: int) -> None:
    result, commands = _run_make(tmp_path, "up", STARTUP_COMMANDS[failed_step])

    assert result.returncode != 0
    assert commands == STARTUP_COMMANDS[: failed_step + 1]
