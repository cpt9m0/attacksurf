"""Check deployed queue consumers without starting containers or reading host secrets."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKER = shutil.which("docker")
pytestmark = pytest.mark.skipif(
    DOCKER is None or not (ROOT / "compose.prod.yaml").is_file(),
    reason="host-side deployment tests need Docker Compose and the production compose file",
)


@pytest.fixture
def services() -> dict[str, Any]:
    assert DOCKER is not None
    result = subprocess.run(  # noqa: S603 (fixed local Compose config, no daemon or secrets)
        [
            DOCKER,
            "compose",
            "-f",
            str(ROOT / "compose.prod.yaml"),
            "config",
            "--no-env-resolution",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["services"]


def test_production_consumes_ai_connection_tests(services: dict[str, Any]) -> None:
    worker = services.get("worker-ai")

    assert worker is not None, "Production needs an ai queue consumer for ai.test_connection"
    command = worker["command"]
    assert command[command.index("-Q") + 1] == "ai"
    assert command[command.index("-n") + 1] == "ai@%h"
    assert worker["image"] == services["web"]["image"]
    assert worker["entrypoint"] == services["web"]["entrypoint"]
    assert worker["environment"] == services["web"]["environment"]
    assert worker["secrets"] == services["web"]["secrets"]
    assert worker["depends_on"]["redis"]["condition"] == "service_healthy"
    assert worker["restart"] == "unless-stopped"
    assert not worker.get("profiles"), "The deploy must start the AI worker by default"


def test_production_ai_healthcheck_targets_its_own_worker(services: dict[str, Any]) -> None:
    worker = services.get("worker-ai")

    assert worker is not None, "Production must health-check its ai queue consumer"
    probe = worker["healthcheck"]["test"]
    assert probe[0] == "CMD-SHELL"
    assert "bash -c" in probe[1]
    assert "redis_password" in probe[1]
    assert "__REDIS_PASS__" in probe[1]
    assert "inspect ping -d ai@$$HOSTNAME" in probe[1]
    assert "passive@" not in probe[1]
