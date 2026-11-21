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


@pytest.fixture
def compose_config() -> dict[str, Any]:
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
    return json.loads(result.stdout)


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


def test_production_stack_publishes_no_ports(services: dict[str, Any]) -> None:
    for name, service in services.items():
        assert not service.get("ports"), f"{name} must not publish host ports"


def test_production_containers_are_hardened(services: dict[str, Any]) -> None:
    for name, service in services.items():
        assert service.get("read_only") is True, f"{name} must use read_only rootfs"
        assert "no-new-privileges:true" in service.get("security_opt", []), name
        assert service.get("cap_drop") == ["ALL"], f"{name} must drop all capabilities"
        assert service.get("pids_limit", 0) > 0, f"{name} must cap PIDs"
        assert service.get("cpus", 0) > 0, f"{name} must cap CPUs"
        assert service.get("mem_limit"), f"{name} must cap memory"
        logging_cfg = service.get("logging", {})
        assert logging_cfg.get("driver") == "json-file", name
        opts = logging_cfg.get("options", {})
        assert opts.get("max-size"), f"{name} must set log max-size"
        assert opts.get("max-file"), f"{name} must set log max-file"


def test_production_internal_network_isolates_db_redis_caddy_and_migrate(
    compose_config: dict[str, Any],
) -> None:
    networks = compose_config["networks"]
    assert networks["internal"].get("internal") is True

    services = compose_config["services"]
    for isolated in ("postgres", "redis", "caddy", "migrate"):
        assert set(services[isolated]["networks"]) == {"internal"}, isolated
    for connected in ("cloudflared", "web", "worker-passive", "worker-ai", "beat"):
        assert set(services[connected]["networks"]) == {"internal", "egress"}, connected


def test_production_web_gunicorn_and_tmpfs_are_tuned_for_uploads(services: dict[str, Any]) -> None:
    web = services["web"]
    cmd = web["command"]
    assert cmd[cmd.index("--timeout") + 1] == "120"
    assert cmd[cmd.index("--graceful-timeout") + 1] == "30"
    assert cmd[cmd.index("--max-requests") + 1] == "1000"
    assert cmd[cmd.index("--worker-tmp-dir") + 1] == "/dev/shm"  # noqa: S108 (compose assertion)

    tmpfs_entries = web["tmpfs"]
    tmp_mount = next(
        entry
        for entry in tmpfs_entries
        if entry.startswith("/tmp:")  # noqa: S108 (compose check)
    )
    assert "size=320m" in tmp_mount


def test_production_redis_bounds_memory(services: dict[str, Any]) -> None:
    redis_entrypoint = " ".join(services["redis"]["entrypoint"])
    assert "--maxmemory 192mb" in redis_entrypoint
    assert "--maxmemory-policy noeviction" in redis_entrypoint
