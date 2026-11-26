"""The dev stack's sandbox walls (ADRs 0016 and 0028), read from the rendered `compose.yaml` (#84).

Nothing is started and the daemon isn't contacted. Only the committed file is rendered: no
`compose.override.yaml`, no `.env` and no shell variables. Failures name services, keys and
mounts, never environment values.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKER = shutil.which("docker")

PROXY = "sandbox-proxy"
LAUNCHER = "sandbox-launcher"
WORKER = "worker-analysis"
SANDBOX_SERVICES = (PROXY, LAUNCHER, WORKER)

# Exact, so any new variable shows up as a change here. Never add the database or Redis URL or an
# encryption key: these two services must not hold app secrets.
PROXY_SETTINGS = frozenset({"ENV", "SANDBOX_ALLOW_RUNC", "SANDBOX_ARTIFACT_ROOT"})
LAUNCHER_SETTINGS = PROXY_SETTINGS | {"SANDBOX_FIXTURE_ANALYZERS"}

DOCKER_SOCKET = "/var/run/docker.sock"
SOURCE_TARGET = "/app/src"
ARTIFACT_STORE_TARGET = "/var/lib/attacksurf/artifact-store"

Mount = tuple[str, str, str, bool]
"""Type, source, target and read-only flag."""


@pytest.fixture(scope="module")
def config(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if DOCKER is None:
        reason = "the sandbox compose guard needs Docker Compose"
        if os.environ.get("CI") == "true":
            pytest.fail(f"{reason}; it must not be skipped in CI")
        pytest.skip(reason)

    # Compose reads `.env` for interpolation unless it is given another file.
    empty_env_file = tmp_path_factory.mktemp("compose") / "empty.env"
    empty_env_file.touch()
    env = {
        name: os.environ[name] for name in ("PATH", "HOME", "DOCKER_CONFIG") if name in os.environ
    }

    result = subprocess.run(  # noqa: S603 (fixed local Compose config, no daemon or secrets)
        [
            DOCKER,
            "compose",
            # Naming the file also keeps a local `compose.override.yaml` out.
            "-f",
            str(ROOT / "compose.yaml"),
            "--env-file",
            str(empty_env_file),
            "--profile",
            "sandbox",
            "config",
            "--no-env-resolution",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def services(config: dict[str, Any]) -> dict[str, Any]:
    return config["services"]


def mounts(service: dict[str, Any]) -> set[Mount]:
    return {
        (
            volume["type"],
            volume.get("source", ""),
            volume["target"],
            volume.get("read_only", False),
        )
        for volume in service.get("volumes", [])
    }


def source_mount(*, read_only: bool) -> Mount:
    return ("bind", str(ROOT / "src"), SOURCE_TARGET, read_only)


def test_only_the_sandbox_proxy_mounts_the_docker_socket(services: dict[str, Any]) -> None:
    holders = {
        name
        for name, service in services.items()
        for _, source, target, _ in mounts(service)
        if "docker.sock" in source or "docker.sock" in target
    }

    assert holders == {PROXY}, f"services mounting the Docker socket: {sorted(holders)}"


@pytest.mark.parametrize(
    ("name", "allowed"), [(PROXY, PROXY_SETTINGS), (LAUNCHER, LAUNCHER_SETTINGS)]
)
def test_sandbox_services_get_only_their_own_settings(
    services: dict[str, Any], name: str, allowed: frozenset[str]
) -> None:
    keys = set(services[name]["environment"])
    other_sources = sorted({"env_file", "secrets"} & set(services[name]))

    assert keys == allowed, (
        f"{name}: forbidden keys {sorted(keys - allowed)}, missing keys {sorted(allowed - keys)}"
    )
    assert not other_sources, f"{name} must not use {other_sources}"


@pytest.mark.parametrize("name", [PROXY, LAUNCHER])
def test_sandbox_services_are_only_on_the_internal_sandbox_network(
    config: dict[str, Any], name: str
) -> None:
    joined = set(config["services"][name].get("networks", {}))

    assert joined == {"sandbox"}, f"{name} is on networks {sorted(joined)}"
    assert config["networks"]["sandbox"].get("internal") is True, "`sandbox` must be internal"


def test_sandbox_network_holds_only_the_sandbox_services(services: dict[str, Any]) -> None:
    members = {
        name for name, service in services.items() if "sandbox" in service.get("networks", {})
    }

    assert members == set(SANDBOX_SERVICES), f"services on `sandbox`: {sorted(members)}"


def test_launcher_mounts_the_artifact_root_read_only_at_the_same_path(
    services: dict[str, Any],
) -> None:
    launcher = services[LAUNCHER]
    # The same path inside and out: Docker resolves the analyzer's bind source on the host.
    root = launcher["environment"]["SANDBOX_ARTIFACT_ROOT"]
    expected = {source_mount(read_only=True), ("bind", root, root, True)}

    found = mounts(launcher)

    assert found == expected, (
        f"{LAUNCHER}: unexpected mounts {sorted(found - expected)}, "
        f"missing mounts {sorted(expected - found)}"
    )


def test_proxy_mounts_only_the_socket_and_read_only_source(services: dict[str, Any]) -> None:
    expected = {source_mount(read_only=True), ("bind", DOCKER_SOCKET, DOCKER_SOCKET, False)}

    found = mounts(services[PROXY])

    assert found == expected, (
        f"{PROXY}: unexpected mounts {sorted(found - expected)}, "
        f"missing mounts {sorted(expected - found)}"
    )


def test_analysis_worker_stages_artifacts_without_the_docker_socket(
    services: dict[str, Any],
) -> None:
    worker = services[WORKER]
    root = services[LAUNCHER]["environment"]["SANDBOX_ARTIFACT_ROOT"]
    worker_uses_same_root = worker["environment"].get("SANDBOX_ARTIFACT_ROOT") == root
    # Staging is read-write here: the worker puts the decrypted artifacts there (ADR 0028).
    expected = {
        source_mount(read_only=False),
        ("volume", "artifact-store", ARTIFACT_STORE_TARGET, False),
        ("bind", root, root, False),
    }

    joined = set(worker.get("networks", {}))
    found = mounts(worker)

    assert joined == {"default", "sandbox"}, f"{WORKER} is on networks {sorted(joined)}"
    assert worker_uses_same_root, f"{WORKER} and {LAUNCHER} differ on SANDBOX_ARTIFACT_ROOT"
    assert found == expected, (
        f"{WORKER}: unexpected mounts {sorted(found - expected)}, "
        f"missing mounts {sorted(expected - found)}"
    )


def test_only_the_analysis_worker_knows_the_launcher_url(services: dict[str, Any]) -> None:
    key = "SANDBOX_LAUNCHER_URL"
    # A service with an env file must pin the key to "", or `.env` could supply a URL.
    wrong = sorted(
        name
        for name, service in services.items()
        if name != WORKER
        and service.get("environment", {}).get(key, None if service.get("env_file") else "") != ""
    )
    worker_has_launcher = services[WORKER]["environment"].get(key) == f"http://{LAUNCHER}:8791"

    assert not wrong, f"these services must have an empty {key}: {wrong}"
    assert worker_has_launcher, f"{WORKER} must point {key} at {LAUNCHER}"


@pytest.mark.parametrize("name", SANDBOX_SERVICES)
def test_sandbox_services_publish_no_ports_and_are_opt_in(
    services: dict[str, Any], name: str
) -> None:
    publishes_ports = bool(services[name].get("ports"))
    profiles = services[name].get("profiles", [])

    assert not publishes_ports, f"{name} must not publish host ports"
    assert profiles == ["sandbox"], f"{name} has profiles {profiles}"
