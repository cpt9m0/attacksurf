"""The real sandbox chain for the runtime tests: worker client, launcher, proxy, Docker (#84).

The launcher and proxy are the real servers, run in this process on the local Docker socket; only
the analyzers run as containers. Nothing here skips: the tests module skips unless
`RUN_SANDBOX_TESTS=1`, and once asked, a missing Docker, a failed build or no permitted runtime
is a failure.
"""

import functools
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid4

import pytest

from attacksurf.config import SandboxLauncherSettings, SandboxProxySettings
from attacksurf.domain.sandbox import SandboxResult
from attacksurf.infra.sandbox import LauncherSandboxRunner
from attacksurf.sandbox_launcher.__main__ import RuntimeUnavailable, select_runtime, select_specs
from attacksurf.sandbox_launcher.catalog import FIXTURE_SPECS, load_catalog
from attacksurf.sandbox_launcher.proxy import ProxyClient
from attacksurf.sandbox_launcher.runner import run_sandbox
from attacksurf.sandbox_launcher.server import make_server as make_launcher
from attacksurf.sandbox_proxy.policy import SandboxPolicy, load_images
from attacksurf.sandbox_proxy.server import make_server as make_proxy
from tests.docker_fakes import serving

ROOT = Path(__file__).resolve().parents[3]
INPUT_TEXT = "hello\n"
# Generous for a slow runner: only the sleep test is meant to hit the wall time.
WALL_TIME_SECONDS = 60
SHORT_WALL_TIME_SECONDS = 3
SENTINEL_NAME = "SANDBOX_TEST_SENTINEL"


def docker(*args: str) -> str:
    binary = shutil.which("docker")
    if binary is None:
        pytest.fail("RUN_SANDBOX_TESTS=1 needs Docker, and there is no `docker` on PATH")
    command = [binary, *args]
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        pytest.fail(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


@pytest.fixture(scope="session")
def image_id() -> str:
    """`SANDBOX_FIXTURE_IMAGE` if set, else the image the build script produces."""
    image = os.environ.get("SANDBOX_FIXTURE_IMAGE")
    if not image:
        script = [str(ROOT / "scripts" / "build-sandbox-images.sh"), "fixture"]
        built = subprocess.run(script, capture_output=True, text=True, check=False)  # noqa: S603
        if built.returncode != 0:
            pytest.fail(f"building the fixture image failed:\n{built.stderr[-4000:]}")
        image = built.stdout.split()[-1]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        pytest.fail("the fixture image ID is not a sha256 digest")
    return image


@pytest.fixture(scope="session")
def image_env_names(image_id: str) -> frozenset[str]:
    entries = json.loads(docker("image", "inspect", "--format", "{{json .Config.Env}}", image_id))
    return frozenset(entry.split("=", 1)[0] for entry in entries)


@pytest.fixture(scope="session")
def fixture_containers(image_id: str) -> Callable[[], list[str]]:
    # By image, not by name: the dev stack's containers are also named `attacksurf-*`.
    return lambda: docker("ps", "-aq", "--filter", f"ancestor={image_id}").split()


@pytest.fixture(autouse=True)
def no_container_survives(fixture_containers: Callable[[], list[str]]) -> Iterator[None]:
    yield
    left = fixture_containers()
    if left:
        docker("rm", "--force", *left)
        pytest.fail(f"containers were left behind (now removed): {left}")


@pytest.fixture(scope="session")
def images_lock(image_id: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The test lock: every fixture name points at the one image. Never the committed lock."""
    path = tmp_path_factory.mktemp("lock") / "sandbox-images.lock"
    path.write_text(json.dumps({spec.name: image_id for spec in FIXTURE_SPECS}))
    return path


@dataclass(frozen=True)
class Staged:
    root: Path
    artifact_id: UUID

    @property
    def directory(self) -> Path:
        return self.root / str(self.artifact_id)


@pytest.fixture(scope="session")
def staged(tmp_path_factory: pytest.TempPathFactory) -> Staged:
    """One staged artifact that file permissions would let the sandbox user change, so only the
    read-only mount can stop a write."""
    artifact = Staged(tmp_path_factory.mktemp("artifacts").resolve(), uuid4())
    artifact.directory.mkdir()
    artifact.directory.chmod(0o777)
    hello = artifact.directory / "hello.txt"
    hello.write_text(INPUT_TEXT)
    hello.chmod(0o666)
    return artifact


@pytest.fixture(scope="session")
def proxy_port(images_lock: Path, staged: Staged) -> Iterator[int]:
    settings = SandboxProxySettings()
    images, osv_image = load_images(images_lock)
    policy = SandboxPolicy(
        images=images,
        runtimes=settings.allowed_runtimes,
        artifact_root=PurePosixPath(staged.root),
        osv_image=osv_image,
    )
    with serving(make_proxy("127.0.0.1", 0, policy, settings.sandbox_docker_socket)) as server:
        yield server.server_address[1]


@pytest.fixture(scope="session")
def proxy(proxy_port: int) -> ProxyClient:
    return ProxyClient("127.0.0.1", proxy_port)


@pytest.fixture(scope="session")
def runtime(proxy: ProxyClient) -> str:
    allow_runc = SandboxLauncherSettings().sandbox_allow_runc
    try:
        return select_runtime(proxy.runtimes(), prod=False, allow_runc=allow_runc)
    except RuntimeUnavailable:
        pytest.fail("no permitted runtime: install runsc, or set SANDBOX_ALLOW_RUNC=true")


@contextmanager
def _launcher(
    wall_time: float, *, lock: Path, root: Path, proxy: ProxyClient, runtime: str
) -> Iterator[LauncherSandboxRunner]:
    server = make_launcher(
        "127.0.0.1",
        0,
        catalog=load_catalog(lock, select_specs(prod=False, fixtures=True)),
        artifact_root=root,
        run=functools.partial(run_sandbox, proxy, runtime=runtime, wall_time=wall_time),
        max_concurrent_runs=2,
    )
    with serving(server):
        yield LauncherSandboxRunner(
            f"http://127.0.0.1:{server.server_address[1]}", timeout_seconds=120
        )


@pytest.fixture(scope="session")
def runner(
    images_lock: Path, staged: Staged, proxy: ProxyClient, runtime: str
) -> Iterator[LauncherSandboxRunner]:
    with _launcher(
        WALL_TIME_SECONDS, lock=images_lock, root=staged.root, proxy=proxy, runtime=runtime
    ) as client:
        yield client


@pytest.fixture(scope="session")
def short_runner(
    images_lock: Path, staged: Staged, proxy: ProxyClient, runtime: str
) -> Iterator[LauncherSandboxRunner]:
    with _launcher(
        SHORT_WALL_TIME_SECONDS, lock=images_lock, root=staged.root, proxy=proxy, runtime=runtime
    ) as client:
        yield client


@dataclass(frozen=True)
class ProbeRun:
    result: SandboxResult
    facts: dict[str, Any]


@pytest.fixture(scope="session")
def probe_run(runner: LauncherSandboxRunner, staged: Staged) -> ProbeRun:
    """The probe runs once; each wall test judges one part of what it reported."""
    with pytest.MonkeyPatch.context() as patch:
        # The services run in this process: this must not reach the sandbox.
        patch.setenv(SENTINEL_NAME, "must-not-leak")
        result = runner.run("fixture-probe", staged.artifact_id)
    assert (result.exit_code, result.timed_out, result.output_exceeded) == (0, False, False)
    return ProbeRun(result, json.loads(result.stdout))
