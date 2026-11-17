"""Fixtures that stand up the real sandbox proxy in front of the fake Docker daemon."""

import socketserver
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

import pytest

from attacksurf.sandbox_launcher.proxy import ProxyClient
from attacksurf.sandbox_proxy.policy import SandboxPolicy
from attacksurf.sandbox_proxy.server import ProxyServer, make_server
from tests.docker_fakes import FakeDocker, serving
from tests.unit.sandbox_launcher.test_container import IMAGE

if not hasattr(socketserver, "UnixStreamServer"):
    # The proxy only runs on Linux; CI runs these tests, Windows dev machines can't.
    pytest.skip("needs Unix domain sockets", allow_module_level=True)


@pytest.fixture
def docker(tmp_path: Path) -> Iterator[FakeDocker]:
    with serving(FakeDocker(str(tmp_path / "d.sock"))) as server:
        yield server


@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    path = tmp_path / "artifacts" / "11111111-1111-4111-8111-111111111111"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def proxy_server(docker: FakeDocker, tmp_path: Path) -> Iterator[ProxyServer]:
    policy = SandboxPolicy(
        images=frozenset({IMAGE}),
        runtimes=frozenset({"runsc"}),
        artifact_root=PurePosixPath(tmp_path / "artifacts"),
        osv_image=None,
    )
    with serving(make_server("127.0.0.1", 0, policy, str(docker.server_address))) as server:
        yield server


@pytest.fixture
def proxy_port(proxy_server: ProxyServer) -> int:
    return proxy_server.server_address[1]


@pytest.fixture
def client(proxy_port: int) -> ProxyClient:
    return ProxyClient("127.0.0.1", proxy_port)
