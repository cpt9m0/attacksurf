"""Launcher start-up: the runtime rule is a pure function, and `main` never starts weaker."""

import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from structlog.testing import capture_logs

from attacksurf.sandbox_launcher import __main__ as launcher_main
from attacksurf.sandbox_launcher.__main__ import (
    RuntimeUnavailable,
    main,
    select_runtime,
    select_specs,
)
from attacksurf.sandbox_launcher.catalog import CATALOG, FIXTURE_SPECS
from attacksurf.sandbox_launcher.server import LauncherServer
from tests.docker_fakes import FakeDocker
from tests.unit.sandbox_launcher.test_container import analyzer

URL_MARKER = "URL-MARKER-84be"

# `proxy_port` comes from this package's conftest: the real proxy in front of `FakeDocker`.


class Started:
    """What `main` built and how it ran, captured instead of serving forever."""

    def __init__(self) -> None:
        self.servers: list[LauncherServer] = []
        self.runs: list[dict[str, Any]] = []


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> Started:
    record = Started()

    def serve_forever(self: LauncherServer, poll_interval: float = 0.5) -> None:
        record.servers.append(self)

    def run_sandbox(*args: Any, **kwargs: Any) -> None:
        record.runs.append({"args": args, **kwargs})

    monkeypatch.setattr(LauncherServer, "serve_forever", serve_forever)
    monkeypatch.setattr(launcher_main, "run_sandbox", run_sandbox)
    return record


@pytest.fixture
def configure(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., None]:
    """Set the launcher's environment; every value can be overridden per test."""
    lock = tmp_path / "images.lock"
    lock.write_text("{}")

    def apply(proxy_url: str, **overrides: str) -> None:
        values = {
            "ENV": "dev",
            "SANDBOX_PROXY_URL": proxy_url,
            "SANDBOX_IMAGES_LOCK": str(lock),
            "SANDBOX_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "SANDBOX_LAUNCHER_HOST": "127.0.0.1",
            "SANDBOX_LAUNCHER_PORT": str(free_port()),
            **overrides,
        }
        for name, value in values.items():
            clean_env.setenv(name, value)

    return apply


def url_of(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def list_runtimes(docker: FakeDocker, *names: str) -> None:
    docker.info_body = json.dumps({"Runtimes": {name: {} for name in names}}).encode()


def fixture_lock(tmp_path: Path, *names: str) -> str:
    """A lock file naming `names` (all fixtures by default); returns its path."""
    path = tmp_path / "fixtures.lock"
    entries = names or tuple(spec.name for spec in FIXTURE_SPECS)
    path.write_text(json.dumps(dict.fromkeys(entries, "sha256:" + "c" * 64)))
    return str(path)


def events(logs: list[Any], name: str) -> list[Any]:
    return [entry for entry in logs if entry["event"] == name]


# --- A. Happy path ------------------------------------------------------------------------------


@pytest.mark.parametrize(("prod", "allow_runc"), [(True, False), (False, False), (False, True)])
def test_select_runtime_prefers_runsc(prod: bool, allow_runc: bool) -> None:
    assert select_runtime(["runc", "runsc"], prod=prod, allow_runc=allow_runc) == "runsc"


def test_main_serves_with_the_chosen_runtime(
    configure: Callable[..., None], proxy_port: int, started: Started
) -> None:
    configure(url_of(proxy_port), SANDBOX_WALL_TIME_SECONDS="120")

    with capture_logs() as logs:
        main()

    (server,) = started.servers
    server.run(analyzer(), Path("/unused"))
    assert started.runs[0]["runtime"] == "runsc"
    assert started.runs[0]["wall_time"] == 120
    event = next(entry for entry in logs if entry["event"] == "sandbox_launcher_started")
    assert event["runtime"] == "runsc"
    assert event["analyzers"] == 0


def test_select_specs_adds_the_fixtures_outside_prod_when_asked() -> None:
    assert select_specs(prod=False, fixtures=True) == CATALOG + FIXTURE_SPECS


def test_main_serves_the_fixture_analyzers_when_enabled(
    configure: Callable[..., None], proxy_port: int, started: Started, tmp_path: Path
) -> None:
    configure(
        url_of(proxy_port),
        SANDBOX_FIXTURE_ANALYZERS="true",
        SANDBOX_IMAGES_LOCK=fixture_lock(tmp_path),
    )

    with capture_logs() as logs:
        main()

    assert set(started.servers[0].catalog) == {spec.name for spec in FIXTURE_SPECS}
    (warning,) = events(logs, "sandbox_launcher_fixture_analyzers_enabled")
    assert warning["log_level"] == "warning"


# --- B. Boundary cases --------------------------------------------------------------------------


def test_select_specs_is_the_catalog_by_default() -> None:
    assert select_specs(prod=False, fixtures=False) == CATALOG
    assert select_specs(prod=True, fixtures=False) == CATALOG


def test_main_ignores_fixtures_in_the_lock_when_disabled(
    configure: Callable[..., None], proxy_port: int, started: Started, tmp_path: Path
) -> None:
    configure(url_of(proxy_port), SANDBOX_IMAGES_LOCK=fixture_lock(tmp_path))

    with capture_logs() as logs:
        main()

    assert started.servers[0].catalog == {}
    assert events(logs, "sandbox_launcher_fixture_analyzers_enabled") == []


def test_main_serves_only_fixtures_named_in_the_lock(
    configure: Callable[..., None], proxy_port: int, started: Started, tmp_path: Path
) -> None:
    configure(
        url_of(proxy_port),
        SANDBOX_FIXTURE_ANALYZERS="true",
        SANDBOX_IMAGES_LOCK=fixture_lock(tmp_path, "fixture-ok"),
    )

    main()

    assert set(started.servers[0].catalog) == {"fixture-ok"}


def test_select_runtime_falls_back_to_runc_only_when_allowed_outside_prod() -> None:
    assert select_runtime(["runc"], prod=False, allow_runc=True) == "runc"


def test_main_logs_the_runc_fallback(
    configure: Callable[..., None], proxy_port: int, docker: FakeDocker, started: Started
) -> None:
    list_runtimes(docker, "runc")
    configure(url_of(proxy_port), SANDBOX_ALLOW_RUNC="true")

    with capture_logs() as logs:
        main()

    (server,) = started.servers
    server.run(analyzer(), Path("/unused"))
    assert started.runs[0]["runtime"] == "runc"
    fallback = next(entry for entry in logs if entry["event"] == "sandbox_launcher_runc_fallback")
    assert fallback["log_level"] == "warning"


def test_main_starts_with_an_empty_catalog(
    configure: Callable[..., None], proxy_port: int, started: Started
) -> None:
    configure(url_of(proxy_port))

    main()

    assert started.servers[0].catalog == {}


# --- C. Refusals --------------------------------------------------------------------------------


@pytest.mark.parametrize("names", [[], ["runc"]])
def test_select_runtime_refuses_without_runsc_in_prod(names: list[str]) -> None:
    with pytest.raises(RuntimeUnavailable):
        select_runtime(names, prod=True, allow_runc=False)


def test_select_runtime_refuses_runc_without_the_fallback() -> None:
    with pytest.raises(RuntimeUnavailable):
        select_runtime(["runc"], prod=False, allow_runc=False)


def test_select_runtime_refuses_when_neither_is_listed() -> None:
    with pytest.raises(RuntimeUnavailable):
        select_runtime(["io.containerd.runc.v2"], prod=False, allow_runc=True)


def test_select_runtime_never_returns_runc_in_prod() -> None:
    with pytest.raises(RuntimeUnavailable):
        select_runtime(["runc"], prod=True, allow_runc=True)


def test_select_specs_never_adds_the_fixtures_in_prod() -> None:
    assert select_specs(prod=True, fixtures=True) == CATALOG


def test_main_refuses_fixture_analyzers_in_prod(
    configure: Callable[..., None], proxy_port: int, started: Started, tmp_path: Path
) -> None:
    configure(
        url_of(proxy_port),
        ENV="prod",
        SANDBOX_FIXTURE_ANALYZERS="true",
        SANDBOX_IMAGES_LOCK=fixture_lock(tmp_path),
    )

    with pytest.raises(ValidationError, match="SANDBOX_FIXTURE_ANALYZERS"):
        main()

    assert started.servers == []


def test_main_exits_without_runsc_in_prod(
    configure: Callable[..., None], proxy_port: int, docker: FakeDocker, started: Started
) -> None:
    list_runtimes(docker, "runc")
    configure(url_of(proxy_port), ENV="prod", SECRET_KEY="x" * 40)

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert str(exit_info.value).startswith("sandbox launcher: ")
    assert started.servers == []


def test_main_exits_without_runsc_in_dev_without_the_fallback(
    configure: Callable[..., None], proxy_port: int, docker: FakeDocker, started: Started
) -> None:
    list_runtimes(docker, "runc")
    configure(url_of(proxy_port))

    with pytest.raises(SystemExit):
        main()

    assert started.servers == []


def test_main_exits_when_the_proxy_is_unreachable(
    configure: Callable[..., None], started: Started
) -> None:
    configure(url_of(free_port()))

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code != 0
    assert started.servers == []


def test_main_exits_on_a_malformed_info_reply(
    configure: Callable[..., None], proxy_port: int, docker: FakeDocker, started: Started
) -> None:
    docker.info_body = b"{}"
    configure(url_of(proxy_port))

    with pytest.raises(SystemExit):
        main()

    assert started.servers == []


def test_main_exits_on_a_bad_images_lock(
    configure: Callable[..., None], proxy_port: int, tmp_path: Path, started: Started
) -> None:
    lock = tmp_path / "bad.lock"
    lock.write_text("not json")
    configure(url_of(proxy_port), SANDBOX_IMAGES_LOCK=str(lock))

    with pytest.raises(SystemExit):
        main()


def test_main_exits_on_a_missing_images_lock(
    configure: Callable[..., None], proxy_port: int, tmp_path: Path, started: Started
) -> None:
    configure(url_of(proxy_port), SANDBOX_IMAGES_LOCK=str(tmp_path / "missing.lock"))

    with pytest.raises(SystemExit):
        main()


def test_main_exits_on_a_proxy_url_the_client_rejects(
    configure: Callable[..., None], started: Started
) -> None:
    configure("http://127.0.0.1:8790/prefix")

    with pytest.raises(SystemExit):
        main()


# --- D. Leakage guard ---------------------------------------------------------------------------


def test_exit_messages_and_logs_omit_the_proxy_url(
    configure: Callable[..., None], started: Started
) -> None:
    dead_port = free_port()
    for url in (f"http://user:{URL_MARKER}@127.0.0.1:{dead_port}", url_of(dead_port)):
        configure(url)
        with capture_logs() as logs, pytest.raises(SystemExit) as exit_info:
            main()

        seen = f"{exit_info.value} {logs}"
        assert URL_MARKER not in seen
        assert str(dead_port) not in seen
