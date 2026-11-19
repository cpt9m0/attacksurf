import io
import logging
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from celery.signals import setup_logging, worker_process_init
from pydantic import SecretStr

from attacksurf.domain.artifacts import ArtifactPolicy, ArtifactStorageUnavailable
from attacksurf.domain.sandbox import SandboxError, UnconfiguredSandboxRunner
from attacksurf.domain.scope import ScopePolicyError
from attacksurf.infra.cache import RedisScanCache
from attacksurf.infra.sandbox import LauncherSandboxRunner
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.workers import app as worker_app
from attacksurf.workers import runtime
from tests.helpers import make_settings
from tests.unit.infra.test_scope_guard import context, scanner, target


def test_session_factory_is_cached_per_process() -> None:
    runtime.session_factory.cache_clear()

    assert runtime.session_factory() is runtime.session_factory()


def test_forked_worker_process_gets_its_own_session_factory() -> None:
    before = runtime.session_factory()

    worker_process_init.send(sender=None)

    assert runtime.session_factory() is not before


def test_worker_logging_goes_through_infra_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = []
    monkeypatch.setattr(worker_app, "configure_logging", configured.append)
    tracer = logging.getLogger("celery.app.trace")
    monkeypatch.setattr(tracer, "level", tracer.level)  # the handler changes it

    setup_logging.send(sender=None)

    assert configured == [runtime.settings()]


def test_celery_tracer_does_not_log_raw_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_app, "configure_logging", lambda _settings: None)
    tracer = logging.getLogger("celery.app.trace")
    monkeypatch.setattr(tracer, "level", tracer.level)  # restore after the test

    setup_logging.send(sender=None)

    assert not tracer.isEnabledFor(logging.ERROR)


def test_scan_cache_is_cached_per_process_and_rebuilt_after_fork() -> None:
    runtime.scan_cache.cache_clear()
    before = runtime.scan_cache()

    assert isinstance(before, RedisScanCache)
    assert runtime.scan_cache() is before
    worker_process_init.send(sender=None)
    assert runtime.scan_cache() is not before


def test_production_gate_checks_ownership_in_the_database() -> None:
    gate = runtime.scanner_gate()

    assert isinstance(gate, ScopeGuard)
    assert isinstance(gate._ownership, DbOwnershipChecker)  # #14: proofs gate active checks
    assert callable(runtime.dns_resolver().resolve_ipv4)
    assert callable(runtime.dns_resolver().lookup_many)
    assert runtime.ip_intel() is runtime.ip_intel()
    assert runtime.http_client() is not runtime.http_client()


LAUNCHER_URL = "http://sandbox-launcher:8791"


@pytest.fixture
def configure_sandbox(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str | None], None]]:
    """Point the worker's settings at a launcher URL (or none), with a fresh cached runner."""

    def configure(url: str | None) -> None:
        settings = make_settings(
            env="test",
            secret_key=SecretStr("test-secret-key"),
            sandbox_launcher_url=SecretStr(url) if url else None,
        )
        monkeypatch.setattr(runtime, "settings", lambda: settings)
        cached_runner.cache_clear()

    # Held by reference: a test may replace `runtime.sandbox_runner` before this teardown runs.
    cached_runner = runtime.sandbox_runner
    cached_runner.cache_clear()
    yield configure
    cached_runner.cache_clear()


def test_gate_refuses_sandbox_runs_without_a_launcher_url(
    configure_sandbox: Callable[[str | None], None],
) -> None:
    configure_sandbox(None)

    gate = runtime.scanner_gate()

    assert isinstance(gate, ScopeGuard)
    assert isinstance(gate._sandbox, UnconfiguredSandboxRunner)
    with pytest.raises(SandboxError):
        gate._sandbox.run("fixture.echo", uuid4())


def test_gate_uses_the_launcher_client_when_configured(
    configure_sandbox: Callable[[str | None], None],
) -> None:
    configure_sandbox(LAUNCHER_URL)

    gate = runtime.scanner_gate()

    assert isinstance(gate, ScopeGuard)
    assert isinstance(gate._sandbox, LauncherSandboxRunner)


def test_sandbox_runner_is_cached_per_process_and_rebuilt_after_fork(
    configure_sandbox: Callable[[str | None], None],
) -> None:
    configure_sandbox(LAUNCHER_URL)
    before = runtime.sandbox_runner()

    assert runtime.sandbox_runner() is before
    worker_process_init.send(sender=None)
    assert runtime.sandbox_runner() is not before


def test_gate_still_enforces_the_analyzer_allowlist(
    configure_sandbox: Callable[[str | None], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_sandbox(LAUNCHER_URL)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    client = LauncherSandboxRunner(LAUNCHER_URL, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(runtime, "sandbox_runner", lambda: client)
    scanner_runtime = runtime.scanner_gate().check(context(), target(), scanner())

    with pytest.raises(ScopePolicyError, match="analyzer"):
        scanner_runtime.sandbox.run("fixture.echo", uuid4())
    assert requests == []


@pytest.mark.parametrize(
    "url", ["http://sandbox-launcher:8791", "http://10.0.0.5:8791/", "http://launcher"]
)
def test_every_valid_setting_builds_a_runner(url: str) -> None:
    settings = make_settings(sandbox_launcher_url=SecretStr(url))

    assert settings.sandbox_launcher_url is not None
    LauncherSandboxRunner(settings.sandbox_launcher_url.get_secret_value())


PROBE_MODULE = """
from attacksurf.workers import runtime
from attacksurf.workers.app import app


@app.task(name="passive.collection_probe")
def probe() -> None: ...


def test_worker_conf_uses_hermetic_settings() -> None:
    assert app.conf.broker_url == runtime.settings().redis_url.get_secret_value()
"""


def test_module_level_tasks_do_not_load_real_settings_during_collection(tmp_path: Path) -> None:
    # Collecting a module-level task finalizes the worker conf; it must already see test
    # settings then, not .env/OS env (#126).
    (tmp_path / "test_probe.py").write_text(PROBE_MODULE)
    env = {**os.environ, "REDIS_URL": "redis://leaked.invalid:1/0"}
    argv = [sys.executable, "-m", "pytest", "-c", os.devnull, "--rootdir", str(tmp_path)]
    argv += ["-p", "no:cacheprovider", "-p", "tests.conftest", "-q", str(tmp_path)]

    result = subprocess.run(  # noqa: S603 (fixed argv)
        argv, env=env, cwd=Path(__file__).parents[3], check=False, capture_output=True
    )

    assert result.returncode == 0, result.stdout.decode()


def _runtime_with(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> None:
    current = make_settings(env="test", secret_key=SecretStr("test-secret-key"), **overrides)
    monkeypatch.setattr(runtime, "settings", lambda: current)
    runtime.artifact_store.cache_clear()
    runtime.artifact_policy.cache_clear()


def test_artifact_store_uses_both_roots_and_the_app_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "run").mkdir()
    _runtime_with(
        monkeypatch,
        app_encryption_key=SecretStr("a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"),
        artifact_store_root=str(tmp_path / "store"),
        sandbox_artifact_root=str(tmp_path / "run"),
    )
    org_id, artifact_id = uuid4(), uuid4()

    store = runtime.artifact_store()
    stored = store.put(org_id, artifact_id, io.BytesIO(b"payload"), max_bytes=100)
    store.stage(org_id, artifact_id, stored.key_envelope, sha256=stored.sha256)

    assert store is runtime.artifact_store()
    assert (tmp_path / "store" / str(org_id) / str(artifact_id)).is_file()
    assert (tmp_path / "run" / str(artifact_id) / "artifact").read_bytes() == b"payload"
    runtime.artifact_store.cache_clear()


def test_artifact_store_without_a_key_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _runtime_with(
        monkeypatch,
        artifact_store_root=str(tmp_path / "store"),
        sandbox_artifact_root=str(tmp_path / "run"),
    )

    with pytest.raises(ArtifactStorageUnavailable):
        runtime.artifact_store().put(uuid4(), uuid4(), io.BytesIO(b"x"), max_bytes=100)

    runtime.artifact_store().delete(uuid4(), uuid4())  # deleting needs no key
    runtime.artifact_store.cache_clear()


def test_artifact_policy_comes_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _runtime_with(
        monkeypatch,
        artifact_max_bytes=1000,
        artifact_org_quota_bytes=5000,
        artifact_retention_hours=48,
    )

    assert runtime.artifact_policy() == ArtifactPolicy(
        max_bytes=1000, org_quota_bytes=5000, retention_hours=48
    )
    runtime.artifact_policy.cache_clear()
