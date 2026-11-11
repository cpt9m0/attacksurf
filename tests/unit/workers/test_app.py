import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from celery.signals import setup_logging, worker_process_init

from attacksurf.infra.cache import RedisScanCache
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.workers import app as worker_app
from attacksurf.workers import runtime


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
    assert runtime.http_client() is not runtime.http_client()


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
