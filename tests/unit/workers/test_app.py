import logging

import pytest
from celery.signals import setup_logging, worker_process_init

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
