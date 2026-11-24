"""Unit tests for system Celery tasks (`passive.vulnintel_sync`)."""

from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from attacksurf.domain.vulnintel import SyncSummary
from attacksurf.workers import runtime
from attacksurf.workers.tasks import system as system_tasks
from tests.helpers import make_settings


class _DummySessionCtx:
    def __init__(self, session: object) -> None:
        self._session = session

    def __enter__(self) -> object:
        return self._session

    def __exit__(self, *_args: object) -> None:
        pass


class _DummyClient:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.closed = False
        self.should_fail = should_fail

    def head(self, *_args: object, **_kwargs: object) -> object:
        raise NotImplementedError

    def get(self, *_args: object, **_kwargs: object) -> object:
        raise NotImplementedError

    def close(self) -> None:
        self.closed = True


def test_vulnintel_sync_task_runs_sync_passes_api_key_and_closes_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    client = _DummyClient()
    fake_session = object()
    settings = make_settings(nvd_api_key=SecretStr("secret-nvd-key"))

    monkeypatch.setattr(runtime, "settings", lambda: settings)
    monkeypatch.setattr(runtime, "vulnintel_http_client", lambda: client)
    monkeypatch.setattr(runtime, "session_factory", lambda: lambda: _DummySessionCtx(fake_session))

    def _fake_sync(session: object, http_client: object, *, nvd_api_key: str | None) -> SyncSummary:
        captured["session"] = session
        captured["client"] = http_client
        captured["nvd_api_key"] = nvd_api_key
        return SyncSummary(
            nvd_cves_upserted=2,
            nvd_ranges_upserted=3,
            kev_updated=1,
            epss_updated=2,
            nvd_cursor=datetime(2026, 11, 23, 3, 25, tzinfo=UTC),
            kev_catalog_version="2026.11.23",
            epss_model_date="2026-11-23",
        )

    monkeypatch.setattr(system_tasks.vulnintel, "sync_vuln_intel", _fake_sync)

    system_tasks.vulnintel_sync()

    assert captured == {
        "session": fake_session,
        "client": client,
        "nvd_api_key": "secret-nvd-key",
    }
    assert client.closed is True


def test_vulnintel_sync_task_closes_client_and_sanitizes_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _DummyClient()
    monkeypatch.setattr(runtime, "vulnintel_http_client", lambda: client)
    monkeypatch.setattr(runtime, "session_factory", lambda: lambda: _DummySessionCtx(object()))

    def _fail(*_args: object, **_kwargs: object) -> SyncSummary:
        raise ValueError("secret-leak-detail")

    monkeypatch.setattr(system_tasks.vulnintel, "sync_vuln_intel", _fail)

    with pytest.raises(RuntimeError, match=r"Vulnerability intelligence sync failed\.") as excinfo:
        system_tasks.vulnintel_sync()

    assert "secret-leak-detail" not in str(excinfo.value)
    assert client.closed is True
