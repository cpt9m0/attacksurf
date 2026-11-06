"""The `llm_live` guard: real-provider tests only run when asked for, never in CI."""

from collections.abc import Callable

import pytest
from pydantic import SecretStr

from attacksurf.config import Settings
from tests.conftest import pytest_collection_modifyitems
from tests.helpers import llm_live_skip_reason, make_settings

CONFIGURED = make_settings(llm_model="muse-spark-1.3", llm_api_key=SecretStr("LLM_test_key"))


def _settings(value: Settings) -> Callable[[], Settings]:
    return lambda: value


def _unreadable() -> Settings:
    raise AssertionError("settings must not be read when live tests are off")


def test_live_tests_never_run_in_ci_even_when_enabled() -> None:
    reason = llm_live_skip_reason({"CI": "true", "RUN_LLM_TESTS": "1"}, _settings(CONFIGURED))

    assert reason is not None
    assert "CI" in reason


def test_live_tests_are_off_unless_enabled() -> None:
    reason = llm_live_skip_reason({}, _unreadable)

    assert reason is not None
    assert "RUN_LLM_TESTS=1" in reason


def test_live_tests_need_a_key_and_a_model() -> None:
    reason = llm_live_skip_reason({"RUN_LLM_TESTS": "1"}, _settings(make_settings()))

    assert reason is not None
    assert "LLM_API_KEY" in reason
    assert "LLM_MODEL" in reason


def test_live_tests_run_when_enabled_and_configured() -> None:
    assert llm_live_skip_reason({"RUN_LLM_TESTS": "1"}, _settings(CONFIGURED)) is None


class _Item:
    def __init__(self, *, live: bool) -> None:
        self.live = live
        self.added: list[pytest.MarkDecorator] = []

    def get_closest_marker(self, name: str) -> object | None:
        return object() if self.live and name == "llm_live" else None

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.added.append(marker)


def test_collection_hook_skips_only_live_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RUN_LLM_TESTS", raising=False)
    live, normal = _Item(live=True), _Item(live=False)

    pytest_collection_modifyitems([live, normal])  # pyright: ignore[reportArgumentType]

    assert [marker.name for marker in live.added] == ["skip"]
    assert normal.added == []
