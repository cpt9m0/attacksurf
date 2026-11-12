"""The Anthropic adapter against a stubbed Messages API (never the network)."""

import json
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
from pydantic import SecretStr
from structlog.testing import capture_logs

from attacksurf.ai.limits import CALL_DEADLINE_SECONDS, MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.ai.providers import anthropic as anthropic_provider
from attacksurf.ai.providers.anthropic import DEFAULT_BASE_URL, AnthropicProvider
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.llm import (
    KeySource,
    LLMConfig,
    LLMError,
    LLMOutputError,
    LLMRequestError,
    LLMUnavailable,
    ProviderKind,
    TokenUsage,
)
from tests.unit.ai.contract import (
    API_KEY,
    CONVERSATION,
    INVALID,
    VALID,
    ProviderContract,
    SentRequest,
    Verdict,
)

MODEL = "test-model"


def _config(base_url: str | None = None) -> LLMConfig:
    return LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model=MODEL,
        api_key=SecretStr(API_KEY),
        source=KeySource.INSTANCE,
        base_url=SecretStr(base_url) if base_url else None,
    )


USAGE = {"input_tokens": 10, "output_tokens": 5}


def _message(
    content: list[dict[str, Any]],
    usage: dict[str, int] | None = None,
    stop_reason: str = "end_turn",
) -> dict[str, Any]:
    """A Messages API response body, in the shape the API documents."""
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": USAGE if usage is None else usage,
    }


def _text(text: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": text}]


def _error(status: int, error_type: str, message: str) -> httpx2.Response:
    body = {"type": "error", "error": {"type": error_type, "message": message}}
    return httpx2.Response(status, json=body, headers={"request-id": "req_test"})


class AnthropicHarness:
    def __init__(self, base_url: str | None = None) -> None:
        # None: the connection fails; a callable answers when it returns (a slow server).
        self._queue: list[httpx2.Response | Callable[[], httpx2.Response] | None] = []
        self.requests: list[httpx2.Request] = []
        client = httpx2.Client(transport=httpx2.MockTransport(self._answer))
        self.provider = AnthropicProvider(_config(base_url), http_client=client)

    def _answer(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        queued = self._queue.pop(0)
        if queued is None:
            raise httpx2.ConnectError("connection refused", request=request)
        return queued() if callable(queued) else queued

    def respond_slowly(self, answer: Callable[[], httpx2.Response]) -> None:
        self._queue.append(answer)

    def read_timeout(self, index: int) -> float:
        return self.requests[index].extensions["timeout"]["read"]

    def reply(self, text: str, *, input_tokens: int = 10, output_tokens: int = 5) -> None:
        usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
        self.reply_body(_message(_text(text), usage))

    def reply_body(self, body: object) -> None:
        self.respond(httpx2.Response(200, json=body))

    def respond(self, response: httpx2.Response) -> None:
        self._queue.append(response)

    def fail(self, status: int | None) -> None:
        self._queue.append(None if status is None else _error(status, "api_error", "stubbed"))

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[index].content)

    @property
    def sent(self) -> list[SentRequest]:
        bodies = [self.body(i) for i in range(len(self.requests))]
        return [
            SentRequest(
                system=body.get("system"),
                messages=tuple((m["role"], m["content"]) for m in body["messages"]),
                max_tokens=body["max_tokens"],
                schema=body["output_config"]["format"]["schema"],
            )
            for body in bodies
        ]


class TestAnthropicProvider(ProviderContract):
    @pytest.fixture
    def harness(self) -> AnthropicHarness:
        return AnthropicHarness()


@pytest.fixture
def harness() -> AnthropicHarness:
    return AnthropicHarness()


def test_request_goes_to_the_messages_api_with_the_configured_model(
    harness: AnthropicHarness,
) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    request = harness.requests[0]
    assert str(request.url) == f"{DEFAULT_BASE_URL}/v1/messages"
    assert harness.body()["model"] == MODEL


def test_key_is_sent_as_a_bearer_token(harness: AnthropicHarness) -> None:
    # SDK 2.x sends api_key= as Bearer, the header Meta's endpoint expects too.
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests[0].headers["authorization"] == f"Bearer {API_KEY}"


def test_configured_base_url_is_used() -> None:
    harness = AnthropicHarness(base_url="https://llm.example.test")
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert str(harness.requests[0].url) == "https://llm.example.test/v1/messages"


def test_environment_cannot_redirect_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://attacker.example.test")
    harness = AnthropicHarness()
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests[0].url.host == "api.anthropic.com"


def test_no_sampling_parameters_are_sent(harness: AnthropicHarness) -> None:
    # API version 2026-10-21 rejects them with a 400 on every model (ADR 0024).
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert not {"temperature", "top_p", "top_k"} & harness.body().keys()


def test_schema_is_sent_in_the_strict_form_the_api_accepts(harness: AnthropicHarness) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    output_format = harness.body()["output_config"]["format"]
    assert output_format["type"] == "json_schema"
    assert output_format["schema"]["additionalProperties"] is False
    assert "tools" not in harness.body()  # native structured output, no forced tool call


@pytest.mark.parametrize(
    "other_block",
    [
        {"type": "thinking", "thinking": "", "signature": "sig"},
        {"type": "block_type_from_the_future", "data": 1},
    ],
    ids=["thinking", "unknown"],
)
def test_only_text_blocks_make_up_the_reply(
    harness: AnthropicHarness, other_block: dict[str, Any]
) -> None:
    harness.reply_body(_message([other_block, *_text(VALID)]))

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.text == VALID


def test_cached_input_tokens_count_as_input(harness: AnthropicHarness) -> None:
    usage = {
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_creation_input_tokens": 100,
        "cache_read_input_tokens": 1000,
    }
    harness.reply_body(_message(_text(VALID), usage))

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.usage == TokenUsage(input_tokens=1110, output_tokens=5)


def test_reply_without_usage_is_kept_with_usage_unreported(harness: AnthropicHarness) -> None:
    body = _message(_text(VALID))
    del body["usage"]
    harness.reply_body(body)

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.parsed == Verdict.model_validate_json(VALID)
    assert result.usage == TokenUsage(reported=False)


@pytest.mark.parametrize(
    ("stop_reason", "error"),
    [
        ("max_tokens", LLMOutputError),
        ("refusal", LLMOutputError),
        ("model_context_window_exceeded", LLMRequestError),
    ],
)
def test_reply_a_correction_cannot_fix_fails_at_once_with_its_usage(
    harness: AnthropicHarness, stop_reason: str, error: type[LLMError]
) -> None:
    usage = {"input_tokens": 100, "output_tokens": 256}
    harness.reply_body(_message(_text('{"severity": "hi'), usage, stop_reason=stop_reason))

    with pytest.raises(error) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert len(harness.requests) == 1  # no paid retry that would end the same way
    assert caught.value.usage == TokenUsage(input_tokens=100, output_tokens=256)
    assert not isinstance(caught.value, TransientJobError)


def test_cut_off_retry_keeps_the_first_attempts_usage(harness: AnthropicHarness) -> None:
    harness.reply(INVALID, input_tokens=100, output_tokens=10)
    usage = {"input_tokens": 130, "output_tokens": 256}
    harness.reply_body(_message(_text('{"sev'), usage, stop_reason="max_tokens"))

    with pytest.raises(LLMOutputError) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert caught.value.usage == TokenUsage(input_tokens=230, output_tokens=266)


def test_empty_reply_is_retried_without_an_empty_assistant_turn(
    harness: AnthropicHarness,
) -> None:
    # Anthropic rejects an empty assistant text block, so the retry must not send one.
    harness.reply_body(_message([]))
    harness.reply(VALID)

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.attempts == 2
    assert [role for role, _ in harness.sent[1].messages] == ["user", "user"]


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(200, text="<html>login</html>", headers={"content-type": "text/html"}),
        httpx2.Response(200, json={"unexpected": "shape"}),
        httpx2.Response(200, json=[1, 2]),
        httpx2.Response(200, json={"type": "message", "content": None, "usage": USAGE}),
        httpx2.Response(200, json={"type": "error", "error": {"type": "overloaded_error"}}),
    ],
    ids=["html", "other-json", "list", "null-content", "error-body"],
)
def test_unreadable_success_response_is_transient(
    harness: AnthropicHarness, response: httpx2.Response
) -> None:
    harness.respond(response)

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)


def test_overloaded_status_is_transient(harness: AnthropicHarness) -> None:
    harness.respond(_error(529, "overloaded_error", "Overloaded"))

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)


def test_rejected_request_is_logged_by_type_without_the_api_message(
    harness: AnthropicHarness,
) -> None:
    harness.respond(_error(400, "invalid_request_error", "echoed: Judge this finding."))

    with capture_logs() as logs, pytest.raises(LLMRequestError):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert logs == [
        {
            "event": "llm request failed",
            "log_level": "warning",
            "status": 400,
            "error_type": "invalid_request_error",
            "request_id": "req_test",
        }
    ]


def test_client_uses_the_shared_timeout_and_no_sdk_retries() -> None:
    provider = AnthropicProvider(_config())

    assert provider._client.timeout == REQUEST_TIMEOUT_SECONDS
    assert provider._client.max_retries == MAX_RETRIES


def test_request_with_time_to_spare_gets_the_full_request_timeout(
    harness: AnthropicHarness,
) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.read_timeout(0) == REQUEST_TIMEOUT_SECONDS


@pytest.fixture
def release() -> Iterator[threading.Event]:
    """Holds stalled stub responses until the test ends, so no stub thread outlives it."""
    event = threading.Event()
    yield event
    event.set()


def _stalled(release: threading.Event) -> Callable[[], httpx2.Response]:
    def answer() -> httpx2.Response:
        release.wait(timeout=30)
        return httpx2.Response(200, json=_message(_text(VALID)))

    return answer


def test_slow_response_is_abandoned_at_the_call_deadline(
    harness: AnthropicHarness, release: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Per-read timeouts can't catch a server that trickles bytes; the call deadline does.
    monkeypatch.setattr(anthropic_provider, "CALL_DEADLINE_SECONDS", 0.2)
    harness.respond_slowly(_stalled(release))
    started = time.monotonic()

    with pytest.raises(LLMUnavailable) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert isinstance(caught.value, TransientJobError)


def test_corrective_retry_gets_only_the_time_left(
    harness: AnthropicHarness, release: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(anthropic_provider, "CALL_DEADLINE_SECONDS", 1.0)

    def slow_invalid() -> httpx2.Response:
        time.sleep(0.5)
        return httpx2.Response(200, json=_message(_text(INVALID)))

    harness.respond_slowly(slow_invalid)
    harness.respond_slowly(_stalled(release))
    started = time.monotonic()

    with pytest.raises(LLMUnavailable) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert len(harness.requests) == 2
    assert harness.read_timeout(1) < 0.6  # what was left, not a fresh 60 s
    assert caught.value.usage == TokenUsage(input_tokens=10, output_tokens=5)


def test_no_request_starts_once_the_deadline_has_passed(
    harness: AnthropicHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, CALL_DEADLINE_SECONDS + 1])  # the deadline is set, then time is up
    monkeypatch.setattr(anthropic_provider, "monotonic", lambda: next(clock))

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests == []


def test_rate_limit_with_a_long_retry_after_fails_at_once(harness: AnthropicHarness) -> None:
    # The SDK would sleep for any Retry-After if it retried; with retries off it doesn't wait.
    response = _error(429, "rate_limit_error", "Rate limited")
    response.headers["retry-after"] = "600"
    harness.respond(response)
    started = time.monotonic()

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert len(harness.requests) == 1
