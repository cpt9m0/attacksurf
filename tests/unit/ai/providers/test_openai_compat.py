"""The OpenAI-compatible adapter against a stubbed Chat Completions API (never the network)."""

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
from attacksurf.ai.providers import openai_compat as openai_compat_provider
from attacksurf.ai.providers.openai_compat import DEFAULT_BASE_URL, OpenAICompatProvider
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.llm import (
    KeySource,
    LLMConfig,
    LLMError,
    LLMOutputError,
    LLMRequestError,
    LLMUnavailable,
    Message,
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
        provider=ProviderKind.OPENAI_COMPAT,
        model=MODEL,
        api_key=SecretStr(API_KEY),
        source=KeySource.INSTANCE,
        base_url=SecretStr(base_url) if base_url else None,
    )


USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def _completion(
    content: str | None,
    *,
    usage: dict[str, int] | None = None,
    finish_reason: str = "stop",
    refusal: str | None = None,
) -> dict[str, Any]:
    """A Chat Completions response body, in the shape the API documents."""
    return {
        "id": "chatcmpl_test",
        "object": "chat.completion",
        "created": 1700000000,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                    "refusal": refusal,
                },
                "finish_reason": finish_reason,
            }
        ],
        "usage": USAGE if usage is None else usage,
    }


def _error(status: int, error_type: str, message: str) -> httpx2.Response:
    body = {"error": {"type": error_type, "message": message}}
    return httpx2.Response(status, json=body, headers={"x-request-id": "req_test"})


class OpenAIHarness:
    def __init__(self, base_url: str | None = None) -> None:
        # None: the connection fails; a callable answers when it returns (a slow server).
        self._queue: list[httpx2.Response | Callable[[], httpx2.Response] | None] = []
        self._has_sticky_failure = False
        self._sticky_failure: httpx2.Response | None = None
        self.requests: list[httpx2.Request] = []
        client = httpx2.Client(transport=httpx2.MockTransport(self._answer))
        self.provider = OpenAICompatProvider(_config(base_url), http_client=client)

    def _answer(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self._queue:
            queued = self._queue.pop(0)
        else:
            assert self._has_sticky_failure, "OpenAIHarness: no response queued"
            queued = self._sticky_failure
        if queued is None:
            raise httpx2.ConnectError("connection refused", request=request)
        return queued() if callable(queued) else queued

    def respond_slowly(self, answer: Callable[[], httpx2.Response]) -> None:
        self._has_sticky_failure = False
        self._queue.append(answer)

    def read_timeout(self, index: int) -> float:
        return self.requests[index].extensions["timeout"]["read"]

    def reply(self, text: str, *, input_tokens: int = 10, output_tokens: int = 5) -> None:
        usage = {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
        self.reply_body(_completion(text, usage=usage))

    def reply_body(self, body: object) -> None:
        self.respond(httpx2.Response(200, json=body))

    def respond(self, response: httpx2.Response) -> None:
        self._has_sticky_failure = False
        self._queue.append(response)

    def fail(self, status: int | None) -> None:
        item = None if status is None else _error(status, "api_error", "stubbed")
        self._queue.append(item)
        # Contract failure tests call `fail(400)` once; fallback tries 3 formats on 400.
        self._has_sticky_failure = True
        self._sticky_failure = item

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[index].content)

    @property
    def sent(self) -> list[SentRequest]:
        bodies = [self.body(i) for i in range(len(self.requests))]
        result: list[SentRequest] = []
        for body in bodies:
            system_msgs = [m["content"] for m in body["messages"] if m["role"] == "system"]
            system = "\n\n".join(system_msgs) if system_msgs else None
            messages = tuple(
                (m["role"], m["content"]) for m in body["messages"] if m["role"] != "system"
            )
            response_format = body.get("response_format")
            schema = (
                response_format["json_schema"]["schema"]
                if isinstance(response_format, dict)
                and response_format.get("type") == "json_schema"
                else None
            )
            result.append(
                SentRequest(
                    system=system,
                    messages=messages,
                    max_tokens=body["max_completion_tokens"],
                    schema=schema,
                )
            )
        return result


class TestOpenAICompatProvider(ProviderContract):
    @pytest.fixture
    def harness(self) -> OpenAIHarness:
        return OpenAIHarness()


@pytest.fixture
def harness() -> OpenAIHarness:
    return OpenAIHarness()


def test_request_goes_to_chat_completions_with_the_configured_model(
    harness: OpenAIHarness,
) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    request = harness.requests[0]
    assert str(request.url) == f"{DEFAULT_BASE_URL}/chat/completions"
    assert harness.body()["model"] == MODEL


def test_key_is_sent_as_a_bearer_token(harness: OpenAIHarness) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests[0].headers["authorization"] == f"Bearer {API_KEY}"


def test_configured_base_url_is_used() -> None:
    harness = OpenAIHarness(base_url="https://llm.example.test/v1")
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert str(harness.requests[0].url) == "https://llm.example.test/v1/chat/completions"


def test_environment_cannot_redirect_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "https://attacker.example.test/v1")
    harness = OpenAIHarness()
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests[0].url.host == "api.openai.com"


def test_no_sampling_parameters_are_sent(harness: OpenAIHarness) -> None:
    # Models run with their defaults (ADR 0024).
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert (
        not {
            "temperature",
            "top_p",
            "top_k",
            "frequency_penalty",
            "presence_penalty",
        }
        & harness.body().keys()
    )


def test_max_tokens_is_sent_as_max_completion_tokens(harness: OpenAIHarness) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.body()["max_completion_tokens"] == 256
    assert "max_tokens" not in harness.body()


def test_schema_is_sent_in_the_strict_form_the_api_accepts(harness: OpenAIHarness) -> None:
    harness.reply(VALID)

    harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    response_format = harness.body()["response_format"]
    assert response_format["type"] == "json_schema"
    json_schema = response_format["json_schema"]
    assert json_schema["name"] == "Verdict"
    assert json_schema["strict"] is True
    assert json_schema["schema"]["additionalProperties"] is False
    assert "tools" not in harness.body()  # native structured output, no forced tool call


def test_400_on_json_schema_falls_back_to_json_object_with_schema_in_system_message(
    harness: OpenAIHarness,
) -> None:
    harness.respond(_error(400, "invalid_request_error", "json_schema is not supported"))
    harness.reply(VALID)

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.parsed == Verdict.model_validate_json(VALID)
    assert result.attempts == 1
    assert len(harness.requests) == 2
    second = harness.body(1)
    assert second["response_format"] == {"type": "json_object"}
    system = second["messages"][0]
    assert system["role"] == "system"
    assert "You judge findings." in system["content"]
    assert '"severity"' in system["content"]
    assert '"reason"' in system["content"]


def test_400_on_json_object_falls_back_to_plain_text_with_schema_in_system_message(
    harness: OpenAIHarness,
) -> None:
    harness.respond(_error(400, "invalid_request_error", "json_schema is not supported"))
    harness.respond(_error(400, "invalid_request_error", "json_object is not supported"))
    harness.reply(f"```json\n{VALID}\n```")

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.parsed == Verdict.model_validate_json(VALID)
    assert result.attempts == 1
    assert len(harness.requests) == 3
    third = harness.body(2)
    assert "response_format" not in third
    system = third["messages"][0]
    assert system["role"] == "system"
    assert "You judge findings." in system["content"]
    assert '"severity"' in system["content"]


def test_fallback_adds_system_message_when_conversation_had_none(
    harness: OpenAIHarness,
) -> None:
    harness.respond(_error(400, "invalid_request_error", "json_schema is not supported"))
    harness.reply(VALID)

    harness.provider.complete(
        (Message("user", "Judge this finding."),), schema=Verdict, max_tokens=256
    )

    assert [m["role"] for m in harness.body(0)["messages"]] == ["user"]
    assert [m["role"] for m in harness.body(1)["messages"]] == ["system", "user"]
    assert '"severity"' in harness.body(1)["messages"][0]["content"]


def test_corrective_retry_after_fallback_keeps_the_working_format(
    harness: OpenAIHarness,
) -> None:
    harness.respond(_error(400, "invalid_request_error", "json_schema is not supported"))
    harness.reply(INVALID, input_tokens=100, output_tokens=10)
    harness.reply(VALID, input_tokens=130, output_tokens=20)

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.attempts == 2
    assert result.usage == TokenUsage(input_tokens=230, output_tokens=30)
    assert len(harness.requests) == 3
    assert harness.body(1)["response_format"] == {"type": "json_object"}
    assert harness.body(2)["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize("status", [401, 403, 404, 422, 429, 500, 503])
def test_non_400_error_does_not_trigger_format_fallback(
    harness: OpenAIHarness, status: int
) -> None:
    harness.fail(status)

    with pytest.raises(LLMError):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert len(harness.requests) == 1


def test_reply_without_usage_is_kept_with_usage_unreported(harness: OpenAIHarness) -> None:
    body = _completion(VALID)
    del body["usage"]
    harness.reply_body(body)

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.parsed == Verdict.model_validate_json(VALID)
    assert result.usage == TokenUsage(reported=False)


@pytest.mark.parametrize(
    ("finish_reason", "refusal", "error"),
    [
        ("length", None, LLMOutputError),
        ("content_filter", None, LLMOutputError),
        ("stop", "I cannot assist with that.", LLMOutputError),
    ],
    ids=["length", "content_filter", "refusal"],
)
def test_reply_a_correction_cannot_fix_fails_at_once_with_its_usage(
    harness: OpenAIHarness,
    finish_reason: str,
    refusal: str | None,
    error: type[LLMError],
) -> None:
    usage = {"prompt_tokens": 100, "completion_tokens": 256, "total_tokens": 356}
    content = None if refusal else '{"severity": "hi'
    harness.reply_body(
        _completion(content, usage=usage, finish_reason=finish_reason, refusal=refusal)
    )

    with pytest.raises(error) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert len(harness.requests) == 1  # no paid retry that would end the same way
    assert caught.value.usage == TokenUsage(input_tokens=100, output_tokens=256)
    assert not isinstance(caught.value, TransientJobError)


def test_cut_off_retry_keeps_the_first_attempts_usage(harness: OpenAIHarness) -> None:
    harness.reply(INVALID, input_tokens=100, output_tokens=10)
    usage = {"prompt_tokens": 130, "completion_tokens": 256, "total_tokens": 386}
    harness.reply_body(_completion('{"sev', usage=usage, finish_reason="length"))

    with pytest.raises(LLMOutputError) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert caught.value.usage == TokenUsage(input_tokens=230, output_tokens=266)


def test_empty_reply_is_retried_without_an_empty_assistant_turn(
    harness: OpenAIHarness,
) -> None:
    harness.reply_body(_completion(""))
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
        httpx2.Response(200, json={"choices": []}),
        httpx2.Response(200, json={"choices": None}),
        httpx2.Response(200, json={"choices": [{"message": None, "finish_reason": "stop"}]}),
        httpx2.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"role": "assistant", "content": None, "refusal": None},
                        "finish_reason": "stop",
                    }
                ]
            },
        ),
        httpx2.Response(200, content=b"{not json", headers={"content-type": "application/json"}),
    ],
    ids=[
        "html",
        "other-json",
        "list",
        "empty-choices",
        "null-choices",
        "null-message",
        "null-content",
        "corrupt-json",
    ],
)
def test_unreadable_success_response_is_transient(
    harness: OpenAIHarness, response: httpx2.Response
) -> None:
    harness.respond(response)

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)


def test_rejected_request_is_logged_by_type_without_the_api_message(
    harness: OpenAIHarness,
) -> None:
    for _ in range(3):
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
    provider = OpenAICompatProvider(_config())

    assert provider._client.timeout == REQUEST_TIMEOUT_SECONDS
    assert provider._client.max_retries == MAX_RETRIES


def test_request_with_time_to_spare_gets_the_full_request_timeout(
    harness: OpenAIHarness,
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
        return httpx2.Response(200, json=_completion(VALID))

    return answer


def test_slow_response_is_abandoned_at_the_call_deadline(
    harness: OpenAIHarness, release: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Per-read timeouts can't catch a server that trickles bytes; the call deadline does.
    monkeypatch.setattr(openai_compat_provider, "CALL_DEADLINE_SECONDS", 0.2)
    harness.respond_slowly(_stalled(release))
    started = time.monotonic()

    with pytest.raises(LLMUnavailable) as caught:
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert isinstance(caught.value, TransientJobError)


def test_fallback_gets_only_the_time_left(
    harness: OpenAIHarness, release: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(openai_compat_provider, "CALL_DEADLINE_SECONDS", 1.0)

    def slow_400() -> httpx2.Response:
        time.sleep(0.5)
        return _error(400, "invalid_request_error", "json_schema is not supported")

    harness.respond_slowly(slow_400)
    harness.respond_slowly(_stalled(release))
    started = time.monotonic()

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert len(harness.requests) == 2
    assert harness.read_timeout(1) < 0.6  # what was left, not a fresh 60 s


def test_corrective_retry_gets_only_the_time_left(
    harness: OpenAIHarness, release: threading.Event, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(openai_compat_provider, "CALL_DEADLINE_SECONDS", 1.0)

    def slow_invalid() -> httpx2.Response:
        time.sleep(0.5)
        return httpx2.Response(200, json=_completion(INVALID))

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
    harness: OpenAIHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, CALL_DEADLINE_SECONDS + 1])  # the deadline is set, then time is up
    monkeypatch.setattr(openai_compat_provider, "monotonic", lambda: next(clock))

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert harness.requests == []


def test_rate_limit_with_a_long_retry_after_fails_at_once(harness: OpenAIHarness) -> None:
    # The SDK would sleep for any Retry-After if it retried; with retries off it doesn't wait.
    response = _error(429, "rate_limit_error", "Rate limited")
    response.headers["retry-after"] = "600"
    harness.respond(response)
    started = time.monotonic()

    with pytest.raises(LLMUnavailable):
        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert time.monotonic() - started < 5
    assert len(harness.requests) == 1
