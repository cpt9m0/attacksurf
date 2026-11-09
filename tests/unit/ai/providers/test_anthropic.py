"""The Anthropic adapter against a stubbed Messages API (never the network)."""

import json
from typing import Any

import httpx2
import pytest
from pydantic import SecretStr

from attacksurf.ai.limits import MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.ai.providers.anthropic import DEFAULT_BASE_URL, AnthropicProvider
from attacksurf.domain.llm import KeySource, LLMConfig, ProviderKind, TokenUsage
from tests.unit.ai.contract import (
    API_KEY,
    CONVERSATION,
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


def _message(content: list[dict[str, Any]], usage: dict[str, int]) -> dict[str, Any]:
    """A Messages API response body, in the shape the API documents."""
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": content,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": usage,
    }


class AnthropicHarness:
    def __init__(self, base_url: str | None = None) -> None:
        self._queue: list[dict[str, Any] | int | None] = []  # body, error status, or no answer
        self.requests: list[httpx2.Request] = []
        client = httpx2.Client(transport=httpx2.MockTransport(self._answer))
        self.provider = AnthropicProvider(_config(base_url), http_client=client)

    def _answer(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        queued = self._queue.pop(0)
        if queued is None:
            raise httpx2.ConnectError("connection refused", request=request)
        if isinstance(queued, int):
            error = {"type": "error", "error": {"type": "api_error", "message": "stubbed"}}
            return httpx2.Response(queued, json=error)
        return httpx2.Response(200, json=queued)

    def reply(self, text: str, *, input_tokens: int = 10, output_tokens: int = 5) -> None:
        usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
        self.reply_body(_message([{"type": "text", "text": text}], usage))

    def reply_body(self, body: dict[str, Any]) -> None:
        self._queue.append(body)

    def fail(self, status: int | None) -> None:
        self._queue.append(status)

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
    # API version 2026-10-21 rejects them with a 400 on every model (ADR 0019).
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


def test_only_text_blocks_make_up_the_reply(harness: AnthropicHarness) -> None:
    thinking = {"type": "thinking", "thinking": "", "signature": "sig"}
    usage = {"input_tokens": 10, "output_tokens": 5}
    harness.reply_body(_message([thinking, {"type": "text", "text": VALID}], usage))

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.text == VALID


def test_cached_input_tokens_count_as_input(harness: AnthropicHarness) -> None:
    usage = {
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_creation_input_tokens": 100,
        "cache_read_input_tokens": 1000,
    }
    harness.reply_body(_message([{"type": "text", "text": VALID}], usage))

    result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    assert result.usage == TokenUsage(input_tokens=1110, output_tokens=5)


def test_client_uses_the_shared_timeout_and_no_sdk_retries() -> None:
    provider = AnthropicProvider(_config())

    assert provider._client.timeout == REQUEST_TIMEOUT_SECONDS
    assert provider._client.max_retries == MAX_RETRIES
