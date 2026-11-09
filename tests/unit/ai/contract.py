"""Behavior every `LLMProvider` must show, whatever API it speaks.

A provider's tests subclass `ProviderContract` and override the `harness` fixture with one that
stubs that provider's HTTP layer (recorded responses, never the network) and turns what it
sent into a `SentRequest`. Stubbed failures stand for the final answer after the SDK's own
retries, so harnesses build their SDK client with retries off. Separately, each adapter's tests
assert that in production it builds its client with `ai/limits.py`'s timeout and retry count,
and that a call stops at `CALL_DEADLINE_SECONDS` (slow response; a large `Retry-After` fails
at once).
"""

from dataclasses import dataclass
from typing import Any, Literal, Protocol

import pytest
from pydantic import BaseModel

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.llm import (
    LLMAuthError,
    LLMOutputError,
    LLMProvider,
    LLMRequestError,
    LLMUnavailable,
    Message,
    TokenUsage,
)

# Harnesses build their provider with this key, so tests can check it never leaks.
API_KEY = "sk-contract-test-0123456789"


class Verdict(BaseModel):
    """The schema every contract test uses; the live tests (#23) round-trip it on both APIs."""

    severity: Literal["low", "medium", "high"]
    reason: str


VALID = '{"severity": "high", "reason": "CNAME points at an unclaimed bucket"}'
INVALID = '{"severity": "catastrophic"}'
CONVERSATION = (
    Message("system", "You judge findings."),
    Message("user", "Judge this finding."),
)


@dataclass(frozen=True)
class SentRequest:
    """What a provider sent, normalized across APIs."""

    system: str | None
    messages: tuple[tuple[str, str], ...]  # (role, content), system prompt excluded
    max_tokens: int
    schema: dict[str, Any] | None  # the JSON schema the API was asked to follow


class ProviderHarness(Protocol):
    provider: LLMProvider

    def reply(self, text: str, *, input_tokens: int = 10, output_tokens: int = 5) -> None:
        """Queue a successful API response carrying `text`."""
        ...

    def fail(self, status: int | None) -> None:
        """Queue an HTTP error with this status (None: the connection failed or timed out)."""
        ...

    @property
    def sent(self) -> list[SentRequest]: ...


class ProviderContract:
    @pytest.fixture
    def harness(self) -> ProviderHarness:
        raise NotImplementedError("each provider's test class supplies its own harness")

    def test_valid_reply_is_parsed_into_the_schema(self, harness: ProviderHarness) -> None:
        harness.reply(VALID)

        result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert result.parsed == Verdict.model_validate_json(VALID)
        assert result.text == VALID
        assert result.attempts == 1

    def test_reported_usage_is_returned(self, harness: ProviderHarness) -> None:
        harness.reply(VALID, input_tokens=120, output_tokens=40)

        result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert result.usage == TokenUsage(input_tokens=120, output_tokens=40)

    def test_system_message_is_sent_as_the_system_prompt(self, harness: ProviderHarness) -> None:
        harness.reply(VALID)

        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert harness.sent[0].system == "You judge findings."
        assert harness.sent[0].messages == (("user", "Judge this finding."),)

    def test_schema_is_requested_from_the_api(self, harness: ProviderHarness) -> None:
        harness.reply(VALID)

        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        schema = harness.sent[0].schema
        assert schema is not None
        assert set(schema["properties"]) == {"severity", "reason"}

    def test_max_tokens_is_sent(self, harness: ProviderHarness) -> None:
        harness.reply(VALID)

        harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=321)

        assert harness.sent[0].max_tokens == 321

    def test_invalid_reply_is_retried_once_with_a_correction(
        self, harness: ProviderHarness
    ) -> None:
        harness.reply(INVALID)
        harness.reply(VALID)

        result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert result.attempts == 2
        retry = harness.sent[1].messages
        assert retry[:2] == (("user", "Judge this finding."), ("assistant", INVALID))
        assert retry[2][0] == "user"
        assert "severity" in retry[2][1]

    def test_usage_is_summed_across_attempts(self, harness: ProviderHarness) -> None:
        harness.reply(INVALID, input_tokens=100, output_tokens=10)
        harness.reply(VALID, input_tokens=130, output_tokens=20)

        result = harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert result.usage == TokenUsage(input_tokens=230, output_tokens=30)

    def test_second_invalid_reply_raises_output_error_with_usage(
        self, harness: ProviderHarness
    ) -> None:
        harness.reply(INVALID, input_tokens=100, output_tokens=10)
        harness.reply(INVALID, input_tokens=130, output_tokens=10)

        with pytest.raises(LLMOutputError) as caught:
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert caught.value.usage == TokenUsage(input_tokens=230, output_tokens=20)
        assert len(harness.sent) == 2

    def test_failed_retry_keeps_the_usage_already_spent(self, harness: ProviderHarness) -> None:
        harness.reply(INVALID, input_tokens=100, output_tokens=10)
        harness.fail(None)

        with pytest.raises(LLMUnavailable) as caught:
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert caught.value.usage == TokenUsage(input_tokens=100, output_tokens=10)

    @pytest.mark.parametrize("status", [None, 408, 429, 500, 503])
    def test_busy_or_unreachable_provider_is_transient(
        self, harness: ProviderHarness, status: int | None
    ) -> None:
        harness.fail(status)

        with pytest.raises(LLMUnavailable) as caught:
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert isinstance(caught.value, TransientJobError)

    @pytest.mark.parametrize("status", [401, 403])
    def test_rejected_key_raises_auth_error(self, harness: ProviderHarness, status: int) -> None:
        harness.fail(status)

        with pytest.raises(LLMAuthError):
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    @pytest.mark.parametrize("status", [400, 404, 422])
    def test_rejected_request_raises_request_error(
        self, harness: ProviderHarness, status: int
    ) -> None:
        harness.fail(status)

        with pytest.raises(LLMRequestError):
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

    @pytest.mark.parametrize("status", [None, 400, 401, 429, 500])
    def test_error_messages_never_contain_the_api_key(
        self, harness: ProviderHarness, status: int | None
    ) -> None:
        harness.fail(status)

        with pytest.raises(Exception) as caught:  # noqa: PT011 (any error: none may leak)
            harness.provider.complete(CONVERSATION, schema=Verdict, max_tokens=256)

        assert API_KEY not in str(caught.value)
        assert API_KEY not in repr(caught.value)
