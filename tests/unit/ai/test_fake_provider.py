"""The fake provider passes the same contract as the real ones, so tests that use it are honest."""

import pytest

from attacksurf.ai.errors import llm_error_for_status
from attacksurf.domain.llm import Completion, TokenUsage
from tests.fakes import FakeLLMProvider
from tests.unit.ai.contract import CONVERSATION, ProviderContract, SentRequest, Verdict


class FakeHarness:
    def __init__(self) -> None:
        self.provider = FakeLLMProvider()

    def reply(self, text: str, *, input_tokens: int = 10, output_tokens: int = 5) -> None:
        self.provider.replies.append(Completion(text, TokenUsage(input_tokens, output_tokens)))

    def fail(self, status: int | None) -> None:
        self.provider.replies.append(llm_error_for_status(status))

    @property
    def sent(self) -> list[SentRequest]:
        return [
            SentRequest(
                system=next((m.content for m in call.messages if m.role == "system"), None),
                messages=tuple((m.role, m.content) for m in call.messages if m.role != "system"),
                max_tokens=call.max_tokens,
                schema=call.schema.model_json_schema(),
            )
            for call in self.provider.calls
        ]


class TestFakeProvider(ProviderContract):
    @pytest.fixture
    def harness(self) -> FakeHarness:
        return FakeHarness()


def test_fake_provider_accepts_plain_text_replies() -> None:
    provider = FakeLLMProvider('{"severity": "low", "reason": "ok"}')

    result = provider.complete(CONVERSATION, schema=Verdict, max_tokens=64)

    assert result.parsed == Verdict(severity="low", reason="ok")


def test_fake_provider_without_queued_replies_fails_loudly() -> None:
    provider = FakeLLMProvider()

    with pytest.raises(AssertionError, match="no reply queued"):
        provider.complete(CONVERSATION, schema=Verdict, max_tokens=64)
