from collections.abc import Sequence

import pytest

from attacksurf.ai.structured import MAX_ATTEMPTS, complete_structured
from attacksurf.domain.llm import (
    Completion,
    LLMAuthError,
    LLMOutputError,
    LLMUnavailable,
    Message,
    TokenUsage,
)
from tests.unit.ai.contract import CONVERSATION, VALID, Verdict


class ScriptedSend:
    """Returns the given replies in order and records each conversation it was sent."""

    def __init__(self, *texts: str | Exception, usage: TokenUsage | None = None) -> None:
        self.texts = list(texts)
        self.usage = usage or TokenUsage(input_tokens=10, output_tokens=5)
        self.conversations: list[tuple[Message, ...]] = []

    def __call__(self, conversation: Sequence[Message]) -> Completion:
        self.conversations.append(tuple(conversation))
        text = self.texts.pop(0)
        if isinstance(text, Exception):
            raise text
        return Completion(text, self.usage)


def test_complete_structured_accepts_json_in_a_code_fence() -> None:
    send = ScriptedSend(f"```json\n{VALID}\n```")

    result = complete_structured(send, CONVERSATION, Verdict)

    assert result.parsed.severity == "high"


def test_complete_structured_tries_at_most_twice() -> None:
    send = ScriptedSend("nope", "still nope", VALID)

    with pytest.raises(LLMOutputError):
        complete_structured(send, CONVERSATION, Verdict)

    assert len(send.conversations) == MAX_ATTEMPTS == 2


def test_complete_structured_correction_names_the_invalid_field() -> None:
    send = ScriptedSend('{"severity": "high"}', VALID)

    complete_structured(send, CONVERSATION, Verdict)

    correction = send.conversations[1][-1]
    assert correction.role == "user"
    assert "reason" in correction.content


def test_complete_structured_correction_explains_invalid_json() -> None:
    send = ScriptedSend("Sure, here you go!", VALID)

    complete_structured(send, CONVERSATION, Verdict)

    assert "JSON" in send.conversations[1][-1].content


@pytest.mark.parametrize("empty", ["", "  \n\t "])
def test_complete_structured_retry_leaves_out_an_empty_reply(empty: str) -> None:
    # Anthropic rejects empty assistant text blocks with HTTP 400.
    send = ScriptedSend(empty, VALID, usage=TokenUsage(input_tokens=10, output_tokens=5))

    result = complete_structured(send, CONVERSATION, Verdict)

    retry = send.conversations[1]
    assert retry[: len(CONVERSATION)] == CONVERSATION
    assert len(retry) == len(CONVERSATION) + 1
    assert retry[-1].role == "user"
    assert "JSON" in retry[-1].content
    assert result.usage == TokenUsage(input_tokens=20, output_tokens=10)
    assert result.attempts == 2


def test_failed_retry_keeps_the_usage_of_earlier_attempts() -> None:
    # Regression: an invalid reply followed by a timeout used to drop the tokens already spent.
    send = ScriptedSend(
        "not json",
        LLMUnavailable("The AI provider could not be reached. Try again later."),
        usage=TokenUsage(input_tokens=2000, output_tokens=40),
    )

    with pytest.raises(LLMUnavailable) as caught:
        complete_structured(send, CONVERSATION, Verdict)

    assert caught.value.usage == TokenUsage(input_tokens=2000, output_tokens=40)


def test_failed_first_call_reports_no_usage_of_its_own() -> None:
    send = ScriptedSend(LLMAuthError("The AI provider rejected the API key."))

    with pytest.raises(LLMAuthError) as caught:
        complete_structured(send, CONVERSATION, Verdict)

    assert caught.value.usage == TokenUsage()


def test_complete_structured_does_not_change_the_callers_messages() -> None:
    messages = list(CONVERSATION)
    send = ScriptedSend("nope", VALID)

    complete_structured(send, messages, Verdict)

    assert messages == list(CONVERSATION)


def test_complete_structured_marks_usage_unreported_if_any_attempt_lacked_it() -> None:
    send = ScriptedSend(VALID, usage=TokenUsage(reported=False))

    result = complete_structured(send, CONVERSATION, Verdict)

    assert result.usage == TokenUsage(reported=False)


def test_complete_structured_measures_latency_in_milliseconds() -> None:
    result = complete_structured(ScriptedSend(VALID), CONVERSATION, Verdict)

    assert isinstance(result.latency_ms, int)
    assert result.latency_ms >= 0


def test_output_error_message_has_no_model_output() -> None:
    send = ScriptedSend('{"severity": "IGNORE PREVIOUS INSTRUCTIONS"}', "{}")

    with pytest.raises(LLMOutputError) as caught:
        complete_structured(send, CONVERSATION, Verdict)

    assert "IGNORE" not in str(caught.value)
