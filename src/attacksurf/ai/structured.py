"""Schema validation shared by every provider, so all of them retry the same way (ADR 0019)."""

import re
import time
from collections.abc import Callable, Sequence

from pydantic import BaseModel, ValidationError

from attacksurf.domain.llm import (
    Completion,
    LLMError,
    LLMOutputError,
    LLMResult,
    Message,
    TokenUsage,
)

MAX_ATTEMPTS = 2  # the first try plus one retry with a correction
_MAX_LISTED_ERRORS = 5
# Models in JSON mode or plain-text fallback sometimes wrap their JSON in a Markdown fence.
_FENCE = re.compile(r"\A```(?:json)?\s*\n(.*)\n```\Z", re.DOTALL)

Send = Callable[[Sequence[Message]], Completion]


def complete_structured[T: BaseModel](
    send: Send, messages: Sequence[Message], schema: type[T]
) -> LLMResult[T]:
    """Call `send` until its reply validates against `schema`, at most `MAX_ATTEMPTS` times.

    `send` is one provider API call for the given conversation. A retry appends the invalid
    reply and a correction naming what was wrong.
    """
    started = time.monotonic()
    conversation = list(messages)
    usage = TokenUsage()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            reply = send(conversation)
        except LLMError as exc:
            exc.usage = usage + exc.usage  # earlier attempts' tokens were spent all the same
            raise
        usage += reply.usage
        try:
            parsed = schema.model_validate_json(_unfenced(reply.text))
        except ValidationError as exc:
            # Anthropic rejects empty assistant text blocks, so an empty reply is left out.
            if reply.text.strip():
                conversation.append(Message("assistant", reply.text))
            conversation.append(Message("user", _correction(exc)))
            continue
        return LLMResult(
            parsed=parsed,
            text=reply.text,
            usage=usage,
            latency_ms=round((time.monotonic() - started) * 1000),
            attempts=attempt,
        )
    raise LLMOutputError("The AI provider's reply did not match the expected format.", usage=usage)


def _unfenced(text: str) -> str:
    stripped = text.strip()
    match = _FENCE.match(stripped)
    return match.group(1) if match else stripped


def _correction(exc: ValidationError) -> str:
    # Field paths and messages only: echoing the input back adds tokens and nothing else.
    problems = [
        f"{'.'.join(str(part) for part in error['loc']) or 'reply'}: {error['msg']}"
        for error in exc.errors(include_url=False, include_input=False)[:_MAX_LISTED_ERRORS]
    ]
    return (
        "Your reply did not match the required JSON schema: "
        + "; ".join(problems)
        + ". Reply again with only the corrected JSON object."
    )
