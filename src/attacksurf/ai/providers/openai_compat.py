"""`LLMProvider` for the OpenAI Chat Completions API and compatible endpoints (ADR 0019)."""

import contextvars
import json
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from time import monotonic
from typing import Any

import httpx2
import openai
import structlog
from openai.lib._pydantic import to_strict_json_schema
from openai.types.chat import ChatCompletion, ChatCompletionMessageParam
from openai.types.chat.completion_create_params import ResponseFormat
from pydantic import BaseModel

from attacksurf.ai.errors import llm_error_for_status
from attacksurf.ai.limits import CALL_DEADLINE_SECONDS, MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.ai.structured import complete_structured
from attacksurf.domain.llm import (
    Completion,
    LLMConfig,
    LLMOutputError,
    LLMResult,
    LLMUnavailable,
    Message,
    TokenUsage,
)

log = structlog.get_logger(__name__)

# Always passed explicitly: with no base URL the SDK reads OPENAI_BASE_URL, and an
# environment variable must not be able to send a key somewhere config didn't choose.
DEFAULT_BASE_URL = "https://api.openai.com/v1"


@dataclass(frozen=True)
class _FormatStep:
    response_format: ResponseFormat | openai.Omit
    schema_in_system: bool


class OpenAICompatProvider:
    """Sends each attempt as a Chat Completions request asking for JSON in the schema's shape.

    Tries `json_schema` first; if the backend rejects that format with HTTP 400, falls back to
    `json_object` with the schema in the system prompt, and then to plain text with the schema
    in the system prompt. All three paths validate through `complete_structured`.

    `http_client` is for tests (a stubbed transport); production uses the SDK's own client.
    """

    def __init__(self, config: LLMConfig, *, http_client: httpx2.Client | None = None) -> None:
        self._model = config.model
        self._client = openai.OpenAI(
            api_key=config.api_key.get_secret_value(),
            base_url=config.base_url.get_secret_value() if config.base_url else DEFAULT_BASE_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_retries=MAX_RETRIES,
            http_client=http_client,
        )

    def complete[T: BaseModel](
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        max_tokens: int,
    ) -> LLMResult[T]:
        strict_schema = to_strict_json_schema(schema)
        steps = _format_steps(schema.__name__, strict_schema)
        # One deadline across every format fallback and the corrective retry.
        deadline = monotonic() + CALL_DEADLINE_SECONDS
        step_index = 0
        format_accepted = False

        def send(conversation: Sequence[Message]) -> Completion:
            nonlocal step_index, format_accepted
            while True:
                step = steps[step_index]
                can_fallback = not format_accepted and step_index + 1 < len(steps)
                try:
                    completion = self._send_once(
                        conversation,
                        step=step,
                        strict_schema=strict_schema,
                        max_tokens=max_tokens,
                        deadline=deadline,
                        can_fallback=can_fallback,
                    )
                except _FormatRejected:
                    step_index += 1
                    continue
                format_accepted = True
                return completion

        return complete_structured(send, messages, schema)

    def _send_once(
        self,
        conversation: Sequence[Message],
        *,
        step: _FormatStep,
        strict_schema: dict[str, Any],
        max_tokens: int,
        deadline: float,
        can_fallback: bool,
    ) -> Completion:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _too_slow()
        chat_messages = _build_messages(
            conversation, strict_schema if step.schema_in_system else None
        )

        # `max_completion_tokens` is the canonical cap on OpenAI (where reasoning models reject
        # `max_tokens`) and on Meta's `/v1/chat/completions` endpoint, counting reasoning too.
        def request() -> ChatCompletion:
            return self._client.chat.completions.create(
                model=self._model,
                max_completion_tokens=max_tokens,
                messages=chat_messages,
                response_format=step.response_format,
                timeout=min(REQUEST_TIMEOUT_SECONDS, remaining),
            )

        try:
            response = _finish_within(remaining, request)
        except openai.BadRequestError as exc:
            if can_fallback:
                raise _FormatRejected from None
            _log_status_error(exc)
            raise llm_error_for_status(exc.status_code) from None
        # `from None`, and only the error type logged: the SDK's error carries the response
        # body, which can echo the prompt.
        except openai.APIStatusError as exc:
            _log_status_error(exc)
            raise llm_error_for_status(exc.status_code) from None
        except openai.APIConnectionError as exc:
            log.warning("llm provider unreachable", error=type(exc).__name__)
            raise llm_error_for_status(None) from None
        except ValueError:
            # A 2xx response with a truncated or non-JSON body raises JSONDecodeError inside
            # the SDK before returning a ChatCompletion.
            log.warning("llm reply unreadable", body_type="invalid_json")
            raise LLMUnavailable("The AI provider sent a reply that could not be read.") from None
        return _completion(response)


class _FormatRejected(Exception):
    """The backend rejected the current `response_format` with HTTP 400; try the next step."""


def _format_steps(name: str, strict_schema: dict[str, Any]) -> tuple[_FormatStep, ...]:
    return (
        _FormatStep(
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": name,
                    "strict": True,
                    "schema": strict_schema,
                },
            },
            schema_in_system=False,
        ),
        _FormatStep(
            response_format={"type": "json_object"},
            schema_in_system=True,
        ),
        _FormatStep(
            response_format=openai.omit,
            schema_in_system=True,
        ),
    )


def _build_messages(
    conversation: Sequence[Message],
    system_schema: dict[str, Any] | None,
) -> list[ChatCompletionMessageParam]:
    system_parts = [m.content for m in conversation if m.role == "system"]
    if system_schema is not None:
        system_parts.append(
            f"Reply with only a JSON object matching this schema:\n{json.dumps(system_schema)}"
        )
    messages: list[ChatCompletionMessageParam] = []
    if system_parts:
        messages.append({"role": "system", "content": "\n\n".join(system_parts)})
    messages.extend(_turn(m) for m in conversation if m.role != "system")
    return messages


def _finish_within[R](seconds: float, call: Callable[[], R]) -> R:
    """`call()`'s result, or `LLMUnavailable` once `seconds` have passed.

    The SDK's timeouts bound each wait for data, not a whole response (a server can keep one
    alive by trickling bytes), so the request runs in its own thread and is abandoned at the
    deadline; its own timeouts end it later. Context variables are copied so its logs keep
    the job's context.
    """
    outcome: list[R] = []
    failure: list[BaseException] = []
    done = threading.Event()

    def run() -> None:
        try:
            outcome.append(call())
        except BaseException as exc:  # handed to the caller's thread below
            failure.append(exc)
        finally:
            done.set()

    context = contextvars.copy_context()
    threading.Thread(target=context.run, args=(run,), name="llm-request", daemon=True).start()
    if not done.wait(seconds):
        raise _too_slow()
    if failure:
        raise failure[0]
    return outcome[0]


def _too_slow() -> LLMUnavailable:
    log.warning("llm call deadline exceeded", deadline_seconds=CALL_DEADLINE_SECONDS)
    return LLMUnavailable("The AI provider took too long to answer. Try again later.")


def _completion(response: ChatCompletion) -> Completion:
    """The reply's text and usage, or the error a retry with a correction couldn't fix."""
    try:
        choice = response.choices[0]
        message = choice.message
        finish_reason = choice.finish_reason
        refusal = message.refusal
        content = message.content
    except (AttributeError, IndexError, TypeError):
        # The SDK doesn't validate a 2xx body: a proxy's HTML page or a malformed JSON reply
        # arrives as an object without the fields of a completion.
        log.warning("llm reply unreadable", body_type=type(response).__name__)
        raise LLMUnavailable("The AI provider sent a reply that could not be read.") from None
    usage = _usage(response)
    if finish_reason == "length":
        raise LLMOutputError("The AI reply was cut off at its token limit.", usage=usage)
    if finish_reason == "content_filter" or (isinstance(refusal, str) and refusal):
        raise LLMOutputError("The AI model declined to answer.", usage=usage)
    if not isinstance(content, str):
        log.warning("llm reply unreadable", body_type=type(response).__name__)
        raise LLMUnavailable("The AI provider sent a reply that could not be read.")
    return Completion(content, usage)


def _usage(response: ChatCompletion) -> TokenUsage:
    # Read defensively for the same reason, and an OpenAI-compatible endpoint may omit usage.
    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "prompt_tokens", None)
    output_tokens = getattr(usage, "completion_tokens", None)
    if not isinstance(input_tokens, int) or not isinstance(output_tokens, int):
        return TokenUsage(reported=False)
    return TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)


def _log_status_error(exc: openai.APIStatusError) -> None:
    # Only the error type is logged, never `exc.message` or `exc.body`.
    log.warning(
        "llm request failed",
        status=exc.status_code,
        error_type=exc.type if isinstance(exc.type, str) else None,
        request_id=exc.request_id,
    )


def _turn(message: Message) -> ChatCompletionMessageParam:
    if message.role == "assistant":
        return {"role": "assistant", "content": message.content}
    return {"role": "user", "content": message.content}
