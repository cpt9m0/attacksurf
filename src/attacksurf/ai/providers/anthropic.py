"""`LLMProvider` for the Anthropic Messages API, and Meta's endpoint in that format (ADR 0019)."""

import contextvars
import threading
from collections.abc import Callable, Sequence
from time import monotonic

import anthropic
import httpx2
import structlog
from anthropic.types import JSONOutputFormatParam, MessageParam
from anthropic.types import Message as APIMessage
from pydantic import BaseModel

from attacksurf.ai.errors import llm_error_for_status
from attacksurf.ai.limits import CALL_DEADLINE_SECONDS, MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.ai.structured import complete_structured
from attacksurf.domain.llm import (
    Completion,
    LLMConfig,
    LLMOutputError,
    LLMRequestError,
    LLMResult,
    LLMUnavailable,
    Message,
    TokenUsage,
)

log = structlog.get_logger(__name__)

# Always passed explicitly: with no base URL the SDK reads ANTHROPIC_BASE_URL, and an
# environment variable must not be able to send a key somewhere config didn't choose.
DEFAULT_BASE_URL = "https://api.anthropic.com"


class AnthropicProvider:
    """Sends each attempt as one Messages request asking for JSON in the schema's shape.

    `http_client` is for tests (a stubbed transport); production uses the SDK's own client.
    """

    def __init__(self, config: LLMConfig, *, http_client: httpx2.Client | None = None) -> None:
        self._model = config.model
        self._client = anthropic.Anthropic(
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
        # Native structured output, not a forced tool call: Meta accepts only tool_choice "auto".
        output_format: JSONOutputFormatParam = {
            "type": "json_schema",
            "schema": anthropic.transform_schema(schema),
        }
        # One deadline for every attempt, so the corrective retry gets only the time left.
        deadline = monotonic() + CALL_DEADLINE_SECONDS

        def send(conversation: Sequence[Message]) -> Completion:
            return self._send(conversation, output_format, max_tokens, deadline)

        return complete_structured(send, messages, schema)

    def _send(
        self,
        conversation: Sequence[Message],
        output_format: JSONOutputFormatParam,
        max_tokens: int,
        deadline: float,
    ) -> Completion:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _too_slow()
        system = "\n\n".join(m.content for m in conversation if m.role == "system")

        def request() -> APIMessage:
            return self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system or anthropic.omit,
                messages=[_turn(m) for m in conversation if m.role != "system"],
                output_config={"format": output_format},
                timeout=min(REQUEST_TIMEOUT_SECONDS, remaining),
            )

        try:
            response = _finish_within(remaining, request)
        # `from None`, and only the error type logged: the SDK's error carries the response
        # body, which can echo the prompt.
        except anthropic.APIStatusError as exc:
            log.warning(
                "llm request failed",
                status=exc.status_code,
                error_type=_error_type(exc.body),
                request_id=exc.request_id,
            )
            raise llm_error_for_status(exc.status_code) from None
        except anthropic.APIConnectionError as exc:
            log.warning("llm provider unreachable", error=type(exc).__name__)
            raise llm_error_for_status(None) from None
        return _completion(response)


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


def _completion(response: APIMessage) -> Completion:
    """The reply's text and usage, or the error a retry with a correction couldn't fix."""
    try:
        # Thinking blocks (always on for some models) come back alongside the reply; skip them.
        text = "".join(block.text for block in response.content if block.type == "text")
    except (AttributeError, TypeError):
        # The SDK doesn't validate a 2xx body: a proxy's HTML page or a malformed JSON reply
        # arrives as an object without the fields of a message.
        log.warning("llm reply unreadable", body_type=type(response).__name__)
        raise LLMUnavailable("The AI provider sent a reply that could not be read.") from None
    usage = _usage(response)
    stop_reason = getattr(response, "stop_reason", None)
    if stop_reason == "max_tokens":
        raise LLMOutputError("The AI reply was cut off at its token limit.", usage=usage)
    if stop_reason == "model_context_window_exceeded":
        raise LLMRequestError("The request is too long for the AI model.", usage=usage)
    if stop_reason == "refusal":
        raise LLMOutputError("The AI model declined to answer.", usage=usage)
    return Completion(text, usage)


def _usage(response: APIMessage) -> TokenUsage:
    # Read defensively for the same reason, and an Anthropic-format endpoint may omit usage.
    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    if not isinstance(input_tokens, int) or not isinstance(output_tokens, int):
        return TokenUsage(reported=False)
    # Cached input tokens are reported apart from `input_tokens`; all of them count to caps.
    cached = _count(getattr(usage, "cache_creation_input_tokens", None)) + _count(
        getattr(usage, "cache_read_input_tokens", None)
    )
    return TokenUsage(input_tokens=input_tokens + cached, output_tokens=output_tokens)


def _count(value: object) -> int:
    return value if isinstance(value, int) else 0


def _error_type(body: object) -> str | None:
    """The API's error type (e.g. `invalid_request_error`), never its message."""
    error = body.get("error") if isinstance(body, dict) else None
    kind = error.get("type") if isinstance(error, dict) else None
    return kind if isinstance(kind, str) else None


def _turn(message: Message) -> MessageParam:
    if message.role == "assistant":
        return {"role": "assistant", "content": message.content}
    return {"role": "user", "content": message.content}
