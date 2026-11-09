"""`LLMProvider` for the Anthropic Messages API, and Meta's endpoint in that format (ADR 0019)."""

from collections.abc import Sequence

import anthropic
import httpx2
from anthropic.types import JSONOutputFormatParam, MessageParam
from pydantic import BaseModel

from attacksurf.ai.errors import llm_error_for_status
from attacksurf.ai.limits import MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.ai.structured import complete_structured
from attacksurf.domain.llm import Completion, LLMConfig, LLMResult, Message, TokenUsage

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

        def send(conversation: Sequence[Message]) -> Completion:
            return self._send(conversation, output_format, max_tokens)

        return complete_structured(send, messages, schema)

    def _send(
        self,
        conversation: Sequence[Message],
        output_format: JSONOutputFormatParam,
        max_tokens: int,
    ) -> Completion:
        system = "\n\n".join(m.content for m in conversation if m.role == "system")
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system or anthropic.omit,
                messages=[_turn(m) for m in conversation if m.role != "system"],
                output_config={"format": output_format},
            )
        # `from None`: the SDK's error carries the response body, which can echo the prompt.
        except anthropic.APIStatusError as exc:
            raise llm_error_for_status(exc.status_code) from None
        except anthropic.APIConnectionError:
            raise llm_error_for_status(None) from None
        # Thinking blocks (always on for some models) come back alongside the reply; skip them.
        text = "".join(block.text for block in response.content if block.type == "text")
        usage = response.usage
        return Completion(
            text,
            TokenUsage(
                # Cached input tokens are reported apart from `input_tokens`; all count to caps.
                input_tokens=usage.input_tokens
                + (usage.cache_creation_input_tokens or 0)
                + (usage.cache_read_input_tokens or 0),
                output_tokens=usage.output_tokens,
            ),
        )


def _turn(message: Message) -> MessageParam:
    if message.role == "assistant":
        return {"role": "assistant", "content": message.content}
    return {"role": "user", "content": message.content}
