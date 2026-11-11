"""The LLM contract: what AI features need from a provider (ADR 0005, ADR 0019).

Implementations live in `ai/providers/` and are the only code that imports a provider SDK.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, SecretStr

from attacksurf.domain.jobs import JobError, TransientJobError

Role = Literal["system", "user", "assistant"]


class ProviderKind(StrEnum):
    """Which API a provider speaks. `openai_compat` covers any OpenAI-compatible base URL."""

    ANTHROPIC = "anthropic"
    OPENAI_COMPAT = "openai_compat"


class KeySource(StrEnum):
    """Whose key pays for a call: org keys are the org's own; instance-key use is capped (#24)."""

    ORG = "org"
    INSTANCE = "instance"


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class OrgLLMConfig:
    """An org's own provider settings (#24 loads them, with the key decrypted).

    `base_url` is org-supplied, so #24 must validate it through ScopeGuard (SSRF) when it is
    saved and when connecting; nothing here checks it.
    """

    provider: ProviderKind
    model: str
    api_key: SecretStr | None
    base_url: SecretStr | None = None


@dataclass(frozen=True)
class LLMConfig:
    """One complete provider config, taken from a single source so values never mix."""

    provider: ProviderKind
    model: str
    api_key: SecretStr
    source: KeySource
    base_url: SecretStr | None = None


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    # False when the backend sent no usage (some OpenAI-compatible ones don't): counts unknown.
    reported: bool = True

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            reported=self.reported and other.reported,
        )


@dataclass(frozen=True)
class Completion:
    """One raw reply from a provider, before schema validation."""

    text: str
    usage: TokenUsage


@dataclass(frozen=True)
class LLMResult[T: BaseModel]:
    parsed: T
    text: str  # the raw reply that was parsed
    usage: TokenUsage  # summed over all attempts: retries cost tokens too
    latency_ms: int
    attempts: int


class LLMProvider(Protocol):
    def complete[T: BaseModel](
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        max_tokens: int,
    ) -> LLMResult[T]:
        """Ask the configured model for a reply that validates against `schema`.

        No sampling settings: the model's defaults always apply (ADR 0019). Raises an
        `LLMError` subclass on failure.
        """
        ...


class LLMError(JobError):
    """A provider call failed. Messages are user-facing: never a key, prompt or model output.

    `usage` counts the tokens already spent on attempts before the failure, so they can still
    be recorded and counted against the instance-key cap (#24). It defaults to nothing spent,
    which also lets Celery rebuild the exception from its message alone.
    """

    def __init__(self, message: str, *, usage: TokenUsage | None = None) -> None:
        super().__init__(message)
        self.usage = usage or TokenUsage()


class LLMUnavailable(LLMError, TransientJobError):
    """Rate limited, overloaded, timed out or unreachable, after the SDK's own retries."""


class LLMAuthError(LLMError):
    """The provider rejected the API key."""


class LLMRequestError(LLMError):
    """The provider rejected the request itself (unknown model, bad parameter, too large)."""


class LLMOutputError(LLMError):
    """The model's reply still didn't match the schema after the retry."""
