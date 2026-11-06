"""One HTTP-status-to-error mapping for every provider, so failures read the same everywhere."""

from http import HTTPStatus

from attacksurf.domain.llm import LLMAuthError, LLMError, LLMRequestError, LLMUnavailable

# Worth retrying later: timeouts, conflicts/locks, rate limits.
_TRANSIENT = frozenset(
    {HTTPStatus.REQUEST_TIMEOUT, HTTPStatus.CONFLICT, HTTPStatus.TOO_MANY_REQUESTS}
)
_AUTH = frozenset({HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN})


def llm_error_for_status(status: int | None) -> LLMError:
    """The error for a failed provider call; `status=None` means no HTTP response at all."""
    if status is None:
        return LLMUnavailable("The AI provider could not be reached. Try again later.")
    if status in _TRANSIENT or status >= HTTPStatus.INTERNAL_SERVER_ERROR:
        return LLMUnavailable("The AI provider is busy or unavailable. Try again later.")
    if status in _AUTH:
        return LLMAuthError("The AI provider rejected the API key.")
    return LLMRequestError(f"The AI provider rejected the request (HTTP {status}).")
