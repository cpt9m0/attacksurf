import pytest

from attacksurf.ai.errors import llm_error_for_status
from attacksurf.domain.llm import LLMAuthError, LLMError, LLMRequestError, LLMUnavailable


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, LLMUnavailable),
        (408, LLMUnavailable),
        (409, LLMUnavailable),
        (429, LLMUnavailable),
        (500, LLMUnavailable),
        (529, LLMUnavailable),
        (401, LLMAuthError),
        (403, LLMAuthError),
        (400, LLMRequestError),
        (404, LLMRequestError),
        (413, LLMRequestError),
        (422, LLMRequestError),
    ],
)
def test_llm_error_for_status_maps_http_status_to_error_type(
    status: int | None, expected: type[LLMError]
) -> None:
    assert type(llm_error_for_status(status)) is expected


def test_llm_error_for_status_message_is_user_facing() -> None:
    assert str(llm_error_for_status(404)) == "The AI provider rejected the request (HTTP 404)."
