import pickle

from attacksurf.domain.jobs import JobError, TransientJobError
from attacksurf.domain.llm import (
    LLMAuthError,
    LLMError,
    LLMOutputError,
    LLMRequestError,
    LLMUnavailable,
    TokenUsage,
)


def test_token_usage_adds_counts() -> None:
    total = TokenUsage(input_tokens=100, output_tokens=10) + TokenUsage(50, 5)

    assert total == TokenUsage(input_tokens=150, output_tokens=15)


def test_token_usage_sum_is_unreported_if_either_side_is() -> None:
    total = TokenUsage(100, 10) + TokenUsage(reported=False)

    assert not total.reported


def test_empty_token_usage_adds_nothing() -> None:
    assert TokenUsage() + TokenUsage(7, 3) == TokenUsage(7, 3)


def test_llm_errors_are_job_errors_so_their_messages_reach_the_job() -> None:
    for error in (LLMAuthError, LLMRequestError, LLMUnavailable):
        assert issubclass(error, LLMError)
        assert issubclass(error, JobError)


def test_only_unavailable_is_retried() -> None:
    assert issubclass(LLMUnavailable, TransientJobError)
    assert not issubclass(LLMAuthError, TransientJobError)
    assert not issubclass(LLMRequestError, TransientJobError)
    assert not issubclass(LLMOutputError, TransientJobError)


def test_every_llm_error_carries_usage_defaulting_to_none_spent() -> None:
    for error in (LLMAuthError, LLMRequestError, LLMUnavailable, LLMOutputError):
        assert error("failed").usage == TokenUsage()


def test_llm_error_survives_pickling_with_its_message() -> None:
    # Celery rebuilds stored exceptions as cls(*args); a required usage argument broke that.
    restored = pickle.loads(pickle.dumps(LLMOutputError("bad output", usage=TokenUsage(3, 1))))  # noqa: S301

    assert type(restored) is LLMOutputError
    assert str(restored) == "bad output"


def test_output_error_keeps_the_usage_it_cost() -> None:
    error = LLMOutputError("bad output", usage=TokenUsage(30, 4))

    assert error.usage == TokenUsage(30, 4)
    assert str(error) == "bad output"
