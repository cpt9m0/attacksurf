"""Cost estimates for LLM calls: list prices only, and no estimate when it would be a guess."""

from decimal import Decimal

from attacksurf.ai.pricing import PRICES, estimate_cost
from attacksurf.domain.llm import TokenUsage


def test_estimate_cost_prices_input_and_output_tokens_separately() -> None:
    usage = TokenUsage(input_tokens=1_000_000, output_tokens=1_000_000)

    assert estimate_cost("muse-spark-1.3", usage) == Decimal("5.500000")


def test_estimate_cost_rounds_to_millionths_of_a_dollar() -> None:
    # 111 x $0.10/M + 564 x $0.20/M = $0.0001239: a real one-sentence reply from the live test.
    usage = TokenUsage(input_tokens=111, output_tokens=564)

    assert estimate_cost("muse-spark-1.3-contributor", usage) == Decimal("0.000124")


def test_estimate_cost_of_no_tokens_is_zero() -> None:
    assert estimate_cost("muse-spark-1.3", TokenUsage()) == Decimal("0.000000")


def test_estimate_cost_is_unknown_for_a_model_without_a_price() -> None:
    usage = TokenUsage(input_tokens=100, output_tokens=100)

    assert estimate_cost("some-self-hosted-model", usage) is None


def test_estimate_cost_is_unknown_when_the_backend_reported_no_usage() -> None:
    # Zero counts that weren't reported aren't a free call.
    usage = TokenUsage(reported=False)

    assert estimate_cost("muse-spark-1.3", usage) is None


def test_model_names_match_exactly() -> None:
    usage = TokenUsage(input_tokens=100, output_tokens=100)

    assert estimate_cost("MUSE-SPARK-1.3", usage) is None


def test_listed_prices_are_not_negative() -> None:
    for price in PRICES.values():
        assert price.input_per_million >= 0
        assert price.output_per_million >= 0
