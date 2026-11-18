"""Estimated cost of an LLM call, recorded with its usage (#23) and shown to orgs (#24).

An estimate from list prices, not a bill: a model missing from `PRICES`, or a call whose backend
reported no token counts, gets no estimate instead of a guess. Prices are keyed by model name
alone, so a model served elsewhere at another price is estimated at its listed price.
Adapters count cached input tokens as input, so a call that hit the provider's cache is
estimated at the full input price, slightly high.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from types import MappingProxyType

from attacksurf.domain.llm import TokenUsage

TOKENS_PER_PRICE_UNIT = 1_000_000
# Millionths of a dollar: small enough to show a one-sentence reply on the cheapest model.
COST_QUANTUM = Decimal("0.000001")


@dataclass(frozen=True)
class ModelPrice:
    """US dollars per million tokens."""

    input_per_million: Decimal
    output_per_million: Decimal


# Meta's list prices, checked 2026-11-12. The contributor model is cheaper because Meta may
# train on its prompts and replies: fixtures only, never real scan data (ADR 0019).
PRICES: Mapping[str, ModelPrice] = MappingProxyType(
    {
        "muse-spark-1.3": ModelPrice(Decimal("1.25"), Decimal("4.25")),
        "muse-spark-1.3-contributor": ModelPrice(Decimal("0.10"), Decimal("0.20")),
    }
)


def estimate_cost(model: str, usage: TokenUsage) -> Decimal | None:
    """The call's cost in US dollars, or None when the model has no price or usage is unknown."""
    price = PRICES.get(model)
    if price is None or not usage.reported:
        return None
    cost = (
        usage.input_tokens * price.input_per_million
        + usage.output_tokens * price.output_per_million
    ) / TOKENS_PER_PRICE_UNIT
    return cost.quantize(COST_QUANTUM, rounding=ROUND_HALF_UP)
