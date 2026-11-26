"""The scale test's time limit (#30): 90 s unless a slower machine asks for longer."""

import pytest

from tests.helpers import scale_budget_seconds


@pytest.mark.parametrize("environ", [{}, {"SCALE_BUDGET_SECONDS": ""}], ids=["unset", "empty"])
def test_scale_budget_is_90_seconds_unless_set(environ: dict[str, str]) -> None:
    assert scale_budget_seconds(environ) == 90.0


@pytest.mark.parametrize(("raw", "seconds"), [("90", 90.0), ("150", 150.0), ("600", 600.0)])
def test_scale_budget_can_be_made_longer(raw: str, seconds: float) -> None:
    assert scale_budget_seconds({"SCALE_BUDGET_SECONDS": raw}) == seconds


@pytest.mark.parametrize("raw", ["89", "0", "-150", "601", "inf", "nan", "150s", "off"])
def test_scale_budget_refuses_a_shorter_endless_or_unreadable_limit(raw: str) -> None:
    with pytest.raises(ValueError, match="SCALE_BUDGET_SECONDS must be a number from 90 to 600"):
        scale_budget_seconds({"SCALE_BUDGET_SECONDS": raw})
