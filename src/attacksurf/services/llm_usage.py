"""What each LLM call spent (#23): the data behind #24's instance-key cap and usage page."""

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.ai.pricing import estimate_cost
from attacksurf.domain.llm import KeySource, LLMConfig, LLMError, LLMResult, ProviderKind
from attacksurf.infra.db.models import LLMUsage
from attacksurf.infra.db.tenancy import scoped

_COST_ZERO = Decimal("0.000000")


@dataclass(frozen=True)
class UsageBreakdownRow:
    """One aggregated usage bucket for the settings usage table."""

    month: str
    purpose: str
    provider: ProviderKind
    model: str
    key_source: KeySource
    calls: int
    failed_calls: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost_usd: Decimal | None
    has_unreported_usage: bool
    has_unpriced_calls: bool


@dataclass(frozen=True)
class UsageSummary:
    """Monthly AI token and estimated cost breakdown for one organization."""

    months: int
    current_month: str
    current_month_tokens: int
    current_month_instance_tokens: int
    current_month_org_tokens: int
    current_month_cost_usd: Decimal | None
    total_tokens: int
    total_cost_usd: Decimal | None
    rows: tuple[UsageBreakdownRow, ...]


def utc_month_bounds(now: datetime | None = None) -> tuple[datetime, datetime]:
    """Start (inclusive) and end (exclusive) of the current UTC calendar month."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    start = datetime(current.year, current.month, 1, tzinfo=UTC)
    if current.month == 12:  # noqa: PLR2004
        end = datetime(current.year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(current.year, current.month + 1, 1, tzinfo=UTC)
    return start, end


def monthly_tokens_used(
    session: Session,
    org_id: UUID,
    *,
    key_source: KeySource,
    now: datetime | None = None,
) -> int:
    """Sum `input_tokens + output_tokens` for `org_id` and `key_source` in the current UTC month."""
    month_start, month_end = utc_month_bounds(now)
    total = func.coalesce(func.sum(LLMUsage.input_tokens + LLMUsage.output_tokens), 0)
    return int(
        session.scalar(
            scoped(LLMUsage, org_id)
            .where(
                LLMUsage.key_source == key_source,
                LLMUsage.created_at >= month_start,
                LLMUsage.created_at < month_end,
            )
            .with_only_columns(total)
        )
        or 0
    )


def get_usage_summary(
    session: Session,
    org_id: UUID,
    *,
    months: int = 6,
    now: datetime | None = None,
) -> UsageSummary:
    """Monthly token and estimated cost breakdown by month, purpose, provider, model and key."""
    if months < 1:
        raise ValueError("months must be at least 1")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    current_ym = current.year * 12 + (current.month - 1)
    start_year, start_month_zero = divmod(current_ym - (months - 1), 12)
    window_start = datetime(start_year, start_month_zero + 1, 1, tzinfo=UTC)
    _, window_end = utc_month_bounds(current)
    current_month = f"{current.year:04d}-{current.month:02d}"

    # Convert timestamptz to UTC before formatting so monthly buckets never depend on DB session TZ.
    month_expr = func.to_char(func.timezone("UTC", LLMUsage.created_at), "YYYY-MM")
    raw_rows = session.execute(
        scoped(LLMUsage, org_id)
        .with_only_columns(
            month_expr.label("month"),
            LLMUsage.purpose,
            LLMUsage.provider,
            LLMUsage.model,
            LLMUsage.key_source,
            func.count().label("calls"),
            func.count().filter(LLMUsage.success.is_(False)).label("failed_calls"),
            func.coalesce(func.sum(LLMUsage.input_tokens), 0).label("input_tokens"),
            func.coalesce(func.sum(LLMUsage.output_tokens), 0).label("output_tokens"),
            func.sum(LLMUsage.estimated_cost_usd).label("estimated_cost_usd"),
            func.bool_or(LLMUsage.usage_reported.is_(False)).label("has_unreported_usage"),
            func.bool_or(
                LLMUsage.usage_reported.is_(True) & LLMUsage.estimated_cost_usd.is_(None)
            ).label("has_unpriced_calls"),
        )
        .where(LLMUsage.created_at >= window_start, LLMUsage.created_at < window_end)
        .group_by(
            month_expr,
            LLMUsage.purpose,
            LLMUsage.provider,
            LLMUsage.model,
            LLMUsage.key_source,
        )
        .order_by(
            month_expr.desc(),
            LLMUsage.purpose.asc(),
            LLMUsage.provider.asc(),
            LLMUsage.model.asc(),
            LLMUsage.key_source.asc(),
        )
    ).all()

    rows = tuple(
        UsageBreakdownRow(
            month=row.month,
            purpose=row.purpose,
            provider=row.provider,
            model=row.model,
            key_source=row.key_source,
            calls=int(row.calls),
            failed_calls=int(row.failed_calls),
            input_tokens=int(row.input_tokens),
            output_tokens=int(row.output_tokens),
            total_tokens=int(row.input_tokens) + int(row.output_tokens),
            estimated_cost_usd=row.estimated_cost_usd,
            has_unreported_usage=bool(row.has_unreported_usage),
            has_unpriced_calls=bool(row.has_unpriced_calls),
        )
        for row in raw_rows
    )
    current_rows = [row for row in rows if row.month == current_month]
    return UsageSummary(
        months=months,
        current_month=current_month,
        current_month_tokens=sum(row.total_tokens for row in current_rows),
        current_month_instance_tokens=sum(
            row.total_tokens for row in current_rows if row.key_source is KeySource.INSTANCE
        ),
        current_month_org_tokens=sum(
            row.total_tokens for row in current_rows if row.key_source is KeySource.ORG
        ),
        current_month_cost_usd=_sum_costs(current_rows),
        total_tokens=sum(row.total_tokens for row in rows),
        total_cost_usd=_sum_costs(rows),
        rows=rows,
    )


def _sum_costs(rows: list[UsageBreakdownRow] | tuple[UsageBreakdownRow, ...]) -> Decimal | None:
    costs = [row.estimated_cost_usd for row in rows if row.estimated_cost_usd is not None]
    return sum(costs, _COST_ZERO) if costs else None


def record_llm_usage(
    session: Session,
    org_id: UUID,
    config: LLMConfig,
    *,
    purpose: str,
    outcome: LLMResult[Any] | LLMError,
) -> LLMUsage:
    """Add one usage row for a finished `complete()` call, successful or not. Doesn't commit.

    A failed call still records the tokens its earlier attempts spent (`LLMError.usage`). The
    caller must commit before re-raising the error: otherwise the row rolls back with the
    failing task, and the cap never counts what the call cost. Only the error's class is
    stored, never its message; the key and base URL are never stored.
    """
    failed = isinstance(outcome, LLMError)
    usage = outcome.usage
    row = LLMUsage(
        org_id=org_id,
        provider=config.provider,
        model=config.model,
        purpose=purpose,
        key_source=config.source,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        usage_reported=usage.reported,
        estimated_cost_usd=estimate_cost(config.model, usage),
        latency_ms=None if failed else outcome.latency_ms,
        success=not failed,
        error_type=type(outcome).__name__ if failed else None,
    )
    session.add(row)
    return row
