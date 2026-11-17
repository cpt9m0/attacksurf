"""What each LLM call spent (#23): the data behind #24's instance-key cap and usage page."""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.ai.pricing import estimate_cost
from attacksurf.domain.llm import LLMConfig, LLMError, LLMResult
from attacksurf.infra.db.models import LLMUsage


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
