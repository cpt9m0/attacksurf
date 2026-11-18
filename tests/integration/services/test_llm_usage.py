"""Recording what each LLM call spent, successful or not (#23)."""

from decimal import Decimal

import pytest
from pydantic import BaseModel, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.llm import (
    KeySource,
    LLMConfig,
    LLMOutputError,
    LLMResult,
    LLMUnavailable,
    ProviderKind,
    TokenUsage,
)
from attacksurf.infra.db.models import LLMUsage, Org
from attacksurf.services.llm_usage import record_llm_usage

API_KEY = "test-key-not-real"


class Verdict(BaseModel):
    reachable: bool


def _config(model: str = "muse-spark-1.3", source: KeySource = KeySource.INSTANCE) -> LLMConfig:
    return LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model=model,
        api_key=SecretStr(API_KEY),
        source=source,
        base_url=SecretStr("https://api.meta.ai"),
    )


def _result(usage: TokenUsage) -> LLMResult[Verdict]:
    return LLMResult(
        parsed=Verdict(reachable=True),
        text='{"reachable": true}',
        usage=usage,
        latency_ms=4600,
        attempts=1,
    )


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


def _recorded(session: Session) -> LLMUsage:
    session.flush()
    session.expire_all()
    return session.scalars(select(LLMUsage)).one()


def test_successful_call_records_its_tokens_cost_and_latency(db_session: Session, org: Org) -> None:
    usage = TokenUsage(input_tokens=1_000, output_tokens=2_000)

    record_llm_usage(db_session, org.id, _config(), purpose="triage", outcome=_result(usage))

    row = _recorded(db_session)
    assert (row.org_id, row.provider, row.model, row.purpose) == (
        org.id,
        ProviderKind.ANTHROPIC,
        "muse-spark-1.3",
        "triage",
    )
    assert (row.input_tokens, row.output_tokens, row.usage_reported) == (1_000, 2_000, True)
    assert row.estimated_cost_usd == Decimal("0.009750")  # 1k x $1.25/M + 2k x $4.25/M
    assert (row.latency_ms, row.success, row.error_type) == (4600, True, None)


def test_failed_call_records_the_tokens_spent_before_it_failed(
    db_session: Session, org: Org
) -> None:
    # An invalid reply, then a timeout on the retry: the first attempt's tokens were still paid.
    error = LLMUnavailable("The AI provider took too long to answer.", usage=TokenUsage(100, 200))

    record_llm_usage(db_session, org.id, _config(), purpose="triage", outcome=error)

    row = _recorded(db_session)
    assert (row.input_tokens, row.output_tokens) == (100, 200)
    assert row.estimated_cost_usd == Decimal("0.000975")
    assert (row.success, row.error_type, row.latency_ms) == (False, "LLMUnavailable", None)


def test_failed_call_stores_the_error_type_not_its_message(db_session: Session, org: Org) -> None:
    error = LLMOutputError("The AI reply was cut off at its token limit.")

    record_llm_usage(db_session, org.id, _config(), purpose="triage", outcome=error)

    row = _recorded(db_session)
    assert row.error_type == "LLMOutputError"
    assert "cut off" not in repr(vars(row))


def test_records_whose_key_paid_for_the_call(db_session: Session, org: Org) -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=10)

    record_llm_usage(
        db_session, org.id, _config(source=KeySource.ORG), purpose="triage", outcome=_result(usage)
    )

    assert _recorded(db_session).key_source == KeySource.ORG


def test_unknown_model_records_tokens_without_a_cost(db_session: Session, org: Org) -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=10)

    record_llm_usage(
        db_session, org.id, _config(model="local-llama"), purpose="triage", outcome=_result(usage)
    )

    row = _recorded(db_session)
    assert (row.input_tokens, row.estimated_cost_usd) == (10, None)


def test_unreported_usage_is_recorded_as_unknown_not_free(db_session: Session, org: Org) -> None:
    record_llm_usage(
        db_session, org.id, _config(), purpose="triage", outcome=_result(TokenUsage(reported=False))
    )

    row = _recorded(db_session)
    assert (row.usage_reported, row.estimated_cost_usd) == (False, None)


def test_usage_row_never_holds_the_key_or_base_url(db_session: Session, org: Org) -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=10)

    record_llm_usage(db_session, org.id, _config(), purpose="triage", outcome=_result(usage))

    stored = repr(vars(_recorded(db_session)))
    assert API_KEY not in stored
    assert "api.meta.ai" not in stored


def test_record_llm_usage_does_not_commit(db_session: Session, org: Org) -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=10)

    row = record_llm_usage(db_session, org.id, _config(), purpose="triage", outcome=_result(usage))
    db_session.rollback()

    assert row not in db_session
    assert db_session.scalars(select(LLMUsage)).all() == []
