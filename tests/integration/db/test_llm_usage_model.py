"""Database-level guarantees of LLM usage rows (#23)."""

from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.llm import KeySource, ProviderKind
from attacksurf.infra.db.models import LLMUsage, Org
from attacksurf.infra.db.tenancy import scoped


def _org(session: Session, name: str) -> Org:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    return org


def _usage(org: Org, **kw: object) -> LLMUsage:
    values: dict[str, object] = {
        "org_id": org.id,
        "provider": ProviderKind.ANTHROPIC,
        "model": "muse-spark-1.3",
        "purpose": "triage",
        "key_source": KeySource.INSTANCE,
        "input_tokens": 111,
        "output_tokens": 564,
        "usage_reported": True,
        "estimated_cost_usd": Decimal("0.002536"),
        "latency_ms": 4600,
        "success": True,
        "error_type": None,
    }
    return LLMUsage(**(values | kw))


@pytest.fixture
def acme(db_session: Session) -> Org:
    return _org(db_session, "acme")


def test_usage_row_keeps_its_cost_exactly(db_session: Session, acme: Org) -> None:
    db_session.add(_usage(acme))
    db_session.flush()
    db_session.expire_all()

    row = db_session.scalars(select(LLMUsage)).one()

    assert row.estimated_cost_usd == Decimal("0.002536")
    assert row.created_at is not None


def test_failed_call_row_has_no_cost_or_latency(db_session: Session, acme: Org) -> None:
    failed = _usage(
        acme, success=False, error_type="LLMUnavailable", estimated_cost_usd=None, latency_ms=None
    )
    db_session.add(failed)
    db_session.flush()
    db_session.expire_all()

    row = db_session.scalars(select(LLMUsage)).one()

    assert (row.success, row.error_type, row.estimated_cost_usd) == (False, "LLMUnavailable", None)


@pytest.mark.parametrize(
    ("field", "constraint"),
    [
        ("input_tokens", "input_tokens_not_negative"),
        ("output_tokens", "output_tokens_not_negative"),
        ("latency_ms", "latency_ms_not_negative"),
        ("estimated_cost_usd", "estimated_cost_not_negative"),
    ],
)
def test_usage_counts_cannot_be_negative(
    db_session: Session, acme: Org, field: str, constraint: str
) -> None:
    db_session.add(_usage(acme, **{field: -1}))

    with pytest.raises(IntegrityError, match=constraint):
        db_session.flush()


def test_successful_call_cannot_have_an_error_type(db_session: Session, acme: Org) -> None:
    db_session.add(_usage(acme, success=True, error_type="LLMUnavailable"))

    with pytest.raises(IntegrityError, match="error_type_matches"):
        db_session.flush()


def test_failed_call_must_name_its_error_type(db_session: Session, acme: Org) -> None:
    db_session.add(_usage(acme, success=False, error_type=None))

    with pytest.raises(IntegrityError, match="error_type_matches"):
        db_session.flush()


def test_scoped_usage_returns_only_the_orgs_own_rows(db_session: Session, acme: Org) -> None:
    globex = _org(db_session, "globex")
    db_session.add_all([_usage(acme, purpose="acme-call"), _usage(globex, purpose="globex-call")])
    db_session.flush()

    rows = db_session.scalars(scoped(LLMUsage, acme.id)).all()

    assert [row.purpose for row in rows] == ["acme-call"]


def test_deleting_an_org_deletes_its_usage(db_session: Session, acme: Org) -> None:
    db_session.add(_usage(acme))
    db_session.flush()

    db_session.delete(acme)
    db_session.flush()

    assert db_session.scalars(select(LLMUsage)).all() == []
