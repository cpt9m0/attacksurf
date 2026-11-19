"""Database-level guarantees of org AI settings (#24)."""

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.domain.llm import ProviderKind
from attacksurf.infra.db.models import Org, OrgSettings
from attacksurf.infra.db.tenancy import get_scoped, scoped


def _org(session: Session, name: str) -> Org:
    org = Org(name=name, slug=name)
    session.add(org)
    session.flush()
    return org


@pytest.fixture
def acme(db_session: Session) -> Org:
    return _org(db_session, "acme")


def test_org_settings_persists_defaults_and_columns(db_session: Session, acme: Org) -> None:
    row = OrgSettings(
        org_id=acme.id,
        model="claude-sonnet-4-5",
        base_url="https://api.example.com/v1",
        api_key_ciphertext=b"cipher-bytes",
        api_key_last4="1234",
        monthly_token_budget=5_000_000_000,  # past 32-bit int: requires BigInteger
    )
    db_session.add(row)
    db_session.flush()
    db_session.expire_all()

    stored = db_session.get_one(OrgSettings, row.id)

    assert stored.ai_enabled is True
    assert stored.provider is ProviderKind.ANTHROPIC
    assert stored.model == "claude-sonnet-4-5"
    assert stored.base_url == "https://api.example.com/v1"
    assert stored.api_key_ciphertext == b"cipher-bytes"
    assert stored.api_key_last4 == "1234"
    assert stored.monthly_token_budget == 5_000_000_000


def test_one_settings_row_per_org(db_session: Session, acme: Org) -> None:
    db_session.add(OrgSettings(org_id=acme.id))
    db_session.flush()
    db_session.add(OrgSettings(org_id=acme.id))

    with pytest.raises(IntegrityError):
        db_session.flush()


@pytest.mark.parametrize(
    "overrides",
    [
        {"monthly_token_budget": -1},
        {"api_key_ciphertext": b"cipher", "api_key_last4": None},
        {"api_key_ciphertext": None, "api_key_last4": "1234"},
    ],
)
def test_invalid_org_settings_rows_are_rejected(
    db_session: Session, acme: Org, overrides: dict[str, object]
) -> None:
    db_session.add(OrgSettings(org_id=acme.id, **overrides))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_unknown_provider_is_rejected_by_database(db_session: Session, acme: Org) -> None:
    row = OrgSettings(org_id=acme.id)
    db_session.add(row)
    db_session.flush()

    with pytest.raises(IntegrityError):
        db_session.execute(
            text("UPDATE org_settings SET provider = 'bedrock' WHERE id = :id"),
            {"id": row.id},
        )


def test_org_settings_are_tenant_scoped_and_cascade_on_org_delete(
    db_session: Session, acme: Org
) -> None:
    globex = _org(db_session, "globex")
    mine = OrgSettings(org_id=acme.id, model="acme-model")
    theirs = OrgSettings(org_id=globex.id, model="globex-model")
    db_session.add_all([mine, theirs])
    db_session.flush()

    assert db_session.scalars(scoped(OrgSettings, acme.id)).all() == [mine]
    assert get_scoped(db_session, OrgSettings, theirs.id, acme.id) is None

    db_session.execute(delete(Org).where(Org.id == acme.id))
    assert db_session.scalars(select(OrgSettings)).all() == [theirs]
