"""Finding status decisions: transitions, comments, audit trail and bulk limits."""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import (
    MAX_STATUS_COMMENT,
    FindingError,
    FindingNotFound,
    FindingStatus,
    InvalidFindingTransition,
)
from attacksurf.infra.db.models import Asset, AuditLog, Org, User
from attacksurf.services import findings as findings_service
from attacksurf.services.assets import record_asset
from tests.integration.factories import T0, make_finding, make_org


@pytest.fixture
def acme(db_session: Session) -> tuple[Org, Asset]:
    org = make_org(db_session)
    root = record_asset(
        db_session, org.id, AssetType.DOMAIN, "example.com", source=AssetSource.USER
    )
    return org, root


def _actor_id(session: Session) -> UUID:
    user = User(email=f"{uuid4().hex}@example.com", password_hash="x")
    session.add(user)
    session.flush()
    return user.id


def _audit_rows(session: Session, finding_id: object) -> list[AuditLog]:
    return list(
        session.scalars(
            select(AuditLog).where(AuditLog.target_id == str(finding_id)).order_by(AuditLog.id)
        )
    )


def test_suppressing_requires_a_comment(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id)

    with pytest.raises(FindingError):
        findings_service.change_finding_status(
            db_session,
            org.id,
            finding.id,
            FindingStatus.ACCEPTED_RISK,
            actor_id=_actor_id(db_session),
        )

    assert finding.status is FindingStatus.OPEN
    assert _audit_rows(db_session, finding.id) == []


def test_accepting_risk_sets_status_and_audits_the_comment(
    db_session: Session, acme: tuple[Org, Asset]
) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id)
    actor = _actor_id(db_session)

    change = findings_service.change_finding_status(
        db_session,
        org.id,
        finding.id,
        FindingStatus.ACCEPTED_RISK,
        actor_id=actor,
        comment="  Risk owner signed off  ",
    )

    assert change.from_status is FindingStatus.OPEN
    assert change.to_status is FindingStatus.ACCEPTED_RISK
    assert finding.status is FindingStatus.ACCEPTED_RISK
    [entry] = _audit_rows(db_session, finding.id)
    assert entry.action == "finding.accepted_risk"
    assert entry.actor_user_id == actor
    assert entry.details == {
        "from": "open",
        "to": "accepted_risk",
        "comment": "Risk owner signed off",
    }


def test_repeating_the_current_status_is_a_no_op(
    db_session: Session, acme: tuple[Org, Asset]
) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id, status=FindingStatus.ACCEPTED_RISK)

    findings_service.change_finding_status(
        db_session,
        org.id,
        finding.id,
        FindingStatus.ACCEPTED_RISK,
        actor_id=_actor_id(db_session),
        comment="again",
    )

    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert _audit_rows(db_session, finding.id) == []


def test_reopening_a_fixed_finding_clears_fixed_at(
    db_session: Session, acme: tuple[Org, Asset]
) -> None:
    org, root = acme
    finding = make_finding(
        db_session,
        org.id,
        root.id,
        status=FindingStatus.FIXED,
        fixed_at=T0 + timedelta(hours=1),
    )

    findings_service.change_finding_status(
        db_session, org.id, finding.id, FindingStatus.OPEN, actor_id=_actor_id(db_session)
    )

    assert finding.status is FindingStatus.OPEN
    assert finding.fixed_at is None
    [entry] = _audit_rows(db_session, finding.id)
    assert entry.action == "finding.reopened"


def test_cannot_suppress_a_fixed_finding(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id, status=FindingStatus.FIXED)

    with pytest.raises(InvalidFindingTransition):
        findings_service.change_finding_status(
            db_session,
            org.id,
            finding.id,
            FindingStatus.ACCEPTED_RISK,
            actor_id=_actor_id(db_session),
            comment="nope",
        )

    assert finding.status is FindingStatus.FIXED


def test_users_cannot_mark_a_finding_fixed(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id)

    with pytest.raises(InvalidFindingTransition):
        findings_service.change_finding_status(
            db_session, org.id, finding.id, FindingStatus.FIXED, actor_id=_actor_id(db_session)
        )


def test_comment_is_capped(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id)

    with pytest.raises(FindingError):
        findings_service.change_finding_status(
            db_session,
            org.id,
            finding.id,
            FindingStatus.FALSE_POSITIVE,
            actor_id=_actor_id(db_session),
            comment="x" * (MAX_STATUS_COMMENT + 1),
        )


def test_bulk_change_is_all_or_nothing(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    first = make_finding(db_session, org.id, root.id, location="a")
    second = make_finding(db_session, org.id, root.id, location="b")

    with pytest.raises(FindingNotFound):
        findings_service.change_findings_status(
            db_session,
            org.id,
            (first.id, second.id, uuid4()),
            FindingStatus.FALSE_POSITIVE,
            actor_id=_actor_id(db_session),
            comment="batch",
        )

    assert first.status is FindingStatus.OPEN
    assert second.status is FindingStatus.OPEN
    assert _audit_rows(db_session, first.id) == []


def test_bulk_change_updates_and_audits_every_finding(
    db_session: Session, acme: tuple[Org, Asset]
) -> None:
    org, root = acme
    first = make_finding(db_session, org.id, root.id, location="a")
    second = make_finding(db_session, org.id, root.id, location="b")

    changed = findings_service.change_findings_status(
        db_session,
        org.id,
        (first.id, second.id),
        FindingStatus.FALSE_POSITIVE,
        actor_id=_actor_id(db_session),
        comment="scanner bug",
    )

    assert changed == 2
    assert first.status is FindingStatus.FALSE_POSITIVE
    assert second.status is FindingStatus.FALSE_POSITIVE
    assert len(_audit_rows(db_session, first.id)) == 1
    assert len(_audit_rows(db_session, second.id)) == 1


def test_bulk_change_enforces_its_limits(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, _ = acme

    with pytest.raises(FindingError):
        findings_service.change_findings_status(
            db_session, org.id, (), FindingStatus.OPEN, actor_id=_actor_id(db_session)
        )
    with pytest.raises(FindingError):
        findings_service.change_findings_status(
            db_session,
            org.id,
            tuple(uuid4() for _ in range(findings_service.MAX_BULK_FINDINGS + 1)),
            FindingStatus.OPEN,
            actor_id=_actor_id(db_session),
        )


def test_other_orgs_findings_are_not_found(db_session: Session, acme: tuple[Org, Asset]) -> None:
    org, root = acme
    finding = make_finding(db_session, org.id, root.id)
    other = make_org(db_session, "globex")

    with pytest.raises(FindingNotFound):
        findings_service.change_finding_status(
            db_session,
            other.id,
            finding.id,
            FindingStatus.ACCEPTED_RISK,
            actor_id=_actor_id(db_session),
            comment="mine now",
        )

    assert finding.status is FindingStatus.OPEN
    assert _audit_rows(db_session, finding.id) == []
