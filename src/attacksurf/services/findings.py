"""Finding workflow: the user's status decisions (scans own fixed/regressed, ADR 0027)."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.domain.findings import (
    ACTIVE_STATUSES,
    MAX_STATUS_COMMENT,
    SUPPRESSED_STATUSES,
    FindingError,
    FindingNotFound,
    FindingStatus,
    InvalidFindingTransition,
)
from attacksurf.infra.db.models import Finding
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services.audit import audit

MAX_BULK_FINDINGS = 50

# A user may suppress a live finding or reopen a suppressed or auto-fixed one. Nothing else:
# marking something fixed is the scan diff's call, and `regressed` follows from a re-observation.
_USER_STATUSES = frozenset(
    {FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE, FindingStatus.OPEN}
)
_ACTION_BY_STATUS = {
    FindingStatus.ACCEPTED_RISK: "finding.accepted_risk",
    FindingStatus.FALSE_POSITIVE: "finding.false_positive",
    FindingStatus.OPEN: "finding.reopened",
}


@dataclass(frozen=True)
class FindingStatusChange:
    finding_id: UUID
    from_status: FindingStatus
    to_status: FindingStatus


def change_finding_status(
    session: Session,
    org_id: UUID,
    finding_id: UUID,
    status: FindingStatus,
    *,
    actor_id: UUID,
    comment: str | None = None,
) -> FindingStatusChange:
    """Apply one user decision, audit it in the same transaction and commit.

    A no-op (the finding already has `status`) changes and audits nothing.
    """
    changes = _change(session, org_id, (finding_id,), status, actor_id=actor_id, comment=comment)
    session.commit()
    return changes[0] if changes else FindingStatusChange(finding_id, status, status)


def change_findings_status(
    session: Session,
    org_id: UUID,
    finding_ids: tuple[UUID, ...],
    status: FindingStatus,
    *,
    actor_id: UUID,
    comment: str | None = None,
) -> int:
    """Apply one decision to up to `MAX_BULK_FINDINGS` findings, all-or-nothing; commit once.

    Any missing/foreign id or invalid transition rejects the whole batch, so the caller never
    has to explain a half-applied bulk action.
    """
    ids = tuple(dict.fromkeys(finding_ids))
    if not ids:
        raise FindingError("Select at least one finding.")
    if len(ids) > MAX_BULK_FINDINGS:
        raise FindingError(f"Select at most {MAX_BULK_FINDINGS} findings at a time.")
    changes = _change(session, org_id, ids, status, actor_id=actor_id, comment=comment)
    session.commit()
    return len(changes)


def _change(
    session: Session,
    org_id: UUID,
    finding_ids: tuple[UUID, ...],
    status: FindingStatus,
    *,
    actor_id: UUID,
    comment: str | None,
) -> list[FindingStatusChange]:
    """Lock, validate, mutate and audit without committing (the public verbs commit)."""
    if status not in _USER_STATUSES:
        raise InvalidFindingTransition(
            "Scans mark findings fixed or regressed; you can accept risk, mark a false "
            "positive, or reopen."
        )
    note = _comment(comment, required=status in SUPPRESSED_STATUSES)
    findings = session.scalars(
        scoped(Finding, org_id)
        .where(Finding.id.in_(finding_ids))
        .order_by(Finding.id)
        .with_for_update()
    ).all()
    if len(findings) != len(finding_ids):
        raise FindingNotFound("Finding not found.")
    for finding in findings:
        _check_transition(finding.status, status)
    changes: list[FindingStatusChange] = []
    for finding in findings:
        previous = finding.status
        if previous is status:
            continue
        finding.status = status
        if status is FindingStatus.OPEN:
            # The model ties `fixed_at` to the fixed state (ADR 0027); a manual reopen clears it.
            finding.fixed_at = None
        audit(
            session,
            org_id,
            _ACTION_BY_STATUS[status],
            actor_id=actor_id,
            target_type="finding",
            target_id=str(finding.id),
            details={
                "from": previous.value,
                "to": status.value,
                **({"comment": note} if note else {}),
            },
        )
        changes.append(FindingStatusChange(finding.id, previous, status))
    return changes


def _check_transition(current: FindingStatus, target: FindingStatus) -> None:
    if current is target:
        return
    if target is FindingStatus.OPEN:
        if current not in SUPPRESSED_STATUSES and current is not FindingStatus.FIXED:
            raise InvalidFindingTransition("Only a suppressed or fixed finding can be reopened.")
        return
    if current not in ACTIVE_STATUSES:
        raise InvalidFindingTransition(
            "Only an open or regressed finding can be accepted or marked false positive."
        )


def _comment(comment: str | None, *, required: bool) -> str | None:
    note = (comment or "").strip()
    if len(note) > MAX_STATUS_COMMENT:
        raise FindingError(f"Keep the comment under {MAX_STATUS_COMMENT} characters.")
    if required and not note:
        raise FindingError("Add a comment explaining why you are suppressing this finding.")
    return note or None
