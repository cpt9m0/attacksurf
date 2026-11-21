"""Email digest notifications and per-user notification preferences (#28, ADR 0032).

`save_notification_preference` and `run_scan_notification` are use cases and commit;
`get_notification_preference` is read-only; `queue_scan_notification` is an idempotent
best-effort trigger called at the end of the post-scan AI phase.
"""

from dataclasses import dataclass
from uuid import UUID

import structlog
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import StoredSummary
from attacksurf.domain.findings import ACTIVE_STATUSES, SEVERITY_RANK, Severity
from attacksurf.domain.jobs import JobNotFound, TaskQueue
from attacksurf.domain.notifications import (
    DEFAULT_EMAIL_ENABLED,
    DEFAULT_MIN_SEVERITY,
    MAX_DIGEST_FINDINGS,
    DigestFinding,
    EmailRecipientRefused,
    EmailSender,
    ScanDigest,
)
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.db.models import (
    Asset,
    Finding,
    FindingObservation,
    Job,
    Membership,
    NotificationDelivery,
    NotificationPreference,
    Org,
    Scan,
    User,
)
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.infra.email import render_digest_email
from attacksurf.services import jobs
from attacksurf.services.audit import audit

NOTIFY_STAGE = "notify"
NOTIFY_TASK_NAME = "passive.notify_scan"

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class NotificationPreferenceView:
    """User's email notification preference for one organization."""

    email_enabled: bool
    min_severity: Severity


def get_notification_preference(
    session: Session, org_id: UUID, user_id: UUID
) -> NotificationPreferenceView:
    """Return the user's saved preference in `org_id`, or defaults when none exists."""
    row = session.scalars(
        scoped(NotificationPreference, org_id).where(NotificationPreference.user_id == user_id)
    ).one_or_none()
    if row is None:
        return NotificationPreferenceView(
            email_enabled=DEFAULT_EMAIL_ENABLED,
            min_severity=DEFAULT_MIN_SEVERITY,
        )
    return NotificationPreferenceView(
        email_enabled=row.email_enabled,
        min_severity=row.min_severity,
    )


def save_notification_preference(
    session: Session,
    org_id: UUID,
    user_id: UUID,
    *,
    email_enabled: bool,
    min_severity: Severity,
) -> NotificationPreferenceView:
    """Upsert the user's notification preference in `org_id`, audit, and commit."""
    stmt = (
        insert(NotificationPreference)
        .values(
            org_id=org_id,
            user_id=user_id,
            email_enabled=email_enabled,
            min_severity=min_severity,
        )
        .on_conflict_do_update(
            index_elements=[NotificationPreference.org_id, NotificationPreference.user_id],
            set_={"email_enabled": email_enabled, "min_severity": min_severity},
        )
    )
    session.execute(stmt)
    audit(
        session,
        org_id,
        "notification.preferences_updated",
        actor_id=user_id,
        target_type="user",
        target_id=str(user_id),
        details={"email_enabled": email_enabled, "min_severity": min_severity.value},
    )
    session.commit()
    return NotificationPreferenceView(email_enabled=email_enabled, min_severity=min_severity)


def queue_scan_notification(
    session: Session, queue: TaskQueue, org_id: UUID, scan_id: UUID
) -> None:
    """Queue `passive.notify_scan` once for a completed scan with an active root.

    Idempotent: if a `notify` job already exists for `(org_id, scan_id)`, does nothing.
    Broker errors are logged and never propagated so callers (AI or scan finalization) stay safe.
    """
    scan = session.scalars(
        scoped(Scan, org_id).where(Scan.id == scan_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if scan is None or scan.status is not ScanStatus.COMPLETED:
        return
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == scan.root_asset_id),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if root is None or not root.is_active:
        return
    existing = session.scalars(
        scoped(Job, org_id).where(Job.scan_id == scan_id, Job.stage == NOTIFY_STAGE)
    ).first()
    if existing is not None:
        return
    try:
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=scan_id,
            stage=NOTIFY_STAGE,
            task_name=NOTIFY_TASK_NAME,
        )
    except Exception as exc:
        log.warning(
            "scan notification not queued",
            org_id=str(org_id),
            scan_id=str(scan_id),
            error=jobs.describe_error(exc),
        )


def run_scan_notification(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    sender: EmailSender | None,
    *,
    app_base_url: str | None = None,
) -> int:
    """Build and send per-recipient scan digest emails for `job_id`; returns emails sent."""
    job = get_scoped(session, Job, job_id, org_id)
    if job is None or job.scan_id is None:
        raise JobNotFound(str(job_id))
    scan = get_scoped(session, Scan, job.scan_id, org_id)
    if scan is None:
        raise JobNotFound(str(job_id))
    scan_id = scan.id
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == scan.root_asset_id),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if root is None or not root.is_active:
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "The domain was archived.")
        return 0
    if scan.status is not ScanStatus.COMPLETED:
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "Scan did not complete.")
        return 0
    if sender is None:
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "SMTP is not configured.")
        return 0

    candidates = _load_digest_findings(session, org_id, scan_id)
    if not candidates:
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "No new or regressed findings.")
        return 0

    recipients = _load_pending_recipients(session, org_id, scan_id)
    if not recipients:
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "No eligible recipients.")
        return 0

    org_name = session.scalar(select(Org.name).where(Org.id == org_id)) or ""
    ai_headline = _summary_headline(scan)
    root_domain = root.value
    triggered_by = scan.triggered_by
    finished_at = scan.finished_at
    # Release DB locks/transaction before outbound SMTP I/O.
    session.rollback()

    counts = {"sent": 0, "refused": 0, "claimed": 0}
    matched_any = False
    for user_id, email, min_severity in recipients:
        threshold = SEVERITY_RANK[min_severity]
        matching = [item for item in candidates if SEVERITY_RANK[item.severity] >= threshold]
        if not matching:
            continue
        matched_any = True
        digest = ScanDigest(
            org_name=org_name,
            scan_id=scan_id,
            root_domain=root_domain,
            triggered_by=triggered_by,
            finished_at=finished_at,
            ai_headline=ai_headline,
            findings=tuple(matching[:MAX_DIGEST_FINDINGS]),
            total_matching=len(matching),
            truncated=len(matching) > MAX_DIGEST_FINDINGS,
            app_base_url=app_base_url,
        )
        outcome = _deliver_recipient(
            session, sender, org_id=org_id, user_id=user_id, email=email, digest=digest
        )
        counts[outcome] += 1

    if not matched_any:
        jobs.mark_job_skipped(session, org_id, job_id, "No recipients matched severity threshold.")
    elif counts["sent"] == 0 and counts["refused"] > 0:
        raise EmailRecipientRefused("SMTP recipient refused.")
    return counts["sent"]


def _deliver_recipient(
    session: Session,
    sender: EmailSender,
    *,
    org_id: UUID,
    user_id: UUID,
    email: str,
    digest: ScanDigest,
) -> str:
    """Claim `(org_id, scan_id, user_id)` and send; returns `'sent'`, `'refused'`, or `'claimed'`."""  # noqa: E501
    claim_id = _claim_delivery(session, org_id, digest.scan_id, user_id)
    if claim_id is None:
        return "claimed"
    try:
        sender.send(render_digest_email(digest, email))
    except EmailRecipientRefused:
        _release_delivery(session, org_id, claim_id)
        log.warning(
            "digest recipient refused",
            org_id=str(org_id),
            scan_id=str(digest.scan_id),
            user_id=str(user_id),
        )
        return "refused"
    except Exception:
        _release_delivery(session, org_id, claim_id)
        raise
    return "sent"


def _claim_delivery(session: Session, org_id: UUID, scan_id: UUID, user_id: UUID) -> UUID | None:
    """Atomically claim `(org_id, scan_id, user_id)` before SMTP I/O; None if already claimed."""
    claim_id = session.scalar(
        insert(NotificationDelivery)
        .values(org_id=org_id, scan_id=scan_id, user_id=user_id)
        .on_conflict_do_nothing(
            index_elements=[
                NotificationDelivery.org_id,
                NotificationDelivery.scan_id,
                NotificationDelivery.user_id,
            ]
        )
        .returning(NotificationDelivery.id)
    )
    session.commit()
    return claim_id


def _release_delivery(session: Session, org_id: UUID, delivery_id: UUID) -> None:
    """Release an uncompleted delivery claim so a retry or later run can re-attempt it."""
    session.execute(
        delete(NotificationDelivery).where(
            NotificationDelivery.org_id == org_id, NotificationDelivery.id == delivery_id
        )
    )
    session.commit()


def _load_digest_findings(session: Session, org_id: UUID, scan_id: UUID) -> list[DigestFinding]:
    rows = session.execute(
        scoped(FindingObservation, org_id)
        .add_columns(
            Finding.id,
            Finding.rule_id,
            Finding.title,
            Finding.severity,
            Finding.first_seen_scan_id,
            FindingObservation.regressed,
            Asset.value,
        )
        .join(
            Finding,
            (Finding.id == FindingObservation.finding_id) & (Finding.org_id == org_id),
        )
        .join(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == org_id))
        .where(
            FindingObservation.scan_id == scan_id,
            Finding.status.in_(ACTIVE_STATUSES),
            (Finding.first_seen_scan_id == scan_id) | FindingObservation.regressed.is_(True),
        )
    ).all()
    items = [
        DigestFinding(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            severity=severity,
            asset_value=asset_value,
            change="new" if first_seen_scan_id == scan_id else "regressed",
        )
        for (
            _obs,
            finding_id,
            rule_id,
            title,
            severity,
            first_seen_scan_id,
            _regressed,
            asset_value,
        ) in rows
    ]
    items.sort(
        key=lambda item: (
            -SEVERITY_RANK[item.severity],
            0 if item.change == "new" else 1,
            item.title,
            item.finding_id,
        )
    )
    return items


def _load_pending_recipients(
    session: Session, org_id: UUID, scan_id: UUID
) -> list[tuple[UUID, str, Severity]]:
    already_sent = (
        select(NotificationDelivery.id)
        .where(
            NotificationDelivery.org_id == org_id,
            NotificationDelivery.scan_id == scan_id,
            NotificationDelivery.user_id == Membership.user_id,
        )
        .exists()
    )
    rows = session.execute(
        scoped(Membership, org_id)
        .select_from(Membership)
        .with_only_columns(
            User.id,
            User.email,
            NotificationPreference.email_enabled,
            NotificationPreference.min_severity,
        )
        .join(User, User.id == Membership.user_id)
        .outerjoin(
            NotificationPreference,
            (NotificationPreference.org_id == org_id)
            & (NotificationPreference.user_id == Membership.user_id),
        )
        .where(User.is_active.is_(True), ~already_sent)
        .order_by(User.email, User.id)
    ).all()
    recipients: list[tuple[UUID, str, Severity]] = []
    for user_id, email, enabled, min_severity in rows:
        is_enabled = DEFAULT_EMAIL_ENABLED if enabled is None else enabled
        if not is_enabled:
            continue
        recipients.append((user_id, email, min_severity or DEFAULT_MIN_SEVERITY))
    return recipients


def _summary_headline(scan: Scan) -> str | None:
    if scan.ai_summary is None:
        return None
    try:
        return StoredSummary.model_validate(scan.ai_summary).headline
    except ValidationError:
        return None
