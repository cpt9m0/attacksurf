"""Ownership verification use cases (#14): issue a token, record a DNS check, find due checks.

`start_verification` is a use case and commits once. `record_check` is a building block: the
worker task that runs it commits. Nothing here performs DNS I/O; the lookup arrives through
`domain.net.TxtLookup`, so the use cases stay testable with a fake.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetType
from attacksurf.domain.jobs import TaskQueue
from attacksurf.domain.verification import (
    GRACE_AFTER_FAILURE,
    RECHECK_AFTER,
    VerificationMethod,
    VerificationStatus,
    matches,
    new_token,
    record_name,
    record_value,
)
from attacksurf.infra.db.models import Asset, Verification
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services import jobs
from attacksurf.services.audit import audit

# One re-verification run never queues more than this, so a mass expiry can't flood the queue.
MAX_DUE_PER_RUN = 200


@dataclass(frozen=True)
class VerificationView:
    """What the UI shows: the record to publish, plus where the proof stands."""

    asset_id: UUID
    status: VerificationStatus
    method: VerificationMethod
    record_name: str
    record_value: str
    verified_at: datetime | None
    last_checked_at: datetime | None
    expires_at: datetime | None


def start_verification(
    session: Session,
    queue: TaskQueue,
    *,
    org_id: UUID,
    asset_id: UUID,
    actor_id: UUID | None,
) -> Verification:
    """Issue (or re-issue) the TXT token for a root domain and queue its first check.

    Re-issuing rotates the token and resets the proof to `pending`: the old record stops
    counting the moment a new token exists, so a copied record can't be replayed.
    Raises `AssetNotFound` unless `asset_id` is one of the org's active root domains.
    """
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == asset_id).with_for_update()
    ).one_or_none()
    if root is None or root.type is not AssetType.DOMAIN or not root.is_active:
        raise AssetNotFound("Asset not found.")
    verification = session.scalars(
        scoped(Verification, org_id).where(Verification.asset_id == root.id).with_for_update()
    ).one_or_none()
    if verification is None:
        verification = Verification(
            org_id=org_id,
            asset_id=root.id,
            method=VerificationMethod.DNS_TXT,
            token=new_token(),
            status=VerificationStatus.PENDING,
        )
        session.add(verification)
    else:
        verification.token = new_token()
        verification.status = VerificationStatus.PENDING
        verification.verified_at = None
        verification.expires_at = None
        verification.last_checked_at = None
    session.flush()
    audit(
        session,
        org_id,
        "asset.verification_started",
        actor_id=actor_id,
        target_type="asset",
        target_id=str(root.id),
        details={"value": root.value},  # not the token: the audit log holds no credentials
    )
    session.commit()
    # The token is committed first, so a broker failure leaves a usable proof to retry by hand
    # rather than losing it; `create_job` still marks its own row failed.
    jobs.create_job(
        session,
        queue,
        org_id=org_id,
        scan_id=None,
        stage="verify",
        task_name="passive.verify_ownership",
        asset_id=root.id,
    )
    session.refresh(verification)
    return verification


def get_verification(session: Session, org_id: UUID, asset_id: UUID) -> VerificationView | None:
    """The asset's proof, rooted at the asset's root. Raises `AssetNotFound`.

    Subdomains inherit whatever their root proved, so the card is the same on both.
    """
    asset = get_scoped(session, Asset, asset_id, org_id)
    if asset is None:
        raise AssetNotFound("Asset not found.")
    root = asset if asset.parent_id is None else get_scoped(session, Asset, asset.parent_id, org_id)
    if root is None:
        return None
    return read_verification(session, org_id, root.id)


def queue_check(
    session: Session, queue: TaskQueue, *, org_id: UUID, asset_id: UUID
) -> Verification:
    """Queue another check of an existing proof, keeping its token ("Verify now").

    The usual path is the scheduled re-check; this lets an admin trigger one right after
    publishing the record, without rotating the token they just copied (`start_verification`
    rotates). Raises `AssetNotFound` unless the asset is an active root with a proof.
    """
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == asset_id).with_for_update()
    ).one_or_none()
    if root is None or root.type is not AssetType.DOMAIN or not root.is_active:
        raise AssetNotFound("Asset not found.")
    verification = session.scalars(
        scoped(Verification, org_id).where(Verification.asset_id == root.id).with_for_update()
    ).one_or_none()
    if verification is None:
        raise AssetNotFound("Asset not found.")
    session.commit()
    jobs.create_job(
        session,
        queue,
        org_id=org_id,
        scan_id=None,
        stage="verify",
        task_name="passive.verify_ownership",
        asset_id=root.id,
    )
    return verification


def verification_for_asset(session: Session, org_id: UUID, asset_id: UUID) -> UUID | None:
    """The id of an asset's proof, or None. Tenant-scoped; used by the worker task."""
    return session.scalar(
        scoped(Verification, org_id)
        .where(Verification.asset_id == asset_id)
        .with_only_columns(Verification.id)
    )


def read_verification(session: Session, org_id: UUID, root_id: UUID) -> VerificationView | None:
    """The verification row of a root, shaped for `web/`. No lookup: the proof is one row."""
    row = session.scalars(
        scoped(Verification, org_id).where(Verification.asset_id == root_id)
    ).one_or_none()
    if row is None:
        return None
    root = get_scoped(session, Asset, root_id, org_id)
    if root is None:
        return None
    return VerificationView(
        asset_id=root_id,
        status=row.status,
        method=row.method,
        record_name=record_name(root.value),
        record_value=record_value(row.token),
        verified_at=row.verified_at,
        last_checked_at=row.last_checked_at,
        expires_at=row.expires_at,
    )


def record_check(
    session: Session,
    verification: Verification,
    values: tuple[str, ...],
    *,
    now: datetime | None = None,
) -> VerificationStatus:
    """Apply one DNS answer to the proof. Doesn't commit.

    Found: verified, and due again after `RECHECK_AFTER`. Not found: pending if it never
    counted, revoked if it had; `expires_at` keeps a verified proof alive for
    `GRACE_AFTER_FAILURE` so one flaky lookup doesn't cut active checks off.
    """
    now = now or datetime.now(UTC)
    found = matches(verification.token, values)
    verification.last_checked_at = now
    if found:
        verification.status = VerificationStatus.VERIFIED
        if verification.verified_at is None:
            verification.verified_at = now
        verification.expires_at = now + RECHECK_AFTER
    elif verification.status is VerificationStatus.VERIFIED and (
        verification.expires_at is None or now >= verification.expires_at
    ):
        verification.status = VerificationStatus.REVOKED
        verification.expires_at = None
    return verification.status


def due_verifications(
    session: Session, now: datetime, limit: int = MAX_DUE_PER_RUN
) -> tuple[tuple[UUID, UUID, UUID], ...]:
    """(org, asset, verification) of proofs to re-check: expired ones, and stale pending ones.

    Cross-tenant on purpose: the hourly re-verification run is system-wide. It only yields ids
    (each job is created with its row's own `org_id`), so no tenant data crosses a boundary.
    """
    stale_grace = now - GRACE_AFTER_FAILURE
    rows = session.execute(
        select(Verification.org_id, Verification.asset_id, Verification.id)
        .join(Asset, Asset.id == Verification.asset_id)
        .where(
            Asset.is_active.is_(True),
            or_(
                (Verification.status == VerificationStatus.VERIFIED)
                & (Verification.expires_at <= now),
                (Verification.status == VerificationStatus.PENDING)
                & or_(
                    Verification.last_checked_at.is_(None),
                    Verification.last_checked_at <= stale_grace,
                ),
            ),
        )
        .order_by(Verification.expires_at, Verification.id)
        .limit(limit)
    ).all()
    return tuple(rows)


def enqueue_due_checks(session: Session, queue: TaskQueue, *, now: datetime) -> int:
    """Queue one tracked check per due proof; returns how many were queued."""
    rows = due_verifications(session, now)
    for org_id, asset_id, _verification_id in rows:
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=None,
            stage="verify",
            task_name="passive.verify_ownership",
            asset_id=asset_id,
        )
    return len(rows)
