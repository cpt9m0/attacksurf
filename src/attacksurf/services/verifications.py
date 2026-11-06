"""Ownership verification use cases (#14): issue a token, record a DNS check, find due checks.

`start_verification` is a use case and commits once. `record_check` is a building block: the
worker task that runs it commits. Nothing here performs DNS I/O; the lookup arrives through
`domain.net.TxtLookup`, so the use cases stay testable with a fake.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetType
from attacksurf.domain.jobs import TaskQueue
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.verification import (
    GRACE_AFTER_FAILURE,
    PROOF_VALID_FOR,
    RECHECK_AFTER,
    OwnershipState,
    VerificationMethod,
    VerificationStatus,
    matches,
    new_token,
    ownership_state,
    record_name,
    record_value,
)
from attacksurf.infra.db.models import Asset, Job, Verification
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services import jobs
from attacksurf.services.audit import audit

# One re-verification run never queues more than this, so a mass expiry can't flood the queue.
MAX_DUE_PER_RUN = 200
# Backoff cap: 2**8 hours is already longer than any lookup outage worth retrying at all.
MAX_BACKOFF_EXP = 8


@dataclass(frozen=True)
class VerificationView:
    """What the UI shows: the record to publish, plus where the proof stands.

    `status` is what is stored; `state` is what it grants now (expired proofs show as such).
    """

    asset_id: UUID
    status: VerificationStatus
    state: OwnershipState
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
        verification.recheck_at = None
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


def check_in_flight(session: Session, org_id: UUID, asset_id: UUID) -> bool:
    """True while a verification job for this root is still queued or running.

    The card polls itself while this is true, so the result of "Verify now" (or of the
    scheduled re-check) appears without the admin reloading the page.
    """
    return (
        session.scalar(
            scoped(Job, org_id)
            .where(
                Job.asset_id == asset_id,
                Job.stage == "verify",
                Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING)),
            )
            .with_only_columns(Job.id)
            .limit(1)
        )
        is not None
    )


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
        state=ownership_state(row.status, row.expires_at, datetime.now(UTC)),
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

    Found: verified, due again after `RECHECK_AFTER` and valid for `PROOF_VALID_FOR` (longer,
    so a late or failed re-check doesn't take access away). Not found: pending if it never
    counted, revoked if it had and its `expires_at` passed.
    """
    now = now or datetime.now(UTC)
    found = matches(verification.token, values)
    verification.last_checked_at = now
    # Any answered lookup clears the backoff, even a negative one: the domain is reachable.
    verification.failed_attempts = 0
    verification.retry_after = None
    if found:
        verification.status = VerificationStatus.VERIFIED
        if verification.verified_at is None:
            verification.verified_at = now
        verification.recheck_at = now + RECHECK_AFTER
        verification.expires_at = now + PROOF_VALID_FOR
    elif verification.status is VerificationStatus.VERIFIED and (
        verification.expires_at is None or now >= verification.expires_at
    ):
        verification.status = VerificationStatus.REVOKED
        verification.expires_at = None
    return verification.status


def record_failure(verification: Verification, *, now: datetime | None = None) -> None:
    """Count one failed lookup and push the next scheduled check back. Doesn't commit.

    Backoff doubles per consecutive failure (1 h, 2 h, 4 h, ... up to `MAX_BACKOFF_EXP`), so a
    domain whose nameservers are gone can't occupy the fixed batch ahead of healthy proofs.
    """
    now = now or datetime.now(UTC)
    verification.failed_attempts += 1
    exponent = min(verification.failed_attempts, MAX_BACKOFF_EXP)
    verification.retry_after = now + timedelta(hours=1) * (2**exponent)


def due_verifications(
    session: Session, now: datetime, limit: int = MAX_DUE_PER_RUN
) -> tuple[tuple[UUID, UUID, UUID], ...]:
    """(org, asset, verification) of proofs to re-check: due renewals and stale pending ones.

    Cross-tenant on purpose: the hourly re-verification run is system-wide. It only yields ids
    (each job is created with its row's own `org_id`), so no tenant data crosses a boundary.
    """
    stale_grace = now - GRACE_AFTER_FAILURE
    # A proof whose lookup keeps failing is retried on a doubling backoff instead of being
    # picked first every hour: sorted last, and skipped until its `retry_after`.
    backoff = case(
        (Verification.failed_attempts == 0, timedelta(0)),
        else_=timedelta(hours=1) * (2 ** func.least(Verification.failed_attempts, MAX_BACKOFF_EXP)),
    )
    rows = session.execute(
        select(Verification.org_id, Verification.asset_id, Verification.id)
        .join(Asset, Asset.id == Verification.asset_id)
        .where(
            Asset.is_active.is_(True),
            or_(
                # Due at `recheck_at`, which is set well before `expires_at`, so a healthy
                # proof is renewed while it still authorizes checks.
                (Verification.status == VerificationStatus.VERIFIED)
                & (or_(Verification.recheck_at.is_(None), Verification.recheck_at <= now)),
                (Verification.status == VerificationStatus.PENDING)
                & or_(
                    Verification.last_checked_at.is_(None),
                    Verification.last_checked_at <= stale_grace,
                ),
            ),
            # Never retry before the backoff elapsed (NULL: no failure yet).
            or_(Verification.retry_after.is_(None), Verification.retry_after <= now),
        )
        .order_by(Verification.failed_attempts, backoff, Verification.recheck_at, Verification.id)
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
