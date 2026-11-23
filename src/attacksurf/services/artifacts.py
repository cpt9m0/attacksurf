"""Artifact use cases (#85, ADR 0028): store, read, stage for a run, delete, purge expired.

Each use case commits once. Bytes go through the `ArtifactStore` port; the row holds the
wrapped key, so a row that is deleted (or marked deleted) leaves its file undecryptable.
Logs carry ids and counts only, never names, paths or content.
"""

from collections.abc import Iterator
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import IO
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    STAGE_MAX_AGE_SECONDS,
    ArtifactKind,
    ArtifactNotFound,
    ArtifactPolicy,
    ArtifactQuotaExceeded,
    ArtifactStorageUnavailable,
    ArtifactStore,
    ArtifactTooLarge,
)
from attacksurf.domain.assets import AssetNotFound
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.models import Artifact, Asset, Org
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)

# With retention 0 an artifact goes when its analysis completes; one that is never analysed
# (failed upload flow, lost job) still goes after this long.
UNANALYZED_TTL_HOURS = 24
# One purge run never deletes more than this, so a mass expiry can't hold the worker.
MAX_PURGE_PER_RUN = 200
# Floor for how long a failed purge waits before retrying, so a batch that cannot be deleted
# can never starve the artifacts behind it (other orgs' included).
PURGE_RETRY_SECONDS = 60


def store_artifact(
    session: Session,
    store: ArtifactStore,
    policy: ArtifactPolicy,
    *,
    org_id: UUID,
    asset_id: UUID,
    kind: ArtifactKind,
    source: IO[bytes],
    actor_id: UUID | None,
    now: datetime | None = None,
) -> Artifact:
    """Encrypt `source` to storage and record it under one of the org's assets.

    Raises `AssetNotFound`, `ArtifactTooLarge`, `ArtifactQuotaExceeded`. Whatever fails after
    the bytes were written, the file is removed again.
    """
    if get_scoped(session, Asset, asset_id, org_id) is None:
        raise AssetNotFound("Asset not found.")
    remaining = policy.org_quota_bytes - _stored_bytes(session, org_id)
    session.rollback()  # no transaction stays open while the upload streams to disk
    if remaining <= 0:
        raise ArtifactQuotaExceeded("The organization's artifact storage is full.")
    artifact_id = uuid7()
    try:
        stored = store.put(org_id, artifact_id, source, max_bytes=min(policy.max_bytes, remaining))
    except ArtifactTooLarge:
        if remaining < policy.max_bytes:
            raise ArtifactQuotaExceeded("The organization's artifact storage is full.") from None
        raise
    try:
        # Serialise the org's uploads: two that each fit must not overshoot the quota together.
        session.execute(select(Org.id).where(Org.id == org_id).with_for_update())
        if _stored_bytes(session, org_id) + stored.size_bytes > policy.org_quota_bytes:
            raise ArtifactQuotaExceeded("The organization's artifact storage is full.")
        lifetime = timedelta(hours=policy.retention_hours or UNANALYZED_TTL_HOURS)
        artifact = Artifact(
            id=artifact_id,
            org_id=org_id,
            asset_id=asset_id,
            kind=kind,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            storage_key=stored.storage_key,
            key_envelope=stored.key_envelope,
            delete_after=(now or datetime.now(UTC)) + lifetime,
        )
        session.add(artifact)
        audit(
            session,
            org_id,
            "artifact.stored",
            actor_id=actor_id,
            target_type="artifact",
            target_id=str(artifact_id),
            details={"kind": kind.value, "size_bytes": stored.size_bytes, "sha256": stored.sha256},
        )
        session.commit()
    except BaseException:
        # Neither cleanup step may replace the error being raised or skip the other.
        try:
            session.rollback()
        finally:
            try:
                store.delete(org_id, artifact_id)
            except ArtifactStorageUnavailable:
                log.warning(
                    "artifact cleanup failed", org_id=str(org_id), artifact_id=str(artifact_id)
                )
        raise
    log.info(
        "artifact stored",
        org_id=str(org_id),
        artifact_id=str(artifact_id),
        size_bytes=stored.size_bytes,
    )
    return artifact


def check_quota(session: Session, policy: ArtifactPolicy, org_id: UUID, size_bytes: int) -> None:
    """Raise `ArtifactQuotaExceeded` if `size_bytes` more would not fit in the org's quota.

    An early answer for callers that create rows before storing; `store_artifact` decides.
    """
    if _stored_bytes(session, org_id) + size_bytes > policy.org_quota_bytes:
        raise ArtifactQuotaExceeded("The organization's artifact storage is full.")


def open_artifact(
    session: Session, store: ArtifactStore, org_id: UUID, artifact_id: UUID
) -> Iterator[bytes]:
    """The artifact's plaintext in chunks. Raises `ArtifactNotFound`, `ArtifactCorrupt`."""
    artifact, key_envelope = _live(session, org_id, artifact_id)
    return store.open(org_id, artifact.id, key_envelope)


def stage_artifact(session: Session, store: ArtifactStore, org_id: UUID, artifact_id: UUID) -> None:
    """Write the plaintext where one sandbox run can mount it. Raises `ArtifactNotFound`.

    The caller must `store.unstage(artifact_id)` when the run ends; the purge task sweeps what
    a crashed caller leaves behind.
    """
    artifact, key_envelope = _live(session, org_id, artifact_id)
    store.stage(org_id, artifact.id, key_envelope, sha256=artifact.sha256)


def delete_artifact(
    session: Session,
    store: ArtifactStore,
    org_id: UUID,
    artifact_id: UUID,
    *,
    actor_id: UUID | None,
    reason: str = "requested",
    now: datetime | None = None,
    retry_at: datetime | None = None,
) -> None:
    """Remove the file and erase the key; the row stays as the record. Idempotent.

    Raises `ArtifactNotFound` for a missing or another org's artifact, and
    `ArtifactStorageUnavailable` (the key is kept) if the file can't be removed. Pass `retry_at`
    to control when a failed deletion is attempted again; the row is only moved while its
    deadline still matches the one this attempt saw.
    """
    artifact = _locked(session, org_id, artifact_id)
    if artifact is None:
        raise ArtifactNotFound("Artifact not found.")
    if artifact.deleted_at is not None:
        session.rollback()  # redelivered or raced: already done, release the row lock
        return
    try:
        store.delete(org_id, artifact_id)
    except ArtifactStorageUnavailable:
        # The file stays, so the row must keep its key. Move the attempt marker on, in a
        # separate transaction, so the purge retries this later instead of first every time.
        _defer_retry(
            session,
            org_id,
            artifact_id,
            retry_at=retry_at,
            attempted_deadline=artifact.delete_after,
        )
        raise
    except BaseException:
        session.rollback()  # release the row lock
        raise
    artifact.key_envelope = None
    artifact.deleted_at = now or datetime.now(UTC)
    audit(
        session,
        org_id,
        "artifact.deleted",
        actor_id=actor_id,
        target_type="artifact",
        target_id=str(artifact_id),
        details={"reason": reason},
    )
    session.commit()
    log.info("artifact deleted", org_id=str(org_id), artifact_id=str(artifact_id), reason=reason)


def purge_expired(
    session: Session, store: ArtifactStore, *, now: datetime, limit: int = MAX_PURGE_PER_RUN
) -> int:
    """Delete artifacts past `delete_after` and sweep stale staged plaintext; returns the count.

    Cross-tenant on purpose: retention is system-wide. It only reads ids; each deletion then
    runs tenant-scoped in its own transaction, so no lock is held across the batch.
    """
    due = session.execute(
        select(Artifact.org_id, Artifact.id)
        .where(Artifact.deleted_at.is_(None), Artifact.delete_after <= now)
        .order_by(Artifact.delete_after)
        .limit(limit)
    ).all()
    oldest_pending = session.scalar(
        select(func.min(Artifact.delete_after)).where(
            Artifact.deleted_at.is_(None), Artifact.delete_after > now
        )
    )
    session.rollback()
    # A row whose deletion fails goes behind everything still waiting (or the retry delay,
    # whichever is later), so a permanently undeletable batch cannot crowd out the rest.
    retry_at = max(
        now + timedelta(seconds=PURGE_RETRY_SECONDS),
        (oldest_pending or now) + timedelta(seconds=PURGE_RETRY_SECONDS),
    )
    purged = 0
    try:
        for org_id, artifact_id in due:
            try:
                delete_artifact(
                    session,
                    store,
                    org_id,
                    artifact_id,
                    actor_id=None,
                    reason="expired",
                    now=now,
                    retry_at=retry_at,
                )
                purged += 1
            except ArtifactNotFound:
                # The asset or org was deleted since the scan: row and key went with it.
                session.rollback()
                with suppress(ArtifactStorageUnavailable):
                    store.delete(org_id, artifact_id)
            except ArtifactStorageUnavailable:
                # Its `delete_after` now sorts it after the rest, so one undeletable file cannot
                # keep the batch, or every later run (it sorts first), from purging the others.
                log.warning(
                    "artifact purge failed", org_id=str(org_id), artifact_id=str(artifact_id)
                )
    finally:
        # Even when an item fails unexpectedly, stale plaintext is still swept.
        swept = store.sweep_staged(older_than_seconds=STAGE_MAX_AGE_SECONDS)
    if purged or swept:
        log.info("artifacts purged", artifacts=purged, staged_swept=swept)
    return purged


def _locked(session: Session, org_id: UUID, artifact_id: UUID) -> Artifact | None:
    """The org's artifact row, locked for update; None for missing or another org's."""
    return session.scalars(
        scoped(Artifact, org_id)
        .where(Artifact.id == artifact_id)
        .with_for_update()
        # A row this session already holds would otherwise keep its stale `deleted_at`.
        .execution_options(populate_existing=True)
    ).one_or_none()


def _defer_retry(
    session: Session,
    org_id: UUID,
    artifact_id: UUID,
    *,
    retry_at: datetime | None,
    attempted_deadline: datetime,
) -> None:
    """Record a failed deletion attempt: push `delete_after` back by the retry delay.

    Nothing else about the row changes. `attempted_deadline` is the deadline the failed attempt
    saw: if it has moved since (a request set a newer one), this attempt's rule no longer
    applies and the row is left alone. A targeted UPDATE carries only `delete_after`, because
    flushing the ORM instance would also write back whatever state this session loaded,
    `key_envelope` included.
    """
    row = _locked(session, org_id, artifact_id)
    if row is None or row.deleted_at is not None or row.delete_after != attempted_deadline:
        # Cascaded away, deleted meanwhile, or given a newer deadline: nothing to defer.
        session.rollback()
        return
    session.execute(
        update(Artifact)
        .where(
            Artifact.org_id == org_id,
            Artifact.id == artifact_id,
            Artifact.deleted_at.is_(None),
        )
        .values(
            delete_after=retry_at or attempted_deadline + timedelta(seconds=PURGE_RETRY_SECONDS)
        )
    )
    session.commit()


def _stored_bytes(session: Session, org_id: UUID) -> int:
    total = func.coalesce(func.sum(Artifact.size_bytes), 0)
    return int(
        session.scalar(
            scoped(Artifact, org_id).where(Artifact.deleted_at.is_(None)).with_only_columns(total)
        )
        or 0
    )


def _live(session: Session, org_id: UUID, artifact_id: UUID) -> tuple[Artifact, bytes]:
    """A stored artifact and its wrapped key; missing, deleted and foreign all look the same."""
    artifact = get_scoped(session, Artifact, artifact_id, org_id)
    if artifact is None or artifact.key_envelope is None:
        raise ArtifactNotFound("Artifact not found.")
    return artifact, artifact.key_envelope
