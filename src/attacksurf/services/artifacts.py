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
from sqlalchemy import func, select
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
) -> None:
    """Remove the file and erase the key; the row stays as the record. Idempotent.

    Raises `ArtifactNotFound` for a missing or another org's artifact, and
    `ArtifactStorageUnavailable` (nothing changed) if the file can't be removed.
    """
    artifact = session.scalars(
        scoped(Artifact, org_id)
        .where(Artifact.id == artifact_id)
        .with_for_update()
        # A row this session already holds would otherwise keep its stale `deleted_at`.
        .execution_options(populate_existing=True)
    ).one_or_none()
    if artifact is None:
        raise ArtifactNotFound("Artifact not found.")
    if artifact.deleted_at is not None:
        session.rollback()  # redelivered or raced: already done, release the row lock
        return
    try:
        store.delete(org_id, artifact_id)
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
    session.rollback()
    purged = 0
    try:
        for org_id, artifact_id in due:
            try:
                delete_artifact(
                    session, store, org_id, artifact_id, actor_id=None, reason="expired", now=now
                )
                purged += 1
            except ArtifactNotFound:
                # The asset or org was deleted since the scan: row and key went with it.
                session.rollback()
                with suppress(ArtifactStorageUnavailable):
                    store.delete(org_id, artifact_id)
            except ArtifactStorageUnavailable:
                # One undeletable file must not keep the rest of the batch (and every later
                # run, since it sorts first) from being purged. It is retried next run.
                log.warning(
                    "artifact purge failed", org_id=str(org_id), artifact_id=str(artifact_id)
                )
    finally:
        # Even when an item fails unexpectedly, stale plaintext is still swept.
        swept = store.sweep_staged(older_than_seconds=STAGE_MAX_AGE_SECONDS)
    if purged or swept:
        log.info("artifacts purged", artifacts=purged, staged_swept=swept)
    return purged


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
