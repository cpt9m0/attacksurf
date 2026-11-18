"""What the upload use cases share (#87 archives, #101 binaries): the file name kept for
display, and the stored artifact with its queued analysis scan."""

import re
from contextlib import suppress
from dataclasses import dataclass
from typing import IO, Any
from uuid import UUID

import structlog
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    ArtifactCorrupt,
    ArtifactError,
    ArtifactKind,
    ArtifactPolicy,
    ArtifactStore,
)
from attacksurf.domain.ids import uuid7
from attacksurf.domain.jobs import TaskQueue
from attacksurf.domain.scans import ScanNotQueued, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Scan
from attacksurf.services import jobs
from attacksurf.services.artifacts import delete_artifact, store_artifact
from attacksurf.services.audit import audit
from attacksurf.services.scans import fail_scan

MAX_FILENAME_LENGTH = 255
log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class AssetUpload:
    asset_id: UUID
    asset_value: str
    artifact_id: UUID
    scan_id: UUID


@dataclass(frozen=True)
class AnalysisRequest:
    """Which scan an upload asks for. The `analysis` queue has no worker until #84: the job
    (and its scan) stays queued until then."""

    kind: ArtifactKind
    profile: str
    task_name: str
    audit_action: str


def display_name(filename: str) -> str:
    """The uploaded file's own name, for display only: templates escape it, nothing parses it.

    Attacker-chosen, so only the last path component survives, without control characters
    (Postgres rejects NUL in JSONB), bounded.
    """
    base = re.split(r"[/\\]", filename)[-1]
    return "".join(ch for ch in base if ch.isprintable())[:MAX_FILENAME_LENGTH]


def store_and_queue_analysis(
    session: Session,
    store: ArtifactStore,
    policy: ArtifactPolicy,
    queue: TaskQueue,
    request: AnalysisRequest,
    *,
    org_id: UUID,
    asset_id: UUID,
    source: IO[bytes],
    actor_id: UUID | None,
    expected_sha256: str | None = None,
    audit_details: dict[str, Any] | None = None,
) -> tuple[UUID, UUID]:
    """Store `source` under the asset and queue its scan; returns `(artifact_id, scan_id)`.

    Commits. The caller has committed the asset and holds no transaction. The scan records the
    artifact's SHA-256 as its revision. Raises what `store_artifact` raises, and
    `ArtifactCorrupt` (artifact deleted) if the stored bytes are not `expected_sha256`. If the
    scan can't be queued it is marked failed, the artifact is deleted and `ScanNotQueued` is
    raised.
    """
    artifact = store_artifact(
        session,
        store,
        policy,
        org_id=org_id,
        asset_id=asset_id,
        kind=request.kind,
        source=source,
        actor_id=actor_id,
    )
    artifact_id, sha256, size_bytes = artifact.id, artifact.sha256, artifact.size_bytes

    def discard(reason: str) -> None:
        with suppress(ArtifactError):  # the purge task removes what this leaves
            delete_artifact(session, store, org_id, artifact_id, actor_id=actor_id, reason=reason)

    if expected_sha256 not in (None, sha256):
        discard("digest_mismatch")
        raise ArtifactCorrupt("The upload changed while it was being stored. Try again.")
    scan_id = uuid7()
    try:
        session.add(
            Scan(
                id=scan_id,
                org_id=org_id,
                root_asset_id=asset_id,
                profile=request.profile,
                status=ScanStatus.QUEUED,
                triggered_by=ScanTrigger.USER,
                stats={"revision": sha256, "artifact_id": str(artifact_id)},
            )
        )
        session.flush()  # the job row below references it
        audit(
            session,
            org_id,
            request.audit_action,
            actor_id=actor_id,
            target_type="asset",
            target_id=str(asset_id),
            details={
                "artifact_id": str(artifact_id),
                "scan_id": str(scan_id),
                "sha256": sha256,
                "size_bytes": size_bytes,
                **(audit_details or {}),
            },
        )
        # Commits everything above, then sends.
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=scan_id,
            stage="analysis",
            task_name=request.task_name,
            asset_id=asset_id,
        )
    except Exception as exc:
        log.warning(
            "analysis scan not queued",
            org_id=str(org_id),
            scan_id=str(scan_id),
            profile=request.profile,
            error=type(exc).__name__,
        )
        session.rollback()
        fail_scan(session, org_id, scan_id)  # a no-op if the scan was never committed
        discard("enqueue_failed")
        raise ScanNotQueued("The scan could not be queued. Try again in a moment.") from exc
    return artifact_id, scan_id
