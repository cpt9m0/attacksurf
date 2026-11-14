"""Codebase sources (#87): an uploaded archive becomes a repo asset, an artifact and a scan."""

import re
from contextlib import suppress
from dataclasses import dataclass
from typing import IO
from uuid import UUID

import structlog
from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    SNIFF_BYTES,
    ArtifactError,
    ArtifactKind,
    ArtifactPolicy,
    ArtifactStore,
    UnsupportedArtifactFormat,
    sniff_archive,
)
from attacksurf.domain.assets import AssetSource, AssetType, upload_repo_value
from attacksurf.domain.ids import uuid7
from attacksurf.domain.jobs import TaskQueue
from attacksurf.domain.scans import ScanNotQueued, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Scan
from attacksurf.scanners.profiles import CODE_PROFILE
from attacksurf.services import jobs
from attacksurf.services.artifacts import delete_artifact, store_artifact
from attacksurf.services.assets import record_asset
from attacksurf.services.audit import audit
from attacksurf.services.scans import fail_scan

# The `analysis` queue has no worker until #84: the job (and its scan) stays queued until then.
CODE_SCAN_TASK = "analysis.code_scan"
MAX_FILENAME_LENGTH = 255
log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RepoUpload:
    asset_id: UUID
    asset_value: str
    artifact_id: UUID
    scan_id: UUID


def upload_repo_archive(
    session: Session,
    store: ArtifactStore,
    policy: ArtifactPolicy,
    queue: TaskQueue,
    *,
    org_id: UUID,
    filename: str,
    source: IO[bytes],
    actor_id: UUID | None,
) -> RepoUpload:
    """Store an uploaded archive under the repo asset `upload/<name>` and queue its code scan.

    `source` must be seekable. Only its leading bytes are looked at here; the archive is never
    opened outside the sandbox (ADR 0017). Uploading the same name again adds an artifact and a
    scan to the same asset. The scan records the archive's SHA-256 as its revision.
    Raises `UnsupportedArtifactFormat` and what `store_artifact` raises. An upload that fails
    in storage (too large, quota) leaves its asset in place, without an artifact: deleting it
    could take a concurrent upload of the same name with it. If the scan can't be queued it is
    marked failed, the artifact is deleted and `ScanNotQueued` is raised.
    """
    head = source.read(SNIFF_BYTES)
    source.seek(0)
    if sniff_archive(head) is None:
        raise UnsupportedArtifactFormat("Upload a .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz file.")
    value = upload_repo_value(filename)
    asset = record_asset(session, org_id, AssetType.REPO, value, source=AssetSource.USER)
    asset.details = {**asset.details, "upload": {"filename": _display_name(filename)}}
    asset_id = asset.id
    session.commit()  # `store_artifact` holds no transaction while it streams
    artifact = store_artifact(
        session,
        store,
        policy,
        org_id=org_id,
        asset_id=asset_id,
        kind=ArtifactKind.REPO,
        source=source,
        actor_id=actor_id,
    )
    artifact_id, sha256, size_bytes = artifact.id, artifact.sha256, artifact.size_bytes
    scan_id = uuid7()
    try:
        session.add(
            Scan(
                id=scan_id,
                org_id=org_id,
                root_asset_id=asset_id,
                profile=CODE_PROFILE,
                status=ScanStatus.QUEUED,
                triggered_by=ScanTrigger.USER,
                stats={"revision": sha256, "artifact_id": str(artifact_id)},
            )
        )
        session.flush()  # the job row below references it
        audit(
            session,
            org_id,
            "repo.archive_uploaded",
            actor_id=actor_id,
            target_type="asset",
            target_id=str(asset_id),
            details={
                "artifact_id": str(artifact_id),
                "scan_id": str(scan_id),
                "sha256": sha256,
                "size_bytes": size_bytes,
            },
        )
        # Commits everything above, then sends.
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=scan_id,
            stage="analysis",
            task_name=CODE_SCAN_TASK,
            asset_id=asset_id,
        )
    except Exception as exc:
        log.warning(
            "code scan not queued",
            org_id=str(org_id),
            scan_id=str(scan_id),
            error=type(exc).__name__,
        )
        session.rollback()
        fail_scan(session, org_id, scan_id)  # a no-op if the scan was never committed
        with suppress(ArtifactError):  # the purge task removes what this leaves
            delete_artifact(
                session, store, org_id, artifact_id, actor_id=actor_id, reason="enqueue_failed"
            )
        raise ScanNotQueued("The scan could not be queued. Try again in a moment.") from exc
    return RepoUpload(asset_id, value, artifact_id, scan_id)


def _display_name(filename: str) -> str:
    """The uploaded file's own name, for display only: templates escape it, nothing parses it.

    Attacker-chosen, so only the last path component survives, without control characters
    (Postgres rejects NUL in JSONB), bounded.
    """
    base = re.split(r"[/\\]", filename)[-1]
    return "".join(ch for ch in base if ch.isprintable())[:MAX_FILENAME_LENGTH]
