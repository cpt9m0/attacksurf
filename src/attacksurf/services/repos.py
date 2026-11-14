"""Codebase sources (#87): an uploaded archive becomes a repo asset, an artifact and a scan."""

from typing import IO
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    SNIFF_BYTES,
    ArtifactKind,
    ArtifactPolicy,
    ArtifactStore,
    UnsupportedArtifactFormat,
    sniff_archive,
)
from attacksurf.domain.assets import AssetSource, AssetType, upload_repo_value
from attacksurf.domain.jobs import TaskQueue
from attacksurf.scanners.profiles import CODE_PROFILE
from attacksurf.services.assets import record_asset
from attacksurf.services.uploads import (
    AnalysisRequest,
    AssetUpload,
    display_name,
    store_and_queue_analysis,
)

CODE_SCAN_TASK = "analysis.code_scan"
_CODE_SCAN = AnalysisRequest(
    ArtifactKind.REPO, CODE_PROFILE, CODE_SCAN_TASK, "repo.archive_uploaded"
)


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
) -> AssetUpload:
    """Store an uploaded archive under the repo asset `upload/<name>` and queue its code scan.

    `source` must be seekable. Only its leading bytes are looked at here; the archive is never
    opened outside the sandbox (ADR 0017). Uploading the same name again adds an artifact and a
    scan to the same asset. The scan records the archive's SHA-256 as its revision.
    Raises `UnsupportedArtifactFormat` and what `store_and_queue_analysis` raises. An upload
    that fails in storage (too large, quota) leaves its asset in place, without an artifact:
    deleting it could take a concurrent upload of the same name with it.
    """
    head = source.read(SNIFF_BYTES)
    source.seek(0)
    if sniff_archive(head) is None:
        raise UnsupportedArtifactFormat("Upload a .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz file.")
    value = upload_repo_value(filename)
    asset = record_asset(session, org_id, AssetType.REPO, value, source=AssetSource.USER)
    asset.details = {**asset.details, "upload": {"filename": display_name(filename)}}
    asset_id = asset.id
    session.commit()  # `store_artifact` holds no transaction while it streams
    artifact_id, scan_id = store_and_queue_analysis(
        session,
        store,
        policy,
        queue,
        _CODE_SCAN,
        org_id=org_id,
        asset_id=asset_id,
        source=source,
        actor_id=actor_id,
    )
    return AssetUpload(asset_id, value, artifact_id, scan_id)
