"""Binary sources (#101): an uploaded executable or mobile app becomes a binary asset named by
its SHA-256, an artifact and a queued static-analysis scan. Never run, never parsed here."""

import hashlib
from typing import IO
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.domain.artifacts import (
    SNIFF_BYTES,
    ArtifactKind,
    ArtifactPolicy,
    ArtifactStore,
    ArtifactTooLarge,
    UnsupportedArtifactFormat,
    sniff_binary,
)
from attacksurf.domain.assets import BINARY_PREFIX, AssetSource, AssetType
from attacksurf.domain.jobs import TaskQueue
from attacksurf.scanners.profiles import BINARY_STATIC_PROFILE
from attacksurf.services.artifacts import check_quota
from attacksurf.services.assets import record_asset
from attacksurf.services.uploads import (
    AnalysisRequest,
    AssetUpload,
    display_name,
    store_and_queue_analysis,
)

BINARY_SCAN_TASK = "analysis.binary_static"
_BINARY_SCAN = AnalysisRequest(
    ArtifactKind.BINARY, BINARY_STATIC_PROFILE, BINARY_SCAN_TASK, "binary.uploaded"
)
_CHUNK = 1024 * 1024


def upload_binary(
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
    """Store an uploaded binary under the asset `sha256:<digest>` and queue its static scan.

    `source` must be seekable: it is read twice, in chunks (hash, then store). Only its leading
    bytes are interpreted here, as a hint; the sandbox detects the real format
    (`sandbox_tools.detect`). The same bytes uploaded again reuse the asset, which then shows
    the latest file name, and add an artifact and a scan.
    Raises `UnsupportedArtifactFormat`, `ArtifactTooLarge` and `ArtifactQuotaExceeded` before
    anything is written, and what `store_and_queue_analysis` raises: a failure there (storage
    down, or a concurrent upload that took the last of the quota) leaves the asset in place.
    """
    hint = sniff_binary(source.read(SNIFF_BYTES))
    if hint is None:
        raise UnsupportedArtifactFormat(
            "Upload an ELF, PE or Mach-O executable, an Android .apk or an iOS .ipa."
        )
    source.seek(0)
    sha256, size_bytes = _sha256(source, policy.max_bytes)
    source.seek(0)
    check_quota(session, policy, org_id, size_bytes)  # before the asset: a refusal leaves none
    asset = record_asset(
        session, org_id, AssetType.BINARY, BINARY_PREFIX + sha256, source=AssetSource.USER
    )
    upload = {"filename": display_name(filename), "format_hint": hint}
    asset.details = {**asset.details, "upload": upload}
    asset_id, value = asset.id, asset.value
    session.commit()  # `store_artifact` holds no transaction while it streams
    artifact_id, scan_id = store_and_queue_analysis(
        session,
        store,
        policy,
        queue,
        _BINARY_SCAN,
        org_id=org_id,
        asset_id=asset_id,
        source=source,
        actor_id=actor_id,
        expected_sha256=sha256,
        audit_details={"format_hint": hint},
    )
    return AssetUpload(asset_id, value, artifact_id, scan_id)


def _sha256(source: IO[bytes], max_bytes: int) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    while chunk := source.read(_CHUNK):
        size += len(chunk)
        if size > max_bytes:
            raise ArtifactTooLarge("The artifact is larger than the allowed size.")
        digest.update(chunk)
    return digest.hexdigest(), size
