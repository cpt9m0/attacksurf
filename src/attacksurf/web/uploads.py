"""Upload plumbing shared by every upload route (#87 archives; binaries later): the request
size gate, the artifact store accessor, the rate limit and the error-to-status mapping."""

from pathlib import Path
from typing import Any

from flask import Flask, Response, current_app, request
from flask_login import current_user

from attacksurf.config import Settings
from attacksurf.domain.artifacts import (
    ArtifactPolicy,
    ArtifactStorageUnavailable,
    ArtifactStore,
    ArtifactTooLarge,
    UnsupportedArtifactFormat,
)
from attacksurf.domain.scans import ScanNotQueued
from attacksurf.infra.crypto import EnvelopeCipher
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.web.rendering import is_htmx_request, render_page

# Every route but uploads: forms and JSON here are tiny, so nothing larger is ever read.
DEFAULT_MAX_BODY_BYTES = 2 * 1024**2
# Room for the multipart boundaries, part headers and the CSRF field around the file.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
# Upload endpoint -> the form partial HTMX swaps in place; re-rendered when an upload is refused.
UPLOAD_ENDPOINTS = {"ui.upload_repo": "pages/_upload_repo_form.html"}
UPLOAD_LIMIT = "20 per hour"  # per signed-in user
# Refusals raised before the view runs (body ceiling, rate limit), shown as the field error.
_REFUSED = {
    413: "That file is too large to upload.",
    429: "Too many uploads. Wait a while and try again.",
}
NOT_CONFIGURED = "Uploads are not configured on this server: it has no encryption key."
_STORE_KEY = "artifact_store"
_POLICY_KEY = "artifact_policy"


def init_uploads(app: Flask, settings: Settings) -> None:
    """Cap request bodies. Call before `init_auth`: CSRF parses the whole form before a view
    runs, so the per-endpoint ceiling has to be set by an earlier `before_request`."""
    app.config["MAX_CONTENT_LENGTH"] = DEFAULT_MAX_BODY_BYTES
    key = settings.app_encryption_key_bytes
    app.extensions[_STORE_KEY] = (
        LocalArtifactStore(
            Path(settings.artifact_store_root),
            Path(settings.sandbox_artifact_root),
            EnvelopeCipher(key, purpose=b"artifact"),
        )
        if key
        else None
    )
    app.extensions[_POLICY_KEY] = ArtifactPolicy(
        max_bytes=settings.artifact_max_bytes,
        org_quota_bytes=settings.artifact_org_quota_bytes,
        retention_hours=settings.artifact_retention_hours,
    )

    @app.before_request
    def _raise_upload_ceiling() -> None:
        # A request that will be refused anyway keeps the small ceiling, and the rate limit is
        # spent here, so neither reads (and spools to disk) a large body first.
        if (
            request.endpoint not in UPLOAD_ENDPOINTS
            or not current_user.is_authenticated
            or get_artifact_store() is None
        ):
            return
        with app.extensions["auth_limiter"].limit(UPLOAD_LIMIT, key_func=_uploader_key):
            # Werkzeug stops reading at this many bytes, with or without a Content-Length.
            request.max_content_length = settings.artifact_max_bytes + MULTIPART_OVERHEAD_BYTES


def get_artifact_store() -> ArtifactStore | None:
    """The app's artifact storage, or None when no `APP_ENCRYPTION_KEY` is set."""
    return current_app.extensions[_STORE_KEY]


def get_artifact_policy() -> ArtifactPolicy:
    return current_app.extensions[_POLICY_KEY]


def upload_error_status(error: Exception) -> int:
    """HTTP status for an error an upload use case raised; 422 for plain invalid input."""
    statuses = {
        ArtifactTooLarge: 413,
        UnsupportedArtifactFormat: 415,
        ArtifactStorageUnavailable: 503,
        ScanNotQueued: 503,
    }
    return statuses.get(type(error), 422)


def upload_context() -> dict[str, Any]:
    """What every upload form partial needs to render."""
    return {
        "uploads_enabled": get_artifact_store() is not None,
        "upload_max_bytes": get_artifact_policy().max_bytes,
        "not_configured": NOT_CONFIGURED,
    }


def upload_form(error: str, status: int) -> Response:
    """The current upload endpoint's form with `error` on its field, for an HTMX swap."""
    template = UPLOAD_ENDPOINTS[request.endpoint or ""]
    return render_page(template, status=status, upload_error=error, **upload_context())


def refused_upload_form(status: int) -> Response | None:
    """The form for an HTMX upload refused before its view ran; None for anything else.

    Without this the generic error page would be swapped over the form.
    """
    if status in _REFUSED and request.endpoint in UPLOAD_ENDPOINTS and is_htmx_request():
        return upload_form(_REFUSED[status], status)
    return None


def _uploader_key() -> str:
    return f"upload:{current_user.session_user.user_id}"
