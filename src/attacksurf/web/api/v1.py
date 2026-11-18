"""JSON API v1 blueprint. Routes are added per feature (assets, scans, findings).

Session-authenticated like the UI (writes need the `X-CSRFToken` header); API tokens are a
later decision (ADR 0009).
"""

from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from flask import Blueprint, Response, jsonify, request, url_for
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetError, AssetNotFound, DomainAlreadyAdded
from attacksurf.domain.scans import ScanAlreadyActive, ScanError, ScanNotFound, ScanRateLimited
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services import asset_views, scan_views
from attacksurf.services import assets as assets_service
from attacksurf.services import scans as scans_service
from attacksurf.web.asset_params import parse_asset_filter
from attacksurf.web.auth import get_settings, require_role
from attacksurf.web.db import get_session
from attacksurf.web.queue import get_task_queue
from attacksurf.web.scan_params import parse_scan_filter

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

log = structlog.get_logger(__name__)


@bp.get("/assets")
def list_assets() -> Response:
    flt, page = parse_asset_filter(request.args)
    result = asset_views.list_assets(get_session(), _org_id(), flt, page)
    return jsonify(
        items=[_json(row) for row in result.items],
        page=result.page,
        pages=result.pages,
        total=result.total,
    )


@bp.post("/assets")
def add_asset() -> Response:
    body = request.get_json(silent=True)
    value = body.get("value") if isinstance(body, dict) else None
    if not isinstance(value, str):
        return _error(422, 'Send a JSON object with a "value" string.')
    session = get_session()
    try:
        asset = assets_service.add_root_domain(
            session, _org_id(), value, actor_id=current_user.session_user.user_id
        )
    except AssetError as exc:
        return _asset_error(exc)
    response = jsonify(_json(asset_views.get_asset(session, _org_id(), asset.id)))
    response.status_code = 201
    response.headers["Location"] = url_for("api_v1.get_asset", asset_id=asset.id)
    return response


@bp.get("/assets/<uuid:asset_id>")
def get_asset(asset_id: UUID) -> Response:
    try:
        detail = asset_views.get_asset_detail(get_session(), _org_id(), asset_id)
    except AssetNotFound as exc:
        return _asset_error(exc)
    return jsonify(_json(detail))


@bp.get("/assets/<uuid:asset_id>/findings")
def list_asset_findings(asset_id: UUID) -> Response:
    try:
        findings = asset_views.list_asset_findings(get_session(), _org_id(), asset_id)
    except AssetNotFound as exc:
        return _asset_error(exc)
    return jsonify(items=[_json(f) for f in findings])


@bp.get("/assets/<uuid:asset_id>/scans")
def list_asset_scans(asset_id: UUID) -> Response:
    try:
        scans = asset_views.list_asset_scans(get_session(), _org_id(), asset_id)
    except AssetNotFound as exc:
        return _asset_error(exc)
    return jsonify(items=[_json(s) for s in scans])


@bp.get("/scans")
def list_scans() -> Response:
    flt, page = parse_scan_filter(request.args)
    result = scan_views.list_scans(get_session(), _org_id(), flt, page)
    return jsonify(
        items=[_json(row) for row in result.items],
        page=result.page,
        pages=result.pages,
        total=result.total,
    )


@bp.post("/scans")
def create_scan() -> Response:
    """Queue a scan of a root domain (session auth, writes need the `X-CSRFToken` header).

    The service refuses unknown profiles, inactive or foreign roots, a second concurrent
    scan of the same root (409, with the running scan's id) and starts over the hourly
    quota (429). A broker failure is already recorded as a failed scan (503 here).
    """
    body = request.get_json(silent=True)
    parsed = _parse_scan_body(body)
    if parsed is None:
        return _error(422, 'Send a JSON object with a "root_asset_id" UUID string.')
    root_id, profile = parsed
    session = get_session()
    try:
        scan = scans_service.start_scan(
            session,
            get_task_queue(),
            org_id=_org_id(),
            root_asset_id=root_id,
            profile=profile,
            registry=registry,
            profiles=PROFILES,
            max_starts_per_hour=get_settings().scan_max_starts_per_hour,
            actor_id=current_user.session_user.user_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        error = _scan_start_error(exc)
        if error is not None:
            return error
        # Broker down: the scan row is already marked failed.
        log.warning("scan not queued", error=type(exc).__name__)
        return _error(503, "The scan could not be queued. Try again in a moment.")
    detail = scan_views.get_scan_detail(session, _org_id(), scan.id)
    response = jsonify(_json(detail))
    response.status_code = 201
    response.headers["Location"] = url_for("api_v1.get_scan", scan_id=scan.id)
    return response


@bp.get("/scans/<uuid:scan_id>")
def get_scan(scan_id: UUID) -> Response:
    try:
        detail = scan_views.get_scan_detail(get_session(), _org_id(), scan_id)
    except ScanNotFound:
        return _error(404, "Scan not found.")
    return jsonify(_json(detail))


def _parse_scan_body(body: Any) -> tuple[UUID, str] | None:
    """`(root_id, profile)` from a `POST /scans` body, or None when it is malformed."""
    fields = body if isinstance(body, dict) else {}
    root_raw = fields.get("root_asset_id")
    profile = fields.get("profile") or "dns_passive"
    if not isinstance(root_raw, str) or not isinstance(profile, str):
        return None
    try:
        return UUID(root_raw), profile
    except ValueError:
        return None


def _scan_start_error(exc: Exception) -> Response | None:
    """The response for a `start_scan` refusal, or None for a broker failure (503)."""
    if isinstance(exc, ScanAlreadyActive):
        response = jsonify(error="Conflict", message=str(exc), scan_id=str(exc.scan_id))
        response.status_code = 409
        return response
    if isinstance(exc, ScanRateLimited):
        return _error(429, str(exc))
    if isinstance(exc, AssetNotFound):
        return _asset_error(exc)
    if isinstance(exc, ScanError):
        return _error(422, str(exc))
    return None


@bp.post("/assets/<uuid:asset_id>/archive")
@require_role(Role.ADMIN)
def archive_asset(asset_id: UUID) -> Response:
    session = get_session()
    try:
        assets_service.archive_root_domain(
            session, _org_id(), asset_id, actor_id=current_user.session_user.user_id
        )
    except AssetNotFound as exc:
        return _asset_error(exc)
    return jsonify(_json(asset_views.get_asset(session, _org_id(), asset_id)))


def _org_id() -> UUID:
    return current_user.session_user.org_id


def _asset_error(exc: AssetError) -> Response:
    # Asset error messages are written for users and never carry other orgs' data.
    if isinstance(exc, AssetNotFound):
        return _error(404, str(exc))
    if isinstance(exc, DomainAlreadyAdded):
        return _error(409, str(exc))
    return _error(422, str(exc))


def _error(status: int, message: str) -> Response:
    names = {
        404: "Not Found",
        409: "Conflict",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        503: "Service Unavailable",
    }
    response = jsonify(error=names[status], message=message)
    response.status_code = status
    return response


def _json(row: "DataclassInstance") -> dict[str, Any]:
    """Dataclass → JSON-ready dict: ISO 8601 datetimes (Flask would send HTTP dates)."""
    return _jsonable(asdict(row))


def _jsonable(value: Any) -> Any:
    match value:
        case datetime():
            return value.isoformat()
        case UUID():
            return str(value)
        case dict():
            return {key: _jsonable(item) for key, item in value.items()}
        case list() | tuple():
            return [_jsonable(item) for item in value]
        case _:
            return value
