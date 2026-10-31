"""JSON API v1 blueprint. Routes are added per feature (assets, scans, findings).

Session-authenticated like the UI (writes need the `X-CSRFToken` header); API tokens are a
later decision (ADR 0009).
"""

from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from flask import Blueprint, Response, jsonify, request, url_for
from flask_login import current_user

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetError, AssetNotFound, DomainAlreadyAdded
from attacksurf.services import asset_views
from attacksurf.services import assets as assets_service
from attacksurf.web.asset_params import parse_asset_filter
from attacksurf.web.auth import require_role
from attacksurf.web.db import get_session

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


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
    names = {404: "Not Found", 409: "Conflict", 422: "Unprocessable Entity"}
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
