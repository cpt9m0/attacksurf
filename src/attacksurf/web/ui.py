"""HTML UI blueprint (Jinja + HTMX pages)."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from flask import Blueprint, Response, abort, flash, redirect, request, url_for
from flask_login import current_user
from werkzeug.wrappers.response import Response as BaseResponse

from attacksurf.domain.accounts import Role, has_role
from attacksurf.domain.assets import AssetError, AssetNotFound, AssetType
from attacksurf.services import asset_views
from attacksurf.services import assets as assets_service
from attacksurf.services.asset_views import AssetFilter, AssetStatus
from attacksurf.web.asset_params import parse_asset_filter
from attacksurf.web.auth import require_role
from attacksurf.web.db import get_session
from attacksurf.web.formatting import exact_time, humanize_delta
from attacksurf.web.rendering import is_htmx_request, render_page

bp = Blueprint("ui", __name__)


@dataclass(frozen=True)
class NavItem:
    endpoint: str
    label: str
    icon: str
    subpages: tuple[str, ...] = ()  # endpoints that keep this item highlighted


NAV_ITEMS = (
    NavItem("ui.dashboard", "Dashboard", "layout-dashboard"),
    NavItem("ui.assets", "Assets", "globe", subpages=("ui.asset_detail",)),
    NavItem("ui.scans", "Scans", "radar"),
    NavItem("ui.findings", "Findings", "bug"),
    NavItem("ui.settings", "Settings", "settings"),
)
# Repo and binary assets don't exist yet (post-MVP modules), so they aren't offered as filters.
_TYPE_LABELS = {
    AssetType.DOMAIN: "Domain",
    AssetType.SUBDOMAIN: "Subdomain",
    AssetType.IP: "IP address",
    AssetType.URL: "URL",
}
ASSET_TABS = (("overview", "Overview"), ("findings", "Findings"), ("scans", "Scan history"))


@bp.app_context_processor
def _layout_context() -> dict[str, Any]:
    return {"nav_items": NAV_ITEMS, "is_htmx": is_htmx_request()}


@bp.app_template_filter("timeago")
def _timeago(value: datetime) -> str:
    return humanize_delta(value, datetime.now(UTC))


@bp.app_template_filter("exact_time")
def _exact_time(value: datetime) -> str:
    return exact_time(value)


@bp.get("/")
def dashboard() -> Response:
    return render_page("pages/dashboard.html")


@bp.get("/assets")
def assets() -> Response:
    flt, page = parse_asset_filter(request.args)
    return _assets_page(flt, page)


@bp.post("/assets")
def add_domain() -> BaseResponse:
    value = request.form.get("value", "")
    try:
        asset = assets_service.add_root_domain(
            get_session(), _org_id(), value, actor_id=current_user.session_user.user_id
        )
    except AssetError as exc:
        if is_htmx_request():
            return render_page(
                "pages/_add_domain_form.html", status=422, add_value=value, add_error=str(exc)
            )
        return _assets_page(AssetFilter(), 1, status=422, add_value=value, add_error=str(exc))
    flash(f"Added {asset.value}. Run a scan to discover what's under it.", "success")
    target = url_for("ui.asset_detail", asset_id=asset.id)
    if is_htmx_request():
        # A redirect would be followed and swapped into the form; this makes HTMX navigate.
        return Response(status=200, headers={"HX-Redirect": target})
    return redirect(target, 303)


@bp.get("/assets/<uuid:asset_id>")
def asset_detail(asset_id: UUID) -> Response:
    tab = request.args.get("tab", "overview")
    if tab not in dict(ASSET_TABS):
        tab = "overview"
    session = get_session()
    try:
        detail = asset_views.get_asset_detail(session, _org_id(), asset_id)
        findings = (
            asset_views.list_asset_findings(session, _org_id(), asset_id)
            if tab == "findings"
            else ()
        )
        scans = asset_views.list_asset_scans(session, _org_id(), asset_id) if tab == "scans" else ()
    except AssetNotFound:
        abort(404)
    asset = detail.asset
    return render_page(
        "pages/asset_detail.html",
        detail=detail,
        asset=asset,
        tab=tab,
        tabs=ASSET_TABS,
        findings=findings,
        scans=scans,
        can_archive=asset.is_active
        and asset.type == AssetType.DOMAIN
        and asset.root_id is None
        and has_role(current_user.role, Role.ADMIN),
    )


@bp.post("/assets/<uuid:asset_id>/archive")
@require_role(Role.ADMIN)
def archive_asset(asset_id: UUID) -> BaseResponse:
    try:
        asset = assets_service.archive_root_domain(
            get_session(), _org_id(), asset_id, actor_id=current_user.session_user.user_id
        )
    except AssetNotFound:
        abort(404)
    flash(f"Archived {asset.value} and the assets discovered under it.", "success")
    return redirect(url_for("ui.assets"), 303)


@bp.get("/scans")
def scans() -> Response:
    return render_page("pages/scans.html")


@bp.get("/findings")
def findings() -> Response:
    return render_page("pages/findings.html")


@bp.get("/settings")
def settings() -> Response:
    return render_page("pages/settings.html")


def _org_id() -> UUID:
    return current_user.session_user.org_id


def _assets_page(flt: AssetFilter, page: int, status: int = 200, **form: str) -> Response:
    session = get_session()
    roots = asset_views.list_root_domains(session, _org_id())
    filter_args = {
        "type": flt.type,
        "root": flt.root_id,
        "tag": flt.tag,
        "q": flt.q,
        "status": None if flt.status is AssetStatus.ACTIVE else flt.status,
    }
    return render_page(
        "pages/assets.html",
        status=status,
        result=asset_views.list_assets(session, _org_id(), flt, page),
        flt=flt,
        filtered=flt != AssetFilter(),
        # Non-default filters only, so pagination links stay short and shareable.
        filter_args={key: value for key, value in filter_args.items() if value},
        type_options=[("", "All types")] + [(t.value, _TYPE_LABELS[t]) for t in _TYPE_LABELS],
        root_options=[("", "All roots")]
        + [(r.id, r.value if r.is_active else f"{r.value} (archived)") for r in roots],
        status_options=[(s.value, s.value.capitalize()) for s in AssetStatus],
        add_value=form.get("add_value", ""),
        add_error=form.get("add_error"),
    )
