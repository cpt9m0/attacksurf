"""HTML UI blueprint (Jinja + HTMX pages)."""

from dataclasses import dataclass
from typing import Any

from flask import Blueprint, Response

from attacksurf.web.rendering import is_htmx_request, render_page

bp = Blueprint("ui", __name__)


@dataclass(frozen=True)
class NavItem:
    endpoint: str
    label: str
    icon: str


NAV_ITEMS = (
    NavItem("ui.dashboard", "Dashboard", "layout-dashboard"),
    NavItem("ui.assets", "Assets", "globe"),
    NavItem("ui.scans", "Scans", "radar"),
    NavItem("ui.findings", "Findings", "bug"),
    NavItem("ui.settings", "Settings", "settings"),
)


@bp.app_context_processor
def _layout_context() -> dict[str, Any]:
    return {"nav_items": NAV_ITEMS, "is_htmx": is_htmx_request()}


@bp.get("/")
def dashboard() -> Response:
    return render_page("pages/dashboard.html")


@bp.get("/assets")
def assets() -> Response:
    return render_page("pages/assets.html")


@bp.get("/scans")
def scans() -> Response:
    return render_page("pages/scans.html")


@bp.get("/findings")
def findings() -> Response:
    return render_page("pages/findings.html")


@bp.get("/settings")
def settings() -> Response:
    return render_page("pages/settings.html")
