"""Render every attacksurf UI page/state hermetically and capture Playwright screenshots.

Usage:
    uv run python scripts/capture_screenshots.py --out screenshots/baseline
"""

import argparse
import html as html_lib
import mimetypes
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

from flask.testing import FlaskClient
from playwright.sync_api import Page, Route, sync_playwright
from pydantic import SecretStr

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import make_session_user  # noqa: E402
from tests.e2e.web.ui_fixtures import (  # noqa: E402
    FINDING_1_ID,
    ROOT_ID,
    SCAN_DONE_ID,
    SCAN_RUNNING_ID,
    SUBDOMAIN_ID,
    patch_empty_ui,
    patch_populated_ui,
)
from tests.helpers import make_settings  # noqa: E402

from attacksurf import create_app  # noqa: E402
from attacksurf.domain.accounts import Role  # noqa: E402
from attacksurf.services import auth as auth_service  # noqa: E402
from attacksurf.services import finding_views  # noqa: E402
from attacksurf.services.auth import SessionUser  # noqa: E402

STATIC_SRC = REPO_ROOT / "src/attacksurf/web/static"
VIEWPORTS: dict[str, tuple[int, int]] = {
    "desktop": (1440, 900),
    "mobile": (390, 844),
}
THEMES = ("light", "dark")


@dataclass(frozen=True)
class ScreenSpec:
    slug: str
    title: str
    render: Callable[[FlaskClient], str]
    after_open: Callable[[Page], None] | None = None


def _extract_csrf(html_doc: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_doc)
    return match.group(1) if match else ""


def _render_login_error(client: FlaskClient) -> str:
    page = client.get("/login").get_data(as_text=True)
    token = _extract_csrf(page)
    resp = client.post(
        "/login",
        data={"csrf_token": token, "email": "alice@acme.example.com", "password": "wrong"},
    )
    if resp.status_code != HTTPStatus.UNPROCESSABLE_ENTITY:
        raise RuntimeError(f"Expected 422 on POST /login, got {resp.status_code}")
    return resp.get_data(as_text=True)


def _open_archive_dialog(page: Page) -> None:
    trigger = page.locator(".confirm button[aria-haspopup='dialog']").first
    if trigger.count():
        trigger.click()


def build_screen_specs(
    anon_client: FlaskClient,
    admin_client: FlaskClient,
    member_client: FlaskClient,
) -> tuple[ScreenSpec, ...]:
    """All 20 canonical UI screens and states."""

    def _with_empty(path: str, client: FlaskClient = admin_client) -> Callable[[FlaskClient], str]:
        def _render(_c: FlaskClient) -> str:
            with patch_empty_ui():
                resp = client.get(path)
                if resp.status_code != HTTPStatus.OK:
                    raise RuntimeError(f"Expected 200 for {path}, got {resp.status_code}")
                return resp.get_data(as_text=True)

        return _render

    def _with_populated(
        path: str,
        client: FlaskClient = admin_client,
        *,
        export_warning: bool = False,
    ) -> Callable[[FlaskClient], str]:
        def _render(_c: FlaskClient) -> str:
            with patch_populated_ui(export_warning=export_warning):
                resp = client.get(path)
                if resp.status_code != HTTPStatus.OK:
                    raise RuntimeError(f"Expected 200 for {path}, got {resp.status_code}")
                return resp.get_data(as_text=True)

        return _render

    def _render_500(_c: FlaskClient) -> str:
        def _boom(*_a: object, **_kw: object) -> object:
            raise RuntimeError("simulated error")

        with patch_populated_ui(), patch.object(finding_views, "get_dashboard", _boom):
            resp = admin_client.get("/")
            if resp.status_code != HTTPStatus.INTERNAL_SERVER_ERROR:
                raise RuntimeError(f"Expected 500 for simulated error, got {resp.status_code}")
            return resp.get_data(as_text=True)

    return (
        ScreenSpec("01-login", "Log in", _with_populated("/login", anon_client)),
        ScreenSpec(
            "02-login-error",
            "Log in (error)",
            lambda _c: _render_login_error_with_fixtures(anon_client),
        ),
        ScreenSpec("03-signup", "Sign up", _with_empty("/signup", anon_client)),
        ScreenSpec("04-dashboard-empty", "Dashboard (empty)", _with_empty("/")),
        ScreenSpec("05-dashboard", "Dashboard (populated)", _with_populated("/")),
        ScreenSpec("06-assets-empty", "Assets (empty)", _with_empty("/assets")),
        ScreenSpec("07-assets", "Assets (populated)", _with_populated("/assets")),
        ScreenSpec(
            "08-asset-detail-root",
            "Asset detail — Root domain (Overview)",
            _with_populated(f"/assets/{ROOT_ID}"),
        ),
        ScreenSpec(
            "09-asset-detail-dialog",
            "Asset detail — Confirm dialog open",
            _with_populated(f"/assets/{ROOT_ID}"),
            after_open=_open_archive_dialog,
        ),
        ScreenSpec(
            "10-asset-detail-subdomain",
            "Asset detail — Subdomain & IP details",
            _with_populated(f"/assets/{SUBDOMAIN_ID}"),
        ),
        ScreenSpec(
            "11-asset-detail-findings",
            "Asset detail — Findings tab",
            _with_populated(f"/assets/{ROOT_ID}?tab=findings"),
        ),
        ScreenSpec(
            "12-asset-detail-scans",
            "Asset detail — Scan history tab",
            _with_populated(f"/assets/{ROOT_ID}?tab=scans"),
        ),
        ScreenSpec("13-scans", "Scans (populated)", _with_populated("/scans")),
        ScreenSpec(
            "14-scan-detail-running",
            "Scan detail — Running",
            _with_populated(f"/scans/{SCAN_RUNNING_ID}"),
        ),
        ScreenSpec(
            "15-scan-detail-completed",
            "Scan detail — Completed (diff + AI summary + AI triage)",
            _with_populated(f"/scans/{SCAN_DONE_ID}"),
        ),
        ScreenSpec(
            "16-findings",
            "Findings (populated + export warning)",
            _with_populated("/findings?new=1", export_warning=True),
        ),
        ScreenSpec(
            "17-finding-detail",
            "Finding detail (evidence + stale AI triage + timeline)",
            _with_populated(f"/findings/{FINDING_1_ID}"),
        ),
        ScreenSpec("18-settings-admin", "Settings (Admin)", _with_populated("/settings")),
        ScreenSpec(
            "19-settings-member",
            "Settings (Member read-only)",
            _with_populated("/settings", member_client),
        ),
        ScreenSpec("20-error-500", "500 Error page", _render_500),
    )


def _render_login_error_with_fixtures(anon_client: FlaskClient) -> str:
    with patch_populated_ui():
        return _render_login_error(anon_client)


def _build_clients() -> tuple[dict[object, SessionUser], FlaskClient, FlaskClient, FlaskClient]:
    settings = make_settings(
        env="test",
        secret_key=SecretStr("test-secret-key"),
        allow_signup=True,
        app_encryption_key=SecretStr("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="),
    )
    app = create_app(settings)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    admin_user = make_session_user(
        role=Role.OWNER, email="alice.security.admin@acme-payments.example.com"
    )
    member_user = make_session_user(
        role=Role.MEMBER, email="bob.developer@acme-payments.example.com"
    )
    users: dict[object, SessionUser] = {
        admin_user.user_id: admin_user,
        member_user.user_id: member_user,
    }
    anon_client = app.test_client()
    admin_client = app.test_client()
    member_client = app.test_client()
    for client, user in ((admin_client, admin_user), (member_client, member_user)):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(user.user_id)
            sess["_fresh"] = True
            sess["auth_at"] = int(time.time())
    return users, anon_client, admin_client, member_client


def capture_all(
    out_dir: Path,
    *,
    themes: tuple[str, ...] = THEMES,
    viewport_names: tuple[str, ...] = ("desktop", "mobile"),
    only: str | None = None,
) -> list[dict[str, object]]:
    users, anon_client, admin_client, member_client = _build_clients()
    specs = build_screen_specs(anon_client, admin_client, member_client)
    if only:
        specs = tuple(s for s in specs if only in s.slug)

    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    current_html = ""

    def _handle_route(route: Route) -> None:
        url = route.request.url
        if "/static/" in url:
            rel = url.split("/static/", 1)[1].split("?", 1)[0]
            asset_path = (STATIC_SRC / rel).resolve()
            if asset_path.is_file() and STATIC_SRC.resolve() in asset_path.parents:
                content_type, _ = mimetypes.guess_type(asset_path.name)
                route.fulfill(
                    status=200,
                    body=asset_path.read_bytes(),
                    content_type=content_type or "application/octet-stream",
                )
                return
            route.fulfill(status=404, body="not found")
            return
        route.fulfill(status=200, body=current_html, content_type="text/html; charset=utf-8")

    with (
        patch.object(auth_service, "load_session_user", lambda _s, uid: users.get(uid)),
        sync_playwright() as playwright,
    ):
        browser = playwright.chromium.launch()

        for spec in specs:
            current_html = spec.render(admin_client)

            for vp_name in viewport_names:
                width, height = VIEWPORTS[vp_name]
                for theme in themes:
                    context = browser.new_context(viewport={"width": width, "height": height})
                    context.route("http://attacksurf.local/**", _handle_route)
                    page = context.new_page()
                    page.goto(f"http://attacksurf.local/{spec.slug}")
                    page.evaluate(
                        "t => document.documentElement.setAttribute('data-theme', t)",
                        theme,
                    )
                    if spec.after_open is not None:
                        spec.after_open(page)
                    scroll_w, inner_w = page.evaluate(
                        "() => [document.documentElement.scrollWidth, window.innerWidth]"
                    )
                    rel_png = f"{vp_name}/{theme}/{spec.slug}.png"
                    png_path = out_dir / rel_png
                    png_path.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(png_path), full_page=True)
                    context.close()
                    records.append(
                        {
                            "slug": spec.slug,
                            "title": spec.title,
                            "viewport": vp_name,
                            "width": width,
                            "theme": theme,
                            "scroll_width": scroll_w,
                            "inner_width": inner_w,
                            "overflow": scroll_w > inner_w,
                            "png": rel_png,
                        }
                    )

        browser.close()

    _write_gallery_index(out_dir, records)
    return records


def _write_gallery_index(out_dir: Path, records: list[dict[str, object]]) -> None:
    cards: list[str] = []
    for rec in records:
        status = (
            f"OVERFLOW ({rec['scroll_width']}px > {rec['inner_width']}px)"
            if rec["overflow"]
            else f"OK ({rec['scroll_width']}px <= {rec['inner_width']}px)"
        )
        title = html_lib.escape(str(rec["title"]))
        meta = f"{rec['viewport']} ({rec['width']}px) · {rec['theme']} · {status}"
        cards.append(
            "<figure style='margin:0;border:1px solid #ccc;padding:12px;"
            "border-radius:8px;background:#fff'>"
            "<figcaption style='font-family:system-ui;font-size:13px;margin-bottom:8px'>"
            f"<strong>{title}</strong><br>"
            f"<code>{rec['slug']}</code> · {meta}"
            "</figcaption>"
            f"<a href='{rec['png']}' target='_blank'>"
            f"<img src='{rec['png']}' style='width:100%;height:auto;"
            "border:1px solid #eee' loading='lazy'>"
            "</a></figure>"
        )
    gallery = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>attacksurf UI Screenshot Gallery</title></head>"
        "<body style='margin:24px;background:#f4f5f7;font-family:system-ui'>"
        "<h1>attacksurf UI Screenshot Gallery</h1>"
        "<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));"
        "gap:16px'>" + "".join(cards) + "</div></body></html>"
    )
    (out_dir / "index.html").write_text(gallery, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "screenshots/latest",
        help="Directory to write PNG screenshots and index.html",
    )
    parser.add_argument(
        "--themes",
        default="light,dark",
        help="Comma-separated themes (light,dark)",
    )
    parser.add_argument(
        "--viewports",
        default="desktop,mobile",
        help="Comma-separated viewports (desktop,mobile)",
    )
    parser.add_argument(
        "--only",
        default=None,
        help="Substring filter on screen slug",
    )
    args = parser.parse_args()
    themes = tuple(t.strip() for t in args.themes.split(",") if t.strip())
    viewports = tuple(v.strip() for v in args.viewports.split(",") if v.strip())
    records = capture_all(args.out, themes=themes, viewport_names=viewports, only=args.only)
    overflows = [r for r in records if r["overflow"]]
    print(f"Captured {len(records)} screenshots into {args.out} (overflows: {len(overflows)})")
    for r in overflows:
        print(
            f"  ! OVERFLOW: {r['slug']} ({r['viewport']}/{r['theme']}): "
            f"{r['scroll_width']}px > {r['inner_width']}px"
        )


if __name__ == "__main__":
    main()
