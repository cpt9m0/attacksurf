"""The app shell must fit a 390px phone viewport (#114) and fill a wide one (#149).

The real templates and stylesheets run in Chromium without a server or a database: the rendered
page is written to a temporary directory next to a copy of `static/` and opened as a `file://`
URL. That keeps the check hermetic (no Compose stack, no network, no login round-trip) while
still measuring what a browser actually lays out, which a CSS rule test cannot.
"""

import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

import pytest
from flask.testing import FlaskClient
from playwright.sync_api import Browser, Error, Page, expect, sync_playwright

from tests.e2e.web.conftest import LONG_EMAIL
from tests.e2e.web.ui_fixtures import (
    FINDING_1_ID,
    ROOT_ID,
    SCAN_DONE_ID,
    patch_populated_ui,
)

pytestmark = [
    pytest.mark.web_e2e,
    pytest.mark.skipif(
        os.environ.get("RUN_WEB_E2E") != "1",
        reason="needs RUN_WEB_E2E=1 + `uv run playwright install chromium`",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[3]
STATIC = REPO_ROOT / "src/attacksurf/web/static"
PHONE_WIDTH = 390
WIDE_WIDTH = 1440
NAV_PAGES = (
    ("/", "Dashboard"),
    ("/assets", "Assets"),
    ("/scans", "Scans"),
    ("/findings", "Findings"),
    ("/settings", "Settings"),
)
THEMES = ("light", "dark")


class Shell(Protocol):
    """Open a rendered page at a viewport width (phone width unless `width` is given)."""

    def __call__(self, path: str, theme: str, *, width: int = PHONE_WIDTH) -> Page: ...


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Error as exc:  # the browser binary is a separate download
            pytest.skip(f"Playwright chromium is not installed ({exc})")
        yield instance
        instance.close()


@pytest.fixture
def shell(browser: Browser, phone_client: FlaskClient, tmp_path: Path) -> Iterator[Shell]:
    """Render a page next to a copy of `static/` and open it at the requested width."""
    shutil.copytree(STATIC, tmp_path / "static")
    opened: list[Page] = []

    def _open(path: str, theme: str, *, width: int = PHONE_WIDTH) -> Page:
        html = phone_client.get(path).get_data(as_text=True)
        # Same document, served from disk: `/static/...` resolves to the copy next to it.
        html = html.replace('"/static/', '"static/').replace("'/static/", "'static/")
        name = path.strip("/").replace("/", "-") or "dashboard"
        document = tmp_path / f"shell-{name}.html"
        document.write_text(html, encoding="utf-8")
        page = browser.new_page(viewport={"width": width, "height": 844})
        opened.append(page)
        page.goto(document.as_uri())
        # theme.js sets this from localStorage; the attribute is what the tokens key off.
        page.evaluate("theme => document.documentElement.setAttribute('data-theme', theme)", theme)
        return page

    yield _open
    for page in opened:
        page.close()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize(("path", "title"), NAV_PAGES)
def test_nav_pages_fit_a_phone_viewport(shell: Shell, path: str, title: str, theme: str) -> None:
    page = shell(path, theme)

    # The real page, not an error page: the error layout would also render the shell.
    assert page.locator("h1").first.inner_text() == title
    scroll_width, inner_width = page.evaluate(
        "() => [document.documentElement.scrollWidth, window.innerWidth]"
    )

    assert inner_width == PHONE_WIDTH
    assert scroll_width <= inner_width, f"{path} is {scroll_width}px wide in the {theme} theme"


@pytest.mark.parametrize("theme", THEMES)
def test_dashboard_fills_the_main_column_on_a_wide_screen(shell: Shell, theme: str) -> None:
    page = shell("/", theme, width=WIDE_WIDTH)

    # The real page, not an error page: the error layout would also render the shell.
    assert page.locator("h1").first.inner_text() == "Dashboard"
    layout = page.evaluate(
        """() => {
            const box = selector => document.querySelector(selector).getBoundingClientRect();
            const content = box('.content');
            return {viewport: window.innerWidth,
                    layoutWidth: document.documentElement.clientWidth,
                    scrollWidth: document.documentElement.scrollWidth,
                    contentLeft: content.left, contentRight: content.right,
                    navRight: box('.sidenav').right};
        }"""
    )

    assert layout["viewport"] == WIDE_WIDTH
    assert round(layout["contentLeft"]) == round(layout["navRight"])  # starts after the nav
    assert round(layout["contentRight"]) == layout["layoutWidth"]  # no unused band on the right
    assert layout["scrollWidth"] <= layout["layoutWidth"]  # the shell still fits the screen


def test_user_menu_truncates_instead_of_widening_the_top_bar(shell: Shell) -> None:
    page = shell("/", "light")

    menu = page.evaluate(
        """() => {
            const el = document.querySelector('.user-menu');
            return {client: el.clientWidth, scroll: el.scrollWidth, title: el.title};
        }"""
    )

    assert len(LONG_EMAIL) == 40
    assert menu["client"] < menu["scroll"]  # ellipsized, not clipped away
    assert menu["title"].startswith(LONG_EMAIL)  # the full text stays available


def test_mobile_nav_scrolls_inside_itself(shell: Shell) -> None:
    page = shell("/", "light")

    nav = page.evaluate(
        """() => {
            const el = document.querySelector('.sidenav');
            return {client: el.clientWidth, scroll: el.scrollWidth,
                    overflow: getComputedStyle(el).overflowX};
        }"""
    )

    assert nav["scroll"] > nav["client"]  # the row is wider than the screen, by design
    assert nav["overflow"] == "auto"


POPULATED_PATHS = (
    "/",
    "/assets",
    f"/assets/{ROOT_ID}",
    f"/assets/{ROOT_ID}?tab=findings",
    "/scans",
    f"/scans/{SCAN_DONE_ID}",
    "/findings",
    f"/findings/{FINDING_1_ID}",
    "/settings",
)


@pytest.mark.parametrize("width", [PHONE_WIDTH, WIDE_WIDTH])
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("path", POPULATED_PATHS)
def test_populated_pages_fit_viewport_without_horizontal_overflow(
    shell: Shell, path: str, theme: str, width: int
) -> None:
    with patch_populated_ui():
        page = shell(path, theme, width=width)

    scroll_width, inner_width = page.evaluate(
        "() => [document.documentElement.scrollWidth, window.innerWidth]"
    )
    assert inner_width == width
    assert scroll_width <= inner_width, (
        f"{path} ({width}px, {theme}) overflowed at {scroll_width}px"
    )


def test_asset_detail_findings_tab_links_to_finding_detail(shell: Shell) -> None:
    with patch_populated_ui():
        page = shell(f"/assets/{ROOT_ID}?tab=findings", "light", width=WIDE_WIDTH)

    href = page.locator("table.data tbody tr a").first.get_attribute("href")
    assert href == f"/findings/{FINDING_1_ID}"


def test_scan_detail_card_headers_are_padded_and_nav_stays_highlighted(shell: Shell) -> None:
    with patch_populated_ui():
        page = shell(f"/scans/{SCAN_DONE_ID}", "light", width=WIDE_WIDTH)

    metrics = page.evaluate(
        """() => {
            const el = document.querySelector('#scan-progress > .card-header');
            const header = getComputedStyle(el);
            const activeNav = document.querySelector('.sidenav a[aria-current="true"]');
            return {
                paddingLeft: parseFloat(header.paddingLeft),
                paddingTop: parseFloat(header.paddingTop),
                activeNavHref: activeNav ? activeNav.getAttribute('href') : null,
            };
        }"""
    )
    assert metrics["paddingLeft"] >= 16
    assert metrics["paddingTop"] >= 12
    assert metrics["activeNavHref"] == "/scans"


def test_finding_detail_copy_button_copies_evidence_body(shell: Shell) -> None:
    with patch_populated_ui():
        page = shell(f"/findings/{FINDING_1_ID}", "light", width=WIDE_WIDTH)

    page.evaluate(
        """() => {
            window.__copiedText = null;
            Object.defineProperty(navigator, "clipboard", {
                value: {
                    writeText(text) {
                        window.__copiedText = text;
                        return Promise.resolve();
                    },
                },
                configurable: true,
            });
        }"""
    )
    copy_btn = page.locator(".evidence").first.locator("button")
    expected = page.locator(".evidence .evidence-body").first.inner_text()
    copy_btn.click()

    expect(copy_btn).to_have_attribute("aria-pressed", "true")
    expect(copy_btn).to_have_text("Copied")
    assert page.evaluate("() => window.__copiedText") == expected
