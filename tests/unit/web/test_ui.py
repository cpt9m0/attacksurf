import json
import re
from pathlib import Path

import pytest
from flask import Flask, Response, flash
from flask.testing import FlaskClient

import attacksurf.web
from attacksurf.web.rendering import render_page

STATIC = Path(attacksurf.web.__file__).parent / "static"

PAGES = [
    ("/", "Dashboard"),
    ("/assets", "Assets"),
    ("/scans", "Scans"),
    ("/findings", "Findings"),
    ("/settings", "Settings"),
]


@pytest.mark.parametrize(("path", "title"), PAGES)
def test_nav_page_renders_in_shell(client: FlaskClient, path: str, title: str) -> None:
    response = client.get(path)
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert f"<title>{title} · attacksurf</title>" in html
    assert 'class="shell"' in html
    assert f"<h1>{title}</h1>" in html


@pytest.mark.parametrize(("path", "title"), PAGES)
def test_current_nav_item_is_marked(client: FlaskClient, path: str, title: str) -> None:
    html = client.get(path).get_data(as_text=True)

    current = re.findall(r'<a href="([^"]+)" aria-current="page">', html)
    assert current == [path]


def test_shell_links_to_source_code(client: FlaskClient) -> None:
    # AGPL-3.0 section 13: network users must be offered the source.
    response = client.get("/")

    assert b'href="https://github.com/cpt9m0/attacksurf"' in response.data


def test_htmx_request_gets_fragment_only(client: FlaskClient) -> None:
    response = client.get("/assets", headers={"HX-Request": "true"})
    html = response.get_data(as_text=True)

    assert "<html" not in html
    assert 'class="shell"' not in html
    assert "<title>Assets · attacksurf</title>" in html
    assert "<h1>Assets</h1>" in html


def test_boosted_htmx_request_gets_full_page(client: FlaskClient) -> None:
    response = client.get("/assets", headers={"HX-Request": "true", "HX-Boosted": "true"})

    assert b'class="shell"' in response.data


def test_pages_vary_on_htmx_headers(client: FlaskClient) -> None:
    vary = client.get("/").headers["Vary"]

    assert "HX-Request" in vary
    assert "HX-Boosted" in vary


def test_htmx_fragment_includes_flash_messages(app: Flask) -> None:
    @app.get("/_test/flash")
    def flashing() -> Response:
        flash("Saved", "success")
        return render_page("pages/assets.html")

    html = (
        app.test_client().get("/_test/flash", headers={"HX-Request": "true"}).get_data(as_text=True)
    )

    assert 'class="shell"' not in html
    assert 'class="flash flash-success">Saved' in html


def test_htmx_config_swaps_error_responses(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    match = re.search(r"<meta name=\"htmx-config\" content='([^']+)'", html)
    assert match
    config = json.loads(match.group(1))
    assert config["includeIndicatorStyles"] is False
    assert config["allowEval"] is False
    assert {"code": "[2345]..", "swap": True} in config["responseHandling"]


def test_theme_toggle_exposes_pressed_state(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    assert 'aria-label="Dark mode" aria-pressed="false" :aria-pressed="pressed"' in html


def test_app_css_uses_tokens_not_raw_colors() -> None:
    # Claude Design swaps tokens.css only; app.css must not hard-code colors.
    css = (STATIC / "css" / "app.css").read_text()

    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(", css)


@pytest.mark.parametrize("path", [p for p, _ in PAGES])
def test_pages_have_no_inline_script_or_style(client: FlaskClient, path: str) -> None:
    # The CSP blocks inline code; this keeps templates from silently breaking under it.
    html = client.get(path).get_data(as_text=True)

    assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html)
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert not re.search(r"\sstyle\s*=", html)
    assert "<style" not in html


def test_shell_loads_vendored_scripts_from_own_origin(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    srcs = re.findall(r'<script src="([^"]+)"', html)
    assert srcs
    assert all(src.startswith("/static/") for src in srcs)


def test_static_assets_are_served(client: FlaskClient) -> None:
    for path in (
        "/static/css/tokens.css",
        "/static/css/app.css",
        "/static/icons.svg",
        "/static/favicon.svg",
    ):
        assert client.get(path).status_code == 200
