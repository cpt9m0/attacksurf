import re

import pytest
from flask.testing import FlaskClient

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


def test_pages_vary_on_htmx_header(client: FlaskClient) -> None:
    response = client.get("/")

    assert "HX-Request" in response.headers["Vary"]


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
