import ast
import re
from pathlib import Path

from flask.testing import FlaskClient

from attacksurf.app import create_app
from tests.helpers import PROD_SECRET_KEY, make_settings

SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "attacksurf"
TEMPLATES_ROOT = SRC_ROOT / "web" / "templates"
TEMPLATE_FILES = sorted(TEMPLATES_ROOT.rglob("*.html"))


def test_csp_forbids_inline_and_eval(client: FlaskClient) -> None:
    csp = client.get("/").headers["Content-Security-Policy"]

    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_security_headers_present(client: FlaskClient) -> None:
    headers = client.get("/").headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in headers["Permissions-Policy"]


def test_security_headers_also_on_errors_and_api(client: FlaskClient) -> None:
    for path in ("/does-not-exist", "/healthz"):
        assert "Content-Security-Policy" in client.get(path).headers


def test_no_hsts_outside_prod(client: FlaskClient) -> None:
    assert "Strict-Transport-Security" not in client.get("/").headers


def test_hsts_in_prod() -> None:
    app = create_app(make_settings(env="prod", secret_key=PROD_SECRET_KEY))

    headers = app.test_client().get("/healthz").headers

    assert headers["Strict-Transport-Security"].startswith("max-age=63072000")


def test_security_headers_present_on_auth_and_api_errors(client: FlaskClient) -> None:
    for path in ("/login", "/signup", "/api/v1/assets"):
        headers = client.get(path).headers
        assert "Content-Security-Policy" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"


def test_templates_enforce_strict_csp_and_autoescape() -> None:
    assert TEMPLATE_FILES
    for template in TEMPLATE_FILES:
        text = re.sub(r"\{#.*?#\}", "", template.read_text(encoding="utf-8"), flags=re.S)
        assert "|safe" not in text, f"|safe forbidden in {template}"
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", text), f"inline script in {template}"
        assert "<style" not in text.lower(), f"<style> tag in {template}"
        assert not re.search(r"\sstyle\s*=", text), f"inline style= in {template}"
        assert not re.search(r"\son[a-z]+\s*=", text), f"inline event handler in {template}"
        assert "javascript:" not in text.lower(), f"javascript: URL in {template}"


def test_application_reads_config_only_through_settings() -> None:
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and node.attr in {"environ", "getenv"}
            ):
                raise AssertionError(f"Direct os.{node.attr} access in {py_file}")
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "os"
                and any(alias.name in {"environ", "getenv"} for alias in node.names)
            ):
                raise AssertionError(f"Direct from os import environ/getenv in {py_file}")
