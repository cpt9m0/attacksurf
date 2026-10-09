from flask.testing import FlaskClient

from attacksurf.app import create_app
from tests.helpers import PROD_SECRET_KEY, make_settings


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
