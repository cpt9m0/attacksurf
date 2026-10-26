import pytest
from flask import Flask, abort
from flask.testing import FlaskClient

from tests.unit.web.conftest import LoginAs, make_session_user


@pytest.fixture
def failing_app(app: Flask) -> Flask:
    def boom() -> str:
        raise RuntimeError("secret internal detail")

    def forbidden() -> str:
        abort(403)

    app.add_url_rule("/_test/boom", view_func=boom)
    app.add_url_rule("/_test/forbidden", view_func=forbidden)
    app.add_url_rule("/api/v1/_test/boom", "api_boom", view_func=boom)
    return app


@pytest.fixture
def failing_client(failing_app: Flask, login_as: LoginAs) -> FlaskClient:
    client = failing_app.test_client()
    login_as(client, make_session_user())
    return client


@pytest.fixture
def no_csrf(app: Flask) -> Flask:
    # These tests are about routing errors, not CSRF (covered in test_auth.py).
    app.config["WTF_CSRF_ENABLED"] = False
    return app


def test_404_renders_error_page_in_shell(client: FlaskClient) -> None:
    response = client.get("/no-such-page")
    html = response.get_data(as_text=True)

    assert response.status_code == 404
    assert "<h1>Not Found</h1>" in html
    assert 'class="shell"' in html
    assert "Request ID" not in html


def test_403_renders_error_page(failing_client: FlaskClient) -> None:
    response = failing_client.get("/_test/forbidden")

    assert response.status_code == 403
    assert b"<h1>Forbidden</h1>" in response.data


def test_500_hides_details_and_shows_request_id(failing_client: FlaskClient) -> None:
    response = failing_client.get("/_test/boom", headers={"X-Request-ID": "req-123"})
    html = response.get_data(as_text=True)

    assert response.status_code == 500
    assert "<h1>Internal Server Error</h1>" in html
    assert "secret internal detail" not in html
    assert "req-123" in html


def test_500_is_logged(failing_client: FlaskClient, caplog: pytest.LogCaptureFixture) -> None:
    failing_client.get("/_test/boom")

    assert any("unhandled exception" in r.getMessage() for r in caplog.records)


def test_405_keeps_allow_header(no_csrf: Flask, client: FlaskClient) -> None:
    response = client.post("/")

    assert response.status_code == 405
    assert "GET" in response.headers["Allow"]
    assert response.mimetype == "text/html"


def test_api_405_is_json_and_keeps_allow_header(
    no_csrf: Flask, failing_client: FlaskClient
) -> None:
    response = failing_client.post("/api/v1/_test/boom")

    assert response.status_code == 405
    assert response.get_json() == {"error": "Method Not Allowed"}
    assert "GET" in response.headers["Allow"]


def test_api_errors_are_json(client: FlaskClient) -> None:
    response = client.get("/api/v1/no-such-endpoint")

    assert response.status_code == 404
    assert response.is_json
    assert response.get_json() == {"error": "Not Found"}


def test_api_500_is_json_without_details(failing_client: FlaskClient) -> None:
    response = failing_client.get("/api/v1/_test/boom")

    assert response.status_code == 500
    assert response.get_json() == {"error": "Internal Server Error"}


def test_htmx_error_returns_fragment(client: FlaskClient) -> None:
    response = client.get("/no-such-page", headers={"HX-Request": "true"})

    assert response.status_code == 404
    assert b'class="shell"' not in response.data
