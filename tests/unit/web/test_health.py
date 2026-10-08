from flask import Flask
from flask.testing import FlaskClient


def test_healthz_returns_ok(client: FlaskClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_api_v1_blueprint_is_mounted_under_prefix(app: Flask) -> None:
    assert app.blueprints["api_v1"].url_prefix == "/api/v1"
