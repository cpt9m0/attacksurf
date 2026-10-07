from flask.testing import FlaskClient


def test_index_renders(client: FlaskClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert b"<title>attacksurf</title>" in response.data
