from flask.testing import FlaskClient


def test_index_renders(client: FlaskClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert b"<title>attacksurf</title>" in response.data


def test_index_links_to_source_code(client: FlaskClient) -> None:
    # AGPL-3.0 section 13: network users must be offered the source.
    response = client.get("/")

    assert b'href="https://github.com/cpt9m0/attacksurf"' in response.data
