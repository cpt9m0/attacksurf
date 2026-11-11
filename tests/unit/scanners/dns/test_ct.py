"""Certificate Transparency source parsing and fallback (no network)."""

import json
from pathlib import Path

import pytest

from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.dns import ct

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "dns" / "discovery"
CRT_SH_NAMES = (
    "api.acme.example",
    "certspotter.acme.example",
    "dev.acme.example",
    "mail.acme.example",
    "www.acme.example",
    "xn--bcher-kva.acme.example",
)
CERTSPOTTER_NAMES = ("api.acme.example", "shop.acme.example", "www.acme.example")


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeHttp:
    def __init__(self, *responses: HttpBody | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.calls.append(url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self) -> None:
        pass


def body(name: str, *, headers: dict[str, str] | None = None) -> HttpBody:
    return HttpBody(status_code=200, content=fixture(name), headers=headers)


def test_crt_sh_parser_keeps_only_normalized_names_under_the_root() -> None:
    result = ct.parse_crt_sh(json.loads(fixture("crt_sh_example.json")), "acme.example")

    assert result.names == CRT_SH_NAMES
    assert result.wildcard_zones == ("acme.example", "dev.acme.example")


def test_crt_sh_parser_uses_common_name_too() -> None:
    result = ct.parse_crt_sh(
        [{"name_value": None, "common_name": "api.acme.example"}], "acme.example"
    )

    assert result.names == ("api.acme.example",)


def test_certspotter_parser_normalizes_names_and_wildcards() -> None:
    result = ct.parse_certspotter(json.loads(fixture("certspotter_example.json")), "acme.example")

    assert result.names == CERTSPOTTER_NAMES
    assert result.wildcard_zones == ("acme.example",)
    assert result.last_id == "2003"
    assert result.empty is False


def test_certspotter_parser_marks_an_empty_page() -> None:
    result = ct.parse_certspotter([], "acme.example")

    assert result.empty is True
    assert result.last_id is None
    assert result.names == ()


@pytest.mark.parametrize("payload", [{"name_value": "x"}, "text", None])
def test_parsers_reject_non_list_payloads(payload: object) -> None:
    with pytest.raises(ValueError, match="payload"):
        ct.parse_crt_sh(payload, "acme.example")
    with pytest.raises(ValueError, match="payload"):
        ct.parse_certspotter(payload, "acme.example")


def test_parser_ignores_a_name_that_is_the_root() -> None:
    result = ct.parse_crt_sh([{"name_value": "ACME.example"}], "acme.example")

    assert result.names == ()
    assert result.wildcard_zones == ()


def test_query_sources_uses_crt_sh_when_it_succeeds() -> None:
    http = FakeHttp(body("crt_sh_example.json"))

    result = ct.query_sources(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.names == CRT_SH_NAMES
    assert len(http.calls) == 1
    assert http.calls[0].startswith("https://crt.sh/?q=%25.acme.example")


@pytest.mark.parametrize(
    "failure",
    [
        HttpBody(status_code=503, content=b"unavailable"),
        HttpBody(status_code=200, content=b"not json"),
        HttpBody(status_code=200, content=fixture("crt_sh_example.json"), truncated=True),
        DnsError(),
        ScopeError("timed out"),
    ],
)
def test_query_sources_falls_back_to_certspotter(failure: HttpBody | Exception) -> None:
    http = FakeHttp(failure, body("certspotter_example.json"), HttpBody(200, b"[]"))

    result = ct.query_sources(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.names == CERTSPOTTER_NAMES
    assert http.calls[0].startswith("https://crt.sh/?q=%25.acme.example")
    assert http.calls[1].startswith("https://api.certspotter.com/v1/issuances?")
    assert http.calls[2].endswith("&after=2003")


def test_query_sources_returns_none_when_both_sources_fail() -> None:
    http = FakeHttp(HttpBody(status_code=503, content=b""), HttpBody(status_code=429, content=b""))

    assert ct.query_sources(http, "acme.example") is None  # type: ignore[arg-type]


def test_fetch_certspotter_uses_the_last_id_and_stops_on_an_empty_page() -> None:
    http = FakeHttp(
        body("certspotter_example.json"),
        body("certspotter_page2.json"),
        HttpBody(200, b"[]"),
    )

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is True
    assert "build.acme.example" in result.names
    assert http.calls == [
        "https://api.certspotter.com/v1/issuances?domain=acme.example&include_subdomains=true&expand=dns_names",
        "https://api.certspotter.com/v1/issuances?domain=acme.example&include_subdomains=true&expand=dns_names&after=2003",
        "https://api.certspotter.com/v1/issuances?domain=acme.example&include_subdomains=true&expand=dns_names&after=2004",
    ]


def test_fetch_certspotter_marks_an_empty_first_page_complete() -> None:
    http = FakeHttp(HttpBody(200, b"[]"))

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is True
    assert result.names == ()
    assert len(http.calls) == 1


def test_fetch_certspotter_is_incomplete_when_the_last_page_has_no_id() -> None:
    payload = json.dumps([{"dns_names": ["www.acme.example"]}]).encode()
    http = FakeHttp(HttpBody(200, payload))

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is False
    assert result.names == ("www.acme.example",)
    assert len(http.calls) == 1


def test_fetch_certspotter_returns_a_partial_result_when_a_later_page_fails() -> None:
    http = FakeHttp(body("certspotter_example.json"), HttpBody(status_code=503, content=b""))

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is False
    assert result.names == CERTSPOTTER_NAMES
    assert len(http.calls) == 2


def test_fetch_certspotter_stops_incomplete_on_a_repeated_cursor() -> None:
    http = FakeHttp(body("certspotter_example.json"), body("certspotter_example.json"))

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is False
    assert len(http.calls) == 2


def test_fetch_certspotter_stops_at_the_page_cap_as_incomplete() -> None:
    pages = [
        HttpBody(
            200,
            json.dumps([{"id": str(index), "dns_names": [f"p{index}.acme.example"]}]).encode(),
        )
        for index in range(1, ct.MAX_CERTSPOTTER_PAGES + 1)
    ]
    http = FakeHttp(*pages)

    result = ct.fetch_certspotter(http, "acme.example")  # type: ignore[arg-type]

    assert result is not None
    assert result.complete is False
    assert len(http.calls) == ct.MAX_CERTSPOTTER_PAGES
