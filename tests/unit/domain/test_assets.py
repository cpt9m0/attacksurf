import pytest

from attacksurf.domain.assets import (
    MAX_URL_LENGTH,
    AssetType,
    InvalidAssetValue,
    UnsupportedAssetType,
    normalize_asset_value,
    normalize_hostname,
    normalize_ip,
    normalize_url,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("  www.example.com.  ", "www.example.com"),
        ("Bücher.Example", "xn--bcher-kva.example"),
        ("straße.de", "xn--strae-oqa.de"),  # IDNA2008, not IDNA2003's "strasse.de"
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a-b.c-d.example", "a-b.c-d.example"),
    ],
)
def test_normalize_hostname(raw: str, expected: str) -> None:
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "localhost",
        "*.example.com",
        "_dmarc.example.com",
        "-bad.example.com",
        "bad-.example.com",
        "exa mple.com",
        "a..example.com",
        "example.123",
        "1.2.3.4",
        "2001:db8::1",
        "a" * 64 + ".com",
        ".".join(["a" * 63] * 4) + ".com",  # > 253 chars
    ],
)
def test_normalize_hostname_rejects_invalid(raw: str) -> None:
    with pytest.raises(InvalidAssetValue):
        normalize_hostname(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.0.2.1", "192.0.2.1"),
        (" 2001:DB8:0:0:0:0:0:1 ", "2001:db8::1"),
        ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
    ],
)
def test_normalize_ip(raw: str, expected: str) -> None:
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["", "300.1.1.1", "192.0.2", "example.com", "fe80::1%eth0"])
def test_normalize_ip_rejects_invalid(raw: str) -> None:
    with pytest.raises(InvalidAssetValue):
        normalize_ip(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM", "https://example.com/"),
        ("https://example.com:443/a?b=1#frag", "https://example.com/a?b=1"),
        ("http://example.com:80/", "http://example.com/"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        ("https://Bücher.example/Path", "https://xn--bcher-kva.example/Path"),
        ("http://192.0.2.1/", "http://192.0.2.1/"),
        ("http://[2001:DB8::1]:8443", "http://[2001:db8::1]:8443/"),
        ("https://www.example.com./login", "https://www.example.com/login"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com/",
        "javascript:alert(1)",
        "example.com/path",
        "https://user:secret@example.com/",
        "https://user@example.com/",
        "https:///path",
        "https://example.com:99999/",
        "https://exa mple.com/",
        "https://example.com/\x00",
        "https://*.example.com/",
        "https://example.com/" + "a" * MAX_URL_LENGTH,
    ],
)
def test_normalize_url_rejects_invalid(raw: str) -> None:
    with pytest.raises(InvalidAssetValue):
        normalize_url(raw)


def test_url_with_credentials_error_does_not_echo_them() -> None:
    with pytest.raises(InvalidAssetValue) as exc:
        normalize_url("https://admin:hunter2@example.com/")

    assert "hunter2" not in str(exc.value)


@pytest.mark.parametrize(
    ("asset_type", "raw", "expected"),
    [
        (AssetType.DOMAIN, "Example.com", "example.com"),
        (AssetType.SUBDOMAIN, "WWW.example.com", "www.example.com"),
        (AssetType.IP, "192.0.2.1", "192.0.2.1"),
        (AssetType.URL, "https://example.com", "https://example.com/"),
    ],
)
def test_normalize_asset_value_dispatches_by_type(
    asset_type: AssetType, raw: str, expected: str
) -> None:
    assert normalize_asset_value(asset_type, raw) == expected


@pytest.mark.parametrize("asset_type", [AssetType.REPO, AssetType.BINARY])
def test_repo_and_binary_are_not_supported_yet(asset_type: AssetType) -> None:
    with pytest.raises(UnsupportedAssetType):
        normalize_asset_value(asset_type, "anything")
