import pytest

from attacksurf.domain.assets import (
    MAX_URL_LENGTH,
    AssetType,
    InvalidAssetValue,
    normalize_asset_value,
    normalize_hostname,
    normalize_ip,
    normalize_url,
    upload_repo_value,
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
        # UTS46 maps capital sigma to small sigma; Python's lower() gives final sigma here.
        ("\u039f\u03a3-a.example", "xn---a-ibcq.example"),
        ("\u03bf\u03c3-a.example", "xn---a-ibcq.example"),
        ("例え。テスト。", "xn--r8jz45g.xn--zckzah"),  # ideographic full stops, root label
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
        "example.com..",  # only one root dot is dropped
        "1.2.3.4.",
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
        ("::ffff:c000:201", "::ffff:192.0.2.1"),  # same address, hex form: one canonical value
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
        ("https://example.com/%7Ealice", "https://example.com/~alice"),
        ("https://example.com/a%2fb?q=%41%3d", "https://example.com/a%2Fb?q=A%3D"),
        ("https://example.com/100%25", "https://example.com/100%25"),
        ("https://example.com/café?q=é", "https://example.com/caf%C3%A9?q=%C3%A9"),
        ("https://example.com/caf%c3%a9", "https://example.com/caf%C3%A9"),
        ("https://example.com/100%", "https://example.com/100%25"),
        ("https://example.com/%GG", "https://example.com/%25GG"),
        ("https://example.com/a|b?x=<y>", "https://example.com/a%7Cb?x=%3Cy%3E"),
        ("https://example.com/?", "https://example.com/?"),
        ("https://example.com?#frag", "https://example.com/?"),
        ("https://example.com/a/./b/../c", "https://example.com/a/c"),
        ("https://example.com/a/%2E%2E/b", "https://example.com/b"),
        ("https://example.com/../a", "https://example.com/a"),
        ("https://example.com/a/b/..", "https://example.com/a/"),
        ("https://example.com/a/.", "https://example.com/a/"),
        ("https://example.com//a/", "https://example.com//a/"),
        ("https://\u039f\u03a3-a.example:8443", "https://xn---a-ibcq.example:8443/"),
        ("https://\u03bf\u03c3-a.example:8443", "https://xn---a-ibcq.example:8443/"),
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
        "http://[::1",  # urlsplit itself raises
        "http://[127.0.0.1]/",  # IPv4 in brackets: urlsplit raises
        "http://[v1.foo]/",  # IPvFuture: would otherwise become the domain "v1.foo"
        "http://[::1]:x/",
        "https://example.com/\ud800",  # lone surrogate: not encodable as UTF-8
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


def test_binary_value_is_the_lowercase_sha256_of_its_bytes() -> None:
    digest = "AB" * 32

    value = normalize_asset_value(AssetType.BINARY, f" sha256:{digest} ")

    assert value == "sha256:" + "ab" * 32
    assert normalize_asset_value(AssetType.BINARY, value) == value


@pytest.mark.parametrize(
    "raw",
    ["", "anything", "ab" * 32, "sha256:" + "ab" * 31, "sha256:" + "zz" * 32, "md5:" + "ab" * 32],
)
def test_binary_value_rejects_anything_but_a_sha256_digest(raw: str) -> None:
    with pytest.raises(InvalidAssetValue):
        normalize_asset_value(AssetType.BINARY, raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("github.com/acme/app", "github.com/acme/app"),
        ("https://GitHub.com/Acme/App.git", "github.com/Acme/App"),
        ("  gitlab.com/group/sub/app/ ", "gitlab.com/group/sub/app"),
        ("upload/my-app", "upload/my-app"),
    ],
)
def test_repo_value_is_host_and_path_without_scheme_or_git_suffix(raw: str, expected: str) -> None:
    assert normalize_asset_value(AssetType.REPO, raw) == expected
    # Stored values are normalized again on every write: the result must be a fixed point.
    assert normalize_asset_value(AssetType.REPO, expected) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "github.com",
        "github.com/acme",
        "http://github.com/acme/app",
        "ssh://github.com/acme/app",
        "git@github.com:acme/app",
        "https://user:token@github.com/acme/app",
        "github.com/acme/app?ref=main",
        "github.com/acme/app#readme",
        "github.com/acme/../app",
        "github.com/./acme/app",
        "github.com/acme//app",
        "github.com/acme/app.git.git",
        "github.com/acme/app.GIT",
        "github.com/acme/app.Git.git",
        "github.com/acme/-app",
        "github.com/acme/a b",
        "github.com/acme/app%2e",
        "github.com\\acme\\app",
        "github.com:8443/acme/app",
        "localhost/acme/app",
        "upload/",
        "upload/My-App",
        "upload/a/b",
        "upload/..",
        "upload/" + "a" * 65,
    ],
)
def test_repo_value_rejects_anything_a_fetch_url_must_not_carry(raw: str) -> None:
    with pytest.raises(InvalidAssetValue):
        normalize_asset_value(AssetType.REPO, raw)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("My App.zip", "upload/my-app"),
        ("app-1.2.tar.gz", "upload/app-1.2"),
        ("src.TGZ", "upload/src"),
        ("../../etc/passwd.tar", "upload/passwd"),
        ("C:\\work\\Proj.tar.xz", "upload/proj"),
        ("<script>.zip", "upload/script"),
        ("...zip", "upload/archive"),
        ("", "upload/archive"),
        ("x" * 200 + ".zip", "upload/" + "x" * 64),
    ],
)
def test_upload_repo_value_is_a_bounded_slug_of_the_file_name(filename: str, expected: str) -> None:
    value = upload_repo_value(filename)

    assert value == expected
    assert normalize_asset_value(AssetType.REPO, value) == value
