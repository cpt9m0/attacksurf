"""Assets: what an org owns or we discovered, and how values are normalized (pure Python)."""

import ipaddress
import re
import string
from enum import StrEnum
from urllib.parse import urlsplit

import idna

MAX_HOSTNAME_LENGTH = 253
MAX_URL_LENGTH = 2048
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Anything a browser would percent-encode or strip; never valid inside a stored URL value.
_UNSAFE_URL_CHARS = re.compile(r"[\x00-\x20\x7f]")
_PERCENT_ENCODED = re.compile(r"%([0-9A-Fa-f]{2})")
# Characters RFC 3986 doesn't allow in a path or query (incl. non-ASCII and a "%" that
# doesn't start an escape); they get UTF-8 percent-encoded, as browsers do.
_NOT_URI_CHAR = re.compile(r"%(?![0-9A-Fa-f]{2})|[^A-Za-z0-9\-._~!$&'()*+,;=:@/?%]")
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")


class AssetType(StrEnum):
    DOMAIN = "domain"  # a root domain the org registers
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    REPO = "repo"
    BINARY = "binary"


class AssetSource(StrEnum):
    USER = "user"
    DISCOVERED = "discovered"


class RelationKind(StrEnum):
    RESOLVES_TO = "resolves_to"
    CNAME_TO = "cname_to"
    SUBDOMAIN_OF = "subdomain_of"
    SERVES = "serves"


class AssetError(Exception):
    """Base for asset errors that `web/` maps to user-facing messages."""


class InvalidAssetValue(AssetError):
    pass


class UnsupportedAssetType(AssetError):
    """The type exists in the model but has no normalization yet (repo, binary)."""


class AssetNotFound(AssetError):
    """The asset doesn't exist or belongs to another org (never says which)."""


def normalize_asset_value(asset_type: AssetType, raw: str) -> str:
    """Canonical form used for storage and the `(org_id, type, value)` uniqueness."""
    match asset_type:
        case AssetType.DOMAIN | AssetType.SUBDOMAIN:
            return normalize_hostname(raw)
        case AssetType.IP:
            return normalize_ip(raw)
        case AssetType.URL:
            return normalize_url(raw)
        case AssetType.REPO | AssetType.BINARY:
            raise UnsupportedAssetType(f"{asset_type} assets are not supported yet")


def normalize_hostname(raw: str) -> str:
    """Lowercase ASCII (punycode) hostname without trailing dot, e.g. `xn--bcher-kva.example`."""
    # No str.lower() first: UTS46 does the case mapping, and Python's context-sensitive
    # lowercasing differs from it (a word-final capital sigma becomes final, not small, sigma).
    name = raw.strip()
    if not name.removesuffix("."):
        raise InvalidAssetValue("Enter a domain name.")
    if _is_ip(name.removesuffix(".")):
        raise InvalidAssetValue(f"{name!r} is an IP address, not a domain.")
    try:
        # UTS46 mapping + IDNA2008; stdlib "idna" codec is IDNA2003 and mishandles e.g. "ß".
        # The root dot is dropped only after mapping: UTS46 also maps e.g. "。" to ".".
        ascii_name = idna.encode(name, uts46=True).decode("ascii").removesuffix(".")
    except idna.IDNAError as exc:
        raise InvalidAssetValue(f"{raw.strip()!r} is not a valid domain name.") from exc
    labels = ascii_name.split(".")
    if (
        len(ascii_name) > MAX_HOSTNAME_LENGTH
        or len(labels) < 2  # noqa: PLR2004
        or not all(_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise InvalidAssetValue(f"{raw.strip()!r} is not a valid domain name.")
    return ascii_name


def normalize_ip(raw: str) -> str:
    """Canonical IPv4/IPv6 text (`ipaddress` compression). Zone IDs are rejected."""
    value = raw.strip()
    if "%" in value:
        raise InvalidAssetValue("IPv6 zone IDs are not allowed.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InvalidAssetValue(f"{value!r} is not a valid IP address.") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Python 3.13 prints these dotted, 3.12 in hex: pin one form so stored values (and
        # uniqueness) don't depend on the interpreter version.
        return f"::ffff:{address.ipv4_mapped}"
    return str(address)


def normalize_url(raw: str) -> str:
    """`scheme://host[:port]/path[?query]`: http(s) only, no credentials, no fragment."""
    value = raw.strip()
    if _UNSAFE_URL_CHARS.search(value):
        raise InvalidAssetValue("URLs can't contain spaces or control characters.")
    try:
        parts = urlsplit(value)
    except ValueError as exc:  # e.g. unbalanced or IPv4-in-brackets hosts: "http://[::1"
        raise InvalidAssetValue("The URL is malformed.") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidAssetValue("Only http and https URLs are supported.")
    if parts.username is not None or parts.password is not None:
        # Never store credentials that came embedded in a URL.
        raise InvalidAssetValue("URLs must not contain credentials.")
    if not parts.hostname:
        raise InvalidAssetValue("The URL has no host.")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidAssetValue("The URL has an invalid port.") from exc

    host = _normalize_url_host(parts.netloc, parts.hostname)
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        host = f"{host}:{port}"
    try:
        path = _remove_dot_segments(_normalize_percent_encoding(parts.path))
        query = _normalize_percent_encoding(parts.query)
    except UnicodeEncodeError as exc:  # lone surrogates
        raise InvalidAssetValue("The URL is malformed.") from exc
    url = f"{scheme}://{host}{path}"
    # An empty query ("/?") is a distinct URI from no query ("/"), but urlsplit drops the "?".
    if query or "?" in value.partition("#")[0]:
        url = f"{url}?{query}"
    if len(url) > MAX_URL_LENGTH:
        raise InvalidAssetValue(f"URLs can be at most {MAX_URL_LENGTH} characters.")
    return url


def _normalize_url_host(netloc: str, hostname: str) -> str:
    if "[" in netloc:
        # Brackets mean an IPv6 literal. Anything else in them (IPvFuture "[v1.foo]") would
        # otherwise be stored as the unrelated DNS name "v1.foo".
        if not _is_ipv6(hostname):
            raise InvalidAssetValue("Only IPv6 addresses may appear in brackets.")
        return f"[{normalize_ip(hostname)}]"
    # From netloc, not `hostname`: urlsplit lowercases that with str.lower(), which UTS46
    # would map differently (see normalize_hostname). Credentials were rejected already.
    host = netloc.partition(":")[0]
    if _is_ip(host):
        return normalize_ip(host)
    return normalize_hostname(host)


def _normalize_percent_encoding(component: str) -> str:
    """RFC 3986 6.2.2 (+ RFC 3987 3.1 for IRIs): percent-encode what isn't allowed, decode
    unreserved characters, uppercase the hex of everything else.

    Otherwise `/%7Ealice` and `/~alice` (or `/café` and `/caf%C3%A9`, `/a|b` and `/a%7Cb`)
    would be two assets for the same resource.
    """

    def encode(match: re.Match[str]) -> str:
        return "".join(f"%{byte:02X}" for byte in match.group().encode())

    def canonical(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else f"%{match.group(1).upper()}"

    return _PERCENT_ENCODED.sub(canonical, _NOT_URI_CHAR.sub(encode, component))


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4 for an absolute path: `/a/./b/../c` -> `/a/c`. Empty path -> `/`."""
    segments = path.split("/")[1:]
    output: list[str] = []
    for segment in segments:
        if segment == "..":
            if output:
                output.pop()
        elif segment != ".":
            output.append(segment)
    if segments and segments[-1] in {".", ".."}:
        output.append("")  # "/a/b/.." -> "/a/", not "/a"
    return "/" + "/".join(output)


def _is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
