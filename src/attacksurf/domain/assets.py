"""Assets: what an org owns or we discovered, and how values are normalized (pure Python)."""

import ipaddress
import re
from enum import StrEnum
from urllib.parse import urlsplit

import idna

MAX_HOSTNAME_LENGTH = 253
MAX_URL_LENGTH = 2048
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Anything a browser would percent-encode or strip; never valid inside a stored URL value.
_UNSAFE_URL_CHARS = re.compile(r"[\x00-\x20\x7f]")


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
    name = raw.strip().lower()
    name = name.removesuffix(".")
    if not name:
        raise InvalidAssetValue("Enter a domain name.")
    if _is_ip(name):
        raise InvalidAssetValue(f"{name!r} is an IP address, not a domain.")
    try:
        # UTS46 mapping + IDNA2008; stdlib "idna" codec is IDNA2003 and mishandles e.g. "ß".
        ascii_name = idna.encode(name, uts46=True).decode("ascii")
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
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise InvalidAssetValue(f"{value!r} is not a valid IP address.") from exc


def normalize_url(raw: str) -> str:
    """`scheme://host[:port]/path[?query]`: http(s) only, no credentials, no fragment."""
    value = raw.strip()
    if _UNSAFE_URL_CHARS.search(value):
        raise InvalidAssetValue("URLs can't contain spaces or control characters.")
    parts = urlsplit(value)
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

    if _is_ip(parts.hostname):
        ip = normalize_ip(parts.hostname)
        host = f"[{ip}]" if ":" in ip else ip
    else:
        host = normalize_hostname(parts.hostname)
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        host = f"{host}:{port}"
    url = f"{scheme}://{host}{parts.path or '/'}"
    if parts.query:
        url = f"{url}?{parts.query}"
    if len(url) > MAX_URL_LENGTH:
        raise InvalidAssetValue(f"URLs can be at most {MAX_URL_LENGTH} characters.")
    return url


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
