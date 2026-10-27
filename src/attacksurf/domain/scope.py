"""Scope rules: what a scanner may reach, expressed without any network access (pure Python).

`infra.scope_guard` resolves names and hands the answers to these helpers; nothing here
performs I/O, so the rules are testable without mocks.
"""

import ipaddress
from enum import StrEnum

from attacksurf.domain.assets import AssetError, AssetType, normalize_hostname
from attacksurf.domain.jobs import JobError

# Names that never resolve on the public internet, so scanning them can only target our own
# network or a misconfiguration. A reserved label anywhere makes the name internal: the
# authoritative `.corp` zone can delegate `www.corp` wherever it likes, and no public zone
# uses these labels, so there is nothing legitimate to lose.
INTERNAL_TLDS = frozenset(
    {
        "alt",
        "corp",
        "home",
        "home.arpa",
        "internal",
        "intranet",
        "invalid",
        "lan",
        "local",
        "localdomain",
        "localhost",
        "private",
        "test",
    }
)
# Single-label names ("printer", "metadata") resolve via search domains: internal by design.
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})
# RFC 6598 shared address space, used by carrier NAT; `is_private` covers it only on newer
# Python patch releases, and containers often use it internally.
_CGNAT_MIN = int(ipaddress.IPv4Address("100.64.0.0"))
_CGNAT_MAX = int(ipaddress.IPv4Address("100.127.255.255"))


class ScopeError(JobError):
    """A target is out of scope. The message is shown to users: no resolved addresses in it."""


class ScopePolicyError(JobError):
    """A scanner asked for access its contract does not authorize (a plugin bug)."""


class HttpPermission(StrEnum):
    """Where a scanner may send HTTP requests. Never arbitrary hosts."""

    SERVICES = "services"  # only the scanner's declared `http_hosts` (CT logs, RDAP, ...)
    TARGET = "target"  # the scanned asset itself (active checks, after ownership proof)
    NONE = "none"  # DNS-only checks: any HTTP request is denied


class TargetKind(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"


class AddressError(ScopeError):
    """A name resolved to (or a literal was) an address we must not contact."""


class PublicSuffix(StrEnum):
    """What the Public Suffix List says about a hostname (classified in `infra`)."""

    ROOT = "root"  # registrable on its own: example.com
    SUBDOMAIN = "subdomain"  # under a registrable domain: www.example.com
    SUFFIX_ONLY = "suffix_only"  # a public suffix itself: com, co.uk
    NONE = "none"  # no known public suffix: internal or made-up TLD


def is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for addresses that must never be contacted (SSRF, internal network, metadata)."""
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            # ::ffff:127.0.0.1 is loopback; catch it on the IPv4 rules, not the "mapped" range.
            return is_blocked_address(mapped)
        embedded = address.sixtofour or (address.teredo[1] if address.teredo else None)
        if embedded is not None and is_blocked_address(embedded):
            return True
        # ULA, link-local, loopback, unspecified, multicast; reserved covers 64:ff9b::/96
        # (NAT64: protocol-dependent embedding) and documentation ranges.
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
    # Python 3.12.4+ folds most special ranges into `is_private`; the explicit checks keep
    # behavior identical on older patch releases and document what is covered.
    return (
        int(address) in range(_CGNAT_MIN, _CGNAT_MAX + 1)
        or address.is_private  # RFC1918, 0.0.0.0/8, 198.18/15, ...
        or address.is_loopback  # 127/8
        or address.is_link_local  # 169.254/16, incl. the 169.254.169.254 metadata endpoint
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def check_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and validate an address a scanner is about to contact."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AddressError("Targets must resolve to IP addresses.") from None
    if is_blocked_address(address):
        raise AddressError("Targets on private, loopback or special-purpose networks are blocked.")
    return address


def check_addresses(
    values: tuple[str, ...],
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Every resolved address must be public: a single internal record defeats pinning.

    Empty input means the name did not resolve; callers decide whether that is an error.
    """
    return tuple(check_address(value) for value in values)


def check_public_hostname(raw: str, suffix: PublicSuffix) -> str:
    """Validate a hostname that will be resolved and contacted (not stored).

    `suffix` classifies the Public Suffix List boundary; the domain layer takes it as a
    parameter instead of depending on `tldextract`. Single-label and internal names are
    rejected, so plumbing like `localhost` or a Kubernetes service name can never be scanned.
    IP literals are rejected too: callers resolve names, so an "IP domain" would skip the
    address checks that only run after resolution.
    """
    name = _normalize(raw)  # rejects IP literals with a dedicated error
    if name in _LOCAL_HOSTNAMES or "." not in name:
        raise ScopeError("Only publicly reachable domain names can be scanned.")
    if any(label in INTERNAL_TLDS for label in name.split(".")):
        raise ScopeError("Internal-only domain names can't be scanned.")
    if suffix is not PublicSuffix.ROOT and suffix is not PublicSuffix.SUBDOMAIN:
        # `NONE`: not under any known suffix. `SUFFIX_ONLY`: a bare public suffix ("co.uk").
        raise ScopeError("This domain doesn't end in a known public suffix.")
    return name


def _normalize(raw: str) -> str:
    try:
        return normalize_hostname(raw)
    except AssetError:
        raise ScopeError("That is not a valid public domain name.") from None


def is_domain_like(asset_type: AssetType) -> bool:
    """Domain assets and the subdomains discovery places under them."""
    return asset_type in {AssetType.DOMAIN, AssetType.SUBDOMAIN}


def asset_kind(asset_type: AssetType) -> TargetKind:
    """Which network checks make sense for an asset. Repo/binary assets are never network."""
    match asset_type:
        case AssetType.IP:
            return TargetKind.IP
        case AssetType.URL:
            return TargetKind.URL
        case _:
            return TargetKind.DOMAIN


def hostname_allowed(host: str, allowlist: frozenset[str]) -> bool:
    """Exact host or a subdomain of an allowlisted host (`crt.sh` covers `*.crt.sh`)."""
    candidate = host.lower().removesuffix(".")
    return any(candidate == allowed or candidate.endswith(f".{allowed}") for allowed in allowlist)
