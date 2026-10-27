"""Pure scope rules: which hosts, answers and URL targets a scanner may touch."""

import ipaddress

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scope import (
    INTERNAL_TLDS,
    AddressError,
    PublicSuffix,
    ScopeError,
    TargetKind,
    asset_kind,
    check_address,
    check_addresses,
    check_public_hostname,
    hostname_allowed,
    is_blocked_address,
    is_domain_like,
)

BLOCKED = [
    "0.0.0.0",  # noqa: S104 - an address to block, not a bind target
    "0.0.0.1",
    "10.0.0.1",
    "10.255.255.255",
    "100.64.0.1",  # CGNAT
    "127.0.0.1",
    "127.1.2.3",
    "169.254.169.254",  # cloud metadata
    "172.16.0.1",
    "192.0.0.1",
    "192.0.2.1",  # TEST-NET-1
    "192.168.1.1",
    "198.18.0.1",  # benchmarking
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "255.255.255.255",
]
BLOCKED_V6 = [
    "::",
    "::1",  # loopback
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
    "::ffff:10.1.2.3",  # IPv4-mapped RFC1918
    "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
    "2001:db8::1",  # documentation
    "2002:a00:1::",  # 6to4 wrapping 10.0.0.1
    "fc00::1",  # ULA
    "fd12:3456::1",
    "fe80::1",  # link-local
    ["fe80::1", "eth0"][0],
    "ff02::1",  # multicast
]
PUBLIC = [
    "1.1.1.1",
    "8.8.8.8",
    "93.184.216.34",
    "203.114.1.1",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
]


@pytest.mark.parametrize("value", BLOCKED + BLOCKED_V6)
def test_internal_and_special_addresses_are_blocked(value: str) -> None:
    assert is_blocked_address(ipaddress.ip_address(value)) is True
    with pytest.raises(AddressError):
        check_address(value)


@pytest.mark.parametrize("value", PUBLIC)
def test_public_addresses_are_allowed(value: str) -> None:
    assert is_blocked_address(ipaddress.ip_address(value)) is False
    assert str(check_address(value)) == value


def test_mapped_addresses_follow_the_ipv4_rules() -> None:
    # Guards against treating ::ffff:127.0.0.1 as a public "IPv6" address.
    assert is_blocked_address(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert is_blocked_address(ipaddress.ip_address("::ffff:8.8.8.8")) is False


def test_non_addresses_are_rejected_without_echoing_input() -> None:
    with pytest.raises(AddressError, match="IP addresses"):
        check_address("not-an-address")


def test_one_blocked_answer_blocks_the_whole_name() -> None:
    # A split answer (public + private) is how rebinding defeats single-record checks.
    with pytest.raises(AddressError):
        check_addresses(("93.184.216.34", "127.0.0.1"))
    assert check_addresses(("93.184.216.34", "1.1.1.1")) == (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("1.1.1.1"),
    )
    assert check_addresses(()) == ()


def test_public_hostnames_are_normalized_and_accepted() -> None:
    assert check_public_hostname("WWW.Example.COM.", PublicSuffix.SUBDOMAIN) == "www.example.com"
    assert check_public_hostname("www.example.com", PublicSuffix.SUBDOMAIN) == "www.example.com"
    # A public suffix on its own never resolves to a host: rejected by the PSL classification.
    with pytest.raises(ScopeError, match="public suffix"):
        check_public_hostname("co.uk", PublicSuffix.SUFFIX_ONLY)
    # `.example` is reserved (ICANN never delegated it): it only resolves via internal DNS.
    with pytest.raises(ScopeError):
        check_public_hostname("printer.example", PublicSuffix.NONE)


@pytest.mark.parametrize("host", ["foo.bar.unknowntld", "foo.local", "intranet", "localhost"])
def test_unknown_suffixes_and_single_labels_are_rejected(host: str) -> None:
    with pytest.raises(ScopeError):
        check_public_hostname(host, PublicSuffix.NONE)


@pytest.mark.parametrize("tld", sorted(INTERNAL_TLDS))
def test_internal_tlds_are_rejected_in_any_position(tld: str) -> None:
    with pytest.raises(ScopeError, match="Internal-only"):
        check_public_hostname(f"host.{tld}", PublicSuffix.SUBDOMAIN)


def test_internal_label_is_rejected_even_under_a_public_domain() -> None:
    with pytest.raises(ScopeError, match="Internal-only"):
        check_public_hostname("printer.corp.example.com", PublicSuffix.SUBDOMAIN)


def test_ip_literals_are_not_accepted_as_hostnames() -> None:
    with pytest.raises(ScopeError):
        check_public_hostname("127.0.0.1", PublicSuffix.NONE)


@pytest.mark.parametrize(
    ("url_host", "allowed"),
    [
        ("crt.sh", True),
        ("api.crt.sh", True),
        ("CRT.SH", True),
        ("evilcrt.sh", False),
        ("crt.sh.evil.example", False),
    ],
)
def test_service_allowlist_matches_host_and_subdomains(url_host: str, allowed: bool) -> None:
    assert hostname_allowed(url_host, frozenset({"crt.sh"})) is allowed


def test_asset_helpers_classify_network_types() -> None:
    assert is_domain_like(AssetType.DOMAIN)
    assert is_domain_like(AssetType.SUBDOMAIN)
    assert not is_domain_like(AssetType.IP)
    assert asset_kind(AssetType.IP) is TargetKind.IP
    assert asset_kind(AssetType.URL) is TargetKind.URL
    assert asset_kind(AssetType.DOMAIN) is TargetKind.DOMAIN
