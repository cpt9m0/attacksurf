"""The production profile must name a registered plugin and carry the discovery cap."""

from attacksurf.scanners.dns import axfr as _axfr  # noqa: F401
from attacksurf.scanners.dns import caa as _caa  # noqa: F401
from attacksurf.scanners.dns import discovery as _discovery  # noqa: F401
from attacksurf.scanners.dns import dnssec as _dnssec  # noqa: F401
from attacksurf.scanners.dns import email as _email  # noqa: F401
from attacksurf.scanners.dns import mx as _mx  # noqa: F401
from attacksurf.scanners.dns import ns as _ns  # noqa: F401
from attacksurf.scanners.dns import resolve as _resolve  # noqa: F401
from attacksurf.scanners.dns import takeover as _takeover  # noqa: F401
from attacksurf.scanners.dns import takeover_http as _takeover_http  # noqa: F401
from attacksurf.scanners.dns import whois as _whois  # noqa: F401
from attacksurf.scanners.profiles import MAX_DISCOVERED_ASSETS, PROFILES
from attacksurf.scanners.registry import registry


def test_dns_passive_profile_is_valid_and_selects_the_ct_discovery_scanner() -> None:
    profile = PROFILES["dns_passive"]

    registry.validate(profile)

    assert profile.discover == ("dns.discovery.ct",)
    assert profile.checks == (
        "dns.resolve",
        "dns.email",
        "dns.takeover",
        "dns.takeover.http",
        "dns.dnssec",
        "dns.ns",
        "dns.mx",
        "dns.caa",
        "dns.whois",
        "dns.axfr",
    )
    assert profile.max_discovered_assets == MAX_DISCOVERED_ASSETS
    scanner = registry.get(profile.discover[0])
    assert scanner.queue == "passive"
    assert not scanner.requires_verification
