"""Production profiles must name registered plugins, carry the discovery cap, and select no
analysis scanner."""

from attacksurf.domain.scope import HttpPermission
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
from attacksurf.scanners.profiles import MAX_DISCOVERED_ASSETS, PROFILES, WORKER_PROFILES
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


def test_scheduled_profile_is_dns_only_and_not_public() -> None:
    profile = WORKER_PROFILES["dns_scheduled"]

    registry.validate(profile)
    assert "dns_scheduled" not in PROFILES
    assert not profile.discover
    assert profile.checks == ("dns.resolve", "dns.email", "dns.dnssec")
    # `dns.resolve` still emits new IP/CNAME assets: keep the same admission cap as `dns_passive`.
    assert profile.max_discovered_assets == MAX_DISCOVERED_ASSETS
    for name in profile.checks:
        scanner = registry.get(name)
        assert scanner.queue == "passive"
        assert scanner.grant.http is HttpPermission.NONE
        assert not scanner.grant.zone_transfer
        assert not scanner.grant.sandbox_analyzers
        assert not scanner.grant.rdap


def test_no_profile_selects_an_analysis_scanner() -> None:
    for profile in PROFILES.values():
        for name in profile.discover + profile.checks:
            scanner = registry.get(name)

            needs_analyzer = scanner.queue == "analysis" or bool(scanner.grant.sandbox_analyzers)

            assert not needs_analyzer, (
                f"profile {profile.name!r} selects {name!r}, which needs a sandbox analyzer; "
                "no profile may until the first analyzer ships (ADR 0031 / #92)"
            )
