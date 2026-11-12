"""The production profile must name a registered plugin and carry the discovery cap."""

from attacksurf.scanners.dns import discovery as _discovery  # noqa: F401
from attacksurf.scanners.dns import resolve as _resolve  # noqa: F401
from attacksurf.scanners.profiles import MAX_DISCOVERED_ASSETS, PROFILES
from attacksurf.scanners.registry import registry


def test_dns_passive_profile_is_valid_and_selects_the_ct_discovery_scanner() -> None:
    profile = PROFILES["dns_passive"]

    registry.validate(profile)

    assert profile.discover == ("dns.discovery.ct",)
    assert profile.checks == ("dns.resolve",)
    assert profile.max_discovered_assets == MAX_DISCOVERED_ASSETS
    scanner = registry.get(profile.discover[0])
    assert scanner.queue == "passive"
    assert not scanner.requires_verification
