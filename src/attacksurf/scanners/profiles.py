"""Scan profiles select registered scanners by name."""

from attacksurf.domain.scanners import ScanProfile

MAX_DISCOVERED_ASSETS = 1000

PROFILES = {
    "dns_passive": ScanProfile(
        name="dns_passive",
        discover=("dns.discovery.ct",),
        checks=("dns.resolve", "dns.email"),
        max_discovered_assets=MAX_DISCOVERED_ASSETS,
    )
}
