"""Scan profiles select registered scanners by name."""

from attacksurf.domain.scanners import ScanProfile

MAX_DISCOVERED_ASSETS = 1000
# Scans of an uploaded or fetched codebase (#87). Deliberately not in `PROFILES`: no profile may
# select an analysis scanner before the first real analyzer ships (#84).
CODE_PROFILE = "code"

PROFILES = {
    "dns_passive": ScanProfile(
        name="dns_passive",
        discover=("dns.discovery.ct",),
        checks=(
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
        ),
        max_discovered_assets=MAX_DISCOVERED_ASSETS,
    )
}
