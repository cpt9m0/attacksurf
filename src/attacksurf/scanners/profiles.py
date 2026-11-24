"""Scan profiles select registered scanners by name."""

from attacksurf.domain.scanners import ScanProfile

MAX_DISCOVERED_ASSETS = 1000
# Scans of an uploaded or fetched codebase (#87). Deliberately not in `PROFILES`: no profile may
# select an analysis scanner before the first real analyzer ships (#84).
CODE_PROFILE = "code"
# Static analysis of an uploaded binary or mobile app (#101); kept out of `PROFILES` likewise.
BINARY_STATIC_PROFILE = "binary_static"

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
    ),
    "web_active": ScanProfile(
        name="web_active",
        discover=("web.probe",),
        checks=("web.components", "web.tls"),
        max_discovered_assets=MAX_DISCOVERED_ASSETS,
    ),
}

# Background-only monitoring profile for recurring scans (#27): read-only DNS configuration
# checks, no discovery, no target HTTP, no zone transfer. Not in `PROFILES`, so no user-facing
# scan-start route can select it.
SCHEDULED_DNS_PROFILE = "dns_scheduled"
WORKER_PROFILES = PROFILES | {
    SCHEDULED_DNS_PROFILE: ScanProfile(
        name=SCHEDULED_DNS_PROFILE,
        checks=("dns.resolve", "dns.email", "dns.dnssec"),
        # `dns.resolve` still emits new IP/CNAME assets, so keep the same per-root admission
        # cap as `dns_passive`: None would disable it in `persist_scan_output`.
        max_discovered_assets=MAX_DISCOVERED_ASSETS,
    ),
}
