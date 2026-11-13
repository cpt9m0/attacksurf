"""Domain registration checks via RDAP (#19, ADR 0026).

`dns.whois` reads the registrable domain's registration data through `ctx.runtime.rdap`
(IANA bootstrap, cached for 24 hours) and reports an approaching expiry
(`dns.whois.expiring_soon`: medium below 30 days, high below 7 days or already expired) and a
missing registrar transfer lock (`dns.whois.registrar_lock_missing`). RDAP status lists are
optional in practice, so an empty list is not treated as "no lock". When RDAP has no usable
answer the check fails open; no finding is invented.
"""

from datetime import UTC, datetime

from attacksurf.domain.findings import EvidenceKind, Severity
from attacksurf.domain.net import DomainRegistration
from attacksurf.domain.scanners import (
    AssetRef,
    AssetType,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.scanners.registry import register_scanner

DNS_LOOKUPS = 4
EXPIRY_HIGH_DAYS = 7
EXPIRY_MEDIUM_DAYS = 30
MAX_STATUSES = 20
TRANSFER_LOCK = "transfer prohibited"


@register_scanner
class DnsRegistration:
    name = "dns.whois"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(rdap=True, dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        org_domain = runtime.org_domain(asset.value) if runtime.org_domain else None
        domain = org_domain or asset.value
        registration = runtime.rdap.lookup(domain)
        if registration is None:
            return ScanOutput()
        findings: list[RawFinding] = []
        expiring = _expiring(domain, registration)
        if expiring is not None:
            findings.append(expiring)
        if registration.statuses and not any(
            TRANSFER_LOCK in status for status in registration.statuses
        ):
            findings.append(_lock_missing(domain, registration))
        return ScanOutput(findings=tuple(findings))


def _expiring(domain: str, registration: DomainRegistration) -> RawFinding | None:
    expires_at = registration.expires_at
    if expires_at is None:
        return None
    days = (expires_at - datetime.now(UTC)).days
    if days >= EXPIRY_MEDIUM_DAYS:
        return None
    return RawFinding(
        rule_id="dns.whois.expiring_soon",
        # Below a week (or already expired) the domain can lapse before a renewal is processed.
        severity=Severity.HIGH if days < EXPIRY_HIGH_DAYS else None,
        evidence=(_evidence(registration),),
        remediation_context={
            "domain": domain,
            "expires_at": expires_at.date().isoformat(),
            "days": str(days),
            "registrar": registration.registrar or "the registrar",
        },
    )


def _lock_missing(domain: str, registration: DomainRegistration) -> RawFinding:
    return RawFinding(
        rule_id="dns.whois.registrar_lock_missing",
        evidence=(_evidence(registration),),
        remediation_context={
            "domain": domain,
            "registrar": registration.registrar or "the registrar",
        },
    )


def _evidence(registration: DomainRegistration) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.RAW,
        data={
            "source": "rdap",
            "domain": registration.domain,
            "registrar": registration.registrar,
            "expires_at": (
                registration.expires_at.isoformat() if registration.expires_at else None
            ),
            "statuses": list(registration.statuses[:MAX_STATUSES]),
        },
    )
