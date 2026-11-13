"""Flag dangling CNAME and NS delegations from DNS alone (#18).

A passive, check-only plugin: it reads the asset's CNAME chain and NS delegation through
ScopeGuard and compares the terminal names with the pinned takeover fingerprint dataset
(`fingerprints.py`). A dangling CNAME is reported only when the target is a known-claimable
service whose deprovisioned instances stop resolving; services that keep resolving are left
to `dns.takeover.http`, which can read the service's "not found" signature. An NS delegation
is reported when a delegated nameserver's name itself no longer resolves. The scanner never
claims, registers or contacts anything; it only reports what DNS already says.
"""

from collections.abc import Sequence

from attacksurf.domain.assets import AssetError, normalize_hostname
from attacksurf.domain.findings import Confidence, EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    DnsError,
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsResolver,
    DnsStatus,
)
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
from attacksurf.domain.scope import HttpPermission
from attacksurf.scanners.dns.fingerprints import (
    Fingerprint,
    load_fingerprints,
    match_service,
)
from attacksurf.scanners.registry import register_scanner

MAX_CNAME_DEPTH = 5
MAX_NS_HOSTS = 5
MAX_EVIDENCE_VALUES = 5
MAX_HOSTNAME_LENGTH = 253
MAX_VALUE_LENGTH = 256
# 2 initial (CNAME + NS) + chain follows + terminal A + up to MAX_NS_HOSTS nameserver A lookups.
DNS_LOOKUPS = 16


@register_scanner
class DnsTakeover:
    name = "dns.takeover"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(dns_lookups=DNS_LOOKUPS, http=HttpPermission.NONE)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        try:
            initial = runtime.dns.lookup_many(
                (
                    DnsQuery(asset.value, DnsRecordType.CNAME),
                    DnsQuery(asset.value, DnsRecordType.NS),
                )
            )
        except DnsError:
            raise TransientJobError("Subdomain takeover check failed.") from None
        if all(result.status is DnsStatus.ERROR for result in initial):
            raise TransientJobError("Subdomain takeover check failed.")
        by_type = {result.query.record_type: result for result in initial}
        fingerprints = load_fingerprints()
        findings: list[RawFinding] = []
        chain, chain_error = cname_chain(runtime.dns, asset.value, by_type[DnsRecordType.CNAME])
        cname_finding = _dangling_cname(runtime.dns, asset, chain, chain_error, fingerprints)
        if cname_finding is not None:
            findings.append(cname_finding)
        findings.extend(_dangling_ns(runtime.dns, asset, by_type[DnsRecordType.NS]))
        return ScanOutput(findings=tuple(findings))


def cname_chain(dns: DnsResolver, start: str, first: DnsLookup) -> tuple[tuple[str, ...], bool]:
    """Follow CNAMEs up to the depth cap; the bool reports a lookup error, not a missing hop.

    Shared with `dns.takeover.http`: both plugins need the same chain for service matching
    and evidence, and neither may read what `dns.resolve` persisted.
    """
    chain = [start]
    seen = {start}
    lookup = first
    for _ in range(MAX_CNAME_DEPTH):
        if lookup.status is DnsStatus.ERROR:
            return tuple(chain), True
        if lookup.status is not DnsStatus.OK or not lookup.values:
            return tuple(chain), False
        target = _hostname(lookup.values[0])
        if target is None or target in seen:
            return tuple(chain), False
        chain.append(target)
        seen.add(target)
        try:
            lookup = dns.lookup_many((DnsQuery(target, DnsRecordType.CNAME),))[0]
        except DnsError:
            return tuple(chain), True
    return tuple(chain), False


def _dangling_cname(
    dns: DnsResolver,
    asset: AssetRef,
    chain: tuple[str, ...],
    chain_error: bool,
    fingerprints: tuple[Fingerprint, ...],
) -> RawFinding | None:
    if chain_error or len(chain) == 1:
        return None
    terminal = chain[-1]
    service = match_service(fingerprints, terminal)
    if service is None or not service.nxdomain:
        return None  # unknown claimability, or the service resolves: the HTTP check decides
    try:
        terminal_lookup = dns.lookup_many((DnsQuery(terminal, DnsRecordType.A),))[0]
    except DnsError:
        return None
    if terminal_lookup.status is not DnsStatus.NXDOMAIN:
        return None
    return RawFinding(
        rule_id="dns.takeover.dangling_cname",
        location=terminal,
        confidence=Confidence.HIGH,
        evidence=(
            _evidence("CNAME", asset.value, chain),
            _status_evidence("A", terminal, terminal_lookup.status),
        ),
        remediation_context={
            "domain": asset.value,
            "target": terminal,
            "service": service.service,
        },
    )


def _dangling_ns(dns: DnsResolver, asset: AssetRef, ns_lookup: DnsLookup) -> list[RawFinding]:
    if ns_lookup.status is DnsStatus.ERROR:
        return []
    hosts: list[str] = []
    for raw in _values(ns_lookup):
        host = _hostname(raw)
        if host is not None and host not in hosts:
            hosts.append(host)
        if len(hosts) >= MAX_NS_HOSTS:
            break
    if not hosts:
        return []
    try:
        results = dns.lookup_many(tuple(DnsQuery(host, DnsRecordType.A) for host in hosts))
    except DnsError:
        return []
    findings: list[RawFinding] = []
    for host, result in zip(hosts, results, strict=True):
        if result.status is not DnsStatus.NXDOMAIN:
            continue  # resolving, empty and failed answers are not proof of a lapsed name
        findings.append(
            RawFinding(
                rule_id="dns.takeover.dangling_ns",
                location=host,
                # NXDOMAIN proves the delegation is broken; that the nameserver's own
                # domain can be re-registered is the inference, hence not high.
                confidence=Confidence.MEDIUM,
                evidence=(
                    _evidence("NS", asset.value, tuple(hosts)),
                    _status_evidence("A", host, result.status),
                ),
                remediation_context={"domain": asset.value, "target": host},
            )
        )
    return findings


def _values(lookup: DnsLookup) -> tuple[str, ...]:
    if lookup.status is not DnsStatus.OK:
        return ()
    seen: set[str] = set()
    result: list[str] = []
    for raw in lookup.values:
        value = raw.strip().replace("\x00", "\\0")
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _hostname(raw: str) -> str | None:
    """Normalize a DNS name (trailing dot stripped); None for anything not a hostname."""
    candidate = raw.strip().removesuffix(".")
    if not candidate or len(candidate) > MAX_HOSTNAME_LENGTH:
        return None
    try:
        return normalize_hostname(candidate)
    except (AssetError, ValueError, UnicodeError):
        return None


def _evidence(record: str, name: str, values: Sequence[str]) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={
            "record": record,
            "name": name,
            "values": [value[:MAX_VALUE_LENGTH] for value in values[:MAX_EVIDENCE_VALUES]],
        },
    )


def _status_evidence(record: str, name: str, status: DnsStatus) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={"record": record, "name": name, "values": [], "status": status.value},
    )
