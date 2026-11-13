"""MX hygiene checks (#19, ADR 0026).

`dns.mx` reads the domain's MX records (falling back to its registrable domain when the scanned
name publishes none) and checks every mail exchanger: an MX target must not be a CNAME
(RFC 5321 section 5.1) and must resolve to an address. A null MX (`0 .`) means the domain
accepts no mail and is not reported.

Answers are untrusted: targets are normalized, deduplicated and capped before any lookup, and
a failed per-target lookup fails open for that target. Only a round where every MX lookup
errored is retryable.
"""

from collections.abc import Sequence

from attacksurf.domain.findings import EvidenceKind
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
from attacksurf.scanners.registry import register_scanner

DNS_LOOKUPS = 20
MAX_MX_RECORDS = 10
MAX_TARGETS = 5
MAX_EVIDENCE_VALUES = 5
MAX_VALUE_LENGTH = 256
_MX_FIELDS = 2
TARGET_TYPES = (DnsRecordType.CNAME, DnsRecordType.A, DnsRecordType.AAAA)


@register_scanner
class DnsMailExchangers:
    name = "dns.mx"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        org_domain = runtime.org_domain(asset.value) if runtime.org_domain else None
        names = [asset.value]
        if org_domain is not None and org_domain != asset.value:
            names.append(org_domain)
        try:
            lookups = runtime.dns.lookup_many(
                tuple(DnsQuery(name, DnsRecordType.MX) for name in names)
            )
        except DnsError:
            raise TransientJobError("MX check failed.") from None
        if all(lookup.status is DnsStatus.ERROR for lookup in lookups):
            raise TransientJobError("MX check failed.")
        source = next((lookup for lookup in lookups if lookup.values), None)
        if source is None:
            return ScanOutput()
        targets = _targets(source.values)
        if not targets:
            return ScanOutput()
        results = _target_lookups(runtime.dns, targets)
        # Evidence names the name the MX RRset was actually read from: with the registrable
        # fallback that is the parent, and claiming the subdomain publishes those records
        # would send remediation to the wrong domain.
        return ScanOutput(
            findings=tuple(_findings(source.query.name, source.values, targets, results))
        )


def _target_lookups(
    dns: DnsResolver, targets: Sequence[str]
) -> dict[tuple[str, DnsRecordType], DnsLookup]:
    """One CNAME/A/AAAA round for every target; a failed round is skipped by the caller."""
    queries = tuple(
        DnsQuery(target, record_type) for target in targets for record_type in TARGET_TYPES
    )
    try:
        results = dns.lookup_many(queries)
    except DnsError:
        raise TransientJobError("MX check failed.") from None
    return {(result.query.name, result.query.record_type): result for result in results}


def _findings(
    domain: str,
    records: Sequence[str],
    targets: Sequence[str],
    results: dict[tuple[str, DnsRecordType], DnsLookup],
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for target in targets:
        cname = results[(target, DnsRecordType.CNAME)]
        addresses = [results[(target, DnsRecordType.A)], results[(target, DnsRecordType.AAAA)]]
        if cname.status is DnsStatus.OK and cname.values:
            findings.append(
                RawFinding(
                    rule_id="dns.mx.points_to_cname",
                    location=target,
                    evidence=(
                        _evidence("MX", domain, records),
                        _evidence("CNAME", target, cname.values),
                    ),
                    remediation_context={"domain": domain, "target": target},
                )
            )
            continue
        if any(lookup.status is DnsStatus.ERROR for lookup in addresses):
            continue  # a failed address lookup cannot prove the target is unresolvable
        if not any(lookup.values for lookup in addresses):
            findings.append(
                RawFinding(
                    rule_id="dns.mx.unresolvable",
                    location=target,
                    evidence=(
                        _evidence("MX", domain, records),
                        _evidence("A", target, ()),
                    ),
                    remediation_context={"domain": domain, "target": target},
                )
            )
    return findings


def _targets(records: Sequence[str]) -> tuple[str, ...]:
    """MX exchange hostnames; empty for a null MX (`0 .`), which accepts no mail (RFC 7505)."""
    targets: list[str] = []
    for record in records[:MAX_MX_RECORDS]:
        parts = record.split()
        if len(parts) != _MX_FIELDS:
            continue
        try:
            int(parts[0])
        except ValueError:
            continue
        host = parts[1].strip().rstrip(".").lower()
        if not host or host == ".":
            return ()  # null MX: the domain explicitly accepts no mail
        if host not in targets:
            targets.append(host)
        if len(targets) >= MAX_TARGETS:
            break
    return tuple(targets)


def _evidence(record: str, name: str, values: Sequence[str]) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={
            "record": record,
            "name": name,
            "values": [value[:MAX_VALUE_LENGTH] for value in values[:MAX_EVIDENCE_VALUES]],
        },
    )
